/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.payment.relay

import akka.actor.ActorRef
import akka.actor.testkit.typed.scaladsl.{ScalaTestWithActorTestKit, TestProbe}
import akka.actor.typed.eventstream.EventStream
import akka.actor.typed.scaladsl.Behaviors
import akka.actor.typed.scaladsl.adapter.{TypedActorContextOps, TypedActorRefOps}
import com.typesafe.config.ConfigFactory
import fr.acinq.bitcoin.scalacompat.ByteVector32
import fr.acinq.eclair.channel._
import fr.acinq.eclair.crypto.Sphinx
import fr.acinq.eclair.payment.IncomingPaymentPacket.FinalPacket
import fr.acinq.eclair.payment.OutgoingPaymentPacket.{Upstream, buildCommand}
import fr.acinq.eclair.payment.PaymentPacketSpec._
import fr.acinq.eclair.payment.relay.Relayer._
import fr.acinq.eclair.payment.{OutgoingPaymentPacket, PaymentPacketSpec}
import fr.acinq.eclair.router.BaseRouterSpec.channelHopFromUpdate
import fr.acinq.eclair.router.Router.NodeHop
import fr.acinq.eclair.wire.protocol.PaymentOnion.FinalPayload
import fr.acinq.eclair.wire.protocol._
import fr.acinq.eclair.{NodeParams, TestConstants, randomBytes32, _}
import org.scalatest.concurrent.PatienceConfiguration
import org.scalatest.funsuite.FixtureAnyFunSuiteLike
import org.scalatest.{Outcome, Tag}

import java.util.UUID
import scala.concurrent.duration.DurationInt
import scala.util.Success

class RelayerSpec extends ScalaTestWithActorTestKit(ConfigFactory.load("application")) with FixtureAnyFunSuiteLike {

  case class FixtureParam(nodeParams: NodeParams, relayer: akka.actor.ActorRef, router: TestProbe[Any], register: TestProbe[Any], childActors: ChildActors, paymentHandler: TestProbe[Any])

  override def withFixture(test: OneArgTest): Outcome = {
    // we are node B in the route A -> B -> C -> ....
    val disableTrampoline = test.tags.contains("trampoline-disabled")
    val nodeParams = TestConstants.Bob.nodeParams.copy(enableTrampolinePayment = !disableTrampoline)
    val router = TestProbe[Any]("router")
    val register = TestProbe[Any]("register")
    val paymentHandler = TestProbe[Any]("payment-handler")
    val probe = TestProbe[Any]()
    // we can't spawn top-level actors with akka typed
    testKit.spawn(Behaviors.setup[Any] { context =>
      val relayer = context.toClassic.actorOf(Relayer.props(nodeParams, router.ref.toClassic, register.ref.toClassic, paymentHandler.ref.toClassic))
      probe.ref ! relayer
      Behaviors.empty[Any]
    })
    val relayer = probe.expectMessageType[akka.actor.ActorRef]
    relayer ! GetChildActors(probe.ref.toClassic)
    val childActors = probe.expectMessageType[ChildActors]
    withFixture(test.toNoArgTest(FixtureParam(nodeParams, relayer, router, register, childActors, paymentHandler)))
  }

  val channelId_ab = randomBytes32()
  val channelId_bc = randomBytes32()

  test("relay an htlc-add") { f =>
    import f._

    // We make sure the channel relayer is initialized
    val sender = TestProbe[Relayer.OutgoingChannels]()
    childActors.channelRelayer ! ChannelRelayer.GetOutgoingChannels(sender.ref.toClassic, GetOutgoingChannels())
    assert(sender.expectMessageType[Relayer.OutgoingChannels].channels.isEmpty)

    // We publish a channel update, that should be picked up by the channel relayer
    val shortIds_bc = ShortIds(RealScidStatus.Final(RealShortChannelId(channelUpdate_bc.shortChannelId.toLong)), ShortChannelId.generateLocalAlias(), remoteAlias_opt = None)
    system.eventStream ! EventStream.Publish(LocalChannelUpdate(null, channelId_bc, shortIds_bc, c, None, channelUpdate_bc, makeCommitments(channelId_bc)))
    eventually(PatienceConfiguration.Timeout(30 seconds), PatienceConfiguration.Interval(1 second)) {
      childActors.channelRelayer ! ChannelRelayer.GetOutgoingChannels(sender.ref.toClassic, GetOutgoingChannels())
      val channels = sender.expectMessageType[Relayer.OutgoingChannels].channels
      require(channels.nonEmpty)
    }

    // we use this to build a valid onion
    val Success((cmd, _)) = buildCommand(ActorRef.noSender, Upstream.Local(UUID.randomUUID()), paymentHash, hops, FinalPayload.Standard.createSinglePartPayload(finalAmount, finalExpiry, paymentSecret, None))
    // and then manually build an htlc
    val add_ab = UpdateAddHtlc(channelId = randomBytes32(), id = 123456, cmd.amount, cmd.paymentHash, cmd.cltvExpiry, cmd.onion, None)
    relayer ! RelayForward(add_ab)
    register.expectMessageType[Register.Forward[CMD_ADD_HTLC]]
  }

  test("relay an htlc-add at the final node to the payment handler") { f =>
    import f._

    val Success((cmd, _)) = buildCommand(ActorRef.noSender, Upstream.Local(UUID.randomUUID()), paymentHash, hops.take(1), FinalPayload.Standard.createSinglePartPayload(finalAmount, finalExpiry, paymentSecret, None))
    val add_ab = UpdateAddHtlc(channelId = channelId_ab, id = 123456, cmd.amount, cmd.paymentHash, cmd.cltvExpiry, cmd.onion, None)

    relayer ! RelayForward(add_ab)

    val fp = paymentHandler.expectMessageType[FinalPacket]
    assert(fp.add == add_ab)
    assert(fp.payload == FinalPayload.Standard.createSinglePartPayload(finalAmount, finalExpiry, paymentSecret, None))

    register.expectNoMessage(50 millis)
  }

  test("relay a trampoline htlc-add at the final node to the payment handler") { f =>
    import PaymentPacketSpec._
    import f._
    val a = PaymentPacketSpec.a

    // We simulate a payment split between multiple trampoline routes.
    val totalAmount = finalAmount * 3
    val trampolineHops = NodeHop(a, b, channelUpdate_ab.cltvExpiryDelta, 0 msat) :: Nil
    val Success((trampolineAmount, trampolineExpiry, trampolineOnion)) = OutgoingPaymentPacket.buildTrampolinePacket(paymentHash, trampolineHops, FinalPayload.Standard.createMultiPartPayload(finalAmount, totalAmount, finalExpiry, paymentSecret, None))
    assert(trampolineAmount == finalAmount)
    assert(trampolineExpiry == finalExpiry)
    val Success((cmd, _)) = buildCommand(ActorRef.noSender, Upstream.Local(UUID.randomUUID()), paymentHash, channelHopFromUpdate(a, b, channelUpdate_ab) :: Nil, FinalPayload.Standard.createTrampolinePayload(trampolineAmount, trampolineAmount, trampolineExpiry, randomBytes32(), trampolineOnion.packet))
    assert(cmd.amount == finalAmount)
    assert(cmd.cltvExpiry == finalExpiry)
    val add_ab = UpdateAddHtlc(channelId = channelId_ab, id = 123456, cmd.amount, cmd.paymentHash, cmd.cltvExpiry, cmd.onion, None)

    relayer ! RelayForward(add_ab)

    val fp = paymentHandler.expectMessageType[FinalPacket]
    assert(fp.add == add_ab)
    assert(fp.payload.isInstanceOf[FinalPayload.Standard])
    assert(fp.payload.amount == finalAmount)
    assert(fp.payload.totalAmount == totalAmount)
    assert(fp.payload.expiry == finalExpiry)
    assert(fp.payload.asInstanceOf[FinalPayload.Standard].paymentSecret == paymentSecret)

    register.expectNoMessage(50 millis)
  }

  test("fail to relay an htlc-add when the onion is malformed") { f =>
    import f._

    // we use this to build a valid onion
    val Success((cmd, _)) = buildCommand(ActorRef.noSender, Upstream.Local(UUID.randomUUID()), paymentHash, hops, FinalPayload.Standard.createSinglePartPayload(finalAmount, finalExpiry, paymentSecret, None))
    // and then manually build an htlc with an invalid onion (hmac)
    val add_ab = UpdateAddHtlc(channelId = channelId_ab, id = 123456, cmd.amount, cmd.paymentHash, cmd.cltvExpiry, cmd.onion.copy(hmac = cmd.onion.hmac.reverse), None)

    relayer ! RelayForward(add_ab)

    val fail = register.expectMessageType[Register.Forward[CMD_FAIL_MALFORMED_HTLC]].message
    assert(fail.id == add_ab.id)
    assert(fail.onionHash == Sphinx.hash(add_ab.onionRoutingPacket))
    assert(fail.failureCode == (FailureMessageCodecs.BADONION | FailureMessageCodecs.PERM | 5))

    register.expectNoMessage(50 millis)
  }

  test("fail to relay a trampoline htlc-add when trampoline is disabled", Tag("trampoline-disabled")) { f =>
    import PaymentPacketSpec._
    import f._
    val a = PaymentPacketSpec.a

    // we use this to build a valid trampoline onion inside a normal onion
    val trampolineHops = NodeHop(a, b, channelUpdate_ab.cltvExpiryDelta, 0 msat) :: NodeHop(b, c, channelUpdate_bc.cltvExpiryDelta, fee_b) :: Nil
    val Success((trampolineAmount, trampolineExpiry, trampolineOnion)) = OutgoingPaymentPacket.buildTrampolinePacket(paymentHash, trampolineHops, FinalPayload.Standard.createSinglePartPayload(finalAmount, finalExpiry, paymentSecret, None))
    val Success((cmd, _)) = buildCommand(ActorRef.noSender, Upstream.Local(UUID.randomUUID()), paymentHash, channelHopFromUpdate(a, b, channelUpdate_ab) :: Nil, FinalPayload.Standard.createTrampolinePayload(trampolineAmount, trampolineAmount, trampolineExpiry, randomBytes32(), trampolineOnion.packet))

    // and then manually build an htlc
    val add_ab = UpdateAddHtlc(channelId = channelId_ab, id = 123456, cmd.amount, cmd.paymentHash, cmd.cltvExpiry, cmd.onion, None)

    relayer ! RelayForward(add_ab)

    val fail = register.expectMessageType[Register.Forward[CMD_FAIL_HTLC]].message
    assert(fail.id == add_ab.id)
    assert(fail.reason == Right(RequiredNodeFeatureMissing))

    register.expectNoMessage(50 millis)
  }

  test("relay htlc settled") { f =>
    import f._

    val replyTo = TestProbe[Any]()
    val add_ab = UpdateAddHtlc(channelId = channelId_ab, id = 42, amountMsat = 11000000 msat, paymentHash = ByteVector32.Zeroes, CltvExpiry(4200), TestConstants.emptyOnionPacket, None)
    val add_bc = UpdateAddHtlc(channelId_bc, 72, 1000 msat, paymentHash, CltvExpiry(1), TestConstants.emptyOnionPacket, None)
    val channelOrigin = Origin.ChannelRelayedHot(replyTo.ref.toClassic, add_ab, 1000 msat)
    val trampolineOrigin = Origin.TrampolineRelayedHot(replyTo.ref.toClassic, Seq(add_ab))

    val addSettled = Seq(
      RES_ADD_SETTLED(channelOrigin, add_bc, HtlcResult.OnChainFulfill(randomBytes32())),
      RES_ADD_SETTLED(channelOrigin, add_bc, HtlcResult.RemoteFulfill(UpdateFulfillHtlc(add_bc.channelId, add_bc.id, randomBytes32()))),
      RES_ADD_SETTLED(channelOrigin, add_bc, HtlcResult.OnChainFail(HtlcsTimedoutDownstream(channelId_bc, Set(add_bc)))),
      RES_ADD_SETTLED(channelOrigin, add_bc, HtlcResult.RemoteFail(UpdateFailHtlc(add_bc.channelId, add_bc.id, randomBytes32()))),
      RES_ADD_SETTLED(trampolineOrigin, add_bc, HtlcResult.OnChainFulfill(randomBytes32())),
      RES_ADD_SETTLED(trampolineOrigin, add_bc, HtlcResult.RemoteFulfill(UpdateFulfillHtlc(add_bc.channelId, add_bc.id, randomBytes32()))),
      RES_ADD_SETTLED(trampolineOrigin, add_bc, HtlcResult.OnChainFail(HtlcsTimedoutDownstream(channelId_bc, Set(add_bc)))),
      RES_ADD_SETTLED(trampolineOrigin, add_bc, HtlcResult.RemoteFail(UpdateFailHtlc(add_bc.channelId, add_bc.id, randomBytes32())))
    )

    for (res <- addSettled) {
      relayer ! res
      replyTo.expectMessage(res)
    }
  }

}
