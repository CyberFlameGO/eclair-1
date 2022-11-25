/*
 * Copyright 2022 ACINQ SAS
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

package fr.acinq.eclair.payment.send

import fr.acinq.bitcoin.scalacompat.ByteVector32
import fr.acinq.bitcoin.scalacompat.Crypto.PublicKey
import fr.acinq.eclair.crypto.Sphinx
import fr.acinq.eclair.payment.OutgoingPaymentPacket.{NodePayload, PaymentPayloads}
import fr.acinq.eclair.payment.{Bolt11Invoice, Bolt12Invoice, Invoice, OutgoingPaymentPacket}
import fr.acinq.eclair.router.Router._
import fr.acinq.eclair.wire.protocol.PaymentOnion.{FinalPayload, IntermediatePayload, OutgoingBlindedPerHopPayload}
import fr.acinq.eclair.wire.protocol.{GenericTlv, OnionRoutingPacket, PaymentOnionCodecs}
import fr.acinq.eclair.{CltvExpiry, Features, InvoiceFeature, MilliSatoshi, MilliSatoshiLong, ShortChannelId, randomKey}
import scodec.bits.ByteVector

import scala.util.{Failure, Success, Try}

/**
 * Created by t-bast on 28/10/2022.
 */

sealed trait Recipient {
  /** Id of the final receiving node. */
  def nodeId: PublicKey

  /** Total amount that will be received by the final receiving node. */
  def totalAmount: MilliSatoshi

  /** Id that should be used when searching for routes in the graph (may be different from [[nodeId]]). */
  def targetNodeId: PublicKey

  /** Total amount that should be sent to the [[targetNodeId]] (may be different from [[totalAmount]]). */
  def targetTotalAmount: MilliSatoshi

  /** Maximum fee that should be allocated when finding routes to the [[targetNodeId]]. */
  def targetMaxFee(routeParams: RouteParams): MilliSatoshi

  /** Features supported by the recipient. */
  def features: Features[InvoiceFeature]

  /** Edges that aren't part of the public graph and can be used to reach the recipient. */
  def extraEdges: Seq[Invoice.ExtraEdge]

  /** Build a payment to the recipient using the route provided. */
  def buildPayloads(paymentHash: ByteVector32, route: Route): Try[PaymentPayloads]

  /** Returns the complete payment route for logging purposes. */
  def fullRoute(route: Route): Seq[Hop] = this match {
    case _: SpontaneousRecipient => route.hops
    case _: ClearRecipient => route.hops
    case _: BlindedRecipient => route.hops
    case r: ClearTrampolineRecipient => route.hops :+ r.trampolineHop
  }

}

object Recipient {
  def verifyChannelHopsOnly(route: Route): Try[Seq[ChannelHop]] = {
    val channelHops = route.hops.collect { case hop: ChannelHop => hop }
    if (channelHops.length != route.hops.length) {
      Failure(new IllegalArgumentException(s"cannot send payment: route contains non-channel hops (${route.printChannels()})"))
    } else {
      Success(channelHops)
    }
  }
}

/** A payment recipient that can directly be found in the routing graph. */
case class ClearRecipient(nodeId: PublicKey,
                          features: Features[InvoiceFeature],
                          totalAmount: MilliSatoshi,
                          expiry: CltvExpiry,
                          paymentSecret: ByteVector32,
                          extraEdges: Seq[Invoice.ChannelEdge] = Nil,
                          paymentMetadata_opt: Option[ByteVector] = None,
                          nextTrampolineOnion_opt: Option[OnionRoutingPacket] = None,
                          customTlvs: Seq[GenericTlv] = Nil) extends Recipient {
  override val targetNodeId = nodeId
  override val targetTotalAmount = totalAmount

  override def targetMaxFee(routeParams: RouteParams): MilliSatoshi = routeParams.getMaxFee(totalAmount)

  override def buildPayloads(paymentHash: ByteVector32, route: Route): Try[PaymentPayloads] = {
    Recipient.verifyChannelHopsOnly(route).map(hops => {
      val finalPayload = nextTrampolineOnion_opt match {
        case Some(trampolinePacket) => NodePayload(nodeId, FinalPayload.Standard.createTrampolinePayload(route.amount, totalAmount, expiry, paymentSecret, trampolinePacket))
        case None => NodePayload(nodeId, FinalPayload.Standard.createPayload(route.amount, totalAmount, expiry, paymentSecret, paymentMetadata_opt, customTlvs))
      }
      OutgoingPaymentPacket.buildPayloads(route.amount, expiry, Seq(finalPayload), hops)
    })
  }
}

object ClearRecipient {
  def apply(invoice: Bolt11Invoice, totalAmount: MilliSatoshi, expiry: CltvExpiry, customTlvs: Seq[GenericTlv]): ClearRecipient = {
    ClearRecipient(invoice.nodeId, invoice.features, totalAmount, expiry, invoice.paymentSecret, invoice.extraEdges, invoice.paymentMetadata, None, customTlvs)
  }
}

/** A payment recipient that doesn't expect to receive a payment and can directly be found in the routing graph. */
case class SpontaneousRecipient(nodeId: PublicKey,
                                totalAmount: MilliSatoshi,
                                expiry: CltvExpiry,
                                preimage: ByteVector32,
                                customTlvs: Seq[GenericTlv] = Nil) extends Recipient {
  override val targetNodeId = nodeId
  override val targetTotalAmount = totalAmount
  override val features = Features.empty
  override val extraEdges = Nil

  override def targetMaxFee(routeParams: RouteParams): MilliSatoshi = routeParams.getMaxFee(totalAmount)

  override def buildPayloads(paymentHash: ByteVector32, route: Route): Try[PaymentPayloads] = {
    Recipient.verifyChannelHopsOnly(route).map(hops => {
      val finalPayload = NodePayload(nodeId, FinalPayload.Standard.createKeySendPayload(route.amount, totalAmount, expiry, preimage, customTlvs))
      OutgoingPaymentPacket.buildPayloads(totalAmount, expiry, Seq(finalPayload), hops)
    })
  }
}

/** A payment recipient that hides its real identity using route blinding. */
case class BlindedRecipient(nodeId: PublicKey,
                            targetNodeId: PublicKey,
                            features: Features[InvoiceFeature],
                            totalAmount: MilliSatoshi,
                            expiry: CltvExpiry,
                            extraEdges: Seq[Invoice.BlindedEdge],
                            customTlvs: Seq[GenericTlv] = Nil) extends Recipient {
  require(extraEdges.forall(_.targetNodeId == targetNodeId), "extra edges must use the same targetNodeId")

  override val targetTotalAmount = totalAmount

  override def targetMaxFee(routeParams: RouteParams): MilliSatoshi = routeParams.getMaxFee(totalAmount)

  private def buildBlindedPayloads(blindedHop: BlindedHop, route: Route): PaymentPayloads = {
    val blinding = blindedHop.route.introductionNode.blindingEphemeralKey
    val payloads = if (blindedHop.route.subsequentNodes.isEmpty) {
      // The recipient is also the introduction node.
      Seq(NodePayload(blindedHop.route.introductionNodeId, OutgoingBlindedPerHopPayload.createFinalIntroductionPayload(route.amount, totalAmount, expiry, blinding, blindedHop.route.introductionNode.encryptedPayload, customTlvs)))
    } else {
      val introductionPayload = NodePayload(blindedHop.route.introductionNodeId, OutgoingBlindedPerHopPayload.createIntroductionPayload(blindedHop.route.introductionNode.encryptedPayload, blinding))
      val intermediatePayloads = blindedHop.route.subsequentNodes.dropRight(1).map(n => NodePayload(n.blindedPublicKey, OutgoingBlindedPerHopPayload.createIntermediatePayload(n.encryptedPayload)))
      val finalPayload = NodePayload(blindedHop.route.blindedNodes.last.blindedPublicKey, OutgoingBlindedPerHopPayload.createFinalPayload(route.amount, totalAmount, expiry, blindedHop.route.blindedNodes.last.encryptedPayload, customTlvs))
      introductionPayload +: intermediatePayloads :+ finalPayload
    }
    val introductionAmount = route.amount + blindedHop.paymentInfo.fee(route.amount)
    val introductionExpiry = expiry + blindedHop.paymentInfo.cltvExpiryDelta
    PaymentPayloads(introductionAmount, introductionExpiry, payloads)
  }

  override def buildPayloads(paymentHash: ByteVector32, route: Route): Try[PaymentPayloads] = {
    extractRoute(route).map { case (channelHops, blindedHop) =>
      val blindedPayloads = buildBlindedPayloads(blindedHop, route)
      if (channelHops.isEmpty) {
        // We are the introduction node of the blinded route.
        blindedPayloads
      } else {
        OutgoingPaymentPacket.buildPayloads(blindedPayloads.amount, blindedPayloads.expiry, blindedPayloads.payloads, channelHops)
      }
    }
  }

  private def extractRoute(route: Route): Try[(Seq[ChannelHop], BlindedHop)] = {
    // The payment route must start with channel hops to reach the introduction node of a blinded route.
    val channelHops = route.hops.dropRight(1).collect { case hop: ChannelHop => hop }
    val blindedHop_opt = route.hops.takeRight(1).collectFirst { case hop: BlindedHop => hop }
    blindedHop_opt match {
      case Some(blindedHop) if channelHops.length == route.hops.length - 1 => Success((channelHops, blindedHop))
      case _ => Failure(new IllegalArgumentException(s"cannot send payment: invalid blinded route (${route.printChannels()})"))
    }
  }
}

object BlindedRecipient {
  def apply(invoice: Bolt12Invoice, totalAmount: MilliSatoshi, expiry: CltvExpiry, customTlvs: Seq[GenericTlv]): BlindedRecipient = {
    // We create a dummy nodeId to ensure that it doesn't conflict with the nodeId of a public node.
    val targetNodeId = randomKey().publicKey
    val extraEdges = invoice.blindedPaths.zip(invoice.blindedPathsInfo).map {
      case (route, info) =>
        // We don't know the scids of channels inside the blinded route, but it's useful to have an ID to refer to a given
        // edge in the graph, so we create a dummy one for the duration of the payment attempt.
        val dummyId = ShortChannelId.generateLocalAlias()
        Invoice.BlindedEdge(dummyId, targetNodeId, route, info)
    }
    BlindedRecipient(invoice.nodeId, targetNodeId, invoice.features, totalAmount, expiry, extraEdges, customTlvs)
  }
}

/**
 * A payment recipient that can be reached through a trampoline node (such recipients usually cannot be found in the
 * public graph). When a payment needs to be split across multiple trampoline nodes, the sender must create multiple
 * recipient objects with distinct partial amounts, trampoline payment secrets and trampoline hops.
 *
 * Note that we don't need to support the case where we'd use multiple trampoline hops in the same route: since we have
 * access to the network graph, it's always more efficient to find a channel route to the last trampoline node.
 */
case class ClearTrampolineRecipient(invoice: Bolt11Invoice,
                                    partialAmount: MilliSatoshi,
                                    totalAmount: MilliSatoshi,
                                    expiry: CltvExpiry,
                                    trampolineHop: NodeHop,
                                    trampolinePaymentSecret: ByteVector32,
                                    customTlvs: Seq[GenericTlv] = Nil) extends Recipient {
  require(trampolineHop.nextNodeId == invoice.nodeId, "trampoline route must end at the recipient")

  override val nodeId = invoice.nodeId
  override val features = invoice.features
  override val extraEdges = Nil

  // We cannot simply inject virtual edges in the graph and let path-finding dynamically select when to use trampoline
  // hops because that would break MPP aggregation at the trampoline node: the fees of the trampoline hop should be paid
  // only once, even if we need to split our payment towards the trampoline node.
  //
  //   +-----> Bob ------+
  //   |                 |
  // Alice             Teddy -----> Dave
  //   |                 |
  //   +-----> Carol ----+
  //
  // It's thus simpler to decide beforehand how to split a payment across different trampoline hops, and then handle the
  // payments to the distinct trampoline nodes separately: from the sender's point of view, those payments behave like
  // standard multi-part payments where the trampoline node acts as the final recipient.
  private val trampolineNodeId = trampolineHop.nodeId
  private val trampolineAmount = partialAmount + trampolineHop.fee(partialAmount)
  private val trampolineExpiry = expiry + trampolineHop.cltvExpiryDelta
  override val targetNodeId = trampolineNodeId
  override val targetTotalAmount = trampolineAmount

  override def targetMaxFee(routeParams: RouteParams): MilliSatoshi = routeParams.getMaxFee(partialAmount) - trampolineHop.fee(partialAmount)

  override def buildPayloads(paymentHash: ByteVector32, route: Route): Try[PaymentPayloads] = {
    require(route.hops.last.nextNodeId == trampolineNodeId, "route must reach the desired trampoline node")
    Recipient.verifyChannelHopsOnly(route).flatMap(hops => {
      createTrampolinePacket(paymentHash).map { case Sphinx.PacketAndSecrets(trampolinePacket, _) =>
        val trampolinePayload = NodePayload(trampolineNodeId, FinalPayload.Standard.createTrampolinePayload(route.amount, trampolineAmount, trampolineExpiry, trampolinePaymentSecret, trampolinePacket))
        OutgoingPaymentPacket.buildPayloads(trampolineAmount, trampolineExpiry, Seq(trampolinePayload), hops)
      }
    })
  }

  def createTrampolinePacket(paymentHash: ByteVector32): Try[Sphinx.PacketAndSecrets] = {
    if (invoice.features.hasFeature(Features.TrampolinePaymentPrototype)) {
      // This is the payload the final recipient will receive, so we use the invoice's payment secret.
      val finalPayload = NodePayload(nodeId, FinalPayload.Standard.createPayload(partialAmount, totalAmount, expiry, invoice.paymentSecret, invoice.paymentMetadata, customTlvs))
      val trampolinePayload = NodePayload(trampolineNodeId, IntermediatePayload.NodeRelay.Standard(partialAmount, expiry, nodeId))
      val payloads = Seq(trampolinePayload, finalPayload)
      OutgoingPaymentPacket.buildOnion(PaymentOnionCodecs.trampolineOnionPayloadLength, payloads, paymentHash)
    } else {
      // The recipient doesn't support trampoline: the trampoline node will convert the payment to a non-trampoline payment.
      // The final payload will thus never reach the recipient, so we create the smallest payload possible to avoid overflowing the trampoline onion size.
      val dummyFinalPayload = NodePayload(nodeId, IntermediatePayload.ChannelRelay.Standard(ShortChannelId(0), 0 msat, CltvExpiry(0)))
      val trampolinePayload = NodePayload(trampolineNodeId, IntermediatePayload.NodeRelay.Standard.createNodeRelayToNonTrampolinePayload(partialAmount, totalAmount, expiry, nodeId, invoice))
      val payloads = Seq(trampolinePayload, dummyFinalPayload)
      OutgoingPaymentPacket.buildOnion(PaymentOnionCodecs.trampolineOnionPayloadLength, payloads, paymentHash)
    }
  }
}
