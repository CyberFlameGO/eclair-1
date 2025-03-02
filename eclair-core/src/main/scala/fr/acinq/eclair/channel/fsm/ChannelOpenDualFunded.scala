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

package fr.acinq.eclair.channel.fsm

import akka.actor.typed.scaladsl.adapter.{ClassicActorContextOps, actorRefAdapter}
import akka.actor.{ActorRef, Status}
import fr.acinq.bitcoin.scalacompat.{SatoshiLong, Script}
import fr.acinq.eclair.blockchain.bitcoind.ZmqWatcher._
import fr.acinq.eclair.channel.Helpers.Funding
import fr.acinq.eclair.channel.InteractiveTxBuilder.{FullySignedSharedTransaction, InteractiveTxParams, PartiallySignedSharedTransaction, RequireConfirmedInputs}
import fr.acinq.eclair.channel._
import fr.acinq.eclair.channel.fsm.Channel._
import fr.acinq.eclair.channel.publish.TxPublisher.SetChannelId
import fr.acinq.eclair.transactions.Scripts
import fr.acinq.eclair.wire.protocol._
import fr.acinq.eclair.{Features, RealShortChannelId, ToMilliSatoshiConversion}

/**
 * Created by t-bast on 19/04/2022.
 */

trait ChannelOpenDualFunded extends DualFundingHandlers with ErrorHandlers {

  this: Channel =>

  /*
                                     INITIATOR                       NON_INITIATOR
                                         |                                 |
                                         |          open_channel2          | WAIT_FOR_OPEN_DUAL_FUNDED_CHANNEL
                                         |-------------------------------->|
     WAIT_FOR_ACCEPT_DUAL_FUNDED_CHANNEL |                                 |
                                         |         accept_channel2         |
                                         |<--------------------------------|
           WAIT_FOR_DUAL_FUNDING_CREATED |                                 | WAIT_FOR_DUAL_FUNDING_CREATED
                                         |    <interactive-tx protocol>    |
                                         |                .                |
                                         |                .                |
                                         |                .                |
                                         |           tx_complete           |
                                         |-------------------------------->|
                                         |           tx_complete           |
                                         |<--------------------------------|
                                         |                                 |
                                         |        commitment_signed        |
                                         |-------------------------------->|
                                         |        commitment_signed        |
                                         |<--------------------------------|
                                         |          tx_signatures          |
                                         |<--------------------------------|
                                         |                                 | WAIT_FOR_DUAL_FUNDING_CONFIRMED
                                         |          tx_signatures          |
                                         |-------------------------------->|
         WAIT_FOR_DUAL_FUNDING_CONFIRMED |                                 |
                                         |           tx_init_rbf           |
                                         |-------------------------------->|
                                         |           tx_ack_rbf            |
                                         |<--------------------------------|
                                         |                                 |
                                         |    <interactive-tx protocol>    |
                                         |                .                |
                                         |                .                |
                                         |                .                |
                                         |           tx_complete           |
                                         |-------------------------------->|
                                         |           tx_complete           |
                                         |<--------------------------------|
                                         |                                 |
                                         |        commitment_signed        |
                                         |-------------------------------->|
                                         |        commitment_signed        |
                                         |<--------------------------------|
                                         |          tx_signatures          |
                                         |<--------------------------------|
                                         |          tx_signatures          |
                                         |-------------------------------->|
                                         |                                 |
                                         |      <other rbf attempts>       |
                                         |                .                |
                                         |                .                |
                                         |                .                |
            WAIT_FOR_DUAL_FUNDING_LOCKED |                                 | WAIT_FOR_DUAL_FUNDING_LOCKED
                                         | funding_locked   funding_locked |
                                         |----------------  ---------------|
                                         |                \/               |
                                         |                /\               |
                                         |<---------------  -------------->|
                                  NORMAL |                                 | NORMAL
 */

  when(WAIT_FOR_INIT_DUAL_FUNDED_CHANNEL)(handleExceptions {
    case Event(input: INPUT_INIT_CHANNEL_INITIATOR, _) =>
      val fundingPubKey = keyManager.fundingPublicKey(input.localParams.fundingKeyPath).publicKey
      val channelKeyPath = keyManager.keyPath(input.localParams, input.channelConfig)
      val upfrontShutdownScript_opt = if (Features.canUseFeature(input.localParams.initFeatures, input.remoteInit.features, Features.UpfrontShutdownScript)) {
        Some(ChannelTlv.UpfrontShutdownScriptTlv(input.localParams.defaultFinalScriptPubKey))
      } else {
        None
      }
      val tlvs: Seq[OpenDualFundedChannelTlv] = Seq(
        upfrontShutdownScript_opt,
        Some(ChannelTlv.ChannelTypeTlv(input.channelType)),
        input.pushAmount_opt.map(amount => ChannelTlv.PushAmountTlv(amount)),
        if (input.requireConfirmedInputs) Some(ChannelTlv.RequireConfirmedInputsTlv()) else None,
      ).flatten
      val open = OpenDualFundedChannel(
        chainHash = nodeParams.chainHash,
        temporaryChannelId = input.temporaryChannelId,
        fundingFeerate = input.fundingTxFeerate,
        commitmentFeerate = input.commitTxFeerate,
        fundingAmount = input.fundingAmount,
        dustLimit = input.localParams.dustLimit,
        maxHtlcValueInFlightMsat = input.localParams.maxHtlcValueInFlightMsat,
        htlcMinimum = input.localParams.htlcMinimum,
        toSelfDelay = input.localParams.toSelfDelay,
        maxAcceptedHtlcs = input.localParams.maxAcceptedHtlcs,
        lockTime = nodeParams.currentBlockHeight.toLong,
        fundingPubkey = fundingPubKey,
        revocationBasepoint = keyManager.revocationPoint(channelKeyPath).publicKey,
        paymentBasepoint = input.localParams.walletStaticPaymentBasepoint.getOrElse(keyManager.paymentPoint(channelKeyPath).publicKey),
        delayedPaymentBasepoint = keyManager.delayedPaymentPoint(channelKeyPath).publicKey,
        htlcBasepoint = keyManager.htlcPoint(channelKeyPath).publicKey,
        firstPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, 0),
        channelFlags = input.channelFlags,
        tlvStream = TlvStream(tlvs))
      goto(WAIT_FOR_ACCEPT_DUAL_FUNDED_CHANNEL) using DATA_WAIT_FOR_ACCEPT_DUAL_FUNDED_CHANNEL(input, open) sending open
  })

  when(WAIT_FOR_OPEN_DUAL_FUNDED_CHANNEL)(handleExceptions {
    case Event(open: OpenDualFundedChannel, d: DATA_WAIT_FOR_OPEN_DUAL_FUNDED_CHANNEL) =>
      import d.init.{localParams, remoteInit}
      Helpers.validateParamsDualFundedNonInitiator(nodeParams, d.init.channelType, open, remoteNodeId, localParams.initFeatures, remoteInit.features) match {
        case Left(t) => handleLocalError(t, d, Some(open))
        case Right((channelFeatures, remoteShutdownScript)) =>
          context.system.eventStream.publish(ChannelCreated(self, peer, remoteNodeId, isInitiator = false, open.temporaryChannelId, open.commitmentFeerate, Some(open.fundingFeerate)))
          val localFundingPubkey = keyManager.fundingPublicKey(localParams.fundingKeyPath).publicKey
          val channelKeyPath = keyManager.keyPath(localParams, d.init.channelConfig)
          val totalFundingAmount = open.fundingAmount + d.init.fundingContribution_opt.getOrElse(0 sat)
          val minimumDepth = Funding.minDepthFundee(nodeParams.channelConf, d.init.localParams.initFeatures, totalFundingAmount)
          val upfrontShutdownScript_opt = if (Features.canUseFeature(localParams.initFeatures, remoteInit.features, Features.UpfrontShutdownScript)) {
            Some(ChannelTlv.UpfrontShutdownScriptTlv(localParams.defaultFinalScriptPubKey))
          } else {
            None
          }
          val tlvs: Seq[AcceptDualFundedChannelTlv] = Seq(
            upfrontShutdownScript_opt,
            Some(ChannelTlv.ChannelTypeTlv(d.init.channelType)),
            d.init.pushAmount_opt.map(amount => ChannelTlv.PushAmountTlv(amount)),
            if (nodeParams.channelConf.requireConfirmedInputsForDualFunding) Some(ChannelTlv.RequireConfirmedInputsTlv()) else None,
          ).flatten
          val accept = AcceptDualFundedChannel(
            temporaryChannelId = open.temporaryChannelId,
            fundingAmount = d.init.fundingContribution_opt.getOrElse(0 sat),
            dustLimit = localParams.dustLimit,
            maxHtlcValueInFlightMsat = localParams.maxHtlcValueInFlightMsat,
            htlcMinimum = localParams.htlcMinimum,
            minimumDepth = minimumDepth.getOrElse(0),
            toSelfDelay = localParams.toSelfDelay,
            maxAcceptedHtlcs = localParams.maxAcceptedHtlcs,
            fundingPubkey = localFundingPubkey,
            revocationBasepoint = keyManager.revocationPoint(channelKeyPath).publicKey,
            paymentBasepoint = localParams.walletStaticPaymentBasepoint.getOrElse(keyManager.paymentPoint(channelKeyPath).publicKey),
            delayedPaymentBasepoint = keyManager.delayedPaymentPoint(channelKeyPath).publicKey,
            htlcBasepoint = keyManager.htlcPoint(channelKeyPath).publicKey,
            firstPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, 0),
            tlvStream = TlvStream(tlvs))
          val remoteParams = RemoteParams(
            nodeId = remoteNodeId,
            dustLimit = open.dustLimit,
            maxHtlcValueInFlightMsat = open.maxHtlcValueInFlightMsat,
            requestedChannelReserve_opt = None, // channel reserve will be computed based on channel capacity
            htlcMinimum = open.htlcMinimum,
            toSelfDelay = open.toSelfDelay,
            maxAcceptedHtlcs = open.maxAcceptedHtlcs,
            fundingPubKey = open.fundingPubkey,
            revocationBasepoint = open.revocationBasepoint,
            paymentBasepoint = open.paymentBasepoint,
            delayedPaymentBasepoint = open.delayedPaymentBasepoint,
            htlcBasepoint = open.htlcBasepoint,
            initFeatures = remoteInit.features,
            shutdownScript = remoteShutdownScript)
          log.debug("remote params: {}", remoteParams)
          // We've exchanged open_channel2 and accept_channel2, we now know the final channelId.
          val channelId = Helpers.computeChannelId(open, accept)
          peer ! ChannelIdAssigned(self, remoteNodeId, accept.temporaryChannelId, channelId) // we notify the peer asap so it knows how to route messages
          txPublisher ! SetChannelId(remoteNodeId, channelId)
          context.system.eventStream.publish(ChannelIdAssigned(self, remoteNodeId, accept.temporaryChannelId, channelId))
          // We start the interactive-tx funding protocol.
          val fundingPubkeyScript = Script.write(Script.pay2wsh(Scripts.multiSig2of2(localFundingPubkey, remoteParams.fundingPubKey)))
          val fundingParams = InteractiveTxParams(
            channelId,
            localParams.isInitiator,
            accept.fundingAmount,
            open.fundingAmount,
            fundingPubkeyScript,
            open.lockTime,
            open.dustLimit.max(accept.dustLimit),
            open.fundingFeerate,
            RequireConfirmedInputs(forLocal = open.requireConfirmedInputs, forRemote = accept.requireConfirmedInputs)
          )
          val txBuilder = context.spawnAnonymous(InteractiveTxBuilder(
            remoteNodeId, fundingParams, keyManager,
            accept.pushAmount, open.pushAmount,
            localParams, remoteParams,
            open.commitmentFeerate,
            open.firstPerCommitmentPoint,
            open.channelFlags, d.init.channelConfig, channelFeatures,
            wallet
          ))
          txBuilder ! InteractiveTxBuilder.Start(self, Nil)
          goto(WAIT_FOR_DUAL_FUNDING_CREATED) using DATA_WAIT_FOR_DUAL_FUNDING_CREATED(channelId, accept.pushAmount, open.pushAmount, txBuilder, None) sending accept
      }

    case Event(c: CloseCommand, d) => handleFastClose(c, d.channelId)

    case Event(e: Error, d: DATA_WAIT_FOR_OPEN_DUAL_FUNDED_CHANNEL) => handleRemoteError(e, d)

    case Event(INPUT_DISCONNECTED, _) => goto(CLOSED)
  })

  when(WAIT_FOR_ACCEPT_DUAL_FUNDED_CHANNEL)(handleExceptions {
    case Event(accept: AcceptDualFundedChannel, d: DATA_WAIT_FOR_ACCEPT_DUAL_FUNDED_CHANNEL) =>
      import d.init.{localParams, remoteInit}
      Helpers.validateParamsDualFundedInitiator(nodeParams, d.init.channelType, localParams.initFeatures, remoteInit.features, d.lastSent, accept) match {
        case Left(t) =>
          channelOpenReplyToUser(Left(LocalError(t)))
          handleLocalError(t, d, Some(accept))
        case Right((channelFeatures, remoteShutdownScript)) =>
          // We've exchanged open_channel2 and accept_channel2, we now know the final channelId.
          val channelId = Helpers.computeChannelId(d.lastSent, accept)
          peer ! ChannelIdAssigned(self, remoteNodeId, accept.temporaryChannelId, channelId) // we notify the peer asap so it knows how to route messages
          txPublisher ! SetChannelId(remoteNodeId, channelId)
          context.system.eventStream.publish(ChannelIdAssigned(self, remoteNodeId, accept.temporaryChannelId, channelId))
          val remoteParams = RemoteParams(
            nodeId = remoteNodeId,
            dustLimit = accept.dustLimit,
            maxHtlcValueInFlightMsat = accept.maxHtlcValueInFlightMsat,
            requestedChannelReserve_opt = None, // channel reserve will be computed based on channel capacity
            htlcMinimum = accept.htlcMinimum,
            toSelfDelay = accept.toSelfDelay,
            maxAcceptedHtlcs = accept.maxAcceptedHtlcs,
            fundingPubKey = accept.fundingPubkey,
            revocationBasepoint = accept.revocationBasepoint,
            paymentBasepoint = accept.paymentBasepoint,
            delayedPaymentBasepoint = accept.delayedPaymentBasepoint,
            htlcBasepoint = accept.htlcBasepoint,
            initFeatures = remoteInit.features,
            shutdownScript = remoteShutdownScript)
          log.debug("remote params: {}", remoteParams)
          // We start the interactive-tx funding protocol.
          val localFundingPubkey = keyManager.fundingPublicKey(localParams.fundingKeyPath)
          val fundingPubkeyScript = Script.write(Script.pay2wsh(Scripts.multiSig2of2(localFundingPubkey.publicKey, remoteParams.fundingPubKey)))
          val fundingParams = InteractiveTxParams(
            channelId,
            localParams.isInitiator,
            d.lastSent.fundingAmount,
            accept.fundingAmount,
            fundingPubkeyScript,
            d.lastSent.lockTime,
            d.lastSent.dustLimit.max(accept.dustLimit),
            d.lastSent.fundingFeerate,
            RequireConfirmedInputs(forLocal = accept.requireConfirmedInputs, forRemote = d.lastSent.requireConfirmedInputs)
          )
          val txBuilder = context.spawnAnonymous(InteractiveTxBuilder(
            remoteNodeId, fundingParams, keyManager,
            d.lastSent.pushAmount, accept.pushAmount,
            localParams, remoteParams,
            d.lastSent.commitmentFeerate,
            accept.firstPerCommitmentPoint,
            d.lastSent.channelFlags, d.init.channelConfig, channelFeatures,
            wallet
          ))
          txBuilder ! InteractiveTxBuilder.Start(self, Nil)
          goto(WAIT_FOR_DUAL_FUNDING_CREATED) using DATA_WAIT_FOR_DUAL_FUNDING_CREATED(channelId, d.lastSent.pushAmount, accept.pushAmount, txBuilder, None)
      }

    case Event(c: CloseCommand, d: DATA_WAIT_FOR_ACCEPT_DUAL_FUNDED_CHANNEL) =>
      channelOpenReplyToUser(Right(ChannelOpenResponse.ChannelClosed(d.channelId)))
      handleFastClose(c, d.channelId)

    case Event(e: Error, d: DATA_WAIT_FOR_ACCEPT_DUAL_FUNDED_CHANNEL) =>
      channelOpenReplyToUser(Left(RemoteError(e)))
      handleRemoteError(e, d)

    case Event(INPUT_DISCONNECTED, _) =>
      channelOpenReplyToUser(Left(LocalError(new RuntimeException("disconnected"))))
      goto(CLOSED)

    case Event(TickChannelOpenTimeout, _) =>
      channelOpenReplyToUser(Left(LocalError(new RuntimeException("open channel cancelled, took too long"))))
      goto(CLOSED)
  })

  when(WAIT_FOR_DUAL_FUNDING_CREATED)(handleExceptions {
    case Event(msg: InteractiveTxMessage, d: DATA_WAIT_FOR_DUAL_FUNDING_CREATED) =>
      msg match {
        case msg: InteractiveTxConstructionMessage =>
          d.txBuilder ! InteractiveTxBuilder.ReceiveTxMessage(msg)
          stay()
        case msg: TxSignatures =>
          d.txBuilder ! InteractiveTxBuilder.ReceiveTxSigs(msg)
          stay()
        case msg: TxAbort =>
          log.info("our peer aborted the dual funding flow: ascii='{}' bin={}", msg.toAscii, msg.data)
          d.txBuilder ! InteractiveTxBuilder.Abort
          channelOpenReplyToUser(Left(LocalError(DualFundingAborted(d.channelId))))
          goto(CLOSED)
        case _: TxInitRbf =>
          log.info("ignoring unexpected tx_init_rbf message")
          stay() sending Warning(d.channelId, InvalidRbfAttempt(d.channelId).getMessage)
        case _: TxAckRbf =>
          log.info("ignoring unexpected tx_ack_rbf message")
          stay() sending Warning(d.channelId, InvalidRbfAttempt(d.channelId).getMessage)
      }

    case Event(commitSig: CommitSig, d: DATA_WAIT_FOR_DUAL_FUNDING_CREATED) =>
      d.txBuilder ! InteractiveTxBuilder.ReceiveCommitSig(commitSig)
      stay()

    case Event(channelReady: ChannelReady, d: DATA_WAIT_FOR_DUAL_FUNDING_CREATED) =>
      log.info("received their channel_ready, deferring message")
      stay() using d.copy(deferred = Some(channelReady))

    case Event(msg: InteractiveTxBuilder.Response, d: DATA_WAIT_FOR_DUAL_FUNDING_CREATED) => msg match {
      case InteractiveTxBuilder.SendMessage(msg) => stay() sending msg
      case InteractiveTxBuilder.Succeeded(fundingParams, fundingTx, commitments) =>
        d.deferred.foreach(self ! _)
        Funding.minDepthDualFunding(nodeParams.channelConf, commitments.localParams.initFeatures, fundingParams) match {
          case Some(fundingMinDepth) =>
            blockchain ! WatchFundingConfirmed(self, commitments.fundingTxId, fundingMinDepth)
            val d1 = DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED(commitments, fundingTx, fundingParams, d.localPushAmount, d.remotePushAmount, Nil, nodeParams.currentBlockHeight, nodeParams.currentBlockHeight, RbfStatus.NoRbf, None)
            fundingTx match {
              case fundingTx: PartiallySignedSharedTransaction => goto(WAIT_FOR_DUAL_FUNDING_CONFIRMED) using d1 storing() sending fundingTx.localSigs
              case fundingTx: FullySignedSharedTransaction => goto(WAIT_FOR_DUAL_FUNDING_CONFIRMED) using d1 storing() sending fundingTx.localSigs calling publishFundingTx(fundingParams, fundingTx)
            }
          case None =>
            watchFundingTx(commitments)
            val (shortIds, channelReady) = acceptFundingTx(commitments, RealScidStatus.Unknown)
            val d1 = DATA_WAIT_FOR_DUAL_FUNDING_READY(commitments, shortIds, channelReady)
            fundingTx match {
              case fundingTx: PartiallySignedSharedTransaction => goto(WAIT_FOR_DUAL_FUNDING_READY) using d1 storing() sending Seq(fundingTx.localSigs, channelReady)
              case fundingTx: FullySignedSharedTransaction => goto(WAIT_FOR_DUAL_FUNDING_READY) using d1 storing() sending Seq(fundingTx.localSigs, channelReady) calling publishFundingTx(fundingParams, fundingTx)
            }
        }
      case f: InteractiveTxBuilder.Failed =>
        channelOpenReplyToUser(Left(LocalError(f.cause)))
        goto(CLOSED) sending Error(d.channelId, f.cause.getMessage)
    }

    case Event(c: CloseCommand, d: DATA_WAIT_FOR_DUAL_FUNDING_CREATED) =>
      d.txBuilder ! InteractiveTxBuilder.Abort
      channelOpenReplyToUser(Right(ChannelOpenResponse.ChannelClosed(d.channelId)))
      handleFastClose(c, d.channelId)

    case Event(e: Error, d: DATA_WAIT_FOR_DUAL_FUNDING_CREATED) =>
      d.txBuilder ! InteractiveTxBuilder.Abort
      channelOpenReplyToUser(Left(RemoteError(e)))
      handleRemoteError(e, d)

    case Event(INPUT_DISCONNECTED, d: DATA_WAIT_FOR_DUAL_FUNDING_CREATED) =>
      d.txBuilder ! InteractiveTxBuilder.Abort
      channelOpenReplyToUser(Left(LocalError(new RuntimeException("disconnected"))))
      goto(CLOSED)

    case Event(TickChannelOpenTimeout, d: DATA_WAIT_FOR_DUAL_FUNDING_CREATED) =>
      d.txBuilder ! InteractiveTxBuilder.Abort
      channelOpenReplyToUser(Left(LocalError(new RuntimeException("open channel cancelled, took too long"))))
      goto(CLOSED)
  })

  when(WAIT_FOR_DUAL_FUNDING_CONFIRMED)(handleExceptions {
    case Event(txSigs: TxSignatures, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      d.fundingTx match {
        case fundingTx: PartiallySignedSharedTransaction => InteractiveTxBuilder.addRemoteSigs(d.fundingParams, fundingTx, txSigs) match {
          case Left(cause) =>
            val unsignedFundingTx = fundingTx.tx.buildUnsignedTx()
            log.warning("received invalid tx_signatures for txid={} (current funding txid={}): {}", txSigs.txId, unsignedFundingTx.txid, cause.getMessage)
            // The funding transaction may still confirm (since our peer should be able to generate valid signatures),
            // so we cannot close the channel yet.
            stay() sending Error(d.channelId, InvalidFundingSignature(d.channelId, Some(unsignedFundingTx.txid)).getMessage)
          case Right(fundingTx) =>
            log.info("publishing funding tx for channelId={} fundingTxId={}", d.channelId, fundingTx.signedTx.txid)
            val d1 = d.copy(fundingTx = fundingTx)
            stay() using d1 storing() calling publishFundingTx(d.fundingParams, fundingTx)
        }
        case _: FullySignedSharedTransaction =>
          d.rbfStatus match {
            case RbfStatus.RbfInProgress(txBuilder) =>
              txBuilder ! InteractiveTxBuilder.ReceiveTxSigs(txSigs)
              stay()
            case _ =>
              // Signatures are retransmitted on reconnection, but we may have already received them.
              log.info("ignoring duplicate tx_signatures for txid={}", txSigs.txId)
              stay()
          }
      }

    case Event(cmd: CMD_BUMP_FUNDING_FEE, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      val replyTo = if (cmd.replyTo == ActorRef.noSender) sender() else cmd.replyTo
      if (!d.fundingParams.isInitiator) {
        replyTo ! Status.Failure(InvalidRbfNonInitiator(d.channelId))
        stay()
      } else {
        d.rbfStatus match {
          case RbfStatus.NoRbf =>
            val minNextFeerate = d.fundingParams.minNextFeerate
            if (cmd.targetFeerate < minNextFeerate) {
              replyTo ! Status.Failure(InvalidRbfFeerate(d.channelId, cmd.targetFeerate, minNextFeerate))
              stay()
            } else {
              stay() using d.copy(rbfStatus = RbfStatus.RbfRequested(cmd.copy(replyTo = replyTo))) sending TxInitRbf(d.channelId, cmd.lockTime, cmd.targetFeerate, d.fundingParams.localAmount)
            }
          case _ =>
            log.warning("cannot initiate rbf, another one is already in progress")
            replyTo ! Status.Failure(InvalidRbfAlreadyInProgress(d.channelId))
            stay()
        }
      }

    case Event(msg: TxInitRbf, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      if (d.fundingParams.isInitiator) {
        // Only the initiator is allowed to initiate RBF.
        log.info("rejecting tx_init_rbf, we're the initiator, not them!")
        stay() sending TxAbort(d.channelId, InvalidRbfNonInitiator(d.channelId).getMessage)
      } else {
        val minNextFeerate = d.fundingParams.minNextFeerate
        if (d.rbfStatus != RbfStatus.NoRbf) {
          log.info("rejecting rbf attempt: the current rbf attempt must be completed or aborted first")
          stay() sending TxAbort(d.channelId, InvalidRbfAlreadyInProgress(d.channelId).getMessage)
        } else if (msg.feerate < minNextFeerate) {
          log.info("rejecting rbf attempt: the new feerate must be at least {} (proposed={})", minNextFeerate, msg.feerate)
          stay() sending TxAbort(d.channelId, InvalidRbfFeerate(d.channelId, msg.feerate, minNextFeerate).getMessage)
        } else if (d.remotePushAmount > msg.fundingContribution) {
          log.info("rejecting rbf attempt: invalid amount pushed (fundingAmount={}, pushAmount={})", msg.fundingContribution, d.remotePushAmount)
          stay() sending TxAbort(d.channelId, InvalidPushAmount(d.channelId, d.remotePushAmount, msg.fundingContribution.toMilliSatoshi).getMessage)
        } else {
          log.info("our peer wants to raise the feerate of the funding transaction (previous={} target={})", d.fundingParams.targetFeerate, msg.feerate)
          val fundingParams = InteractiveTxParams(
            d.channelId,
            d.fundingParams.isInitiator,
            d.fundingParams.localAmount, // we don't change our funding contribution
            msg.fundingContribution,
            d.fundingParams.fundingPubkeyScript,
            msg.lockTime,
            d.fundingParams.dustLimit,
            msg.feerate,
            d.fundingParams.requireConfirmedInputs,
          )
          val txBuilder = context.spawnAnonymous(InteractiveTxBuilder(
            remoteNodeId, fundingParams, keyManager,
            d.localPushAmount, d.remotePushAmount,
            d.commitments.localParams, d.commitments.remoteParams,
            d.commitments.localCommit.spec.commitTxFeerate,
            d.commitments.remoteCommit.remotePerCommitmentPoint,
            d.commitments.channelFlags, d.commitments.channelConfig, d.commitments.channelFeatures,
            wallet))
          txBuilder ! InteractiveTxBuilder.Start(self, d.fundingTx +: d.previousFundingTxs.map(_.fundingTx))
          stay() using d.copy(rbfStatus = RbfStatus.RbfInProgress(txBuilder)) sending TxAckRbf(d.channelId, fundingParams.localAmount)
        }
      }

    case Event(msg: TxAckRbf, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      d.rbfStatus match {
        case RbfStatus.RbfRequested(cmd) if d.remotePushAmount > msg.fundingContribution =>
          log.info("rejecting rbf attempt: invalid amount pushed (fundingAmount={}, pushAmount={})", msg.fundingContribution, d.remotePushAmount)
          val error = InvalidPushAmount(d.channelId, d.remotePushAmount, msg.fundingContribution.toMilliSatoshi)
          cmd.replyTo ! RES_FAILURE(cmd, error)
          stay() using d.copy(rbfStatus = RbfStatus.NoRbf) sending TxAbort(d.channelId, error.getMessage)
        case RbfStatus.RbfRequested(cmd) =>
          log.info("our peer accepted our rbf attempt and will contribute {} to the funding transaction", msg.fundingContribution)
          cmd.replyTo ! RES_SUCCESS(cmd, d.channelId)
          val fundingParams = InteractiveTxParams(
            d.channelId,
            d.fundingParams.isInitiator,
            d.fundingParams.localAmount, // we don't change our funding contribution
            msg.fundingContribution,
            d.fundingParams.fundingPubkeyScript,
            cmd.lockTime,
            d.fundingParams.dustLimit,
            cmd.targetFeerate,
            d.fundingParams.requireConfirmedInputs,
          )
          val txBuilder = context.spawnAnonymous(InteractiveTxBuilder(
            remoteNodeId, fundingParams, keyManager,
            d.localPushAmount, d.remotePushAmount,
            d.commitments.localParams, d.commitments.remoteParams,
            d.commitments.localCommit.spec.commitTxFeerate,
            d.commitments.remoteCommit.remotePerCommitmentPoint,
            d.commitments.channelFlags, d.commitments.channelConfig, d.commitments.channelFeatures,
            wallet))
          txBuilder ! InteractiveTxBuilder.Start(self, d.fundingTx +: d.previousFundingTxs.map(_.fundingTx))
          stay() using d.copy(rbfStatus = RbfStatus.RbfInProgress(txBuilder))
        case _ =>
          log.info("ignoring unexpected tx_ack_rbf")
          stay() sending Warning(d.channelId, UnexpectedInteractiveTxMessage(d.channelId, msg).getMessage)
      }

    case Event(msg: InteractiveTxConstructionMessage, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      d.rbfStatus match {
        case RbfStatus.RbfInProgress(txBuilder) =>
          txBuilder ! InteractiveTxBuilder.ReceiveTxMessage(msg)
          stay()
        case _ =>
          log.info("ignoring unexpected interactive-tx message: {}", msg.getClass.getSimpleName)
          stay() sending Warning(d.channelId, UnexpectedInteractiveTxMessage(d.channelId, msg).getMessage)
      }

    case Event(commitSig: CommitSig, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      d.rbfStatus match {
        case RbfStatus.RbfInProgress(txBuilder) =>
          txBuilder ! InteractiveTxBuilder.ReceiveCommitSig(commitSig)
          stay()
        case _ =>
          log.info("ignoring unexpected commit_sig")
          stay() sending Warning(d.channelId, UnexpectedCommitSig(d.channelId).getMessage)
      }

    case Event(msg: TxAbort, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      d.rbfStatus match {
        case RbfStatus.RbfInProgress(txBuilder) =>
          log.info("our peer aborted the rbf attempt: ascii='{}' bin={}", msg.toAscii, msg.data)
          txBuilder ! InteractiveTxBuilder.Abort
          stay() using d.copy(rbfStatus = RbfStatus.NoRbf)
        case RbfStatus.RbfRequested(cmd) =>
          log.info("our peer rejected our rbf attempt: ascii='{}' bin={}", msg.toAscii, msg.data)
          cmd.replyTo ! Status.Failure(new RuntimeException(s"rbf attempt rejected by our peer: ${msg.toAscii}"))
          stay() using d.copy(rbfStatus = RbfStatus.NoRbf)
        case RbfStatus.NoRbf =>
          log.info("ignoring unexpected tx_abort message")
          stay() sending Warning(d.channelId, UnexpectedInteractiveTxMessage(d.channelId, msg).getMessage)
      }

    case Event(msg: InteractiveTxBuilder.Response, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) => msg match {
      case InteractiveTxBuilder.SendMessage(msg) => stay() sending msg
      case InteractiveTxBuilder.Succeeded(fundingParams, fundingTx, commitments) =>
        // We now have more than one version of the funding tx, so we cannot use zero-conf.
        val fundingMinDepth = Funding.minDepthDualFunding(nodeParams.channelConf, commitments.localParams.initFeatures, fundingParams).getOrElse(nodeParams.channelConf.minDepthBlocks.toLong)
        blockchain ! WatchFundingConfirmed(self, commitments.fundingTxId, fundingMinDepth)
        val previousFundingTxs = DualFundingTx(d.fundingTx, d.commitments) +: d.previousFundingTxs
        val d1 = DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED(commitments, fundingTx, fundingParams, d.localPushAmount, d.remotePushAmount, previousFundingTxs, d.waitingSince, d.lastChecked, RbfStatus.NoRbf, d.deferred)
        fundingTx match {
          case fundingTx: PartiallySignedSharedTransaction => stay() using d1 storing() sending fundingTx.localSigs
          case fundingTx: FullySignedSharedTransaction => stay() using d1 storing() sending fundingTx.localSigs calling publishFundingTx(fundingParams, fundingTx)
        }
      case f: InteractiveTxBuilder.Failed =>
        log.info("rbf attempt failed: {}", f.cause.getMessage)
        stay() using d.copy(rbfStatus = RbfStatus.NoRbf) sending TxAbort(d.channelId, f.cause.getMessage)
    }

    case Event(WatchFundingConfirmedTriggered(blockHeight, txIndex, confirmedTx), d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      // We find which funding transaction got confirmed.
      val allFundingTxs = DualFundingTx(d.fundingTx, d.commitments) +: d.previousFundingTxs
      allFundingTxs.find(_.commitments.fundingTxId == confirmedTx.txid) match {
        case Some(DualFundingTx(_, commitments)) =>
          log.info("channelId={} was confirmed at blockHeight={} txIndex={} with funding txid={}", d.channelId, blockHeight, txIndex, confirmedTx.txid)
          watchFundingTx(commitments)
          context.system.eventStream.publish(TransactionConfirmed(commitments.channelId, remoteNodeId, confirmedTx))
          val realScidStatus = RealScidStatus.Temporary(RealShortChannelId(blockHeight, txIndex, commitments.commitInput.outPoint.index.toInt))
          val (shortIds, channelReady) = acceptFundingTx(commitments, realScidStatus = realScidStatus)
          d.deferred.foreach(self ! _)
          val otherFundingTxs = allFundingTxs.filter(_.commitments.fundingTxId != confirmedTx.txid).map(_.fundingTx)
          rollbackDualFundingTxs(otherFundingTxs)
          val toSend = d.rbfStatus match {
            case RbfStatus.RbfInProgress(txBuilder) =>
              txBuilder ! InteractiveTxBuilder.Abort
              Seq(TxAbort(d.channelId, InvalidRbfTxConfirmed(d.channelId).getMessage), channelReady)
            case RbfStatus.RbfRequested(cmd) =>
              cmd.replyTo ! Status.Failure(InvalidRbfTxConfirmed(d.channelId))
              Seq(TxAbort(d.channelId, InvalidRbfTxConfirmed(d.channelId).getMessage), channelReady)
            case RbfStatus.NoRbf =>
              Seq(channelReady)
          }
          goto(WAIT_FOR_DUAL_FUNDING_READY) using DATA_WAIT_FOR_DUAL_FUNDING_READY(commitments, shortIds, channelReady) storing() sending toSend
        case None =>
          log.error(s"internal error: the funding tx that confirmed doesn't match any of our funding txs: ${confirmedTx.bin}")
          rollbackDualFundingTxs(allFundingTxs.map(_.fundingTx))
          goto(CLOSED)
      }

    case Event(ProcessCurrentBlockHeight(c), d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) => handleNewBlockDualFundingUnconfirmed(c, d)

    case Event(e: BITCOIN_FUNDING_DOUBLE_SPENT, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) => handleDualFundingDoubleSpent(e, d)

    case Event(remoteChannelReady: ChannelReady, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      // We can skip waiting for confirmations if:
      //  - there is a single version of the funding tx (otherwise we don't know which one to use)
      //  - they didn't contribute to the funding output or we trust them to not double-spend
      val canUseZeroConf = remoteChannelReady.alias_opt.isDefined &&
        d.previousFundingTxs.isEmpty &&
        (d.fundingParams.remoteAmount == 0.sat || d.commitments.localParams.initFeatures.hasFeature(Features.ZeroConf))
      if (canUseZeroConf) {
        log.info("this channel isn't zero-conf, but they sent an early channel_ready with an alias: no need to wait for confirmations")
        watchFundingTx(d.commitments)
        val (shortIds, localChannelReady) = acceptFundingTx(d.commitments, RealScidStatus.Unknown)
        self ! remoteChannelReady
        // NB: we will receive a WatchFundingConfirmedTriggered later that will simply be ignored
        goto(WAIT_FOR_DUAL_FUNDING_READY) using DATA_WAIT_FOR_DUAL_FUNDING_READY(d.commitments, shortIds, localChannelReady) storing() sending localChannelReady
      } else {
        log.info("received their channel_ready, deferring message")
        stay() using d.copy(deferred = Some(remoteChannelReady)) // no need to store, they will re-send if we get disconnected
      }

    case Event(remoteAnnSigs: AnnouncementSignatures, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) if d.commitments.announceChannel =>
      delayEarlyAnnouncementSigs(remoteAnnSigs)
      stay()

    case Event(INPUT_DISCONNECTED, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) =>
      d.rbfStatus match {
        case RbfStatus.RbfInProgress(txBuilder) => txBuilder ! InteractiveTxBuilder.Abort
        case RbfStatus.RbfRequested(cmd) => cmd.replyTo ! Status.Failure(new RuntimeException("rbf attempt failed: disconnected"))
        case RbfStatus.NoRbf => // nothing to do
      }
      goto(OFFLINE) using d.copy(rbfStatus = RbfStatus.NoRbf)

    case Event(e: Error, d: DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED) => handleRemoteError(e, d)
  })

  when(WAIT_FOR_DUAL_FUNDING_READY)(handleExceptions {
    case Event(channelReady: ChannelReady, d: DATA_WAIT_FOR_DUAL_FUNDING_READY) =>
      val d1 = receiveChannelReady(d.shortIds, channelReady, d.commitments)
      goto(NORMAL) using d1 storing()

    case Event(_: TxInitRbf, d: DATA_WAIT_FOR_DUAL_FUNDING_READY) =>
      // Our peer may not have received the funding transaction confirmation.
      stay() sending TxAbort(d.channelId, InvalidRbfTxConfirmed(d.channelId).getMessage)

    case Event(remoteAnnSigs: AnnouncementSignatures, d: DATA_WAIT_FOR_DUAL_FUNDING_READY) if d.commitments.announceChannel =>
      delayEarlyAnnouncementSigs(remoteAnnSigs)
      stay()

    case Event(WatchFundingSpentTriggered(tx), d: DATA_WAIT_FOR_DUAL_FUNDING_READY) if tx.txid == d.commitments.remoteCommit.txid => handleRemoteSpentCurrent(tx, d)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_WAIT_FOR_DUAL_FUNDING_READY) => handleInformationLeak(tx, d)

    case Event(e: Error, d: DATA_WAIT_FOR_DUAL_FUNDING_READY) => handleRemoteError(e, d)
  })

}
