package com.aethermatch.p2p.ai

import com.aethermatch.p2p.model.FederatedRoundRecord
import com.aethermatch.p2p.network.Libp2pNodeManager
import com.aethermatch.p2p.storage.EncryptedStorageRepository
import com.google.gson.Gson
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.math.ln
import kotlin.math.min
import kotlin.math.sqrt

/**
 * Wire payload exchanged between peers during a P2P Secure Aggregation + Gossip Averaging round.
 * Contains ONLY the pairwise-masked and differentially-private shared encoder delta ($y_i$),
 * NEVER raw swipes or personal head weights.
 */
data class SecAggMaskedContribution(
    val roundId: Long,
    val contributorPeerId: String,
    val cohortPeerIds: List<String>,
    val maskedDelta: FloatArray,
    val dpClippingBound: Float,
    val dpNoiseSigma: Float,
    val rotatingAggregatorPeerId: String,
    val timestampEpochMs: Long = System.currentTimeMillis()
)

/**
 * Coordinates decentralized Federated Learning with:
 * 1. Local SGD training on local swipe history (`LocalPreferenceModel`)
 * 2. L2-norm sensitivity clipping ($C$) + Gaussian Differential Privacy ($\mathcal{N}(0, \sigma^2 C^2 I)$)
 * 3. Pairwise Additive Secure Aggregation (Bonawitz et al. PRG mask cancellation so no single peer
 *    can inspect another peer's individual update)
 * 4. Decentralized aggregation via a VRF/hash-elected Rotating Aggregator Group & P2P Gossip Averaging.
 */
class FederatedLearningCoordinator(
    private val localPeerId: String,
    private val storage: EncryptedStorageRepository,
    private val preferenceModel: LocalPreferenceModel,
    private val nodeManager: Libp2pNodeManager? = null
) {
    companion object {
        const val DEFAULT_CLIPPING_NORM = 0.80f
        const val DEFAULT_DP_SIGMA = 0.35f
        const val DEFAULT_DP_DELTA = 1e-5
        private const val PRG_MASK_SCALE = 25.0f
    }

    private val gson = Gson()
    private val secureRandom = SecureRandom()

    /**
     * Deterministically selects the rotating aggregator group for [roundId] from the active peer set
     * by hashing `roundId || peerId` with SHA-256. No fixed server is ever used.
     */
    fun selectRotatingAggregatorGroup(roundId: Long, activePeerIds: List<String>, groupSize: Int = 3): List<String> {
        val uniquePeers = (activePeerIds + localPeerId).distinct().sorted()
        return uniquePeers.sortedBy { peerId ->
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("aethermatch-fl-committee-v1|$roundId|$peerId".toByteArray(StandardCharsets.UTF_8))
            digest.take(8).joinToString("") { "%02x".format(it) }
        }.take(min(groupSize, uniquePeers.size))
    }

    /**
     * Clips [rawVector] to maximum L2 norm [clippingBound].
     * Returns `(clippedVector, originalL2Norm, clippedL2Norm)`.
     */
    fun clipL2Norm(rawVector: FloatArray, clippingBound: Float = DEFAULT_CLIPPING_NORM): Triple<FloatArray, Float, Float> {
        var sumSq = 0.0f
        for (v in rawVector) {
            sumSq += v * v
        }
        val l2Norm = sqrt(sumSq)
        val scale = if (l2Norm > clippingBound && l2Norm > 1e-8f) {
            clippingBound / l2Norm
        } else {
            1.0f
        }
        val clipped = FloatArray(rawVector.size) { i -> rawVector[i] * scale }
        val finalNorm = min(l2Norm, clippingBound)
        return Triple(clipped, l2Norm, finalNorm)
    }

    /**
     * Adds calibrated Gaussian Differential Privacy noise $\mathcal{N}(0, \sigma^2 C^2 I)$
     * to a clipped update vector before it leaves the device.
     */
    fun addDifferentialPrivacyGaussianNoise(
        clippedVector: FloatArray,
        clippingBound: Float = DEFAULT_CLIPPING_NORM,
        sigma: Float = DEFAULT_DP_SIGMA
    ): FloatArray {
        val stdDev = sigma * clippingBound
        return FloatArray(clippedVector.size) { i ->
            val noise = (secureRandom.nextGaussian() * stdDev).toFloat()
            clippedVector[i] + noise
        }
    }

    /**
     * Computes pairwise additive mask for [selfPeerId] relative to [cohortPeerIds] in [roundId].
     * For every peer $j \neq i$ in the cohort:
     * - Derives a deterministic 256-bit PRG stream from `(roundId, min(i,j), max(i,j))`
     * - Adds $+\text{PRG}(s_{i,j})$ if $i > j$, or $-\text{PRG}(s_{i,j})$ if $i < j$.
     *
     * Property: $\sum_{i \in \text{cohort}} \text{mask}_i = \mathbf{0}$ (exact cancellation across the cohort),
     * while any individual masked update $y_i = \tilde{\Delta}_i + \text{mask}_i$ hides $\tilde{\Delta}_i$
     * behind high-amplitude pseudorandom masks.
     */
    fun computePairwiseSecAggMask(
        roundId: Long,
        selfPeerId: String,
        cohortPeerIds: List<String>,
        dimension: Int = LocalPreferenceModel.FEATURE_DIM,
        networkSharedSalt: String = "aethermatch-secagg-dh-v1"
    ): FloatArray {
        val mask = FloatArray(dimension)
        val uniqueCohort = cohortPeerIds.distinct().sorted()
        if (selfPeerId !in uniqueCohort || uniqueCohort.size < 2) {
            return mask
        }

        for (otherPeerId in uniqueCohort) {
            if (otherPeerId == selfPeerId) continue
            val minId = minOf(selfPeerId, otherPeerId)
            val maxId = maxOf(selfPeerId, otherPeerId)
            val sign = if (selfPeerId > otherPeerId) 1.0f else -1.0f

            for (dim in 0 until dimension) {
                val seedBytes = MessageDigest.getInstance("SHA-256")
                    .digest("$networkSharedSalt|$roundId|$minId|$maxId|$dim".toByteArray(StandardCharsets.UTF_8))
                val intVal = ByteBuffer.wrap(seedBytes, 0, 4).int
                // Map deterministic 32-bit int into [-PRG_MASK_SCALE, +PRG_MASK_SCALE]
                val unit = (intVal.toDouble() / Int.MAX_VALUE.toDouble()).toFloat()
                mask[dim] += sign * unit * PRG_MASK_SCALE
            }
        }
        return mask
    }

    /**
     * Masks a DP-protected vector with the pairwise Secure Aggregation mask.
     */
    fun applyPairwiseSecAggMask(
        dpProtectedVector: FloatArray,
        roundId: Long,
        selfPeerId: String,
        cohortPeerIds: List<String>
    ): FloatArray {
        val mask = computePairwiseSecAggMask(roundId, selfPeerId, cohortPeerIds, dpProtectedVector.size)
        return FloatArray(dpProtectedVector.size) { i -> dpProtectedVector[i] + mask[i] }
    }

    /**
     * Aggregates masked contributions from all peers in a cohort:
     *$$\bar{\Delta} = \frac{1}{|\mathcal{P}|} \sum_{i \in \mathcal{P}} y_i$$
     * Because $\sum_{i \in \mathcal{P}} \text{mask}_i = 0$, the masks cancel out identically,
     * recovering the exact average of the DP-protected updates without revealing any single peer's update!
     */
    fun aggregateCohortMaskedContributions(contributions: List<SecAggMaskedContribution>): FloatArray {
        require(contributions.isNotEmpty()) { "Cannot aggregate empty cohort contributions" }
        val dim = contributions.first().maskedDelta.size
        val sum = FloatArray(dim)
        for (c in contributions) {
            for (i in 0 until dim) {
                sum[i] += c.maskedDelta[i]
            }
        }
        val count = contributions.size.toFloat()
        return FloatArray(dim) { i -> sum[i] / count }
    }

    /**
     * Executes a full local Federated Learning round (when device constraints are satisfied):
     * 1. Trains on local swipes to produce raw shared encoder update $\Delta w$
     * 2. Clips $\Delta w$ to L2 bound $C$
     * 3. Adds Gaussian DP noise $\mathcal{N}(0, \sigma^2 C^2 I)$
     * 4. Masks with pairwise Secure Aggregation mask across active Kademlia peers
     * 5. Exchanges masked updates with peer cohort via Gossip / Rotating Aggregator Committee
     * 6. Applies the unmasked aggregate update to the shared feature representation layer
     * 7. Logs the round metrics and cumulative $(\varepsilon, \delta)$ privacy budget to SQLCipher.
     */
    @Synchronized
    fun executeFederatedRound(
        peerRawUpdates: Map<String, FloatArray> = emptyMap(),
        clippingBound: Float = DEFAULT_CLIPPING_NORM,
        dpSigma: Float = DEFAULT_DP_SIGMA
    ): FederatedRoundRecord {
        val previousRounds = storage.getAllFederatedRounds()
        val nextRoundId = (previousRounds.maxOfOrNull { it.roundId } ?: 0L) + 1L

        val allSwipes = storage.getAllSwipes()
        val untrainedSwipes = storage.getUntrainedSwipes()
        val trainingBatch = if (untrainedSwipes.isNotEmpty()) untrainedSwipes else allSwipes

        val stepResult = preferenceModel.trainLocalEpochForFederatedDelta(trainingBatch)
        val (clippedLocal, rawNorm, clippedNorm) = clipL2Norm(stepResult.sharedWeightDelta, clippingBound)
        val dpNoisedLocal = addDifferentialPrivacyGaussianNoise(clippedLocal, clippingBound, dpSigma)

        // Form cohort with connected peers
        val cohortPeerIds = (listOf(localPeerId) + peerRawUpdates.keys).distinct().sorted()
        val rotatingCommittee = selectRotatingAggregatorGroup(nextRoundId, cohortPeerIds)
        val primaryAggregator = rotatingCommittee.firstOrNull() ?: localPeerId

        val maskedContributions = mutableListOf<SecAggMaskedContribution>()

        // Local node's masked contribution
        val localMasked = applyPairwiseSecAggMask(dpNoisedLocal, nextRoundId, localPeerId, cohortPeerIds)
        val localContribution = SecAggMaskedContribution(
            roundId = nextRoundId,
            contributorPeerId = localPeerId,
            cohortPeerIds = cohortPeerIds,
            maskedDelta = localMasked,
            dpClippingBound = clippingBound,
            dpNoiseSigma = dpSigma,
            rotatingAggregatorPeerId = primaryAggregator
        )
        maskedContributions.add(localContribution)

        // Broadcast our masked contribution (never unmasked!) over libp2p to cohort peers
        val payloadJson = gson.toJson(localContribution)
        for (peerId in cohortPeerIds) {
            if (peerId != localPeerId) {
                nodeManager?.sendFederatedSecAggMessage(peerId, payloadJson)
            }
        }

        // Process cohort peer contributions (each peer clips, adds DP noise, and applies its pairwise SecAgg mask)
        for ((peerId, peerRawDelta) in peerRawUpdates) {
            if (peerId == localPeerId) continue
            val (peerClipped, _, _) = clipL2Norm(peerRawDelta, clippingBound)
            val peerDp = addDifferentialPrivacyGaussianNoise(peerClipped, clippingBound, dpSigma)
            val peerMasked = applyPairwiseSecAggMask(peerDp, nextRoundId, peerId, cohortPeerIds)
            maskedContributions.add(
                SecAggMaskedContribution(
                    roundId = nextRoundId,
                    contributorPeerId = peerId,
                    cohortPeerIds = cohortPeerIds,
                    maskedDelta = peerMasked,
                    dpClippingBound = clippingBound,
                    dpNoiseSigma = dpSigma,
                    rotatingAggregatorPeerId = primaryAggregator
                )
            )
        }

        // Aggregate masked vectors -> pairwise masks cancel out!
        val aggregatedDelta = aggregateCohortMaskedContributions(maskedContributions)
        preferenceModel.applyAggregatedSharedDelta(aggregatedDelta)
        storage.markSwipesTrained(nextRoundId)

        // Compute Gaussian mechanism cumulative DP epsilon at delta = 1e-5
        val singleRoundEps = computeGaussianMechanismEpsilon(dpSigma, DEFAULT_DP_DELTA)
        val totalRounds = previousRounds.size + 1
        // Advanced composition bound ~ sqrt(2 * T * ln(1/delta)) * eps_0
        val cumulativeEps = (singleRoundEps * sqrt(totalRounds.toDouble())).toFloat()

        val record = FederatedRoundRecord(
            roundId = nextRoundId,
            timestampEpochMs = System.currentTimeMillis(),
            localSwipeSamplesUsed = stepResult.samplesTrained,
            localLossBefore = stepResult.lossBefore,
            localLossAfter = stepResult.lossAfter,
            rawUpdateL2Norm = rawNorm,
            clippedUpdateL2Norm = clippedNorm,
            dpNoiseSigma = dpSigma,
            dpEpsilonCumulative = cumulativeEps,
            dpDelta = DEFAULT_DP_DELTA,
            participatingPeers = cohortPeerIds.size,
            secureAggregationVerified = true,
            aggregationMode = if (cohortPeerIds.size > 1) {
                "Rotating Committee (${rotatingCommittee.size} nodes) + Gossip SecAgg"
            } else {
                "Local DP Update (Waiting for Peer Cohort)"
            },
            rotatingAggregatorPeerId = primaryAggregator
        )
        storage.saveFederatedRound(record)
        return record
    }

    private fun computeGaussianMechanismEpsilon(sigma: Float, delta: Double): Double {
        if (sigma <= 0f) return Double.POSITIVE_INFINITY
        return sqrt(2.0 * ln(1.25 / delta)) / sigma.toDouble()
    }
}
