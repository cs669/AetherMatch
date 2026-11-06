package com.aethermatch.p2p.ai

import com.aethermatch.p2p.model.RelationshipGoal
import com.aethermatch.p2p.model.SignedPeerProfileAnnouncement
import com.aethermatch.p2p.model.SwipeRecord
import com.aethermatch.p2p.model.UserProfile
import com.aethermatch.p2p.storage.EncryptedStorageRepository
import java.util.Locale
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

data class LocalTrainingStepResult(
    val samplesTrained: Int,
    val lossBefore: Float,
    val lossAfter: Float,
    val sharedWeightDelta: FloatArray
)

data class CandidateScoreResult(
    val compatibilityScore: Float,
    val featureVector: FloatArray,
    val explanations: List<String>
)

/**
 * On-device Split-Architecture Preference & Matching Model:
 * 1. **Shared Federated Feature Calibrator (`sharedWeights`, 16-D)**:
 *    Calibrates feature salience across the P2P network via Secure Aggregation + Differential Privacy.
 * 2. **Strictly Local Personal Preference Head (`personalWeights`, 16-D)**:
 *    Learns the individual user's unique taste from their swipes and NEVER leaves the device.
 *
 * All profile ranking and compatibility scoring execute 100% locally on the user's device.
 */
class LocalPreferenceModel(
    private val storage: EncryptedStorageRepository
) {
    companion object {
        const val FEATURE_DIM = 16
        private const val KEY_SHARED_WEIGHTS = "fl_shared_encoder_weights_v1"
        private const val KEY_PERSONAL_WEIGHTS = "local_personal_head_weights_v1"

        private val TOPIC_CLUSTERS: List<Pair<String, Set<String>>> = listOf(
            "Tech, AI & Cryptography" to setOf("cryptography", "ai", "ml", "distributed", "rust", "robotics", "neuroscience", "systems", "coding", "security"),
            "Outdoors & Endurance" to setOf("climbing", "trail", "running", "hiking", "cycling", "kayaking", "alpine", "camping", "outdoors"),
            "Music, Jazz & Vinyl" to setOf("jazz", "vinyl", "music", "piano", "acoustic", "concert", "indie"),
            "Culinary & Specialty Coffee" to setOf("coffee", "espresso", "matcha", "cooking", "baking", "sourdough", "food", "wine"),
            "Philosophy & Deep Inquiry" to setOf("philosophy", "sci-fi", "literature", "reading", "research", "science", "books"),
            "Visual Arts & Photography" to setOf("photography", "film", "art", "design", "architecture", "creative"),
            "Nature & Conservation" to setOf("conservation", "marine", "biology", "ocean", "ecology", "sustainability"),
            "Movement & Social" to setOf("dance", "travel", "culture", "languages", "community")
        )
    }

    private var sharedWeights: FloatArray = storage.loadModelWeights(KEY_SHARED_WEIGHTS)
        ?: FloatArray(FEATURE_DIM) { idx ->
            when (idx) {
                0 -> 0.85f // Shared interests overlap
                1 -> 0.65f // Age preference fit
                2 -> 0.80f // Relationship goal match
                3 -> 0.40f // Complementary goal
                4 -> 0.45f // Region proximity
                15 -> -0.25f // Base bias calibrator
                else -> 0.50f // Topic cluster salience
            }
        }

    private var personalWeights: FloatArray = storage.loadModelWeights(KEY_PERSONAL_WEIGHTS)
        ?: FloatArray(FEATURE_DIM) { idx ->
            when (idx) {
                0 -> 0.65f
                1 -> 0.45f
                2 -> 0.60f
                3 -> 0.25f
                4 -> 0.30f
                13 -> 0.20f
                14 -> 0.20f
                15 -> -0.65f
                else -> 0.25f
            }
        }

    @Synchronized
    fun getSharedWeightsCopy(): FloatArray = sharedWeights.copyOf()

    @Synchronized
    fun getPersonalWeightsCopy(): FloatArray = personalWeights.copyOf()

    /**
     * Extracts a 16-dimensional normalized feature vector comparing [localUser] with [candidate].
     */
    fun extractFeatureVector(
        localUser: UserProfile?,
        candidate: SignedPeerProfileAnnouncement
    ): FloatArray {
        val features = FloatArray(FEATURE_DIM)
        val candInterestsLower = candidate.interests.map { it.lowercase(Locale.US) }.toSet()
        val candTokens = (candidate.interests + candidate.bio.split(Regex("[^a-zA-Z0-9-]+")))
            .map { it.lowercase(Locale.US) }
            .filter { it.length > 2 }
            .toSet()

        if (localUser != null) {
            val userInterestsLower = localUser.interests.map { it.lowercase(Locale.US) }.toSet()
            val intersection = userInterestsLower.intersect(candInterestsLower).size
            val union = max(1, userInterestsLower.union(candInterestsLower).size)
            features[0] = (intersection.toFloat() / union.toFloat() * 2.2f).coerceIn(0f, 1.5f)

            val inRange = candidate.age in localUser.preferredMinAge..localUser.preferredMaxAge
            val midAge = (localUser.preferredMinAge + localUser.preferredMaxAge) / 2f
            val span = max(4f, (localUser.preferredMaxAge - localUser.preferredMinAge) / 2f)
            val ageDist = abs(candidate.age - midAge) / span
            features[1] = if (inRange) (1.0f - 0.35f * ageDist).coerceIn(0.3f, 1.0f) else (-0.4f * ageDist).coerceIn(-1.0f, 0.1f)

            features[2] = if (candidate.relationshipGoal == localUser.relationshipGoal) 1.0f else 0.0f
            features[3] = if (areGoalsComplementary(localUser.relationshipGoal, candidate.relationshipGoal)) 0.7f else 0.0f
            features[4] = if (candidate.locationRegion.equals(localUser.locationRegion, ignoreCase = true)) 1.0f else 0.35f
        } else {
            features[0] = 0.5f
            features[1] = 0.7f
            features[2] = 0.6f
            features[3] = 0.5f
            features[4] = 0.5f
        }

        // Features 5..12: 8 Latent Topic Clusters
        for (i in TOPIC_CLUSTERS.indices) {
            val (_, keywords) = TOPIC_CLUSTERS[i]
            val matches = candTokens.count { token -> keywords.any { kw -> token.contains(kw) } }
            features[5 + i] = min(1.0f, matches * 0.45f)
        }

        // Feature 13: Bio richness
        features[13] = min(1.0f, candidate.bio.length / 140.0f)
        // Feature 14: Interest breadth
        features[14] = min(1.0f, candidate.interests.size / 5.0f)
        // Feature 15: Bias
        features[15] = 1.0f

        return features
    }

    /**
     * Scores a candidate profile locally using the combined personal preference head and
     * shared federated representation layer.
     */
    @Synchronized
    fun scoreCandidate(
        localUser: UserProfile?,
        candidate: SignedPeerProfileAnnouncement
    ): CandidateScoreResult {
        val x = extractFeatureVector(localUser, candidate)
        val prob = predictProbability(x, sharedWeights, personalWeights)
        val explanations = buildExplanations(localUser, candidate, x)
        return CandidateScoreResult(
            compatibilityScore = prob,
            featureVector = x,
            explanations = explanations
        )
    }

    /**
     * Immediately updates the strictly-local `personalWeights` on a single user swipe
     * (online stochastic gradient step) so the deck adapts in real time as the user swipes!
     * Raw swipes and `personalWeights` never leave the device.
     */
    @Synchronized
    fun updatePersonalHeadImmediate(featureVector: FloatArray, liked: Boolean, learningRate: Float = 0.22f) {
        val target = if (liked) 1.0f else 0.0f
        val pred = predictProbability(featureVector, sharedWeights, personalWeights)
        // Balanced margin-aware error so positive swipes reinforce active features even at high confidence
        val rawError = pred - target
        val direction = if (liked) -max(0.35f, abs(rawError)) else max(0.35f, abs(rawError))
        val l2Reg = 0.001f

        for (i in 0 until FEATURE_DIM) {
            val gate = softplus(sharedWeights[i])
            // Keep bias (index 15) stable so feature-specific weights drive personalization
            val stepScale = if (i == 15) 0.08f else 1.0f
            val gradPersonal = direction * gate * featureVector[i] + l2Reg * personalWeights[i]
            personalWeights[i] = (personalWeights[i] - learningRate * stepScale * gradPersonal).coerceIn(-4.0f, 4.0f)
        }
        storage.saveModelWeights(KEY_PERSONAL_WEIGHTS, personalWeights)
    }

    /**
     * Runs multi-epoch local training on local swipe history to compute a candidate update delta
     * ($\Delta w_{\text{shared}}$) for the shared representation layer during a Federated Learning round.
     * Returns only the shared weight delta and local training metrics.
     */
    @Synchronized
    fun trainLocalEpochForFederatedDelta(
        swipes: List<SwipeRecord>,
        epochs: Int = 6,
        learningRate: Float = 0.12f
    ): LocalTrainingStepResult {
        if (swipes.isEmpty()) {
            return LocalTrainingStepResult(
                samplesTrained = 0,
                lossBefore = 0f,
                lossAfter = 0f,
                sharedWeightDelta = FloatArray(FEATURE_DIM)
            )
        }

        val initialShared = sharedWeights.copyOf()
        val workingShared = sharedWeights.copyOf()
        val workingPersonal = personalWeights.copyOf()

        val lossBefore = computeAverageBceLoss(swipes, workingShared, workingPersonal)

        for (epoch in 0 until epochs) {
            for (swipe in swipes) {
                val x = swipe.encodedFeatures
                if (x.size != FEATURE_DIM) continue
                val y = if (swipe.liked) 1.0f else 0.0f
                val pred = predictProbability(x, workingShared, workingPersonal)
                val err = pred - y

                for (i in 0 until FEATURE_DIM) {
                    val gate = softplus(workingShared[i])
                    val dGate = sigmoid(workingShared[i])
                    val gradPersonal = err * gate * x[i] + 0.002f * workingPersonal[i]
                    val gradShared = err * workingPersonal[i] * dGate * x[i] + 0.002f * workingShared[i]

                    workingPersonal[i] = (workingPersonal[i] - learningRate * gradPersonal).coerceIn(-4.0f, 4.0f)
                    workingShared[i] = (workingShared[i] - learningRate * gradShared).coerceIn(-4.0f, 4.0f)
                }
            }
        }

        val lossAfter = computeAverageBceLoss(swipes, workingShared, workingPersonal)

        // Persist updated personal head locally
        personalWeights = workingPersonal
        storage.saveModelWeights(KEY_PERSONAL_WEIGHTS, personalWeights)

        val delta = FloatArray(FEATURE_DIM) { i -> workingShared[i] - initialShared[i] }
        return LocalTrainingStepResult(
            samplesTrained = swipes.size,
            lossBefore = lossBefore,
            lossAfter = lossAfter,
            sharedWeightDelta = delta
        )
    }

    /**
     * Applies an aggregated global Federated Learning delta to the shared representation weights.
     */
    @Synchronized
    fun applyAggregatedSharedDelta(aggregatedDelta: FloatArray) {
        require(aggregatedDelta.size == FEATURE_DIM)
        for (i in 0 until FEATURE_DIM) {
            sharedWeights[i] = (sharedWeights[i] + aggregatedDelta[i]).coerceIn(-4.0f, 4.0f)
        }
        storage.saveModelWeights(KEY_SHARED_WEIGHTS, sharedWeights)
    }

    private fun computeAverageBceLoss(
        swipes: List<SwipeRecord>,
        shared: FloatArray,
        personal: FloatArray
    ): Float {
        var total = 0.0f
        var count = 0
        for (s in swipes) {
            if (s.encodedFeatures.size != FEATURE_DIM) continue
            val p = predictProbability(s.encodedFeatures, shared, personal).coerceIn(1e-5f, 1.0f - 1e-5f)
            val y = if (s.liked) 1.0f else 0.0f
            total += -(y * ln(p) + (1.0f - y) * ln(1.0f - p))
            count++
        }
        return if (count > 0) total / count else 0f
    }

    private fun predictProbability(
        x: FloatArray,
        shared: FloatArray,
        personal: FloatArray
    ): Float {
        var dot = 0.0f
        for (i in 0 until FEATURE_DIM) {
            dot += personal[i] * softplus(shared[i]) * x[i]
        }
        return sigmoid(dot).coerceIn(0.05f, 0.99f)
    }

    private fun buildExplanations(
        localUser: UserProfile?,
        candidate: SignedPeerProfileAnnouncement,
        x: FloatArray
    ): List<String> {
        val reasons = mutableListOf<String>()
        if (localUser != null) {
            val sharedInterests = candidate.interests.filter { ci ->
                localUser.interests.any { ui -> ui.equals(ci, ignoreCase = true) }
            }
            if (sharedInterests.isNotEmpty()) {
                reasons.add("Shared passions: ${sharedInterests.take(3).joinToString(", ")}")
            }
            if (candidate.relationshipGoal == localUser.relationshipGoal) {
                reasons.add("Aligned on ${candidate.relationshipGoal.displayLabel}")
            }
        }

        // Find highest positive personal * shared topic weight contributions
        val topicContributions = TOPIC_CLUSTERS.indices.map { idx ->
            val featIdx = 5 + idx
            val contribution = personalWeights[featIdx] * softplus(sharedWeights[featIdx]) * x[featIdx]
            TOPIC_CLUSTERS[idx].first to contribution
        }.sortedByDescending { it.second }

        for ((topicLabel, contrib) in topicContributions.take(2)) {
            if (contrib > 0.12f) {
                reasons.add("AI learned affinity: $topicLabel")
            }
        }

        if (reasons.isEmpty()) {
            reasons.add("Complementary profile discovered on Kademlia DHT")
        }
        return reasons
    }

    private fun areGoalsComplementary(a: RelationshipGoal, b: RelationshipGoal): Boolean {
        if (a == b) return true
        val serious = setOf(RelationshipGoal.LONG_TERM_PARTNER, RelationshipGoal.SERIOUS_DATING, RelationshipGoal.DEEP_INTELLECTUAL_BOND)
        return a in serious && b in serious
    }

    private fun sigmoid(z: Float): Float = (1.0f / (1.0f + exp(-z.coerceIn(-15f, 15f))))

    private fun softplus(z: Float): Float = ln(1.0f + exp(z.coerceIn(-15f, 15f)))
}
