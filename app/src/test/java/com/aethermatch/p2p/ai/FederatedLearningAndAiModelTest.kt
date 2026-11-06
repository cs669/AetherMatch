package com.aethermatch.p2p.ai

import com.aethermatch.p2p.model.RelationshipGoal
import com.aethermatch.p2p.model.SignedPeerProfileAnnouncement
import com.aethermatch.p2p.model.SwipeRecord
import com.aethermatch.p2p.model.UserProfile
import com.aethermatch.p2p.security.JvmAesGcmMasterKeyWrapper
import com.aethermatch.p2p.security.KeystoreKeyManager
import com.aethermatch.p2p.storage.EncryptedRecordStorageRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

class FederatedLearningAndAiModelTest {

    @Test
    fun `LocalPreferenceModel adapts personal head weights on user swipes and improves ranking`() {
        val keyManager = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val storage = EncryptedRecordStorageRepository(keyManager)
        val model = LocalPreferenceModel(storage)

        val localUser = UserProfile(
            peerId = "12D3KooWLocal",
            displayName = "Alex",
            age = 29,
            bio = "Systems programmer & trail runner",
            interests = listOf("Cryptography", "Climbing"),
            relationshipGoal = RelationshipGoal.LONG_TERM_PARTNER,
            locationRegion = "Metro Core"
        )

        val preferredCandidate = SignedPeerProfileAnnouncement(
            peerId = "12D3KooWCandidateA",
            displayName = "Maya",
            age = 28,
            bio = "Cryptography researcher and alpine climbing enthusiast",
            interests = listOf("Cryptography", "Climbing", "AI & ML"),
            relationshipGoal = RelationshipGoal.LONG_TERM_PARTNER,
            locationRegion = "Metro Core",
            listenMultiaddrs = emptyList(),
            signalPreKeyBundleJson = "{}",
            matchCommitPublicKeyBase64 = "",
            timestampEpochMs = 1000L,
            ed25519PublicKeyBase64 = "",
            ed25519SignatureBase64 = ""
        )

        val nonPreferredCandidate = SignedPeerProfileAnnouncement(
            peerId = "12D3KooWCandidateB",
            displayName = "Other",
            age = 44,
            bio = "Casual concerts",
            interests = listOf("Concerts"),
            relationshipGoal = RelationshipGoal.NEW_FRIENDS_AND_DATES,
            locationRegion = "Other Region",
            listenMultiaddrs = emptyList(),
            signalPreKeyBundleJson = "{}",
            matchCommitPublicKeyBase64 = "",
            timestampEpochMs = 1000L,
            ed25519PublicKeyBase64 = "",
            ed25519SignatureBase64 = ""
        )

        val initialPrefScore = model.scoreCandidate(localUser, preferredCandidate)
        val initialNonPrefScore = model.scoreCandidate(localUser, nonPreferredCandidate)
        assertTrue(initialPrefScore.compatibilityScore > initialNonPrefScore.compatibilityScore)

        // Train on positive swipes for preferred features and negative swipes for non-preferred features
        repeat(6) {
            model.updatePersonalHeadImmediate(initialPrefScore.featureVector, liked = true)
            model.updatePersonalHeadImmediate(initialNonPrefScore.featureVector, liked = false)
        }

        val updatedPrefScore = model.scoreCandidate(localUser, preferredCandidate)
        val updatedNonPrefScore = model.scoreCandidate(localUser, nonPreferredCandidate)

        assertTrue(updatedPrefScore.compatibilityScore > initialPrefScore.compatibilityScore)
        assertTrue(updatedNonPrefScore.compatibilityScore < initialNonPrefScore.compatibilityScore)
    }

    @Test
    fun `Pairwise Secure Aggregation masks hide individual updates and cancel out identically across cohort`() {
        val keyManager = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val storage = EncryptedRecordStorageRepository(keyManager)
        val model = LocalPreferenceModel(storage)
        val coordinator = FederatedLearningCoordinator("Peer_A", storage, model, null)

        val cohort = listOf("Peer_A", "Peer_B", "Peer_C", "Peer_D")
        val roundId = 42L
        val dim = LocalPreferenceModel.FEATURE_DIM

        val rawDpVectors = mapOf(
            "Peer_A" to FloatArray(dim) { i -> 0.10f * (i + 1) },
            "Peer_B" to FloatArray(dim) { i -> -0.05f * (i + 1) },
            "Peer_C" to FloatArray(dim) { i -> 0.20f * (i + 1) },
            "Peer_D" to FloatArray(dim) { i -> 0.15f * (i + 1) }
        )

        val maskedContributions = cohort.map { peerId ->
            val unmasked = rawDpVectors.getValue(peerId)
            val masked = coordinator.applyPairwiseSecAggMask(unmasked, roundId, peerId, cohort)

            // Verify the masked vector does NOT reveal the unmasked vector
            val maxDiff = unmasked.indices.maxOf { idx -> abs(masked[idx] - unmasked[idx]) }
            assertTrue("Individual masked vector must be strongly obfuscated by pairwise PRG masks", maxDiff > 1.0f)

            SecAggMaskedContribution(
                roundId = roundId,
                contributorPeerId = peerId,
                cohortPeerIds = cohort,
                maskedDelta = masked,
                dpClippingBound = 0.8f,
                dpNoiseSigma = 0.35f,
                rotatingAggregatorPeerId = "Peer_B"
            )
        }

        // Aggregate all masked contributions -> pairwise masks must cancel out to 0!
        val aggregatedFromMasked = coordinator.aggregateCohortMaskedContributions(maskedContributions)

        for (i in 0 until dim) {
            val expectedTrueAverage = cohort.map { rawDpVectors.getValue(it)[i] }.average().toFloat()
            assertEquals(
                "Pairwise SecAgg masks must cancel out identically at dimension $i",
                expectedTrueAverage,
                aggregatedFromMasked[i],
                1e-4f
            )
        }
    }

    @Test
    fun `L2 norm clipping and full Federated Learning round record DP privacy budget`() {
        val keyManager = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val storage = EncryptedRecordStorageRepository(keyManager)
        val model = LocalPreferenceModel(storage)
        val coordinator = FederatedLearningCoordinator("12D3KooWNode1", storage, model, null)

        val largeVector = FloatArray(LocalPreferenceModel.FEATURE_DIM) { 2.0f } // L2 norm = sqrt(16 * 4) = 8.0
        val (clipped, origNorm, finalNorm) = coordinator.clipL2Norm(largeVector, clippingBound = 0.80f)
        assertEquals(8.0f, origNorm, 1e-4f)
        assertEquals(0.80f, finalNorm, 1e-4f)

        var checkSq = 0f
        for (v in clipped) checkSq += v * v
        assertEquals(0.80f, kotlin.math.sqrt(checkSq), 1e-3f)

        // Record local swipes and execute a Federated Learning round with 2 cohort peers
        storage.recordSwipe(
            SwipeRecord(
                peerId = "12D3KooWPeerX",
                liked = true,
                encodedFeatures = FloatArray(LocalPreferenceModel.FEATURE_DIM) { 0.6f },
                compatibilityAtSwipe = 0.8f
            )
        )
        storage.recordSwipe(
            SwipeRecord(
                peerId = "12D3KooWPeerY",
                liked = false,
                encodedFeatures = FloatArray(LocalPreferenceModel.FEATURE_DIM) { -0.3f },
                compatibilityAtSwipe = 0.2f
            )
        )

        val roundRecord = coordinator.executeFederatedRound(
            peerRawUpdates = mapOf(
                "12D3KooWNode2" to FloatArray(LocalPreferenceModel.FEATURE_DIM) { 0.05f },
                "12D3KooWNode3" to FloatArray(LocalPreferenceModel.FEATURE_DIM) { 0.03f }
            )
        )

        assertEquals(1L, roundRecord.roundId)
        assertEquals(2, roundRecord.localSwipeSamplesUsed)
        assertEquals(3, roundRecord.participatingPeers)
        assertTrue(roundRecord.secureAggregationVerified)
        assertTrue(roundRecord.dpEpsilonCumulative > 0f)
        assertNotEquals("", roundRecord.rotatingAggregatorPeerId)
    }
}
