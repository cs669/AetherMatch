package com.aethermatch.p2p.model

/**
 * Represents the user's own profile stored in SQLCipher and signed before publishing to the Kademlia DHT.
 */
data class UserProfile(
    val peerId: String,
    val displayName: String,
    val age: Int,
    val bio: String,
    val interests: List<String>,
    val relationshipGoal: RelationshipGoal,
    val locationRegion: String,
    val preferredMinAge: Int = 21,
    val preferredMaxAge: Int = 45,
    val updatedAtEpochMs: Long = System.currentTimeMillis()
)

enum class RelationshipGoal(val displayLabel: String) {
    LONG_TERM_PARTNER("Long-Term Partner"),
    SERIOUS_DATING("Serious Dating"),
    NEW_FRIENDS_AND_DATES("Friends & Connections"),
    DEEP_INTELLECTUAL_BOND("Intellectual & Creative Bond")
}

/**
 * Signed public profile + Signal PreKeyBundle published to the Kademlia DHT under key `/aethermatch/profile/<peerId>`.
 * All fields are covered by the Ed25519 signature (`ed25519SignatureBase64`).
 */
data class SignedPeerProfileAnnouncement(
    val peerId: String,
    val displayName: String,
    val age: Int,
    val bio: String,
    val interests: List<String>,
    val relationshipGoal: RelationshipGoal,
    val locationRegion: String,
    val listenMultiaddrs: List<String>,
    val signalPreKeyBundleJson: String,
    val matchCommitPublicKeyBase64: String,
    val timestampEpochMs: Long,
    val ed25519PublicKeyBase64: String,
    val ed25519SignatureBase64: String
)

/**
 * A discovered peer profile enriched with local AI compatibility scoring.
 * Ranking and compatibility scoring run 100% locally on the user's device.
 */
data class DiscoveredProfile(
    val announcement: SignedPeerProfileAnnouncement,
    val localCompatibilityScore: Float, // 0.0f .. 1.0f
    val compatibilityExplanation: List<String>,
    val signatureVerified: Boolean,
    val discoveredVia: DiscoverySource,
    val swiped: Boolean = false
)

enum class DiscoverySource(val label: String) {
    KADEMLIA_DHT("Kademlia DHT"),
    LOCAL_MDNS("Local mDNS"),
    GOSSIP_RELAY("Circuit Relay / Gossip"),
    VIRTUAL_SWARM_DEBUG("Virtual Swarm (Debug Only)")
}

/**
 * Strictly local swipe record stored only inside SQLCipher.
 * Raw swipes and personal preference weights NEVER leave the device.
 */
data class SwipeRecord(
    val peerId: String,
    val liked: Boolean,
    val encodedFeatures: FloatArray,
    val compatibilityAtSwipe: Float,
    val timestampEpochMs: Long = System.currentTimeMillis(),
    val trainedInRound: Long? = null
)

/**
 * Mutual match established via bilateral cryptographic match handshake.
 */
data class MatchRecord(
    val peerId: String,
    val displayName: String,
    val age: Int,
    val bio: String,
    val interests: List<String>,
    val safetyNumberFingerprint: String,
    val matchedAtEpochMs: Long,
    val lastMessagePreview: String = "End-to-end encrypted Signal session established",
    val lastActivityEpochMs: Long = matchedAtEpochMs
)

/**
 * End-to-end encrypted chat message using `libsignal-client` (X3DH + Double Ratchet).
 */
data class ChatMessage(
    val messageId: String,
    val conversationPeerId: String,
    val senderPeerId: String,
    val plaintextBody: String,
    val ciphertextHexPreview: String,
    val signalMessageType: String, // "PreKeySignalMessage (X3DH)" or "SignalMessage (DoubleRatchet)"
    val timestampEpochMs: Long,
    val verifiedAuthentic: Boolean = true
)

/**
 * Record of a local Federated Learning training & Secure Aggregation round.
 */
data class FederatedRoundRecord(
    val roundId: Long,
    val timestampEpochMs: Long,
    val localSwipeSamplesUsed: Int,
    val localLossBefore: Float,
    val localLossAfter: Float,
    val rawUpdateL2Norm: Float,
    val clippedUpdateL2Norm: Float,
    val dpNoiseSigma: Float,
    val dpEpsilonCumulative: Float,
    val dpDelta: Double,
    val participatingPeers: Int,
    val secureAggregationVerified: Boolean,
    val aggregationMode: String, // "Rotating Committee SecAgg" or "P2P Gossip SecAgg"
    val rotatingAggregatorPeerId: String
)
