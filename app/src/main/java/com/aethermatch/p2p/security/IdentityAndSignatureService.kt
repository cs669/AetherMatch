package com.aethermatch.p2p.security

import com.aethermatch.p2p.model.RelationshipGoal
import com.aethermatch.p2p.model.SignedPeerProfileAnnouncement
import com.aethermatch.p2p.model.UserProfile
import io.libp2p.core.PeerId
import io.libp2p.core.crypto.PrivKey
import io.libp2p.core.crypto.PubKey
import io.libp2p.crypto.keys.generateEd25519KeyPair
import io.libp2p.crypto.keys.unmarshalEd25519PrivateKey
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Manages the node's libp2p Ed25519 cryptographic identity (persisted wrapped in Android Keystore)
 * and signs/verifies Kademlia DHT profile & PreKeyBundle records so no peer can tamper with or
 * forge another peer's profile or Signal PreKeyBundle.
 */
class IdentityAndSignatureService(
    private val keystoreKeyManager: KeystoreKeyManager
) {
    val privKey: PrivKey by lazy {
        val rawBytes = keystoreKeyManager.getOrCreateLibp2pPrivateKeyBytes {
            val (priv, _) = generateEd25519KeyPair()
            priv.raw()
        }
        unmarshalEd25519PrivateKey(rawBytes)
    }

    val pubKey: PubKey
        get() = privKey.publicKey()

    val localPeerId: PeerId
        get() = PeerId.fromPubKey(pubKey)

    val localPeerIdBase58: String
        get() = localPeerId.toBase58()

    /**
     * Produces a canonical byte payload covering all fields of a peer's public profile announcement
     * and Signal PreKeyBundle for Ed25519 signing and verification.
     */
    private fun canonicalSigningPayload(
        peerId: String,
        displayName: String,
        age: Int,
        bio: String,
        interests: List<String>,
        relationshipGoal: RelationshipGoal,
        locationRegion: String,
        listenMultiaddrs: List<String>,
        signalPreKeyBundleJson: String,
        matchCommitPublicKeyBase64: String,
        timestampEpochMs: Long,
        ed25519PublicKeyBase64: String
    ): ByteArray {
        val canonical = buildString {
            append("aethermatch-profile-v1|")
            append(peerId).append('|')
            append(displayName).append('|')
            append(age).append('|')
            append(bio).append('|')
            append(interests.joinToString(",")).append('|')
            append(relationshipGoal.name).append('|')
            append(locationRegion).append('|')
            append(listenMultiaddrs.sorted().joinToString(",")).append('|')
            append(signalPreKeyBundleJson).append('|')
            append(matchCommitPublicKeyBase64).append('|')
            append(timestampEpochMs).append('|')
            append(ed25519PublicKeyBase64)
        }
        return canonical.toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Signs the local [UserProfile], [signalPreKeyBundleJson], and [listenMultiaddrs] with this
     * node's Ed25519 private key for publication into the Kademlia DHT.
     */
    fun signProfileAnnouncement(
        profile: UserProfile,
        listenMultiaddrs: List<String>,
        signalPreKeyBundleJson: String,
        timestampEpochMs: Long = System.currentTimeMillis()
    ): SignedPeerProfileAnnouncement {
        val encoder = Base64.getEncoder()
        val pubKeyBase64 = encoder.encodeToString(pubKey.raw())
        val payload = canonicalSigningPayload(
            peerId = localPeerIdBase58,
            displayName = profile.displayName,
            age = profile.age,
            bio = profile.bio,
            interests = profile.interests,
            relationshipGoal = profile.relationshipGoal,
            locationRegion = profile.locationRegion,
            listenMultiaddrs = listenMultiaddrs,
            signalPreKeyBundleJson = signalPreKeyBundleJson,
            matchCommitPublicKeyBase64 = pubKeyBase64,
            timestampEpochMs = timestampEpochMs,
            ed25519PublicKeyBase64 = pubKeyBase64
        )
        val signature = privKey.sign(payload)
        return SignedPeerProfileAnnouncement(
            peerId = localPeerIdBase58,
            displayName = profile.displayName,
            age = profile.age,
            bio = profile.bio,
            interests = profile.interests,
            relationshipGoal = profile.relationshipGoal,
            locationRegion = profile.locationRegion,
            listenMultiaddrs = listenMultiaddrs,
            signalPreKeyBundleJson = signalPreKeyBundleJson,
            matchCommitPublicKeyBase64 = pubKeyBase64,
            timestampEpochMs = timestampEpochMs,
            ed25519PublicKeyBase64 = pubKeyBase64,
            ed25519SignatureBase64 = encoder.encodeToString(signature)
        )
    }

    /**
     * Cryptographically verifies an incoming [SignedPeerProfileAnnouncement]:
     * 1. Unmarshals the Ed25519 public key and verifies that `PeerId.fromPubKey(pubKey).toBase58() == announcement.peerId`.
     * 2. Verifies the Ed25519 signature over the canonical profile & Signal PreKeyBundle fields.
     */
    fun verifyProfileAnnouncement(announcement: SignedPeerProfileAnnouncement): Boolean {
        return runCatching {
            val decoder = Base64.getDecoder()
            val rawPubKey = decoder.decode(announcement.ed25519PublicKeyBase64)
            val remotePubKey = unmarshalEd25519PublicKey(rawPubKey)
            val derivedPeerId = PeerId.fromPubKey(remotePubKey).toBase58()
            if (derivedPeerId != announcement.peerId) {
                return false
            }

            val payload = canonicalSigningPayload(
                peerId = announcement.peerId,
                displayName = announcement.displayName,
                age = announcement.age,
                bio = announcement.bio,
                interests = announcement.interests,
                relationshipGoal = announcement.relationshipGoal,
                locationRegion = announcement.locationRegion,
                listenMultiaddrs = announcement.listenMultiaddrs,
                signalPreKeyBundleJson = announcement.signalPreKeyBundleJson,
                matchCommitPublicKeyBase64 = announcement.matchCommitPublicKeyBase64,
                timestampEpochMs = announcement.timestampEpochMs,
                ed25519PublicKeyBase64 = announcement.ed25519PublicKeyBase64
            )
            val sigBytes = decoder.decode(announcement.ed25519SignatureBase64)
            remotePubKey.verify(payload, sigBytes)
        }.getOrDefault(false)
    }
}
