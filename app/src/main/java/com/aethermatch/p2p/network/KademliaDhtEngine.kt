package com.aethermatch.p2p.network

import com.aethermatch.p2p.model.SignedPeerProfileAnnouncement
import com.aethermatch.p2p.security.IdentityAndSignatureService
import com.google.gson.Gson
import io.libp2p.core.PeerId
import io.libp2p.crypto.keys.unmarshalEd25519PublicKey
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

data class KadPeerEntry(
    val peerId: String,
    val multiaddrs: List<String>,
    val canActAsRelay: Boolean = true,
    val canActAsBootstrap: Boolean = true,
    val lastSeenEpochMs: Long = System.currentTimeMillis()
)

data class SignedDhtRecord(
    val key: String,
    val valueJson: String,
    val publisherPeerId: String,
    val timestampEpochMs: Long,
    val ed25519PublicKeyBase64: String,
    val ed25519SignatureBase64: String
)

data class KademliaRoutingDiagnostics(
    val localKadIdHex: String,
    val populatedBucketsCount: Int,
    val totalKnownPeers: Int,
    val totalStoredDhtRecords: Int,
    val closestPeersSample: List<String>
)

/**
 * Kademlia DHT engine implementing 256-bit SHA-256 XOR metric routing tables (256 k-buckets, k=20)
 * and Ed25519-authenticated `PUT_VALUE` / `GET_VALUE` / `FIND_NODE` operations over libp2p streams.
 *
 * Any user device on the network participates symmetrically in the DHT and can serve as a bootstrap
 * or relay node without any central server.
 */
class KademliaDhtEngine(
    private val localPeerId: String,
    private val identityService: IdentityAndSignatureService
) {
    companion object {
        const val K_BUCKET_SIZE = 20
        const val KEYSPACE_BITS = 256
        const val PROFILE_KEY_PREFIX = "/aethermatch/profile/"
        const val RELAY_DIRECTORY_KEY = "/aethermatch/relays/directory"
    }

    private val gson = Gson()
    val localKadId: ByteArray = sha256(localPeerId.toByteArray(StandardCharsets.UTF_8))

    // 256 k-buckets indexed by common prefix length (0..255)
    private val kBuckets = Array(KEYSPACE_BITS) { CopyOnWriteArrayList<KadPeerEntry>() }
    private val dhtStore = ConcurrentHashMap<String, SignedDhtRecord>()

    object Capabilities {
        fun sha256(input: ByteArray): ByteArray {
            return MessageDigest.getInstance("SHA-256").digest(input)
        }

        fun xorDistance(idA: ByteArray, idB: ByteArray): BigInteger {
            require(idA.size == 32 && idB.size == 32) { "Kademlia IDs must be 256-bit (32 bytes)" }
            val xor = ByteArray(32)
            for (i in 0 until 32) {
                xor[i] = (idA[i].toInt() xor idB[i].toInt()).toByte()
            }
            return BigInteger(1, xor)
        }

        fun bucketIndexForDistance(distance: BigInteger): Int {
            if (distance == BigInteger.ZERO) return 0
            return (distance.bitLength() - 1).coerceIn(0, KEYSPACE_BITS - 1)
        }
    }

    private fun sha256(input: ByteArray): ByteArray = Capabilities.sha256(input)

    fun computeXorDistanceToPeer(peerId: String): BigInteger {
        val peerKadId = sha256(peerId.toByteArray(StandardCharsets.UTF_8))
        return Capabilities.xorDistance(localKadId, peerKadId)
    }

    fun computeXorDistanceBetween(keyOrPeerA: String, keyOrPeerB: String): BigInteger {
        val idA = sha256(keyOrPeerA.toByteArray(StandardCharsets.UTF_8))
        val idB = sha256(keyOrPeerB.toByteArray(StandardCharsets.UTF_8))
        return Capabilities.xorDistance(idA, idB)
    }

    /**
     * Inserts or refreshes a peer in the appropriate Kademlia k-bucket based on XOR distance.
     */
    @Synchronized
    fun addOrUpdatePeer(entry: KadPeerEntry) {
        if (entry.peerId == localPeerId || entry.peerId.isBlank()) return
        val dist = computeXorDistanceToPeer(entry.peerId)
        val bucketIdx = Capabilities.bucketIndexForDistance(dist)
        val bucket = kBuckets[bucketIdx]

        val existingIdx = bucket.indexOfFirst { it.peerId == entry.peerId }
        if (existingIdx >= 0) {
            val existing = bucket.removeAt(existingIdx)
            val mergedAddrs = (entry.multiaddrs + existing.multiaddrs).distinct()
            bucket.add(entry.copy(multiaddrs = mergedAddrs, lastSeenEpochMs = System.currentTimeMillis()))
        } else if (bucket.size < K_BUCKET_SIZE) {
            bucket.add(entry)
        } else {
            // Evict oldest if stale, otherwise keep head
            bucket.removeAt(0)
            bucket.add(entry)
        }
    }

    /**
     * Kademlia `FIND_NODE`: returns up to [count] peers closest in XOR distance to [targetKey].
     */
    fun findClosestPeers(targetKey: String, count: Int = K_BUCKET_SIZE): List<KadPeerEntry> {
        val targetKadId = sha256(targetKey.toByteArray(StandardCharsets.UTF_8))
        return getAllPeers()
            .sortedBy { peer ->
                val peerKadId = sha256(peer.peerId.toByteArray(StandardCharsets.UTF_8))
                Capabilities.xorDistance(targetKadId, peerKadId)
            }
            .take(count)
    }

    fun getAllPeers(): List<KadPeerEntry> {
        return kBuckets.flatMap { it }
    }

    /**
     * Signs and stores a DHT record locally, returning the [SignedDhtRecord] for replication
     * to the k-closest peers over `/aethermatch/kad/1.0.0`.
     */
    fun createSignedRecord(key: String, valueJson: String, timestampMs: Long = System.currentTimeMillis()): SignedDhtRecord {
        val encoder = Base64.getEncoder()
        val pubKeyB64 = encoder.encodeToString(identityService.pubKey.raw())
        val payload = canonicalRecordPayload(key, valueJson, localPeerId, timestampMs, pubKeyB64)
        val signature = identityService.privKey.sign(payload)
        val record = SignedDhtRecord(
            key = key,
            valueJson = valueJson,
            publisherPeerId = localPeerId,
            timestampEpochMs = timestampMs,
            ed25519PublicKeyBase64 = pubKeyB64,
            ed25519SignatureBase64 = encoder.encodeToString(signature)
        )
        putSignedRecord(record)
        return record
    }

    /**
     * Verifies the Ed25519 signature and PeerId ownership of a [SignedDhtRecord] before storing it.
     */
    fun putSignedRecord(record: SignedDhtRecord): Boolean {
        if (!verifySignedRecord(record)) {
            return false
        }
        val existing = dhtStore[record.key]
        if (existing == null || record.timestampEpochMs >= existing.timestampEpochMs) {
            dhtStore[record.key] = record
        }
        return true
    }

    fun verifySignedRecord(record: SignedDhtRecord): Boolean {
        return runCatching {
            val decoder = Base64.getDecoder()
            val pubKey = unmarshalEd25519PublicKey(decoder.decode(record.ed25519PublicKeyBase64))
            val derivedPeerId = PeerId.fromPubKey(pubKey).toBase58()
            if (derivedPeerId != record.publisherPeerId) {
                return false
            }
            // If key is a per-peer profile key, enforce that only that peer can write it
            if (record.key.startsWith(PROFILE_KEY_PREFIX)) {
                val expectedPeerId = record.key.removePrefix(PROFILE_KEY_PREFIX)
                if (expectedPeerId != record.publisherPeerId) {
                    return false
                }
            }
            val payload = canonicalRecordPayload(
                record.key,
                record.valueJson,
                record.publisherPeerId,
                record.timestampEpochMs,
                record.ed25519PublicKeyBase64
            )
            val sig = decoder.decode(record.ed25519SignatureBase64)
            pubKey.verify(payload, sig)
        }.getOrDefault(false)
    }

    fun getRecord(key: String): SignedDhtRecord? = dhtStore[key]

    fun getAllProfileRecords(): List<SignedPeerProfileAnnouncement> {
        return dhtStore.entries
            .filter { it.key.startsWith(PROFILE_KEY_PREFIX) }
            .mapNotNull { entry ->
                runCatching {
                    val announcement = gson.fromJson(entry.value.valueJson, SignedPeerProfileAnnouncement::class.java)
                    if (identityService.verifyProfileAnnouncement(announcement)) announcement else null
                }.getOrNull()
            }
    }

    fun getAllSignedRecords(): List<SignedDhtRecord> = dhtStore.values.toList()

    fun getDiagnostics(): KademliaRoutingDiagnostics {
        val populated = kBuckets.count { it.isNotEmpty() }
        val allPeers = getAllPeers()
        val closest = findClosestPeers(localPeerId, 5).map { it.peerId }
        return KademliaRoutingDiagnostics(
            localKadIdHex = localKadId.take(12).joinToString("") { "%02x".format(it) } + "...",
            populatedBucketsCount = populated,
            totalKnownPeers = allPeers.size,
            totalStoredDhtRecords = dhtStore.size,
            closestPeersSample = closest
        )
    }

    private fun canonicalRecordPayload(
        key: String,
        valueJson: String,
        publisherPeerId: String,
        timestampEpochMs: Long,
        ed25519PublicKeyBase64: String
    ): ByteArray {
        return "aethermatch-dht-v1|$key|$valueJson|$publisherPeerId|$timestampEpochMs|$ed25519PublicKeyBase64"
            .toByteArray(StandardCharsets.UTF_8)
    }
}
