package com.aethermatch.p2p.network

import com.aethermatch.p2p.BuildConfig
import com.aethermatch.p2p.model.DiscoverySource
import com.aethermatch.p2p.model.RelationshipGoal
import com.aethermatch.p2p.model.UserProfile
import com.aethermatch.p2p.security.IdentityAndSignatureService
import com.aethermatch.p2p.security.KeystoreKeyManager
import com.aethermatch.p2p.security.MasterKeyWrapper
import com.aethermatch.p2p.security.SignalProtocolEngine
import com.aethermatch.p2p.security.SqlCipherSignalProtocolStore
import com.aethermatch.p2p.storage.EncryptedRecordStorageRepository
import java.util.concurrent.CopyOnWriteArrayList
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Ephemeral AES-256-GCM key wrapper used by isolated virtual peer nodes in DEBUG builds only.
 */
private class EphemeralNodeMasterKeyWrapper : MasterKeyWrapper {
    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    override fun wrapSecret(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(associatedData)
        return cipher.iv + cipher.doFinal(plaintext)
    }

    override fun unwrapSecret(wrappedBlob: ByteArray, associatedData: ByteArray): ByteArray {
        val iv = wrappedBlob.copyOfRange(0, 12)
        val ct = wrappedBlob.copyOfRange(12, wrappedBlob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        cipher.updateAAD(associatedData)
        return cipher.doFinal(ct)
    }

    override fun isHardwareBacked(): Boolean = false
}

data class VirtualPeerInstance(
    val profile: UserProfile,
    val identityService: IdentityAndSignatureService,
    val signalEngine: SignalProtocolEngine,
    val nodeManager: Libp2pNodeManager,
    val localFeatureWeights: FloatArray,
    val autoLikeBack: Boolean
)

/**
 * Development & Testing Virtual Peer Swarm Simulator.
 *
 * STRICTLY DISABLED IN RELEASE BUILDS (`BuildConfig.DEBUG && BuildConfig.ENABLE_VIRTUAL_SWARM`).
 * When started in a Debug build, spawns real in-process `jvm-libp2p` nodes (each with its own
 * Noise XX TCP socket, Ed25519 identity, Kademlia DHT table, and `libsignal-client` X3DH/Double Ratchet
 * engine) so a developer can test internet-grade P2P discovery, Signal E2EE chat, and multi-peer
 * Federated Learning Secure Aggregation on a single device or in automated tests.
 */
class VirtualPeerSwarmSimulator {

    private val activePeers = CopyOnWriteArrayList<VirtualPeerInstance>()

    val isAllowedInCurrentBuild: Boolean
        get() = BuildConfig.DEBUG && BuildConfig.ENABLE_VIRTUAL_SWARM

    fun getActiveVirtualPeers(): List<VirtualPeerInstance> {
        if (!isAllowedInCurrentBuild) return emptyList()
        return activePeers.toList()
    }

    /**
     * Spawns real local libp2p + Signal + Kademlia DHT peer nodes and bootstraps them with [localNode].
     * No-op if called in a release build.
     */
    @Synchronized
    fun startDebugSwarm(localNode: Libp2pNodeManager): List<String> {
        if (!isAllowedInCurrentBuild) {
            return emptyList()
        }
        if (activePeers.isNotEmpty()) {
            return activePeers.flatMap { it.nodeManager.listenMultiaddrs.value }
        }

        val specs = listOf(
            Triple(
                UserProfile(
                    peerId = "",
                    displayName = "Dr. Maya Lin",
                    age = 29,
                    bio = "Cryptography researcher working on zero-knowledge proofs & alpine climbing. Looking for someone curious and outdoorsy.",
                    interests = listOf("Cryptography", "Climbing", "AI & ML", "Trail Running", "Specialty Coffee"),
                    relationshipGoal = RelationshipGoal.LONG_TERM_PARTNER,
                    locationRegion = "Metro Core"
                ),
                true,
                "Hey! Awesome to match with you over libp2p! My node verified your Ed25519 DHT profile and Signal PQXDH session."
            ),
            Triple(
                UserProfile(
                    peerId = "",
                    displayName = "Julian Thorne",
                    age = 31,
                    bio = "Distributed systems architect, jazz pianist, and sourdough baker. Always up for late-night philosophy.",
                    interests = listOf("Distributed Systems", "Jazz & Vinyl", "Cooking", "Philosophy", "Sci-Fi"),
                    relationshipGoal = RelationshipGoal.SERIOUS_DATING,
                    locationRegion = "Metro Core"
                ),
                true,
                "Hi there! Signal Double Ratchet verified. What are you reading or building lately?"
            ),
            Triple(
                UserProfile(
                    peerId = "",
                    displayName = "Sora Takahashi",
                    age = 27,
                    bio = "Robotics engineer & analog film photographer. Weekend gravel cyclist and matcha enthusiast.",
                    interests = listOf("AI & ML", "Photography", "Cycling", "Indie Art", "Travel"),
                    relationshipGoal = RelationshipGoal.LONG_TERM_PARTNER,
                    locationRegion = "Coastal District"
                ),
                true,
                "Hello! Our local preference models both scored high compatibility. How's your week going?"
            ),
            Triple(
                UserProfile(
                    peerId = "",
                    displayName = "Lucas Vermeer",
                    age = 33,
                    bio = "Marine biologist & sea kayaker. Loves acoustic folk music and coastal conservation.",
                    interests = listOf("Kayaking", "Conservation", "Live Music", "Hiking", "Cooking"),
                    relationshipGoal = RelationshipGoal.DEEP_INTELLECTUAL_BOND,
                    locationRegion = "Harbor Front"
                ),
                true,
                "Hey! Great to connect on the decentralized mesh."
            ),
            Triple(
                UserProfile(
                    peerId = "",
                    displayName = "Amara Okafor",
                    age = 28,
                    bio = "Computational neuroscientist exploring neural representations, contemporary dance, and espresso tonic.",
                    interests = listOf("AI & ML", "Neuroscience", "Specialty Coffee", "Philosophy", "Dance"),
                    relationshipGoal = RelationshipGoal.LONG_TERM_PARTNER,
                    locationRegion = "University Quarter"
                ),
                true,
                "Hi! Fascinating seeing Federated Secure Aggregation and Signal E2EE working peer-to-peer!"
            )
        )

        val spawnedAddrs = mutableListOf<String>()

        for ((rawProfile, autoLike, greeting) in specs) {
            val keyManager = KeystoreKeyManager(
                context = null,
                masterKeyWrapper = EphemeralNodeMasterKeyWrapper(),
                backingMap = mutableMapOf()
            )
            val identity = IdentityAndSignatureService(keyManager)
            val storage = EncryptedRecordStorageRepository(keyManager)
            val signalStore = SqlCipherSignalProtocolStore(storage)
            val signalEngine = SignalProtocolEngine(identity.localPeerIdBase58, signalStore)
            val node = Libp2pNodeManager(identityService = identity, requestedListenPort = 0)

            val addrs = node.startNode(enableMdns = false)
            val peerProfile = rawProfile.copy(peerId = identity.localPeerIdBase58)
            val signedAnnouncement = identity.signProfileAnnouncement(
                profile = peerProfile,
                listenMultiaddrs = addrs,
                signalPreKeyBundleJson = signalEngine.exportPreKeyBundleJson()
            )
            node.publishSignedProfileToDht(signedAnnouncement)

            // When the local user likes this virtual peer, if autoLike is enabled, reciprocate the like
            // and send an authentic Signal Protocol E2EE greeting over libp2p!
            node.onMatchHandshakeReceived = { senderPeerId, _ ->
                if (autoLike) {
                    node.sendLikeHandshake(senderPeerId)
                    val senderProfile = node.kadDht.getAllProfileRecords().find { it.peerId == senderPeerId }
                    if (senderProfile != null) {
                        runCatching {
                            val encryptedGreeting = signalEngine.encryptMessage(
                                remotePeerId = senderPeerId,
                                plaintext = greeting,
                                remotePreKeyBundleJson = senderProfile.signalPreKeyBundleJson
                            )
                            node.sendSignalEncryptedChat(encryptedGreeting)
                        }
                    }
                }
            }

            // When the local user sends a Signal E2EE chat message to this virtual peer, decrypt it
            // with libsignal-client and reply using the Double Ratchet!
            node.onSignalEnvelopeReceived = { incomingEnvelope ->
                runCatching {
                    val decrypted = signalEngine.decryptMessage(incomingEnvelope)
                    val replyText = "[${peerProfile.displayName} via Signal Double Ratchet]: Received \"${decrypted.plaintext}\" cleanly (type: ${decrypted.signalMessageTypeLabel})."
                    val replyEnvelope = signalEngine.encryptMessage(
                        remotePeerId = incomingEnvelope.senderPeerId,
                        plaintext = replyText
                    )
                    node.sendSignalEncryptedChat(replyEnvelope)
                }
            }

            val instance = VirtualPeerInstance(
                profile = peerProfile,
                identityService = identity,
                signalEngine = signalEngine,
                nodeManager = node,
                localFeatureWeights = FloatArray(16) { idx -> ((idx % 5) - 2) * 0.15f },
                autoLikeBack = autoLike
            )
            activePeers.add(instance)
            spawnedAddrs.addAll(addrs)
        }

        // Cross-connect swarm peers into a Kademlia mesh and bootstrap with localNode
        val allNodes = activePeers.map { it.nodeManager }
        for (i in allNodes.indices) {
            for (j in allNodes.indices) {
                if (i != j) {
                    val targetAddr = allNodes[j].listenMultiaddrs.value.firstOrNull() ?: continue
                    allNodes[i].bootstrapWithPeer(targetAddr, DiscoverySource.VIRTUAL_SWARM_DEBUG)
                }
            }
            val localAddr = localNode.listenMultiaddrs.value.firstOrNull()
            if (localAddr != null) {
                allNodes[i].bootstrapWithPeer(localAddr, DiscoverySource.VIRTUAL_SWARM_DEBUG)
            }
            val peerAddr = allNodes[i].listenMultiaddrs.value.firstOrNull()
            if (peerAddr != null) {
                localNode.bootstrapWithPeer(peerAddr, DiscoverySource.VIRTUAL_SWARM_DEBUG)
            }
        }

        return spawnedAddrs
    }

    @Synchronized
    fun stopDebugSwarm() {
        for (peer in activePeers) {
            peer.nodeManager.stopNode()
        }
        activePeers.clear()
    }
}
