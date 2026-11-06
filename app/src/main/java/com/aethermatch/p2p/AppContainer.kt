package com.aethermatch.p2p

import android.content.Context
import com.aethermatch.p2p.ai.DeviceConstraintMonitor
import com.aethermatch.p2p.ai.DeviceConstraintStatus
import com.aethermatch.p2p.ai.FederatedLearningCoordinator
import com.aethermatch.p2p.ai.LocalPreferenceModel
import com.aethermatch.p2p.model.ChatMessage
import com.aethermatch.p2p.model.DiscoveredProfile
import com.aethermatch.p2p.model.DiscoverySource
import com.aethermatch.p2p.model.FederatedRoundRecord
import com.aethermatch.p2p.model.MatchRecord
import com.aethermatch.p2p.model.SignedPeerProfileAnnouncement
import com.aethermatch.p2p.model.SwipeRecord
import com.aethermatch.p2p.model.UserProfile
import com.aethermatch.p2p.network.KademliaDhtEngine
import com.aethermatch.p2p.network.Libp2pNodeDiagnostics
import com.aethermatch.p2p.network.Libp2pNodeManager
import com.aethermatch.p2p.network.VirtualPeerSwarmSimulator
import com.aethermatch.p2p.security.IdentityAndSignatureService
import com.aethermatch.p2p.security.KeystoreDiagnostics
import com.aethermatch.p2p.security.KeystoreKeyManager
import com.aethermatch.p2p.security.SignalCryptoDiagnostics
import com.aethermatch.p2p.security.SignalProtocolEngine
import com.aethermatch.p2p.security.SqlCipherSignalProtocolStore
import com.aethermatch.p2p.storage.EncryptedStorageRepository
import com.aethermatch.p2p.storage.SqlCipherDatabaseManager
import com.aethermatch.p2p.storage.SqlCipherStatusReport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class SystemDiagnosticsSnapshot(
    val keystore: KeystoreDiagnostics,
    val sqlCipher: SqlCipherStatusReport,
    val signal: SignalCryptoDiagnostics,
    val libp2p: Libp2pNodeDiagnostics,
    val deviceConstraints: DeviceConstraintStatus,
    val debugVirtualSwarmEnabled: Boolean,
    val activeVirtualPeersCount: Int
)

/**
 * Coordinates the dependency graph and reactive data flows across:
 * 1. Android Keystore + SQLCipher Encrypted Storage + Signal Protocol (`libsignal-client`)
 * 2. `jvm-libp2p` (Noise XX, Kademlia DHT, AutoNAT/DCUtR hole punching, Circuit Relay v2, mDNS)
 * 3. On-Device Preference Model + Federated Learning Coordinator (Secure Aggregation + DP)
 */
class AppContainer(
    context: Context?,
    customKeyManager: KeystoreKeyManager? = null,
    customStorage: EncryptedStorageRepository? = null
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    val keystoreKeyManager: KeystoreKeyManager = customKeyManager
        ?: KeystoreKeyManager(context = context)

    val storage: EncryptedStorageRepository = customStorage
        ?: SqlCipherDatabaseManager(requireNotNull(context), keystoreKeyManager)

    val identityService = IdentityAndSignatureService(keystoreKeyManager)
    val signalStore = SqlCipherSignalProtocolStore(storage)
    val signalEngine = SignalProtocolEngine(identityService.localPeerIdBase58, signalStore)
    val kadDht = KademliaDhtEngine(identityService.localPeerIdBase58, identityService)
    val libp2pNode = Libp2pNodeManager(identityService, kadDht)
    val preferenceModel = LocalPreferenceModel(storage)
    val federatedCoordinator = FederatedLearningCoordinator(
        localPeerId = identityService.localPeerIdBase58,
        storage = storage,
        preferenceModel = preferenceModel,
        nodeManager = libp2pNode
    )
    val constraintMonitor = DeviceConstraintMonitor(context)
    val virtualSwarm = VirtualPeerSwarmSimulator()

    private val _localProfile = MutableStateFlow<UserProfile?>(storage.getLocalUserProfile())
    val localProfile: StateFlow<UserProfile?> = _localProfile.asStateFlow()

    private val _discoveredProfiles = MutableStateFlow<List<DiscoveredProfile>>(storage.getAllDiscoveredProfiles())
    val discoveredProfiles: StateFlow<List<DiscoveredProfile>> = _discoveredProfiles.asStateFlow()

    private val _matches = MutableStateFlow<List<MatchRecord>>(storage.getAllMatches())
    val matches: StateFlow<List<MatchRecord>> = _matches.asStateFlow()

    private val _federatedRounds = MutableStateFlow<List<FederatedRoundRecord>>(storage.getAllFederatedRounds())
    val federatedRounds: StateFlow<List<FederatedRoundRecord>> = _federatedRounds.asStateFlow()

    private val _chatMessagesByPeer = MutableStateFlow<Map<String, List<ChatMessage>>>(emptyMap())
    val chatMessagesByPeer: StateFlow<Map<String, List<ChatMessage>>> = _chatMessagesByPeer.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    init {
        wireP2pCallbacks()
        refreshAllStateFlows()
    }

    private fun wireP2pCallbacks() {
        libp2pNode.onProfileDiscovered = { announcement, source ->
            handleDiscoveredProfileAnnouncement(announcement, source)
        }

        libp2pNode.onMatchHandshakeReceived = { senderPeerId, _ ->
            // Check if we already liked this peer -> if so, finalize mutual match!
            val alreadyLikedByUs = storage.getAllSwipes().any { it.peerId == senderPeerId && it.liked }
            if (alreadyLikedByUs) {
                finalizeMutualMatch(senderPeerId)
            }
        }

        libp2pNode.onSignalEnvelopeReceived = { envelope ->
            runCatching {
                val decrypted = signalEngine.decryptMessage(envelope)
                val chatMsg = ChatMessage(
                    messageId = decrypted.messageId,
                    conversationPeerId = decrypted.senderPeerId,
                    senderPeerId = decrypted.senderPeerId,
                    plaintextBody = decrypted.plaintext,
                    ciphertextHexPreview = decrypted.ciphertextHexPreview,
                    signalMessageType = decrypted.signalMessageTypeLabel,
                    timestampEpochMs = decrypted.timestampEpochMs,
                    verifiedAuthentic = true
                )
                storage.saveChatMessage(chatMsg)
                // Ensure match record exists if a peer with a valid Signal PreKey session messaged us
                if (storage.getAllMatches().none { it.peerId == decrypted.senderPeerId }) {
                    finalizeMutualMatch(decrypted.senderPeerId)
                }
                refreshChatMessages(decrypted.senderPeerId)
                _matches.value = storage.getAllMatches()
            }
        }
    }

    fun startNetworking(enableDebugSwarmIfAllowed: Boolean = true) {
        scope.launch {
            runCatching {
                libp2pNode.startNode(enableMdns = true)
                _localProfile.value?.let { publishProfileToNetwork(it) }
                if (enableDebugSwarmIfAllowed && virtualSwarm.isAllowedInCurrentBuild) {
                    virtualSwarm.startDebugSwarm(libp2pNode)
                }
                rescoreAndRefreshDeck()
            }
        }
    }

    @Synchronized
    fun saveAndPublishUserProfile(profile: UserProfile) {
        val withPeerId = profile.copy(
            peerId = identityService.localPeerIdBase58,
            updatedAtEpochMs = System.currentTimeMillis()
        )
        storage.saveLocalUserProfile(withPeerId)
        _localProfile.value = withPeerId
        scope.launch {
            publishProfileToNetwork(withPeerId)
            rescoreAndRefreshDeck()
        }
    }

    private fun publishProfileToNetwork(profile: UserProfile) {
        val signed = identityService.signProfileAnnouncement(
            profile = profile,
            listenMultiaddrs = libp2pNode.listenMultiaddrs.value,
            signalPreKeyBundleJson = signalEngine.exportPreKeyBundleJson()
        )
        libp2pNode.publishSignedProfileToDht(signed)
    }

    @Synchronized
    fun handleDiscoveredProfileAnnouncement(
        announcement: SignedPeerProfileAnnouncement,
        source: DiscoverySource
    ) {
        if (!identityService.verifyProfileAnnouncement(announcement)) return
        val existing = storage.getAllDiscoveredProfiles().find { it.announcement.peerId == announcement.peerId }
        val scored = preferenceModel.scoreCandidate(_localProfile.value, announcement)
        val discovered = DiscoveredProfile(
            announcement = announcement,
            localCompatibilityScore = scored.compatibilityScore,
            compatibilityExplanation = scored.explanations,
            signatureVerified = true,
            discoveredVia = source,
            swiped = existing?.swiped ?: false
        )
        storage.upsertDiscoveredProfile(discovered)
        _discoveredProfiles.value = storage.getAllDiscoveredProfiles()
    }

    /**
     * Records a local user swipe, immediately updates the strictly-local personal preference head,
     * re-ranks remaining profiles on-device, and sends a cryptographic like-handshake if `liked == true`.
     */
    @Synchronized
    fun performSwipe(targetProfile: DiscoveredProfile, liked: Boolean) {
        val scored = preferenceModel.scoreCandidate(_localProfile.value, targetProfile.announcement)
        val swipe = SwipeRecord(
            peerId = targetProfile.announcement.peerId,
            liked = liked,
            encodedFeatures = scored.featureVector,
            compatibilityAtSwipe = scored.compatibilityScore
        )
        storage.recordSwipe(swipe)

        // Immediately adapt local personal preference weights on-device
        preferenceModel.updatePersonalHeadImmediate(scored.featureVector, liked)

        if (liked) {
            scope.launch {
                val peerId = targetProfile.announcement.peerId
                libp2pNode.sendLikeHandshake(peerId)
                if (libp2pNode.hasPeerLikedUs(peerId)) {
                    finalizeMutualMatch(peerId)
                }
            }
        }

        // Re-score and re-rank remaining unswiped profiles using the updated personal model
        rescoreAndRefreshDeck()
    }

    @Synchronized
    private fun finalizeMutualMatch(remotePeerId: String) {
        val discovered = storage.getAllDiscoveredProfiles().find { it.announcement.peerId == remotePeerId }
            ?: return
        val announcement = discovered.announcement

        runCatching {
            signalEngine.ensureSessionWithPeer(remotePeerId, announcement.signalPreKeyBundleJson)
        }
        val safetyNumber = signalEngine.computeSafetyNumber(remotePeerId)

        val match = MatchRecord(
            peerId = remotePeerId,
            displayName = announcement.displayName,
            age = announcement.age,
            bio = announcement.bio,
            interests = announcement.interests,
            safetyNumberFingerprint = safetyNumber,
            matchedAtEpochMs = System.currentTimeMillis()
        )
        storage.saveMatch(match)
        _matches.value = storage.getAllMatches()
        refreshChatMessages(remotePeerId)
    }

    /**
     * Encrypts [plaintext] using the Signal Double Ratchet (`libsignal-client`) and sends it
     * over a libp2p Noise XX stream (with automatic hole-punch / Circuit Relay v2 fallback).
     */
    fun sendEncryptedChatMessage(recipientPeerId: String, plaintext: String) {
        if (plaintext.isBlank()) return
        scope.launch {
            runCatching {
                val discovered = storage.getAllDiscoveredProfiles().find { it.announcement.peerId == recipientPeerId }
                val preKeyJson = discovered?.announcement?.signalPreKeyBundleJson
                val envelope = signalEngine.encryptMessage(
                    remotePeerId = recipientPeerId,
                    plaintext = plaintext.trim(),
                    remotePreKeyBundleJson = preKeyJson
                )
                val rawCiphertext = java.util.Base64.getDecoder().decode(envelope.ciphertextBase64)
                val hexPreview = rawCiphertext.take(24).joinToString("") { "%02x".format(it) }
                val typeLabel = if (envelope.ciphertextType == 3) {
                    "PreKeySignalMessage (PQXDH/X3DH)"
                } else {
                    "SignalMessage (Double Ratchet)"
                }

                val localMsg = ChatMessage(
                    messageId = envelope.messageId,
                    conversationPeerId = recipientPeerId,
                    senderPeerId = identityService.localPeerIdBase58,
                    plaintextBody = plaintext.trim(),
                    ciphertextHexPreview = hexPreview,
                    signalMessageType = typeLabel,
                    timestampEpochMs = envelope.timestampEpochMs,
                    verifiedAuthentic = true
                )
                storage.saveChatMessage(localMsg)
                refreshChatMessages(recipientPeerId)
                _matches.value = storage.getAllMatches()

                libp2pNode.sendSignalEncryptedChat(envelope)
            }
        }
    }

    /**
     * Connects to a custom peer multiaddr (any user device can act as a bootstrap or relay node).
     */
    fun connectBootstrapPeer(multiaddr: String) {
        scope.launch {
            val ok = libp2pNode.bootstrapWithPeer(multiaddr.trim(), DiscoverySource.KADEMLIA_DHT)
            _statusMessage.value = if (ok) {
                "Connected & synced Kademlia DHT with peer $multiaddr"
            } else {
                "Could not dial $multiaddr — check multiaddr format (/ip4/.../tcp/.../p2p/12D3KooW...)"
            }
        }
    }

    /**
     * Runs a Federated Learning + Secure Aggregation + Differential Privacy training round
     * ONLY if the device is Idle, Charging, and on Unmetered Wi-Fi (or if `forceDebugOverride`
     * is explicitly used in a Debug build).
     */
    @Synchronized
    fun triggerConstrainedTrainingRoundIfEligible(forceDebugOverride: Boolean = false): FederatedRoundRecord? {
        val status = constraintMonitor.getCurrentStatus()
        val allowed = status.allConstraintsMetForBackgroundTraining || (forceDebugOverride && BuildConfig.DEBUG)
        if (!allowed) {
            _statusMessage.value = "Training deferred: Requires Phone Idle (${status.isDeviceIdle}), Charging (${status.isCharging}), and Unmetered Wi-Fi (${status.isOnUnmeteredWifi})."
            return null
        }

        // Gather cohort updates from connected virtual/live peers
        val peerUpdates = mutableMapOf<String, FloatArray>()
        if (virtualSwarm.isAllowedInCurrentBuild) {
            for (vp in virtualSwarm.getActiveVirtualPeers()) {
                peerUpdates[vp.identityService.localPeerIdBase58] = vp.localFeatureWeights
            }
        }

        val round = federatedCoordinator.executeFederatedRound(peerRawUpdates = peerUpdates)
        _federatedRounds.value = storage.getAllFederatedRounds()
        rescoreAndRefreshDeck()
        _statusMessage.value = "Completed Federated SecAgg Round #${round.roundId} (DP ε=${"%.2f".format(round.dpEpsilonCumulative)}, ${round.participatingPeers} peers)"
        return round
    }

    @Synchronized
    fun rescoreAndRefreshDeck() {
        val user = _localProfile.value
        val all = storage.getAllDiscoveredProfiles()
        for (item in all) {
            val rescored = preferenceModel.scoreCandidate(user, item.announcement)
            storage.upsertDiscoveredProfile(
                item.copy(
                    localCompatibilityScore = rescored.compatibilityScore,
                    compatibilityExplanation = rescored.explanations
                )
            )
        }
        _discoveredProfiles.value = storage.getAllDiscoveredProfiles()
    }

    fun refreshChatMessages(peerId: String) {
        val current = _chatMessagesByPeer.value.toMutableMap()
        current[peerId] = storage.getChatMessagesForPeer(peerId)
        _chatMessagesByPeer.value = current
    }

    fun refreshAllStateFlows() {
        _localProfile.value = storage.getLocalUserProfile()
        _discoveredProfiles.value = storage.getAllDiscoveredProfiles()
        _matches.value = storage.getAllMatches()
        _federatedRounds.value = storage.getAllFederatedRounds()
        val map = mutableMapOf<String, List<ChatMessage>>()
        for (m in _matches.value) {
            map[m.peerId] = storage.getChatMessagesForPeer(m.peerId)
        }
        _chatMessagesByPeer.value = map
    }

    fun getDiagnosticsSnapshot(): SystemDiagnosticsSnapshot {
        return SystemDiagnosticsSnapshot(
            keystore = keystoreKeyManager.getKeystoreDiagnosticSummary(),
            sqlCipher = storage.getSqlCipherStatusReport(),
            signal = signalEngine.getDiagnostics(),
            libp2p = libp2pNode.getDiagnostics(),
            deviceConstraints = constraintMonitor.getCurrentStatus(),
            debugVirtualSwarmEnabled = virtualSwarm.isAllowedInCurrentBuild,
            activeVirtualPeersCount = virtualSwarm.getActiveVirtualPeers().size
        )
    }

    fun clearStatusMessage() {
        _statusMessage.value = null
    }
}
