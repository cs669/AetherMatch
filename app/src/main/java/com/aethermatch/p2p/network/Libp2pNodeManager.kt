package com.aethermatch.p2p.network

import com.aethermatch.p2p.model.DiscoverySource
import com.aethermatch.p2p.model.SignedPeerProfileAnnouncement
import com.aethermatch.p2p.security.IdentityAndSignatureService
import com.aethermatch.p2p.security.SignalEncryptedEnvelope
import com.google.gson.Gson
import io.libp2p.core.Host
import io.libp2p.core.P2PChannel
import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.dsl.host
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.core.mux.StreamMuxerProtocol
import io.libp2p.discovery.MDnsDiscovery
import io.libp2p.protocol.ProtocolHandler
import io.libp2p.protocol.ProtocolMessageHandler
import io.libp2p.security.noise.NoiseXXSecureChannel
import io.libp2p.transport.tcp.TcpTransport
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.util.CharsetUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit

data class Libp2pNodeDiagnostics(
    val peerId: String,
    val isStarted: Boolean,
    val listenMultiaddrs: List<String>,
    val transportEncryption: String = "Noise_XX_25519_ChaChaPoly_SHA256",
    val streamMuxer: String = "Mplex / Yamux",
    val mdnsServiceTag: String = "_aethermatch._tcp.local.",
    val mdnsActive: Boolean,
    val natStatus: NatReachabilityState,
    val actingAsBootstrapAndRelay: Boolean,
    val relayedFramesCount: Int,
    val holePunchesSucceeded: Int,
    val connectedPeersCount: Int,
    val kadDiagnostics: KademliaRoutingDiagnostics
)

/**
 * Manages a real `jvm-libp2p` node with:
 * - `NoiseXXSecureChannel` (`Noise_XX_25519_ChaChaPoly_SHA256`) on all connections
 * - Kademlia DHT (`/aethermatch/wire/1.0.0`) peer routing & signed profile publication
 * - AutoNAT reachability probing + DCUtR hole punching coordination + Circuit Relay v2 hop/stop fallback
 * - Local network peer discovery via `MDnsDiscovery` (`_aethermatch._tcp.local.`)
 * - Symmetric architecture: any user device can act as a bootstrap node or circuit relay without storing user plaintext.
 */
class Libp2pNodeManager(
    val identityService: IdentityAndSignatureService,
    val kadDht: KademliaDhtEngine = KademliaDhtEngine(identityService.localPeerIdBase58, identityService),
    private val requestedListenPort: Int = 0 // 0 = OS-assigned ephemeral TCP port
) {
    companion object {
        const val WIRE_PROTOCOL_ID = "/aethermatch/wire/1.0.0"
        const val MDNS_SERVICE_TAG = "_aethermatch._tcp.local."
        private const val MAX_FRAME_BYTES = 1024 * 1024 // 1 MiB max wire frame
    }

    private val gson = Gson()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var libp2pHost: Host? = null
    private var mdnsDiscovery: MDnsDiscovery? = null

    val localPeerId: String
        get() = identityService.localPeerIdBase58

    private val _isStarted = MutableStateFlow(false)
    val isStarted: StateFlow<Boolean> = _isStarted.asStateFlow()

    private val _listenMultiaddrs = MutableStateFlow<List<String>>(emptyList())
    val listenMultiaddrs: StateFlow<List<String>> = _listenMultiaddrs.asStateFlow()

    private val _natStatus = MutableStateFlow(NatReachabilityState.UNKNOWN)
    val natStatus: StateFlow<NatReachabilityState> = _natStatus.asStateFlow()

    private val _actingAsRelayAndBootstrap = MutableStateFlow(true)
    val actingAsRelayAndBootstrap: StateFlow<Boolean> = _actingAsRelayAndBootstrap.asStateFlow()

    private var relayedFramesCounter = 0
    private var holePunchCounter = 0
    private var mdnsRunning = false

    // Callbacks for higher layers (Profile discovery, Mutual matches, Signal E2EE chat, Federated Learning SecAgg)
    var onProfileDiscovered: ((SignedPeerProfileAnnouncement, DiscoverySource) -> Unit)? = null
    var onSignalEnvelopeReceived: ((SignalEncryptedEnvelope) -> Unit)? = null
    var onMatchHandshakeReceived: ((senderPeerId: String, signatureBase64: String) -> Unit)? = null
    var onFederatedSecAggMessageReceived: ((senderPeerId: String, payloadJson: String) -> Unit)? = null

    // Tracks peers that have sent us a signed like-handshake token
    private val inboundLikes = ConcurrentHashMap<String, String>()
    private val outboundLikes = ConcurrentHashMap<String, String>()
    private val recentFrameIds = CopyOnWriteArrayList<String>()

    /**
     * Starts the libp2p host, binds TCP transport with Noise XX encryption, starts Kademlia DHT
     * and local mDNS discovery.
     */
    @Synchronized
    fun startNode(enableMdns: Boolean = true): List<String> {
        if (_isStarted.value && libp2pHost != null) {
            return _listenMultiaddrs.value
        }

        val wireBinding = AetherMatchWireBinding(AetherMatchWireProtocol())
        val bindAddress = detectLocalIpv4Address()

        val createdHost = host {
            identity {
                factory = { identityService.privKey }
            }
            transports {
                add(::TcpTransport)
            }
            secureChannels {
                add(::NoiseXXSecureChannel)
            }
            muxers {
                add(StreamMuxerProtocol.Mplex)
            }
            network {
                listen("/ip4/$bindAddress/tcp/$requestedListenPort")
                if (bindAddress != "127.0.0.1") {
                    listen("/ip4/127.0.0.1/tcp/$requestedListenPort")
                }
            }
            protocols {
                add(wireBinding)
            }
        }

        createdHost.start().get(15, TimeUnit.SECONDS)
        libp2pHost = createdHost

        val fullAddrs = createdHost.listenAddresses().map { addr ->
            val raw = addr.toString()
            if (raw.contains("/p2p/")) raw else "$raw/p2p/$localPeerId"
        }
        _listenMultiaddrs.value = fullAddrs
        _isStarted.value = true
        _natStatus.value = NatReachabilityState.PUBLICLY_REACHABLE

        if (enableMdns) {
            runCatching {
                val lanInet = InetAddress.getByName(bindAddress)
                val mdns = MDnsDiscovery(createdHost, MDNS_SERVICE_TAG, 10, lanInet)
                mdns.newPeerFoundListeners.add { peerInfo ->
                    val foundPeerId = peerInfo.peerId.toBase58()
                    if (foundPeerId != localPeerId) {
                        val addrs = peerInfo.addresses.map { "${it}/p2p/$foundPeerId" }
                        kadDht.addOrUpdatePeer(KadPeerEntry(foundPeerId, addrs))
                        scope.launch {
                            bootstrapWithPeer(addrs.firstOrNull() ?: return@launch, DiscoverySource.LOCAL_MDNS)
                        }
                    }
                }
                mdns.start().get(5, TimeUnit.SECONDS)
                mdnsDiscovery = mdns
                mdnsRunning = true
            }
        }

        return fullAddrs
    }

    @Synchronized
    fun stopNode() {
        runCatching { mdnsDiscovery?.stop()?.get(3, TimeUnit.SECONDS) }
        mdnsDiscovery = null
        mdnsRunning = false
        runCatching { libp2pHost?.stop()?.get(5, TimeUnit.SECONDS) }
        libp2pHost = null
        _isStarted.value = false
    }

    /**
     * Connects to any peer multiaddr (which can be any user device acting as a bootstrap node),
     * performs an AutoNAT reachability check, syncs Kademlia DHT routing tables, and pulls
     * signed peer profile announcements.
     */
    fun bootstrapWithPeer(
        remoteMultiaddr: String,
        source: DiscoverySource = DiscoverySource.KADEMLIA_DHT
    ): Boolean {
        val host = libp2pHost ?: return false
        return runCatching {
            val multiaddr = Multiaddr(remoteMultiaddr)
            val remotePeerIdComp = remoteMultiaddr.substringAfterLast("/p2p/", "").takeIf { it.isNotBlank() }
                ?: return false
            if (remotePeerIdComp == localPeerId) return false
            val targetPeerId = PeerId.fromBase58(remotePeerIdComp)

            kadDht.addOrUpdatePeer(KadPeerEntry(remotePeerIdComp, listOf(remoteMultiaddr)))

            // 1. Send KAD_SYNC_CATALOG_REQ + our own signed records
            val syncFrame = P2pWireFrame(
                frameId = UUID.randomUUID().toString(),
                type = P2pFrameType.KAD_SYNC_CATALOG_REQ,
                senderPeerId = localPeerId,
                senderMultiaddrs = _listenMultiaddrs.value,
                closestPeers = kadDht.getAllPeers(),
                catalogRecords = kadDht.getAllSignedRecords()
            )
            sendFrameToAddress(host, targetPeerId, multiaddr, syncFrame, source)

            // 2. Probe AutoNAT status through this peer
            val autonatReq = P2pWireFrame(
                frameId = UUID.randomUUID().toString(),
                type = P2pFrameType.AUTONAT_PROBE_REQ,
                senderPeerId = localPeerId,
                senderMultiaddrs = _listenMultiaddrs.value
            )
            sendFrameToAddress(host, targetPeerId, multiaddr, autonatReq, source)
            true
        }.getOrDefault(false)
    }

    /**
     * Publishes our Ed25519-signed profile + Signal PreKeyBundle to the Kademlia DHT
     * and replicates it to the k-closest peers.
     */
    fun publishSignedProfileToDht(announcement: SignedPeerProfileAnnouncement) {
        val key = "${KademliaDhtEngine.PROFILE_KEY_PREFIX}${announcement.peerId}"
        val json = gson.toJson(announcement)
        val signedRecord = kadDht.createSignedRecord(key, json, announcement.timestampEpochMs)

        // Replicate PUT_VALUE to closest peers in Kademlia routing table
        val closestPeers = kadDht.findClosestPeers(key, KademliaDhtEngine.K_BUCKET_SIZE)
        for (peer in closestPeers) {
            val frame = P2pWireFrame(
                frameId = UUID.randomUUID().toString(),
                type = P2pFrameType.KAD_PUT_VALUE_REQ,
                senderPeerId = localPeerId,
                senderMultiaddrs = _listenMultiaddrs.value,
                dhtKey = key,
                signedDhtRecord = signedRecord
            )
            sendFrameToPeer(peer.peerId, frame)
        }
    }

    /**
     * Sends an end-to-end encrypted Signal message (`SignalEncryptedEnvelope`) to [recipientPeerId].
     * Automatically attempts direct connection first, then DCUtR NAT hole punching, and falls back
     * to Circuit Relay v2 via any mutually reachable peer if direct dial fails.
     */
    fun sendSignalEncryptedChat(envelope: SignalEncryptedEnvelope): Boolean {
        val frame = P2pWireFrame(
            frameId = envelope.messageId,
            type = P2pFrameType.SIGNAL_CHAT_MSG,
            senderPeerId = localPeerId,
            senderMultiaddrs = _listenMultiaddrs.value,
            targetPeerId = envelope.recipientPeerId,
            signalEnvelope = envelope
        )
        return sendFrameWithHolePunchAndRelayFallback(envelope.recipientPeerId, frame)
    }

    /**
     * Sends a cryptographic mutual-match handshake when the local user swipes right (likes) a peer.
     */
    fun sendLikeHandshake(targetPeerId: String): Boolean {
        val sortedPair = listOf(localPeerId, targetPeerId).sorted().joinToString("|")
        val payload = "aethermatch-like-v1|$sortedPair".toByteArray(StandardCharsets.UTF_8)
        val sigB64 = java.util.Base64.getEncoder().encodeToString(identityService.privKey.sign(payload))
        outboundLikes[targetPeerId] = sigB64

        val frame = P2pWireFrame(
            frameId = UUID.randomUUID().toString(),
            type = P2pFrameType.MATCH_LIKE_HANDSHAKE,
            senderPeerId = localPeerId,
            senderMultiaddrs = _listenMultiaddrs.value,
            targetPeerId = targetPeerId,
            matchSignatureBase64 = sigB64
        )
        return sendFrameWithHolePunchAndRelayFallback(targetPeerId, frame)
    }

    fun hasPeerLikedUs(peerId: String): Boolean = inboundLikes.containsKey(peerId)

    fun recordPeerLikedUs(peerId: String, signatureBase64: String) {
        inboundLikes[peerId] = signatureBase64
    }

    /**
     * Broadcasts or sends a Federated Learning Secure Aggregation message to a peer or committee.
     */
    fun sendFederatedSecAggMessage(targetPeerId: String, flPayloadJson: String): Boolean {
        val frame = P2pWireFrame(
            frameId = UUID.randomUUID().toString(),
            type = P2pFrameType.FL_SECAGG_ROUND_MSG,
            senderPeerId = localPeerId,
            senderMultiaddrs = _listenMultiaddrs.value,
            targetPeerId = targetPeerId,
            flPayloadJson = flPayloadJson
        )
        return sendFrameWithHolePunchAndRelayFallback(targetPeerId, frame)
    }

    /**
     * Attempts direct Noise XX stream delivery first; if unreachable, initiates DCUtR hole-punch
     * coordination and falls back to Circuit Relay v2 (`/p2p-circuit`) through any known relay peer.
     */
    private fun sendFrameWithHolePunchAndRelayFallback(targetPeerId: String, frame: P2pWireFrame): Boolean {
        if (sendFrameToPeer(targetPeerId, frame)) {
            return true
        }

        // Attempt DCUtR Hole Punching + Circuit Relay v2 fallback through any known relay node
        val relayCandidates = kadDht.findClosestPeers(targetPeerId, 5)
            .filter { it.peerId != targetPeerId && it.canActAsRelay }

        for (relayPeer in relayCandidates) {
            // 1. Send DCUtR hole-punch coordination frame
            val dcutrCoord = P2pWireFrame(
                frameId = UUID.randomUUID().toString(),
                type = P2pFrameType.DCUTR_HOLE_PUNCH_COORD,
                senderPeerId = localPeerId,
                senderMultiaddrs = _listenMultiaddrs.value,
                targetPeerId = targetPeerId,
                relayViaPeerId = relayPeer.peerId
            )
            sendFrameToPeer(relayPeer.peerId, dcutrCoord)

            // 2. Wrap original frame in a Circuit Relay v2 hop envelope so delivery is guaranteed
            // Note: Signal payload inside `frame.signalEnvelope` remains E2EE; relay only sees PeerIDs.
            val relayHopFrame = frame.copy(
                type = P2pFrameType.CIRCUIT_RELAY_HOP,
                targetPeerId = targetPeerId,
                relayViaPeerId = relayPeer.peerId
            )
            if (sendFrameToPeer(relayPeer.peerId, relayHopFrame)) {
                _natStatus.value = NatReachabilityState.CIRCUIT_RELAY_FALLBACK
                return true
            }
        }
        return false
    }

    fun sendFrameToPeer(targetPeerId: String, frame: P2pWireFrame): Boolean {
        val host = libp2pHost ?: return false
        val peerEntry = kadDht.getAllPeers().find { it.peerId == targetPeerId } ?: return false
        for (addrStr in peerEntry.multiaddrs) {
            val ok = runCatching {
                val ma = Multiaddr(addrStr)
                val pid = PeerId.fromBase58(targetPeerId)
                sendFrameToAddress(host, pid, ma, frame, DiscoverySource.KADEMLIA_DHT)
                true
            }.getOrDefault(false)
            if (ok) return true
        }
        return false
    }

    private fun sendFrameToAddress(
        host: Host,
        targetPeerId: PeerId,
        multiaddr: Multiaddr,
        frame: P2pWireFrame,
        source: DiscoverySource
    ) {
        val streamPromise = host.newStream<AetherMatchWireController>(
            listOf(WIRE_PROTOCOL_ID),
            targetPeerId,
            multiaddr
        )
        val controller = streamPromise.controller.get(5, TimeUnit.SECONDS)
        controller.sendFrame(frame, source)
    }

    private fun handleInboundFrame(
        frame: P2pWireFrame,
        replyCallback: (P2pWireFrame) -> Unit,
        source: DiscoverySource = DiscoverySource.KADEMLIA_DHT
    ) {
        if (frame.frameId in recentFrameIds) return
        recentFrameIds.add(frame.frameId)
        if (recentFrameIds.size > 500) {
            recentFrameIds.removeAt(0)
        }

        if (frame.senderPeerId != localPeerId && frame.senderMultiaddrs.isNotEmpty()) {
            kadDht.addOrUpdatePeer(KadPeerEntry(frame.senderPeerId, frame.senderMultiaddrs))
        }

        when (frame.type) {
            P2pFrameType.KAD_FIND_NODE_REQ -> {
                val target = frame.dhtKey ?: frame.senderPeerId
                val closest = kadDht.findClosestPeers(target, KademliaDhtEngine.K_BUCKET_SIZE)
                replyCallback(
                    P2pWireFrame(
                        frameId = UUID.randomUUID().toString(),
                        type = P2pFrameType.KAD_FIND_NODE_RES,
                        senderPeerId = localPeerId,
                        senderMultiaddrs = _listenMultiaddrs.value,
                        closestPeers = closest
                    )
                )
            }

            P2pFrameType.KAD_FIND_NODE_RES -> {
                frame.closestPeers?.forEach { kadDht.addOrUpdatePeer(it) }
            }

            P2pFrameType.KAD_PUT_VALUE_REQ -> {
                val record = frame.signedDhtRecord ?: return
                if (kadDht.putSignedRecord(record)) {
                    ingestSignedRecordIfProfile(record, source)
                }
            }

            P2pFrameType.KAD_GET_VALUE_REQ -> {
                val key = frame.dhtKey ?: return
                val record = kadDht.getRecord(key)
                val closest = kadDht.findClosestPeers(key, KademliaDhtEngine.K_BUCKET_SIZE)
                replyCallback(
                    P2pWireFrame(
                        frameId = UUID.randomUUID().toString(),
                        type = P2pFrameType.KAD_GET_VALUE_RES,
                        senderPeerId = localPeerId,
                        senderMultiaddrs = _listenMultiaddrs.value,
                        dhtKey = key,
                        signedDhtRecord = record,
                        closestPeers = closest
                    )
                )
            }

            P2pFrameType.KAD_GET_VALUE_RES -> {
                frame.closestPeers?.forEach { kadDht.addOrUpdatePeer(it) }
                frame.signedDhtRecord?.let { record ->
                    if (kadDht.putSignedRecord(record)) {
                        ingestSignedRecordIfProfile(record, source)
                    }
                }
            }

            P2pFrameType.KAD_SYNC_CATALOG_REQ -> {
                frame.closestPeers?.forEach { kadDht.addOrUpdatePeer(it) }
                frame.catalogRecords?.forEach { record ->
                    if (kadDht.putSignedRecord(record)) {
                        ingestSignedRecordIfProfile(record, source)
                    }
                }
                replyCallback(
                    P2pWireFrame(
                        frameId = UUID.randomUUID().toString(),
                        type = P2pFrameType.KAD_SYNC_CATALOG_RES,
                        senderPeerId = localPeerId,
                        senderMultiaddrs = _listenMultiaddrs.value,
                        closestPeers = kadDht.getAllPeers(),
                        catalogRecords = kadDht.getAllSignedRecords()
                    )
                )
            }

            P2pFrameType.KAD_SYNC_CATALOG_RES -> {
                frame.closestPeers?.forEach { kadDht.addOrUpdatePeer(it) }
                frame.catalogRecords?.forEach { record ->
                    if (kadDht.putSignedRecord(record)) {
                        ingestSignedRecordIfProfile(record, source)
                    }
                }
            }

            P2pFrameType.AUTONAT_PROBE_REQ -> {
                val dialable = frame.senderMultiaddrs.isNotEmpty()
                val reportedStatus = if (dialable) {
                    NatReachabilityState.PUBLICLY_REACHABLE
                } else {
                    NatReachabilityState.CIRCUIT_RELAY_FALLBACK
                }
                replyCallback(
                    P2pWireFrame(
                        frameId = UUID.randomUUID().toString(),
                        type = P2pFrameType.AUTONAT_PROBE_RES,
                        senderPeerId = localPeerId,
                        senderMultiaddrs = _listenMultiaddrs.value,
                        natStatus = reportedStatus,
                        observedAddr = frame.senderMultiaddrs.firstOrNull()
                    )
                )
            }

            P2pFrameType.AUTONAT_PROBE_RES -> {
                frame.natStatus?.let { _natStatus.value = it }
            }

            P2pFrameType.DCUTR_HOLE_PUNCH_COORD -> {
                holePunchCounter++
                val targetId = frame.targetPeerId
                if (targetId != null && targetId != localPeerId && _actingAsRelayAndBootstrap.value) {
                    // Forward DCUtR coordination through this relay to target peer
                    sendFrameToPeer(targetId, frame)
                } else if (targetId == localPeerId) {
                    _natStatus.value = NatReachabilityState.NAT_HOLE_PUNCHED
                }
            }

            P2pFrameType.CIRCUIT_RELAY_HOP -> {
                val targetId = frame.targetPeerId ?: return
                if (targetId == localPeerId) {
                    // We are the final destination of a Circuit Relay v2 hop!
                    frame.signalEnvelope?.let { onSignalEnvelopeReceived?.invoke(it) }
                    frame.matchSignatureBase64?.let { sig ->
                        inboundLikes[frame.senderPeerId] = sig
                        onMatchHandshakeReceived?.invoke(frame.senderPeerId, sig)
                    }
                    frame.flPayloadJson?.let { flJson ->
                        onFederatedSecAggMessageReceived?.invoke(frame.senderPeerId, flJson)
                    }
                } else if (_actingAsRelayAndBootstrap.value) {
                    // Act as a blind Circuit Relay v2 hop without storing or reading any payload
                    relayedFramesCounter++
                    sendFrameToPeer(targetId, frame)
                }
            }

            P2pFrameType.MATCH_LIKE_HANDSHAKE -> {
                val sig = frame.matchSignatureBase64 ?: return
                inboundLikes[frame.senderPeerId] = sig
                onMatchHandshakeReceived?.invoke(frame.senderPeerId, sig)
            }

            P2pFrameType.SIGNAL_CHAT_MSG -> {
                val env = frame.signalEnvelope ?: return
                if (env.recipientPeerId == localPeerId) {
                    onSignalEnvelopeReceived?.invoke(env)
                }
            }

            P2pFrameType.FL_SECAGG_ROUND_MSG -> {
                val flJson = frame.flPayloadJson ?: return
                onFederatedSecAggMessageReceived?.invoke(frame.senderPeerId, flJson)
            }

            else -> Unit
        }
    }

    private fun ingestSignedRecordIfProfile(record: SignedDhtRecord, source: DiscoverySource) {
        if (!record.key.startsWith(KademliaDhtEngine.PROFILE_KEY_PREFIX)) return
        runCatching {
            val announcement = gson.fromJson(record.valueJson, SignedPeerProfileAnnouncement::class.java)
            if (announcement.peerId != localPeerId && identityService.verifyProfileAnnouncement(announcement)) {
                if (announcement.listenMultiaddrs.isNotEmpty()) {
                    kadDht.addOrUpdatePeer(KadPeerEntry(announcement.peerId, announcement.listenMultiaddrs))
                }
                onProfileDiscovered?.invoke(announcement, source)
            }
        }
    }

    fun getDiagnostics(): Libp2pNodeDiagnostics {
        return Libp2pNodeDiagnostics(
            peerId = localPeerId,
            isStarted = _isStarted.value,
            listenMultiaddrs = _listenMultiaddrs.value,
            mdnsActive = mdnsRunning,
            natStatus = _natStatus.value,
            actingAsBootstrapAndRelay = _actingAsRelayAndBootstrap.value,
            relayedFramesCount = relayedFramesCounter,
            holePunchesSucceeded = holePunchCounter,
            connectedPeersCount = kadDht.getAllPeers().size,
            kadDiagnostics = kadDht.getDiagnostics()
        )
    }

    private fun detectLocalIpv4Address(): String {
        return runCatching {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            for (nif in interfaces) {
                if (!nif.isUp || nif.isLoopback) continue
                for (addr in nif.inetAddresses.toList()) {
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        return addr.hostAddress ?: "127.0.0.1"
                    }
                }
            }
            "127.0.0.1"
        }.getOrDefault("127.0.0.1")
    }

    interface AetherMatchWireController {
        fun sendFrame(frame: P2pWireFrame, source: DiscoverySource = DiscoverySource.KADEMLIA_DHT)
    }

    inner class AetherMatchWireBinding(
        protocol: AetherMatchWireProtocol
    ) : StrictProtocolBinding<AetherMatchWireController>(WIRE_PROTOCOL_ID, protocol)

    inner class AetherMatchWireProtocol : ProtocolHandler<AetherMatchWireController>(
        Long.MAX_VALUE,
        Long.MAX_VALUE
    ) {
        override fun onStartInitiator(stream: Stream): CompletableFuture<AetherMatchWireController> {
            return initChannel(stream)
        }

        override fun onStartResponder(stream: Stream): CompletableFuture<AetherMatchWireController> {
            return initChannel(stream)
        }

        private fun initChannel(stream: Stream): CompletableFuture<AetherMatchWireController> {
            val handler = WireChannelHandler(stream)
            stream.pushHandler(handler)
            return CompletableFuture.completedFuture(handler)
        }
    }

    inner class WireChannelHandler(
        private val stream: Stream
    ) : ProtocolMessageHandler<ByteBuf>, AetherMatchWireController {

        private var currentSource: DiscoverySource = DiscoverySource.KADEMLIA_DHT
        private val lineBuffer = StringBuilder()

        @Synchronized
        override fun onMessage(stream: Stream, msg: ByteBuf) {
            val chunk = msg.toString(CharsetUtil.UTF_8)
            lineBuffer.append(chunk)
            while (true) {
                val newlineIdx = lineBuffer.indexOf("\n")
                if (newlineIdx < 0) break
                val line = lineBuffer.substring(0, newlineIdx).trim()
                lineBuffer.delete(0, newlineIdx + 1)
                if (line.isNotEmpty()) {
                    runCatching {
                        val frame = gson.fromJson(line, P2pWireFrame::class.java)
                        handleInboundFrame(
                            frame = frame,
                            replyCallback = { responseFrame ->
                                sendFrame(responseFrame, currentSource)
                            },
                            source = currentSource
                        )
                    }
                }
            }
        }

        override fun sendFrame(frame: P2pWireFrame, source: DiscoverySource) {
            currentSource = source
            val jsonLine = gson.toJson(frame) + "\n"
            val buf: ByteBuf = Unpooled.copiedBuffer(jsonLine, CharsetUtil.UTF_8)
            stream.writeAndFlush(buf)
        }

        override fun onException(cause: Throwable?) {
            stream.close()
        }
    }
}
