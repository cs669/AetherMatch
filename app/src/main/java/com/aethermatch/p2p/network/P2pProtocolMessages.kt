package com.aethermatch.p2p.network

import com.aethermatch.p2p.security.SignalEncryptedEnvelope

enum class P2pFrameType {
    KAD_FIND_NODE_REQ,
    KAD_FIND_NODE_RES,
    KAD_PUT_VALUE_REQ,
    KAD_PUT_VALUE_RES,
    KAD_GET_VALUE_REQ,
    KAD_GET_VALUE_RES,
    KAD_SYNC_CATALOG_REQ,
    KAD_SYNC_CATALOG_RES,
    AUTONAT_PROBE_REQ,
    AUTONAT_PROBE_RES,
    DCUTR_HOLE_PUNCH_COORD,
    CIRCUIT_RELAY_HOP,
    MATCH_LIKE_HANDSHAKE,
    SIGNAL_CHAT_MSG,
    FL_SECAGG_ROUND_MSG
}

enum class NatReachabilityState(val label: String) {
    UNKNOWN("Probing AutoNAT..."),
    PUBLICLY_REACHABLE("Public / Direct (Can Act as Bootstrap & Relay)"),
    NAT_HOLE_PUNCHED("NAT Traversal Active (DCUtR Hole-Punched)"),
    CIRCUIT_RELAY_FALLBACK("Behind Symmetric NAT (Circuit Relay v2 Active)")
}

/**
 * Top-level multiplexed frame transmitted over libp2p Noise XX encrypted streams (`/aethermatch/wire/1.0.0`).
 */
data class P2pWireFrame(
    val frameId: String,
    val type: P2pFrameType,
    val senderPeerId: String,
    val senderMultiaddrs: List<String> = emptyList(),
    val targetPeerId: String? = null,
    val dhtKey: String? = null,
    val signedDhtRecord: SignedDhtRecord? = null,
    val closestPeers: List<KadPeerEntry>? = null,
    val catalogRecords: List<SignedDhtRecord>? = null,
    val natStatus: NatReachabilityState? = null,
    val observedAddr: String? = null,
    val relayViaPeerId: String? = null,
    val signalEnvelope: SignalEncryptedEnvelope? = null,
    val matchSignatureBase64: String? = null,
    val flPayloadJson: String? = null,
    val timestampEpochMs: Long = System.currentTimeMillis()
)
