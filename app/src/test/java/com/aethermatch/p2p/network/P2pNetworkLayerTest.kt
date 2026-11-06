package com.aethermatch.p2p.network

import com.aethermatch.p2p.model.RelationshipGoal
import com.aethermatch.p2p.model.SignedPeerProfileAnnouncement
import com.aethermatch.p2p.model.UserProfile
import com.aethermatch.p2p.security.IdentityAndSignatureService
import com.aethermatch.p2p.security.JvmAesGcmMasterKeyWrapper
import com.aethermatch.p2p.security.KeystoreKeyManager
import com.aethermatch.p2p.security.SignalEncryptedEnvelope
import com.aethermatch.p2p.security.SignalProtocolEngine
import com.aethermatch.p2p.security.SqlCipherSignalProtocolStore
import com.aethermatch.p2p.storage.EncryptedRecordStorageRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class P2pNetworkLayerTest {

    @Test
    fun `Kademlia DHT orders peers by 256-bit SHA256 XOR distance and verifies signed records`() {
        val keyManager = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val identity = IdentityAndSignatureService(keyManager)
        val kad = KademliaDhtEngine(identity.localPeerIdBase58, identity)

        kad.addOrUpdatePeer(KadPeerEntry("12D3KooWPeerAlpha", listOf("/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWPeerAlpha")))
        kad.addOrUpdatePeer(KadPeerEntry("12D3KooWPeerBeta", listOf("/ip4/127.0.0.1/tcp/4002/p2p/12D3KooWPeerBeta")))
        kad.addOrUpdatePeer(KadPeerEntry("12D3KooWPeerGamma", listOf("/ip4/127.0.0.1/tcp/4003/p2p/12D3KooWPeerGamma")))

        val targetKey = "/aethermatch/profile/12D3KooWPeerBeta"
        val closest = kad.findClosestPeers(targetKey, 3)
        assertEquals(3, closest.size)

        // Verify distances are monotonically non-decreasing
        val d0 = kad.computeXorDistanceBetween(targetKey, closest[0].peerId)
        val d1 = kad.computeXorDistanceBetween(targetKey, closest[1].peerId)
        val d2 = kad.computeXorDistanceBetween(targetKey, closest[2].peerId)
        assertTrue(d0 <= d1)
        assertTrue(d1 <= d2)

        // Verify signed DHT record creation and tamper rejection
        val ownKey = "${KademliaDhtEngine.PROFILE_KEY_PREFIX}${identity.localPeerIdBase58}"
        val record = kad.createSignedRecord(ownKey, "{\"hello\":\"world\"}")
        assertTrue(kad.verifySignedRecord(record))

        val tampered = record.copy(valueJson = "{\"hello\":\"tampered\"}")
        assertFalse(kad.verifySignedRecord(tampered))
        assertFalse(kad.putSignedRecord(tampered))
    }

    @Test
    fun `Real libp2p nodes with Noise XX exchange DHT profiles and Signal E2EE messages directly and via Circuit Relay`() {
        val kmA = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val kmRelay = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val kmB = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())

        val idA = IdentityAndSignatureService(kmA)
        val idRelay = IdentityAndSignatureService(kmRelay)
        val idB = IdentityAndSignatureService(kmB)

        val sigA = SignalProtocolEngine(idA.localPeerIdBase58, SqlCipherSignalProtocolStore(EncryptedRecordStorageRepository(kmA)))
        val sigB = SignalProtocolEngine(idB.localPeerIdBase58, SqlCipherSignalProtocolStore(EncryptedRecordStorageRepository(kmB)))

        val nodeA = Libp2pNodeManager(idA)
        val nodeRelay = Libp2pNodeManager(idRelay)
        val nodeB = Libp2pNodeManager(idB)

        try {
            val addrsA = nodeA.startNode(enableMdns = false)
            val addrsRelay = nodeRelay.startNode(enableMdns = false)
            val addrsB = nodeB.startNode(enableMdns = false)

            assertTrue(addrsA.isNotEmpty())
            assertTrue(addrsRelay.isNotEmpty())
            assertTrue(addrsB.isNotEmpty())

            val profileDiscoveryLatch = CountDownLatch(1)
            var discoveredByA: SignedPeerProfileAnnouncement? = null
            nodeA.onProfileDiscovered = { announcement, _ ->
                if (announcement.peerId == idB.localPeerIdBase58) {
                    discoveredByA = announcement
                    profileDiscoveryLatch.countDown()
                }
            }

            val chatLatch = CountDownLatch(1)
            var receivedEnvelopeAtB: SignalEncryptedEnvelope? = null
            nodeB.onSignalEnvelopeReceived = { envelope ->
                receivedEnvelopeAtB = envelope
                chatLatch.countDown()
            }

            // Node B publishes its signed profile + Signal PreKeyBundle to Relay Node
            val profileB = UserProfile(
                peerId = idB.localPeerIdBase58,
                displayName = "Node B User",
                age = 28,
                bio = "Testing Noise XX + Kademlia DHT",
                interests = listOf("libp2p", "Cryptography"),
                relationshipGoal = RelationshipGoal.LONG_TERM_PARTNER,
                locationRegion = "TestNet"
            )
            val signedB = idB.signProfileAnnouncement(
                profile = profileB,
                listenMultiaddrs = addrsB,
                signalPreKeyBundleJson = sigB.exportPreKeyBundleJson()
            )
            nodeB.publishSignedProfileToDht(signedB)

            // Connect B <-> Relay and A <-> Relay
            val relayAddr = addrsRelay.first { it.contains("127.0.0.1") }
            assertTrue(nodeB.bootstrapWithPeer(relayAddr))
            Thread.sleep(300)
            assertTrue(nodeA.bootstrapWithPeer(relayAddr))

            assertTrue("Node A should discover Node B's signed profile via Kademlia DHT sync",
                profileDiscoveryLatch.await(8, TimeUnit.SECONDS))
            assertNotNull(discoveredByA)
            assertEquals("Node B User", discoveredByA!!.displayName)

            // Node A encrypts a message for Node B using Node B's DHT PreKeyBundle and sends over libp2p
            val encryptedEnvelope = sigA.encryptMessage(
                remotePeerId = idB.localPeerIdBase58,
                plaintext = "Hello over libp2p Noise XX!",
                remotePreKeyBundleJson = discoveredByA!!.signalPreKeyBundleJson
            )
            assertTrue(nodeA.sendSignalEncryptedChat(encryptedEnvelope))

            assertTrue("Node B should receive the SignalEncryptedEnvelope over libp2p",
                chatLatch.await(8, TimeUnit.SECONDS))
            assertNotNull(receivedEnvelopeAtB)

            val decryptedAtB = sigB.decryptMessage(receivedEnvelopeAtB!!)
            assertEquals("Hello over libp2p Noise XX!", decryptedAtB.plaintext)
        } finally {
            nodeA.stopNode()
            nodeRelay.stopNode()
            nodeB.stopNode()
        }
    }
}
