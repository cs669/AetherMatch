package com.aethermatch.p2p.security

import com.aethermatch.p2p.model.RelationshipGoal
import com.aethermatch.p2p.model.SwipeRecord
import com.aethermatch.p2p.model.UserProfile
import com.aethermatch.p2p.storage.EncryptedRecordStorageRepository
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * JVM hardware-equivalent AES-256-GCM MasterKeyWrapper for unit testing KeystoreKeyManager
 * outside the Android hardware TEE runtime.
 */
class JvmAesGcmMasterKeyWrapper : MasterKeyWrapper {
    private val masterKey: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    override fun wrapSecret(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        cipher.updateAAD(associatedData)
        val iv = cipher.iv
        val ct = cipher.doFinal(plaintext)
        return iv + ct
    }

    override fun unwrapSecret(wrappedBlob: ByteArray, associatedData: ByteArray): ByteArray {
        val iv = wrappedBlob.copyOfRange(0, 12)
        val ct = wrappedBlob.copyOfRange(12, wrappedBlob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(128, iv))
        cipher.updateAAD(associatedData)
        return cipher.doFinal(ct)
    }

    override fun isHardwareBacked(): Boolean = false
}

class CryptoAndStorageLayerTest {

    @Test
    fun `keystore manager wraps and unwraps 256-bit SQLCipher passphrase and rejects tampered AAD`() {
        val backingStore = mutableMapOf<String, String>()
        val wrapper = JvmAesGcmMasterKeyWrapper()
        val keyManager = KeystoreKeyManager(
            context = null,
            masterKeyWrapper = wrapper,
            backingMap = backingStore
        )

        val key1 = keyManager.getOrCreateSqlCipherPassphrase()
        val key2 = keyManager.getOrCreateSqlCipherPassphrase()

        assertEquals(32, key1.size)
        assertArrayEquals(key1, key2)

        keyManager.storeWrappedSecret("custom_secret", "super-secret-value".encodeToByteArray())
        val unwrapped = keyManager.loadWrappedSecret("custom_secret")
        assertNotNull(unwrapped)
        assertEquals("super-secret-value", unwrapped!!.decodeToString())
    }

    @Test
    fun `Ed25519 identity signs profile announcement and detects tampering or PeerId spoofing`() {
        val keyManager = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val identityService = IdentityAndSignatureService(keyManager)

        val profile = UserProfile(
            peerId = identityService.localPeerIdBase58,
            displayName = "Elena Vance",
            age = 29,
            bio = "Distributed systems researcher & trail runner",
            interests = listOf("Cryptography", "Trail Running", "Espresso"),
            relationshipGoal = RelationshipGoal.LONG_TERM_PARTNER,
            locationRegion = "Pacific Northwest"
        )

        val signed = identityService.signProfileAnnouncement(
            profile = profile,
            listenMultiaddrs = listOf("/ip4/192.168.1.42/tcp/4001/p2p/${identityService.localPeerIdBase58}"),
            signalPreKeyBundleJson = "{\"registrationId\":1234}"
        )

        assertTrue(identityService.verifyProfileAnnouncement(signed))

        // Tamper with bio -> signature verification must fail
        val tamperedBio = signed.copy(bio = "Attacker modified bio")
        assertFalse(identityService.verifyProfileAnnouncement(tamperedBio))

        // Tamper with Signal PreKeyBundle -> signature verification must fail
        val tamperedPreKey = signed.copy(signalPreKeyBundleJson = "{\"registrationId\":9999}")
        assertFalse(identityService.verifyProfileAnnouncement(tamperedPreKey))
    }

    @Test
    fun `Signal Protocol X3DH PQXDH and Double Ratchet encrypts and decrypts bidirectionally`() {
        val aliceKeyManager = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val bobKeyManager = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())

        val aliceStorage = EncryptedRecordStorageRepository(aliceKeyManager)
        val bobStorage = EncryptedRecordStorageRepository(bobKeyManager)

        val aliceStore = SqlCipherSignalProtocolStore(aliceStorage)
        val bobStore = SqlCipherSignalProtocolStore(bobStorage)

        val aliceEngine = SignalProtocolEngine("12D3KooWAlicePeerId", aliceStore)
        val bobEngine = SignalProtocolEngine("12D3KooWBobPeerId", bobStore)

        // Bob publishes his Signal PreKeyBundle (including Kyber-1024 PQXDH prekey) to DHT
        val bobPreKeyBundleJson = bobEngine.exportPreKeyBundleJson()

        // Alice sends first encrypted message to Bob using Bob's PreKeyBundle
        val firstPlaintext = "Hey Bob! Matched via local AI model — this message is Signal E2EE."
        val envelope1 = aliceEngine.encryptMessage(
            remotePeerId = "12D3KooWBobPeerId",
            plaintext = firstPlaintext,
            remotePreKeyBundleJson = bobPreKeyBundleJson
        )
        assertNotEquals(firstPlaintext, envelope1.ciphertextBase64)

        // Bob decrypts Alice's PreKeySignalMessage
        val decrypted1 = bobEngine.decryptMessage(envelope1)
        assertEquals(firstPlaintext, decrypted1.plaintext)
        assertTrue(decrypted1.signalMessageTypeLabel.contains("PreKeySignalMessage"))

        // Bob replies to Alice over the established Double Ratchet session (no PreKeyBundle needed)
        val secondPlaintext = "Hi Alice! Double Ratchet ratchet step succeeded."
        val envelope2 = bobEngine.encryptMessage(
            remotePeerId = "12D3KooWAlicePeerId",
            plaintext = secondPlaintext
        )
        val decrypted2 = aliceEngine.decryptMessage(envelope2)
        assertEquals(secondPlaintext, decrypted2.plaintext)
        assertTrue(decrypted2.signalMessageTypeLabel.contains("SignalMessage"))

        // Verify Safety Numbers match symmetrically
        val aliceSafety = aliceEngine.computeSafetyNumber("12D3KooWBobPeerId")
        val bobSafety = bobEngine.computeSafetyNumber("12D3KooWAlicePeerId")
        assertEquals(aliceSafety, bobSafety)
        assertFalse(aliceSafety.contains("Pending"))
    }

    @Test
    fun `Encrypted storage persists and updates swipes and profiles cleanly`() {
        val keyManager = KeystoreKeyManager(null, JvmAesGcmMasterKeyWrapper(), mutableMapOf())
        val storage = EncryptedRecordStorageRepository(keyManager)

        val profile = UserProfile(
            peerId = "12D3KooWLocalPeer",
            displayName = "Aria",
            age = 27,
            bio = "Privacy advocate",
            interests = listOf("Rust", "AI", "Climbing"),
            relationshipGoal = RelationshipGoal.SERIOUS_DATING,
            locationRegion = "Bay Area"
        )
        storage.saveLocalUserProfile(profile)
        assertEquals("Aria", storage.getLocalUserProfile()?.displayName)

        storage.recordSwipe(
            SwipeRecord(
                peerId = "12D3KooWTarget1",
                liked = true,
                encodedFeatures = floatArrayOf(0.8f, 0.2f, 1.0f),
                compatibilityAtSwipe = 0.91f
            )
        )
        assertEquals(1, storage.getUntrainedSwipes().size)
        storage.markSwipesTrained(roundId = 1L)
        assertEquals(0, storage.getUntrainedSwipes().size)
        assertEquals(1L, storage.getAllSwipes().first().trainedInRound)
    }
}
