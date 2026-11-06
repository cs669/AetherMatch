package com.aethermatch.p2p.security

import com.google.gson.Gson
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.ecc.Curve
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import java.util.Base64
import java.util.UUID

/**
 * Serializable representation of a peer's Signal PreKeyBundle (X3DH + PQXDH Kyber-1024)
 * published inside their Ed25519-signed Kademlia DHT profile announcement.
 */
data class PublishedSignalPreKeyBundle(
    val registrationId: Int,
    val deviceId: Int,
    val preKeyId: Int,
    val preKeyPublicBase64: String,
    val signedPreKeyId: Int,
    val signedPreKeyPublicBase64: String,
    val signedPreKeySignatureBase64: String,
    val identityKeyPublicBase64: String,
    val kyberPreKeyId: Int,
    val kyberPreKeyPublicBase64: String,
    val kyberPreKeySignatureBase64: String
)

/**
 * Wire envelope for Signal Protocol encrypted messages sent over libp2p streams.
 */
data class SignalEncryptedEnvelope(
    val messageId: String = UUID.randomUUID().toString(),
    val senderPeerId: String,
    val recipientPeerId: String,
    val ciphertextType: Int, // CiphertextMessage.PREKEY_TYPE (3) or WHISPER_TYPE (2)
    val ciphertextBase64: String,
    val timestampEpochMs: Long = System.currentTimeMillis()
)

data class DecryptedSignalMessage(
    val messageId: String,
    val senderPeerId: String,
    val plaintext: String,
    val ciphertextHexPreview: String,
    val signalMessageTypeLabel: String,
    val timestampEpochMs: Long
)

data class SignalCryptoDiagnostics(
    val localRegistrationId: Int,
    val identityKeyFingerprintHex: String,
    val signedPreKeyId: Int,
    val kyberPreKeyId: Int,
    val activeDoubleRatchetSessions: Int
)

/**
 * End-to-end encryption engine powered exclusively by the official `org.signal:libsignal-client` library.
 * Implements X3DH + PQXDH (Kyber-1024) key agreement, Double Ratchet encryption/decryption,
 * and 60-digit Numeric Safety Number generation.
 */
class SignalProtocolEngine(
    private val localPeerId: String,
    val signalStore: SqlCipherSignalProtocolStore
) {
    companion object {
        const val DEFAULT_DEVICE_ID = 1
        private const val INITIAL_PREKEY_ID = 101
        private const val INITIAL_SIGNED_PREKEY_ID = 201
        private const val INITIAL_KYBER_PREKEY_ID = 301
        private const val FINGERPRINT_ITERATIONS = 5200
    }

    private val gson = Gson()

    init {
        ensureLocalPreKeysInitialized()
    }

    @Synchronized
    private fun ensureLocalPreKeysInitialized() {
        val identityKeyPair = signalStore.identityKeyPair
        signalStore.localRegistrationId // Ensures registration ID is persisted

        if (!signalStore.containsPreKey(INITIAL_PREKEY_ID)) {
            val preKeyPair = Curve.generateKeyPair()
            val preKeyRecord = PreKeyRecord(INITIAL_PREKEY_ID, preKeyPair)
            signalStore.storePreKey(INITIAL_PREKEY_ID, preKeyRecord)
        }

        if (!signalStore.containsSignedPreKey(INITIAL_SIGNED_PREKEY_ID)) {
            val signedPreKeyPair = Curve.generateKeyPair()
            val signature = identityKeyPair.privateKey.calculateSignature(
                signedPreKeyPair.publicKey.serialize()
            )
            val signedPreKeyRecord = SignedPreKeyRecord(
                INITIAL_SIGNED_PREKEY_ID,
                System.currentTimeMillis(),
                signedPreKeyPair,
                signature
            )
            signalStore.storeSignedPreKey(INITIAL_SIGNED_PREKEY_ID, signedPreKeyRecord)
        }

        if (!signalStore.containsKyberPreKey(INITIAL_KYBER_PREKEY_ID)) {
            val kemKeyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val kyberSig = identityKeyPair.privateKey.calculateSignature(
                kemKeyPair.publicKey.serialize()
            )
            val kyberRecord = KyberPreKeyRecord(
                INITIAL_KYBER_PREKEY_ID,
                System.currentTimeMillis(),
                kemKeyPair,
                kyberSig
            )
            signalStore.storeKyberPreKey(INITIAL_KYBER_PREKEY_ID, kyberRecord)
        }
    }

    /**
     * Exports this node's public Signal PreKeyBundle (including post-quantum Kyber-1024 prekey)
     * so peers can establish an asynchronous X3DH/PQXDH session.
     */
    @Synchronized
    fun exportPreKeyBundle(): PublishedSignalPreKeyBundle {
        ensureLocalPreKeysInitialized()
        val identityKey = signalStore.identityKeyPair.publicKey
        val preKey = signalStore.loadPreKey(INITIAL_PREKEY_ID)
        val signedPreKey = signalStore.loadSignedPreKey(INITIAL_SIGNED_PREKEY_ID)
        val kyberPreKey = signalStore.loadKyberPreKey(INITIAL_KYBER_PREKEY_ID)

        val encoder = Base64.getEncoder()
        return PublishedSignalPreKeyBundle(
            registrationId = signalStore.localRegistrationId,
            deviceId = DEFAULT_DEVICE_ID,
            preKeyId = preKey.id,
            preKeyPublicBase64 = encoder.encodeToString(preKey.keyPair.publicKey.serialize()),
            signedPreKeyId = signedPreKey.id,
            signedPreKeyPublicBase64 = encoder.encodeToString(signedPreKey.keyPair.publicKey.serialize()),
            signedPreKeySignatureBase64 = encoder.encodeToString(signedPreKey.signature),
            identityKeyPublicBase64 = encoder.encodeToString(identityKey.serialize()),
            kyberPreKeyId = kyberPreKey.id,
            kyberPreKeyPublicBase64 = encoder.encodeToString(kyberPreKey.keyPair.publicKey.serialize()),
            kyberPreKeySignatureBase64 = encoder.encodeToString(kyberPreKey.signature)
        )
    }

    fun exportPreKeyBundleJson(): String = gson.toJson(exportPreKeyBundle())

    /**
     * Processes a remote peer's [PublishedSignalPreKeyBundle] to initialize a Signal X3DH/PQXDH session
     * if one does not already exist.
     */
    @Synchronized
    fun ensureSessionWithPeer(remotePeerId: String, remoteBundleJson: String) {
        val bundleDto = gson.fromJson(remoteBundleJson, PublishedSignalPreKeyBundle::class.java)
        ensureSessionWithPeer(remotePeerId, bundleDto)
    }

    @Synchronized
    fun ensureSessionWithPeer(remotePeerId: String, bundleDto: PublishedSignalPreKeyBundle) {
        val address = SignalProtocolAddress(remotePeerId, bundleDto.deviceId)
        if (signalStore.containsSession(address)) {
            return
        }

        val decoder = Base64.getDecoder()
        val preKeyPub = ECPublicKey(decoder.decode(bundleDto.preKeyPublicBase64))
        val signedPreKeyPub = ECPublicKey(decoder.decode(bundleDto.signedPreKeyPublicBase64))
        val signedPreKeySig = decoder.decode(bundleDto.signedPreKeySignatureBase64)
        val identityKey = IdentityKey(decoder.decode(bundleDto.identityKeyPublicBase64), 0)
        val kyberPreKeyPub = KEMPublicKey(decoder.decode(bundleDto.kyberPreKeyPublicBase64))
        val kyberPreKeySig = decoder.decode(bundleDto.kyberPreKeySignatureBase64)

        val preKeyBundle = PreKeyBundle(
            bundleDto.registrationId,
            bundleDto.deviceId,
            bundleDto.preKeyId,
            preKeyPub,
            bundleDto.signedPreKeyId,
            signedPreKeyPub,
            signedPreKeySig,
            identityKey,
            bundleDto.kyberPreKeyId,
            kyberPreKeyPub,
            kyberPreKeySig
        )

        val sessionBuilder = SessionBuilder(signalStore, address)
        sessionBuilder.process(preKeyBundle)
    }

    /**
     * Encrypts a plaintext message for [remotePeerId] using the Signal Double Ratchet.
     */
    @Synchronized
    fun encryptMessage(
        remotePeerId: String,
        plaintext: String,
        remotePreKeyBundleJson: String? = null
    ): SignalEncryptedEnvelope {
        val address = SignalProtocolAddress(remotePeerId, DEFAULT_DEVICE_ID)
        if (!signalStore.containsSession(address)) {
            requireNotNull(remotePreKeyBundleJson) {
                "No existing Signal session with $remotePeerId and no PreKeyBundle provided"
            }
            ensureSessionWithPeer(remotePeerId, remotePreKeyBundleJson)
        }

        val sessionCipher = SessionCipher(signalStore, address)
        val ciphertextMessage: CiphertextMessage = sessionCipher.encrypt(plaintext.encodeToByteArray())
        val rawCiphertext = ciphertextMessage.serialize()

        // Ensure our one-time prekey is replenished if consumed
        ensureLocalPreKeysInitialized()

        return SignalEncryptedEnvelope(
            senderPeerId = localPeerId,
            recipientPeerId = remotePeerId,
            ciphertextType = ciphertextMessage.type,
            ciphertextBase64 = Base64.getEncoder().encodeToString(rawCiphertext)
        )
    }

    /**
     * Decrypts an incoming [SignalEncryptedEnvelope] from a remote peer using the Signal Double Ratchet.
     */
    @Synchronized
    fun decryptMessage(envelope: SignalEncryptedEnvelope): DecryptedSignalMessage {
        val senderAddress = SignalProtocolAddress(envelope.senderPeerId, DEFAULT_DEVICE_ID)
        val sessionCipher = SessionCipher(signalStore, senderAddress)
        val rawCiphertext = Base64.getDecoder().decode(envelope.ciphertextBase64)

        val plaintextBytes: ByteArray
        val typeLabel: String
        when (envelope.ciphertextType) {
            CiphertextMessage.PREKEY_TYPE -> {
                val preKeyMsg = PreKeySignalMessage(rawCiphertext)
                plaintextBytes = sessionCipher.decrypt(preKeyMsg)
                typeLabel = "PreKeySignalMessage (PQXDH/X3DH)"
            }
            CiphertextMessage.WHISPER_TYPE -> {
                val signalMsg = SignalMessage(rawCiphertext)
                plaintextBytes = sessionCipher.decrypt(signalMsg)
                typeLabel = "SignalMessage (Double Ratchet)"
            }
            else -> throw IllegalArgumentException("Unsupported Signal CiphertextMessage type: ${envelope.ciphertextType}")
        }

        // Replenish prekeys if an incoming PreKeySignalMessage consumed our prekey
        ensureLocalPreKeysInitialized()

        val hexPreview = rawCiphertext.take(24).joinToString("") { "%02x".format(it) }
        return DecryptedSignalMessage(
            messageId = envelope.messageId,
            senderPeerId = envelope.senderPeerId,
            plaintext = plaintextBytes.decodeToString(),
            ciphertextHexPreview = hexPreview,
            signalMessageTypeLabel = typeLabel,
            timestampEpochMs = envelope.timestampEpochMs
        )
    }

    /**
     * Computes the official 60-digit Signal Safety Number between the local user and [remotePeerId].
     */
    @Synchronized
    fun computeSafetyNumber(remotePeerId: String, remoteIdentityKeyBase64: String? = null): String {
        val localIdentity = signalStore.identityKeyPair.publicKey
        val address = SignalProtocolAddress(remotePeerId, DEFAULT_DEVICE_ID)
        val remoteIdentity = signalStore.getIdentity(address)
            ?: remoteIdentityKeyBase64?.let { IdentityKey(Base64.getDecoder().decode(it), 0) }
            ?: return "Pending X3DH Key Exchange"

        val generator = NumericFingerprintGenerator(FINGERPRINT_ITERATIONS)
        val fingerprint = generator.createFor(
            2,
            localPeerId.encodeToByteArray(),
            localIdentity,
            remotePeerId.encodeToByteArray(),
            remoteIdentity
        )
        return fingerprint.displayableFingerprint.displayText.chunked(5).joinToString(" ")
    }

    @Synchronized
    fun getDiagnostics(): SignalCryptoDiagnostics {
        val pubBytes = signalStore.identityKeyPair.publicKey.serialize()
        val fpHex = pubBytes.take(16).joinToString(":") { "%02X".format(it) }
        return SignalCryptoDiagnostics(
            localRegistrationId = signalStore.localRegistrationId,
            identityKeyFingerprintHex = fpHex,
            signedPreKeyId = INITIAL_SIGNED_PREKEY_ID,
            kyberPreKeyId = INITIAL_KYBER_PREKEY_ID,
            activeDoubleRatchetSessions = signalStore.getActiveSessionPeerIds().size
        )
    }
}
