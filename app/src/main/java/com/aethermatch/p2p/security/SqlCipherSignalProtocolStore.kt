package com.aethermatch.p2p.security

import com.aethermatch.p2p.storage.EncryptedStorageRepository
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID

/**
 * Persistent [SignalProtocolStore] backed by our SQLCipher-encrypted database ([EncryptedStorageRepository]).
 * Stores local Signal identity key pair, registration ID, X3DH prekeys, signed prekeys,
 * post-quantum Kyber-1024 prekeys (PQXDH), peer identity keys (TOFU + fingerprint verification),
 * and Double Ratchet session records.
 */
class SqlCipherSignalProtocolStore(
    private val storage: EncryptedStorageRepository
) : SignalProtocolStore {

    companion object {
        private const val NS_META = "meta"
        private const val NS_IDENTITIES = "identities"
        private const val NS_PREKEYS = "prekeys"
        private const val NS_SIGNED_PREKEYS = "signed_prekeys"
        private const val NS_KYBER_PREKEYS = "kyber_prekeys"
        private const val NS_SESSIONS = "sessions"
        private const val NS_SENDER_KEYS = "sender_keys"

        private const val KEY_LOCAL_IDENTITY = "local_identity_key_pair"
        private const val KEY_REGISTRATION_ID = "local_registration_id"
    }

    private val secureRandom = SecureRandom()

    @Synchronized
    override fun getIdentityKeyPair(): IdentityKeyPair {
        val existing = storage.getSignalStoreBlob(NS_META, KEY_LOCAL_IDENTITY)
        if (existing != null) {
            return IdentityKeyPair(existing)
        }
        val generated = IdentityKeyPair.generate()
        storage.putSignalStoreBlob(NS_META, KEY_LOCAL_IDENTITY, generated.serialize())
        return generated
    }

    @Synchronized
    override fun getLocalRegistrationId(): Int {
        val existing = storage.getSignalStoreBlob(NS_META, KEY_REGISTRATION_ID)
        if (existing != null && existing.size == 4) {
            return ByteBuffer.wrap(existing).int
        }
        val regId = (secureRandom.nextInt(16380) + 1)
        val buf = ByteBuffer.allocate(4).putInt(regId).array()
        storage.putSignalStoreBlob(NS_META, KEY_REGISTRATION_ID, buf)
        return regId
    }

    @Synchronized
    override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): Boolean {
        val key = "${address.name}:${address.deviceId}"
        val existingBytes = storage.getSignalStoreBlob(NS_IDENTITIES, key)
        val serialized = identityKey.serialize()
        val replaced = existingBytes != null && !existingBytes.contentEquals(serialized)
        storage.putSignalStoreBlob(NS_IDENTITIES, key, serialized)
        return replaced
    }

    @Synchronized
    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction
    ): Boolean {
        val key = "${address.name}:${address.deviceId}"
        val existingBytes = storage.getSignalStoreBlob(NS_IDENTITIES, key) ?: return true // TOFU on first contact
        return existingBytes.contentEquals(identityKey.serialize())
    }

    @Synchronized
    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? {
        val key = "${address.name}:${address.deviceId}"
        val bytes = storage.getSignalStoreBlob(NS_IDENTITIES, key) ?: return null
        return IdentityKey(bytes, 0)
    }

    @Synchronized
    override fun loadPreKey(preKeyId: Int): PreKeyRecord {
        val bytes = storage.getSignalStoreBlob(NS_PREKEYS, preKeyId.toString())
            ?: throw org.signal.libsignal.protocol.InvalidKeyIdException("No PreKey with id $preKeyId")
        return PreKeyRecord(bytes)
    }

    @Synchronized
    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        storage.putSignalStoreBlob(NS_PREKEYS, preKeyId.toString(), record.serialize())
    }

    @Synchronized
    override fun containsPreKey(preKeyId: Int): Boolean {
        return storage.getSignalStoreBlob(NS_PREKEYS, preKeyId.toString()) != null
    }

    @Synchronized
    override fun removePreKey(preKeyId: Int) {
        storage.removeSignalStoreBlob(NS_PREKEYS, preKeyId.toString())
    }

    @Synchronized
    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord {
        val bytes = storage.getSignalStoreBlob(NS_SIGNED_PREKEYS, signedPreKeyId.toString())
            ?: throw org.signal.libsignal.protocol.InvalidKeyIdException("No SignedPreKey with id $signedPreKeyId")
        return SignedPreKeyRecord(bytes)
    }

    @Synchronized
    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> {
        return storage.getAllSignalStoreEntries(NS_SIGNED_PREKEYS).values.map { SignedPreKeyRecord(it) }
    }

    @Synchronized
    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        storage.putSignalStoreBlob(NS_SIGNED_PREKEYS, signedPreKeyId.toString(), record.serialize())
    }

    @Synchronized
    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean {
        return storage.getSignalStoreBlob(NS_SIGNED_PREKEYS, signedPreKeyId.toString()) != null
    }

    @Synchronized
    override fun removeSignedPreKey(signedPreKeyId: Int) {
        storage.removeSignalStoreBlob(NS_SIGNED_PREKEYS, signedPreKeyId.toString())
    }

    @Synchronized
    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord {
        val bytes = storage.getSignalStoreBlob(NS_KYBER_PREKEYS, kyberPreKeyId.toString())
            ?: throw org.signal.libsignal.protocol.InvalidKeyIdException("No KyberPreKey with id $kyberPreKeyId")
        return KyberPreKeyRecord(bytes)
    }

    @Synchronized
    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> {
        return storage.getAllSignalStoreEntries(NS_KYBER_PREKEYS).values.map { KyberPreKeyRecord(it) }
    }

    @Synchronized
    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
        storage.putSignalStoreBlob(NS_KYBER_PREKEYS, kyberPreKeyId.toString(), record.serialize())
    }

    @Synchronized
    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean {
        return storage.getSignalStoreBlob(NS_KYBER_PREKEYS, kyberPreKeyId.toString()) != null
    }

    @Synchronized
    override fun markKyberPreKeyUsed(kyberPreKeyId: Int) {
        // Keep record available for out-of-order PreKeyMessages or rotate on next prekey refresh
    }

    @Synchronized
    override fun loadSession(address: SignalProtocolAddress): SessionRecord {
        val key = "${address.name}:${address.deviceId}"
        val bytes = storage.getSignalStoreBlob(NS_SESSIONS, key)
        return if (bytes != null) SessionRecord(bytes) else SessionRecord()
    }

    @Synchronized
    override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> {
        return addresses.map { addr ->
            val key = "${addr.name}:${addr.deviceId}"
            val bytes = storage.getSignalStoreBlob(NS_SESSIONS, key)
                ?: throw org.signal.libsignal.protocol.NoSessionException("No session for $key")
            SessionRecord(bytes)
        }
    }

    @Synchronized
    override fun getSubDeviceSessions(name: String): List<Int> {
        val prefix = "$name:"
        return storage.getAllSignalStoreEntries(NS_SESSIONS).keys
            .filter { it.startsWith(prefix) }
            .mapNotNull { it.removePrefix(prefix).toIntOrNull() }
            .filter { it != 1 }
    }

    @Synchronized
    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        val key = "${address.name}:${address.deviceId}"
        storage.putSignalStoreBlob(NS_SESSIONS, key, record.serialize())
    }

    @Synchronized
    override fun containsSession(address: SignalProtocolAddress): Boolean {
        val key = "${address.name}:${address.deviceId}"
        val bytes = storage.getSignalStoreBlob(NS_SESSIONS, key) ?: return false
        return runCatching {
            val rec = SessionRecord(bytes)
            rec.hasSenderChain()
        }.getOrDefault(false)
    }

    @Synchronized
    override fun deleteSession(address: SignalProtocolAddress) {
        val key = "${address.name}:${address.deviceId}"
        storage.removeSignalStoreBlob(NS_SESSIONS, key)
    }

    @Synchronized
    override fun deleteAllSessions(name: String) {
        val prefix = "$name:"
        val keys = storage.getAllSignalStoreEntries(NS_SESSIONS).keys.filter { it.startsWith(prefix) }
        for (k in keys) {
            storage.removeSignalStoreBlob(NS_SESSIONS, k)
        }
    }

    @Synchronized
    override fun storeSenderKey(
        sender: SignalProtocolAddress,
        distributionId: UUID,
        record: org.signal.libsignal.protocol.groups.state.SenderKeyRecord
    ) {
        val key = "${sender.name}:${sender.deviceId}:$distributionId"
        storage.putSignalStoreBlob(NS_SENDER_KEYS, key, record.serialize())
    }

    @Synchronized
    override fun loadSenderKey(
        sender: SignalProtocolAddress,
        distributionId: UUID
    ): org.signal.libsignal.protocol.groups.state.SenderKeyRecord? {
        val key = "${sender.name}:${sender.deviceId}:$distributionId"
        val bytes = storage.getSignalStoreBlob(NS_SENDER_KEYS, key) ?: return null
        return org.signal.libsignal.protocol.groups.state.SenderKeyRecord(bytes)
    }

    fun getActiveSessionPeerIds(): List<String> {
        return storage.getAllSignalStoreEntries(NS_SESSIONS).keys.map { it.substringBefore(":") }.distinct()
    }
}
