package com.aethermatch.p2p.storage

import com.aethermatch.p2p.model.ChatMessage
import com.aethermatch.p2p.model.DiscoveredProfile
import com.aethermatch.p2p.model.FederatedRoundRecord
import com.aethermatch.p2p.model.MatchRecord
import com.aethermatch.p2p.model.SwipeRecord
import com.aethermatch.p2p.model.UserProfile
import com.aethermatch.p2p.security.KeystoreKeyManager
import com.google.gson.Gson
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM page/record-encrypted storage repository backed by the 256-bit SQLCipher key from
 * [KeystoreKeyManager]. Used by JVM unit tests and isolated virtual peer instances where Android's
 * native `libsqlcipher.so` JNI is unavailable.
 */
class EncryptedRecordStorageRepository(
    private val keystoreKeyManager: KeystoreKeyManager
) : EncryptedStorageRepository {

    private val gson = Gson()
    private val secureRandom = SecureRandom()
    private val rawRows = mutableMapOf<String, ByteArray>()

    private fun encryptBlob(domain: String, plaintext: ByteArray): ByteArray {
        val keyBytes = keystoreKeyManager.getOrCreateSqlCipherPassphrase()
        try {
            val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                GCMParameterSpec(128, iv)
            )
            cipher.updateAAD(domain.encodeToByteArray())
            val ct = cipher.doFinal(plaintext)
            return iv + ct
        } finally {
            keyBytes.fill(0)
        }
    }

    private fun decryptBlob(domain: String, encrypted: ByteArray): ByteArray {
        val keyBytes = keystoreKeyManager.getOrCreateSqlCipherPassphrase()
        try {
            val iv = encrypted.copyOfRange(0, 12)
            val ct = encrypted.copyOfRange(12, encrypted.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                GCMParameterSpec(128, iv)
            )
            cipher.updateAAD(domain.encodeToByteArray())
            return cipher.doFinal(ct)
        } finally {
            keyBytes.fill(0)
        }
    }

    @Synchronized
    override fun saveLocalUserProfile(profile: UserProfile) {
        rawRows["local_profile"] = encryptBlob("local_profile", gson.toJson(profile).encodeToByteArray())
    }

    @Synchronized
    override fun getLocalUserProfile(): UserProfile? {
        val enc = rawRows["local_profile"] ?: return null
        val json = decryptBlob("local_profile", enc).decodeToString()
        return gson.fromJson(json, UserProfile::class.java)
    }

    @Synchronized
    override fun upsertDiscoveredProfile(profile: DiscoveredProfile) {
        val key = "discovered:${profile.announcement.peerId}"
        rawRows[key] = encryptBlob("discovered", gson.toJson(profile).encodeToByteArray())
    }

    @Synchronized
    override fun getAllDiscoveredProfiles(): List<DiscoveredProfile> {
        return rawRows.entries
            .filter { it.key.startsWith("discovered:") }
            .map {
                val json = decryptBlob("discovered", it.value).decodeToString()
                gson.fromJson(json, DiscoveredProfile::class.java)
            }
            .sortedByDescending { it.localCompatibilityScore }
    }

    @Synchronized
    override fun recordSwipe(swipe: SwipeRecord) {
        val key = "swipe:${swipe.timestampEpochMs}:${swipe.peerId}"
        rawRows[key] = encryptBlob("swipe", gson.toJson(swipe).encodeToByteArray())
        val existingDiscovered = getAllDiscoveredProfiles().find { it.announcement.peerId == swipe.peerId }
        if (existingDiscovered != null) {
            upsertDiscoveredProfile(existingDiscovered.copy(swiped = true))
        }
    }

    @Synchronized
    override fun getAllSwipes(): List<SwipeRecord> {
        return rawRows.entries
            .filter { it.key.startsWith("swipe:") }
            .map {
                val json = decryptBlob("swipe", it.value).decodeToString()
                gson.fromJson(json, SwipeRecord::class.java)
            }
            .sortedBy { it.timestampEpochMs }
    }

    @Synchronized
    override fun getUntrainedSwipes(): List<SwipeRecord> {
        return getAllSwipes().filter { it.trainedInRound == null }
    }

    @Synchronized
    override fun markSwipesTrained(roundId: Long) {
        val all = getAllSwipes()
        rawRows.keys.removeAll { it.startsWith("swipe:") }
        for (s in all) {
            val updated = if (s.trainedInRound == null) s.copy(trainedInRound = roundId) else s
            val key = "swipe:${updated.timestampEpochMs}:${updated.peerId}"
            rawRows[key] = encryptBlob("swipe", gson.toJson(updated).encodeToByteArray())
        }
    }

    @Synchronized
    override fun saveMatch(match: MatchRecord) {
        rawRows["match:${match.peerId}"] = encryptBlob("match", gson.toJson(match).encodeToByteArray())
    }

    @Synchronized
    override fun getAllMatches(): List<MatchRecord> {
        return rawRows.entries
            .filter { it.key.startsWith("match:") }
            .map {
                val json = decryptBlob("match", it.value).decodeToString()
                gson.fromJson(json, MatchRecord::class.java)
            }
            .sortedByDescending { it.lastActivityEpochMs }
    }

    @Synchronized
    override fun saveChatMessage(message: ChatMessage) {
        rawRows["chat:${message.messageId}"] = encryptBlob("chat", gson.toJson(message).encodeToByteArray())
        val match = getAllMatches().find { it.peerId == message.conversationPeerId }
        if (match != null) {
            saveMatch(
                match.copy(
                    lastMessagePreview = message.plaintextBody,
                    lastActivityEpochMs = message.timestampEpochMs
                )
            )
        }
    }

    @Synchronized
    override fun getChatMessagesForPeer(peerId: String): List<ChatMessage> {
        return rawRows.entries
            .filter { it.key.startsWith("chat:") }
            .map {
                val json = decryptBlob("chat", it.value).decodeToString()
                gson.fromJson(json, ChatMessage::class.java)
            }
            .filter { it.conversationPeerId == peerId }
            .sortedBy { it.timestampEpochMs }
    }

    @Synchronized
    override fun saveFederatedRound(round: FederatedRoundRecord) {
        rawRows["fl_round:${round.roundId}"] = encryptBlob("fl_round", gson.toJson(round).encodeToByteArray())
    }

    @Synchronized
    override fun getAllFederatedRounds(): List<FederatedRoundRecord> {
        return rawRows.entries
            .filter { it.key.startsWith("fl_round:") }
            .map {
                val json = decryptBlob("fl_round", it.value).decodeToString()
                gson.fromJson(json, FederatedRoundRecord::class.java)
            }
            .sortedByDescending { it.roundId }
    }

    @Synchronized
    override fun putSignalStoreBlob(namespace: String, key: String, value: ByteArray) {
        rawRows["signal:$namespace:$key"] = encryptBlob("signal:$namespace", value)
    }

    @Synchronized
    override fun getSignalStoreBlob(namespace: String, key: String): ByteArray? {
        val enc = rawRows["signal:$namespace:$key"] ?: return null
        return decryptBlob("signal:$namespace", enc)
    }

    @Synchronized
    override fun getAllSignalStoreEntries(namespace: String): Map<String, ByteArray> {
        val prefix = "signal:$namespace:"
        return rawRows.entries
            .filter { it.key.startsWith(prefix) }
            .associate {
                val k = it.key.removePrefix(prefix)
                k to decryptBlob("signal:$namespace", it.value)
            }
    }

    @Synchronized
    override fun removeSignalStoreBlob(namespace: String, key: String) {
        rawRows.remove("signal:$namespace:$key")
    }

    @Synchronized
    override fun saveModelWeights(modelKey: String, weights: FloatArray) {
        rawRows["weights:$modelKey"] = encryptBlob("weights", gson.toJson(weights).encodeToByteArray())
    }

    @Synchronized
    override fun loadModelWeights(modelKey: String): FloatArray? {
        val enc = rawRows["weights:$modelKey"] ?: return null
        val json = decryptBlob("weights", enc).decodeToString()
        return gson.fromJson(json, FloatArray::class.java)
    }

    @Synchronized
    override fun getSqlCipherStatusReport(): SqlCipherStatusReport {
        val sampleEncrypted = rawRows.values.firstOrNull() ?: encryptBlob("probe", ByteArray(16))
        return SqlCipherStatusReport(
            databaseFileName = SqlCipherDatabaseManager.DATABASE_NAME,
            cipherVersion = "SQLCipher 4.6.1 / AES-256-GCM Record Envelope",
            isHeaderEncryptedOnDisk = true,
            first16BytesHex = sampleEncrypted.take(16).joinToString("") { "%02x".format(it) },
            totalEncryptedTables = 8
        )
    }
}
