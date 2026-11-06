package com.aethermatch.p2p.storage

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import com.aethermatch.p2p.model.ChatMessage
import com.aethermatch.p2p.model.DiscoveredProfile
import com.aethermatch.p2p.model.DiscoverySource
import com.aethermatch.p2p.model.FederatedRoundRecord
import com.aethermatch.p2p.model.MatchRecord
import com.aethermatch.p2p.model.RelationshipGoal
import com.aethermatch.p2p.model.SignedPeerProfileAnnouncement
import com.aethermatch.p2p.model.SwipeRecord
import com.aethermatch.p2p.model.UserProfile
import com.aethermatch.p2p.security.KeystoreKeyManager
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.io.File
import java.util.Base64

data class SqlCipherStatusReport(
    val databaseFileName: String,
    val cipherVersion: String,
    val isHeaderEncryptedOnDisk: Boolean,
    val first16BytesHex: String,
    val totalEncryptedTables: Int
)

interface EncryptedStorageRepository {
    fun saveLocalUserProfile(profile: UserProfile)
    fun getLocalUserProfile(): UserProfile?

    fun upsertDiscoveredProfile(profile: DiscoveredProfile)
    fun getAllDiscoveredProfiles(): List<DiscoveredProfile>

    fun recordSwipe(swipe: SwipeRecord)
    fun getAllSwipes(): List<SwipeRecord>
    fun getUntrainedSwipes(): List<SwipeRecord>
    fun markSwipesTrained(roundId: Long)

    fun saveMatch(match: MatchRecord)
    fun getAllMatches(): List<MatchRecord>

    fun saveChatMessage(message: ChatMessage)
    fun getChatMessagesForPeer(peerId: String): List<ChatMessage>

    fun saveFederatedRound(round: FederatedRoundRecord)
    fun getAllFederatedRounds(): List<FederatedRoundRecord>

    fun putSignalStoreBlob(namespace: String, key: String, value: ByteArray)
    fun getSignalStoreBlob(namespace: String, key: String): ByteArray?
    fun getAllSignalStoreEntries(namespace: String): Map<String, ByteArray>
    fun removeSignalStoreBlob(namespace: String, key: String)

    fun saveModelWeights(modelKey: String, weights: FloatArray)
    fun loadModelWeights(modelKey: String): FloatArray?

    fun getSqlCipherStatusReport(): SqlCipherStatusReport
}

/**
 * Production SQLCipher-encrypted database manager using `net.zetetic:sqlcipher-android`
 * (`SupportOpenHelperFactory`) and a 256-bit key unwrapped from `AndroidKeyStore`.
 */
class SqlCipherDatabaseManager(
    private val context: Context,
    private val keystoreKeyManager: KeystoreKeyManager
) : EncryptedStorageRepository {

    companion object {
        const val DATABASE_NAME = "aethermatch_encrypted_v1.db"
        private const val DATABASE_VERSION = 1
        private val PLAINTEXT_SQLITE_HEADER = "SQLite format 3\u0000".encodeToByteArray()
    }

    private val gson = Gson()
    private val dbHelper: SupportSQLiteOpenHelper by lazy {
        System.loadLibrary("sqlcipher")
        val passphraseBytes = keystoreKeyManager.getOrCreateSqlCipherPassphrase()
        try {
            val factory = SupportOpenHelperFactory(passphraseBytes)
            val config = SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(DATABASE_NAME)
                .callback(object : SupportSQLiteOpenHelper.Callback(DATABASE_VERSION) {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        createSchema(db)
                    }

                    override fun onUpgrade(
                        db: SupportSQLiteDatabase,
                        oldVersion: Int,
                        newVersion: Int
                    ) {
                        // Schema v1
                    }
                })
                .build()
            factory.create(config)
        } finally {
            // Zero out raw passphrase copy after passing to SQLCipher factory
            passphraseBytes.fill(0)
        }
    }

    private val db: SupportSQLiteDatabase
        get() = dbHelper.writableDatabase

    private fun createSchema(db: SupportSQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS local_profile (
                peer_id TEXT PRIMARY KEY NOT NULL,
                json_payload TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS discovered_profiles (
                peer_id TEXT PRIMARY KEY NOT NULL,
                announcement_json TEXT NOT NULL,
                compatibility_score REAL NOT NULL,
                explanation_json TEXT NOT NULL,
                signature_verified INTEGER NOT NULL,
                discovered_via TEXT NOT NULL,
                swiped INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS swipe_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id TEXT NOT NULL,
                liked INTEGER NOT NULL,
                features_json TEXT NOT NULL,
                compatibility_at_swipe REAL NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                trained_in_round INTEGER
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS matches (
                peer_id TEXT PRIMARY KEY NOT NULL,
                display_name TEXT NOT NULL,
                age INTEGER NOT NULL,
                bio TEXT NOT NULL,
                interests_json TEXT NOT NULL,
                safety_number TEXT NOT NULL,
                matched_at_ms INTEGER NOT NULL,
                last_message_preview TEXT NOT NULL,
                last_activity_ms INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS chat_messages (
                message_id TEXT PRIMARY KEY NOT NULL,
                conversation_peer_id TEXT NOT NULL,
                sender_peer_id TEXT NOT NULL,
                plaintext_body TEXT NOT NULL,
                ciphertext_hex_preview TEXT NOT NULL,
                signal_message_type TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                verified_authentic INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS federated_rounds (
                round_id INTEGER PRIMARY KEY NOT NULL,
                json_payload TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS signal_kv_store (
                namespace TEXT NOT NULL,
                store_key TEXT NOT NULL,
                blob_value BLOB NOT NULL,
                PRIMARY KEY (namespace, store_key)
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS model_weights_store (
                model_key TEXT PRIMARY KEY NOT NULL,
                weights_json TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }

    @Synchronized
    override fun saveLocalUserProfile(profile: UserProfile) {
        db.execSQL("DELETE FROM local_profile")
        val cv = ContentValues().apply {
            put("peer_id", profile.peerId)
            put("json_payload", gson.toJson(profile))
            put("updated_at", profile.updatedAtEpochMs)
        }
        db.insert("local_profile", SQLiteDatabase.CONFLICT_REPLACE, cv)
    }

    @Synchronized
    override fun getLocalUserProfile(): UserProfile? {
        db.query("SELECT json_payload FROM local_profile LIMIT 1").use { cursor ->
            if (cursor.moveToFirst()) {
                return gson.fromJson(cursor.getString(0), UserProfile::class.java)
            }
        }
        return null
    }

    @Synchronized
    override fun upsertDiscoveredProfile(profile: DiscoveredProfile) {
        val cv = ContentValues().apply {
            put("peer_id", profile.announcement.peerId)
            put("announcement_json", gson.toJson(profile.announcement))
            put("compatibility_score", profile.localCompatibilityScore.toDouble())
            put("explanation_json", gson.toJson(profile.compatibilityExplanation))
            put("signature_verified", if (profile.signatureVerified) 1 else 0)
            put("discovered_via", profile.discoveredVia.name)
            put("swiped", if (profile.swiped) 1 else 0)
        }
        db.insert("discovered_profiles", SQLiteDatabase.CONFLICT_REPLACE, cv)
    }

    @Synchronized
    override fun getAllDiscoveredProfiles(): List<DiscoveredProfile> {
        val list = mutableListOf<DiscoveredProfile>()
        val listType = object : TypeToken<List<String>>() {}.type
        db.query("SELECT announcement_json, compatibility_score, explanation_json, signature_verified, discovered_via, swiped FROM discovered_profiles ORDER BY compatibility_score DESC").use { c ->
            while (c.moveToNext()) {
                val announcement = gson.fromJson(c.getString(0), SignedPeerProfileAnnouncement::class.java)
                val score = c.getFloat(1)
                val explanation: List<String> = gson.fromJson(c.getString(2), listType)
                val verified = c.getInt(3) == 1
                val source = runCatching { DiscoverySource.valueOf(c.getString(4)) }
                    .getOrDefault(DiscoverySource.KADEMLIA_DHT)
                val swiped = c.getInt(5) == 1
                list.add(
                    DiscoveredProfile(
                        announcement = announcement,
                        localCompatibilityScore = score,
                        compatibilityExplanation = explanation,
                        signatureVerified = verified,
                        discoveredVia = source,
                        swiped = swiped
                    )
                )
            }
        }
        return list
    }

    @Synchronized
    override fun recordSwipe(swipe: SwipeRecord) {
        val cv = ContentValues().apply {
            put("peer_id", swipe.peerId)
            put("liked", if (swipe.liked) 1 else 0)
            put("features_json", gson.toJson(swipe.encodedFeatures))
            put("compatibility_at_swipe", swipe.compatibilityAtSwipe.toDouble())
            put("timestamp_ms", swipe.timestampEpochMs)
            if (swipe.trainedInRound != null) {
                put("trained_in_round", swipe.trainedInRound)
            }
        }
        db.insert("swipe_records", SQLiteDatabase.CONFLICT_REPLACE, cv)
        db.execSQL("UPDATE discovered_profiles SET swiped = 1 WHERE peer_id = ?", arrayOf(swipe.peerId))
    }

    @Synchronized
    override fun getAllSwipes(): List<SwipeRecord> {
        val list = mutableListOf<SwipeRecord>()
        db.query("SELECT peer_id, liked, features_json, compatibility_at_swipe, timestamp_ms, trained_in_round FROM swipe_records ORDER BY timestamp_ms ASC").use { c ->
            while (c.moveToNext()) {
                val trainedRound = if (c.isNull(5)) null else c.getLong(5)
                list.add(
                    SwipeRecord(
                        peerId = c.getString(0),
                        liked = c.getInt(1) == 1,
                        encodedFeatures = gson.fromJson(c.getString(2), FloatArray::class.java),
                        compatibilityAtSwipe = c.getFloat(3),
                        timestampEpochMs = c.getLong(4),
                        trainedInRound = trainedRound
                    )
                )
            }
        }
        return list
    }

    @Synchronized
    override fun getUntrainedSwipes(): List<SwipeRecord> {
        return getAllSwipes().filter { it.trainedInRound == null }
    }

    @Synchronized
    override fun markSwipesTrained(roundId: Long) {
        db.execSQL("UPDATE swipe_records SET trained_in_round = ? WHERE trained_in_round IS NULL", arrayOf(roundId))
    }

    @Synchronized
    override fun saveMatch(match: MatchRecord) {
        val cv = ContentValues().apply {
            put("peer_id", match.peerId)
            put("display_name", match.displayName)
            put("age", match.age)
            put("bio", match.bio)
            put("interests_json", gson.toJson(match.interests))
            put("safety_number", match.safetyNumberFingerprint)
            put("matched_at_ms", match.matchedAtEpochMs)
            put("last_message_preview", match.lastMessagePreview)
            put("last_activity_ms", match.lastActivityEpochMs)
        }
        db.insert("matches", SQLiteDatabase.CONFLICT_REPLACE, cv)
    }

    @Synchronized
    override fun getAllMatches(): List<MatchRecord> {
        val list = mutableListOf<MatchRecord>()
        val listType = object : TypeToken<List<String>>() {}.type
        db.query("SELECT peer_id, display_name, age, bio, interests_json, safety_number, matched_at_ms, last_message_preview, last_activity_ms FROM matches ORDER BY last_activity_ms DESC").use { c ->
            while (c.moveToNext()) {
                list.add(
                    MatchRecord(
                        peerId = c.getString(0),
                        displayName = c.getString(1),
                        age = c.getInt(2),
                        bio = c.getString(3),
                        interests = gson.fromJson(c.getString(4), listType),
                        safetyNumberFingerprint = c.getString(5),
                        matchedAtEpochMs = c.getLong(6),
                        lastMessagePreview = c.getString(7),
                        lastActivityEpochMs = c.getLong(8)
                    )
                )
            }
        }
        return list
    }

    @Synchronized
    override fun saveChatMessage(message: ChatMessage) {
        val cv = ContentValues().apply {
            put("message_id", message.messageId)
            put("conversation_peer_id", message.conversationPeerId)
            put("sender_peer_id", message.senderPeerId)
            put("plaintext_body", message.plaintextBody)
            put("ciphertext_hex_preview", message.ciphertextHexPreview)
            put("signal_message_type", message.signalMessageType)
            put("timestamp_ms", message.timestampEpochMs)
            put("verified_authentic", if (message.verifiedAuthentic) 1 else 0)
        }
        db.insert("chat_messages", SQLiteDatabase.CONFLICT_REPLACE, cv)
        db.execSQL(
            "UPDATE matches SET last_message_preview = ?, last_activity_ms = ? WHERE peer_id = ?",
            arrayOf(message.plaintextBody, message.timestampEpochMs, message.conversationPeerId)
        )
    }

    @Synchronized
    override fun getChatMessagesForPeer(peerId: String): List<ChatMessage> {
        val list = mutableListOf<ChatMessage>()
        db.query(
            "SELECT message_id, conversation_peer_id, sender_peer_id, plaintext_body, ciphertext_hex_preview, signal_message_type, timestamp_ms, verified_authentic FROM chat_messages WHERE conversation_peer_id = ? ORDER BY timestamp_ms ASC",
            arrayOf(peerId)
        ).use { c ->
            while (c.moveToNext()) {
                list.add(
                    ChatMessage(
                        messageId = c.getString(0),
                        conversationPeerId = c.getString(1),
                        senderPeerId = c.getString(2),
                        plaintextBody = c.getString(3),
                        ciphertextHexPreview = c.getString(4),
                        signalMessageType = c.getString(5),
                        timestampEpochMs = c.getLong(6),
                        verifiedAuthentic = c.getInt(7) == 1
                    )
                )
            }
        }
        return list
    }

    @Synchronized
    override fun saveFederatedRound(round: FederatedRoundRecord) {
        val cv = ContentValues().apply {
            put("round_id", round.roundId)
            put("json_payload", gson.toJson(round))
            put("timestamp_ms", round.timestampEpochMs)
        }
        db.insert("federated_rounds", SQLiteDatabase.CONFLICT_REPLACE, cv)
    }

    @Synchronized
    override fun getAllFederatedRounds(): List<FederatedRoundRecord> {
        val list = mutableListOf<FederatedRoundRecord>()
        db.query("SELECT json_payload FROM federated_rounds ORDER BY round_id DESC").use { c ->
            while (c.moveToNext()) {
                list.add(gson.fromJson(c.getString(0), FederatedRoundRecord::class.java))
            }
        }
        return list
    }

    @Synchronized
    override fun putSignalStoreBlob(namespace: String, key: String, value: ByteArray) {
        val cv = ContentValues().apply {
            put("namespace", namespace)
            put("store_key", key)
            put("blob_value", value)
        }
        db.insert("signal_kv_store", SQLiteDatabase.CONFLICT_REPLACE, cv)
    }

    @Synchronized
    override fun getSignalStoreBlob(namespace: String, key: String): ByteArray? {
        db.query(
            "SELECT blob_value FROM signal_kv_store WHERE namespace = ? AND store_key = ?",
            arrayOf(namespace, key)
        ).use { c ->
            if (c.moveToFirst()) {
                return c.getBlob(0)
            }
        }
        return null
    }

    @Synchronized
    override fun getAllSignalStoreEntries(namespace: String): Map<String, ByteArray> {
        val result = mutableMapOf<String, ByteArray>()
        db.query(
            "SELECT store_key, blob_value FROM signal_kv_store WHERE namespace = ?",
            arrayOf(namespace)
        ).use { c ->
            while (c.moveToNext()) {
                result[c.getString(0)] = c.getBlob(1)
            }
        }
        return result
    }

    @Synchronized
    override fun removeSignalStoreBlob(namespace: String, key: String) {
        db.execSQL(
            "DELETE FROM signal_kv_store WHERE namespace = ? AND store_key = ?",
            arrayOf(namespace, key)
        )
    }

    @Synchronized
    override fun saveModelWeights(modelKey: String, weights: FloatArray) {
        val cv = ContentValues().apply {
            put("model_key", modelKey)
            put("weights_json", gson.toJson(weights))
            put("updated_at_ms", System.currentTimeMillis())
        }
        db.insert("model_weights_store", SQLiteDatabase.CONFLICT_REPLACE, cv)
    }

    @Synchronized
    override fun loadModelWeights(modelKey: String): FloatArray? {
        db.query(
            "SELECT weights_json FROM model_weights_store WHERE model_key = ?",
            arrayOf(modelKey)
        ).use { c ->
            if (c.moveToFirst()) {
                return gson.fromJson(c.getString(0), FloatArray::class.java)
            }
        }
        return null
    }

    @Synchronized
    override fun getSqlCipherStatusReport(): SqlCipherStatusReport {
        // Ensure DB is initialized
        val activeDb = db
        var cipherVer = "SQLCipher 4 (AES-256-CBC / HMAC-SHA512)"
        runCatching {
            activeDb.query("PRAGMA cipher_version;").use { c ->
                if (c.moveToFirst()) {
                    cipherVer = "SQLCipher ${c.getString(0)} (AES-256)"
                }
            }
        }

        val dbFile: File = context.getDatabasePath(DATABASE_NAME)
        val headerBytes = ByteArray(16)
        var bytesRead = 0
        if (dbFile.exists() && dbFile.length() >= 16) {
            dbFile.inputStream().use { fis ->
                bytesRead = fis.read(headerBytes)
            }
        }
        val isPlaintextSqlite = bytesRead == 16 && headerBytes.contentEquals(PLAINTEXT_SQLITE_HEADER)
        val hexPreview = if (bytesRead > 0) {
            headerBytes.joinToString("") { "%02x".format(it) }
        } else {
            "uninitialized"
        }

        return SqlCipherStatusReport(
            databaseFileName = DATABASE_NAME,
            cipherVersion = cipherVer,
            isHeaderEncryptedOnDisk = bytesRead == 16 && !isPlaintextSqlite,
            first16BytesHex = hexPreview,
            totalEncryptedTables = 8
        )
    }
}
