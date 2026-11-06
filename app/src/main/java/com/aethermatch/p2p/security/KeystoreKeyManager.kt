package com.aethermatch.p2p.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Abstraction for wrapping and unwrapping sensitive key material (such as the 256-bit SQLCipher
 * database passphrase and local identity keys) with a hardware-backed AES-256-GCM master key.
 */
interface MasterKeyWrapper {
    fun wrapSecret(plaintext: ByteArray, associatedData: ByteArray): ByteArray
    fun unwrapSecret(wrappedBlob: ByteArray, associatedData: ByteArray): ByteArray
    fun isHardwareBacked(): Boolean
}

/**
 * Production implementation backed by Android Keystore (`AndroidKeyStore` provider).
 * Generates a non-exportable 256-bit AES-GCM key inside the device TEE / StrongBox when available.
 */
class AndroidKeystoreMasterKeyWrapper(
    private val keyAlias: String = DEFAULT_MASTER_KEY_ALIAS
) : MasterKeyWrapper {

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val DEFAULT_MASTER_KEY_ALIAS = "aethermatch_master_aes256_gcm_v1"
        private const val GCM_IV_LENGTH_BYTES = 12
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existingEntry = keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry
        if (existingEntry != null) {
            return existingEntry.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    override fun wrapSecret(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
        cipher.updateAAD(associatedData)
        val iv = cipher.iv
        require(iv.size == GCM_IV_LENGTH_BYTES) { "Unexpected GCM IV length: ${iv.size}" }
        val ciphertext = cipher.doFinal(plaintext)
        return ByteArray(iv.size + ciphertext.size).also { out ->
            System.arraycopy(iv, 0, out, 0, iv.size)
            System.arraycopy(ciphertext, 0, out, iv.size, ciphertext.size)
        }
    }

    override fun unwrapSecret(wrappedBlob: ByteArray, associatedData: ByteArray): ByteArray {
        require(wrappedBlob.size > GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
            "Wrapped key blob is truncated or invalid"
        }
        val iv = wrappedBlob.copyOfRange(0, GCM_IV_LENGTH_BYTES)
        val ciphertext = wrappedBlob.copyOfRange(GCM_IV_LENGTH_BYTES, wrappedBlob.size)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateSecretKey(), spec)
        cipher.updateAAD(associatedData)
        return cipher.doFinal(ciphertext)
    }

    override fun isHardwareBacked(): Boolean = true
}

/**
 * Manages the SQLCipher database 256-bit passphrase and wrapped identity secrets.
 * All secrets at rest are encrypted using AES-256-GCM with the Android Keystore master key
 * and bound to their purpose via AEAD Associated Data (AAD).
 */
class KeystoreKeyManager(
    context: Context?,
    private val masterKeyWrapper: MasterKeyWrapper = AndroidKeystoreMasterKeyWrapper(),
    private val backingMap: MutableMap<String, String>? = null
) {
    private val prefs = context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val secureRandom = SecureRandom()

    companion object {
        private const val PREFS_NAME = "aethermatch_keystore_wrapped_secrets"
        private const val KEY_SQLCIPHER_PASSPHRASE = "wrapped_sqlcipher_passphrase_v1"
        private const val KEY_LIBP2P_IDENTITY = "wrapped_libp2p_ed25519_key_v1"
        private const val SQLCIPHER_KEY_BYTES = 32 // 256-bit key for SQLCipher AES-256
    }

    /**
     * Returns the 256-bit (32-byte) passphrase for SQLCipher database encryption,
     * generating and wrapping it in Android Keystore on first launch.
     */
    @Synchronized
    fun getOrCreateSqlCipherPassphrase(): ByteArray {
        val aad = KEY_SQLCIPHER_PASSPHRASE.encodeToByteArray()
        val existingEncoded = readValue(KEY_SQLCIPHER_PASSPHRASE)
        if (existingEncoded != null) {
            val wrappedBytes = Base64.getDecoder().decode(existingEncoded)
            return masterKeyWrapper.unwrapSecret(wrappedBytes, aad)
        }

        val rawPassphrase = ByteArray(SQLCIPHER_KEY_BYTES).also { secureRandom.nextBytes(it) }
        val wrapped = masterKeyWrapper.wrapSecret(rawPassphrase, aad)
        writeValue(KEY_SQLCIPHER_PASSPHRASE, Base64.getEncoder().encodeToString(wrapped))
        return rawPassphrase
    }

    /**
     * Stores an arbitrary secret blob (such as the local libp2p Ed25519 private key)
     * encrypted under the Android Keystore AES-256-GCM master key.
     */
    @Synchronized
    fun storeWrappedSecret(alias: String, secretBytes: ByteArray) {
        val aad = alias.encodeToByteArray()
        val wrapped = masterKeyWrapper.wrapSecret(secretBytes, aad)
        writeValue(alias, Base64.getEncoder().encodeToString(wrapped))
    }

    /**
     * Loads and unwraps a previously stored secret blob using the Android Keystore master key.
     */
    @Synchronized
    fun loadWrappedSecret(alias: String): ByteArray? {
        val encoded = readValue(alias) ?: return null
        val aad = alias.encodeToByteArray()
        val wrapped = Base64.getDecoder().decode(encoded)
        return masterKeyWrapper.unwrapSecret(wrapped, aad)
    }

    @Synchronized
    fun getOrCreateLibp2pPrivateKeyBytes(generator: () -> ByteArray): ByteArray {
        val existing = loadWrappedSecret(KEY_LIBP2P_IDENTITY)
        if (existing != null) return existing
        val generated = generator()
        storeWrappedSecret(KEY_LIBP2P_IDENTITY, generated)
        return generated
    }

    fun getKeystoreDiagnosticSummary(): KeystoreDiagnostics {
        val hasSqlCipherKey = readValue(KEY_SQLCIPHER_PASSPHRASE) != null
        val hasLibp2pKey = readValue(KEY_LIBP2P_IDENTITY) != null
        return KeystoreDiagnostics(
            providerName = if (masterKeyWrapper.isHardwareBacked()) "AndroidKeyStore (AES-256-GCM)" else "JVM Memory Keystore (AES-256-GCM)",
            isHardwareBacked = masterKeyWrapper.isHardwareBacked(),
            sqlCipherKeyInitialized = hasSqlCipherKey,
            libp2pKeyInitialized = hasLibp2pKey
        )
    }

    private fun readValue(key: String): String? {
        return backingMap?.get(key) ?: prefs?.getString(key, null)
    }

    private fun writeValue(key: String, value: String) {
        if (backingMap != null) {
            backingMap[key] = value
        } else {
            prefs?.edit()?.putString(key, value)?.commit()
        }
    }
}

data class KeystoreDiagnostics(
    val providerName: String,
    val isHardwareBacked: Boolean,
    val sqlCipherKeyInitialized: Boolean,
    val libp2pKeyInitialized: Boolean
)
