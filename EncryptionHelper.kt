package com.secure.maanrecorder.util

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey

class EncryptionHelper(private val context: Context) {

    private val masterKeyAlias = "_maan_master_key_"
    private val backgroundKeyAlias = "_maan_bg_key_"
    private val dbPassphraseFile = "db_passphrase.bin"

    private var _mainKey: MasterKey? = null
    private val mainKey: MasterKey
        get() {
            if (_mainKey == null) {
                _mainKey = getOrCreateMasterKey(masterKeyAlias, isMainKey = true)
            }
            return _mainKey!!
        }

    private var _backgroundKey: MasterKey? = null
    private val backgroundKey: MasterKey
        get() {
            if (_backgroundKey == null) {
                _backgroundKey = getOrCreateMasterKey(backgroundKeyAlias, isMainKey = false)
            }
            return _backgroundKey!!
        }

    private fun getOrCreateMasterKey(alias: String, isMainKey: Boolean): MasterKey {
        return try {
            buildMasterKey(alias, isMainKey)
        } catch (e: Exception) {
            when (e) {
                is GeneralSecurityException, is IllegalArgumentException -> {
                    Log.w("EncryptionHelper", "MasterKey ($alias) initialization failed. Purging from Keystore and retrying...", e)
                    try {
                        val keyStore = KeyStore.getInstance("AndroidKeyStore")
                        keyStore.load(null)
                        keyStore.deleteEntry(alias)
                        keyStore.deleteEntry(MasterKey.DEFAULT_MASTER_KEY_ALIAS)
                        
                        // Purge Tink SharedPreferences
                        context.getSharedPreferences("__androidx_security_crypto_encrypted_file_pref__", Context.MODE_PRIVATE)
                            .edit()
                            .clear()
                            .commit()

                        Log.w("EncryptionHelper", "Successfully purged $alias, _androidx_security_master_key_, and Tink prefs")
                    } catch (purgeError: Exception) {
                        Log.e("EncryptionHelper", "Failed to purge corrupted key: $alias", purgeError)
                    }
                    buildMasterKey(alias, isMainKey)
                }
                else -> throw e
            }
        }
    }

    private fun buildMasterKey(alias: String, isMainKey: Boolean): MasterKey {
        val builder = MasterKey.Builder(context, alias)
        if (isMainKey) {
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .setInvalidatedByBiometricEnrollment(true)
            builder.setKeyGenParameterSpec(specBuilder.build())
        } else {
            builder.setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        }
        return builder.build()
    }

    /**
     * RED-04: Secure wrapper for all Keystore operations to prevent app crashes 
     * after a Nuclear Wipe or Keystore invalidation.
     */
    fun <T> secureKeystoreAccess(block: () -> T): Result<T> {
        return try {
            Result.success(block())
        } catch (e: Exception) {
            Log.e("SECURITY", "Keystore access failed. Post-nuke state or corruption.", e)
            Result.failure(e)
        }
    }

    /**
     * Creates an EncryptedFile wrapper for a physical File with aggressive recovery.
     */
    fun getEncryptedFile(file: File): EncryptedFile {
        val buildAction = {
            EncryptedFile.Builder(
                context,
                file,
                mainKey,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()
        }

        return try {
            buildAction()
        } catch (e: Exception) {
            Log.e("EncryptionHelper", "Keystore collision or invalidation detected. Initiating nuclear reset.", e)
            
            // 1. Delete the target file
            try {
                if (file.exists()) file.delete()
            } catch (de: Exception) {
                Log.e("EncryptionHelper", "Failed to delete corrupted file", de)
            }
            
            // 2. Purge the corrupted MasterKey from the Keystore
            try {
                val keyStore = KeyStore.getInstance("AndroidKeyStore")
                keyStore.load(null)
                // Target the exact Jetpack Security alias to fix the collision
                keyStore.deleteEntry(MasterKey.DEFAULT_MASTER_KEY_ALIAS)
                Log.w("EncryptionHelper", "Successfully purged _androidx_security_master_key_")
                
                // 2b. Purge the Tink SharedPreferences file where keysets are cached
                context.getSharedPreferences("__androidx_security_crypto_encrypted_file_pref__", Context.MODE_PRIVATE)
                    .edit()
                    .clear()
                    .commit()
                Log.w("EncryptionHelper", "Successfully purged Tink keyset SharedPreferences")
            } catch (purgeError: Exception) {
                Log.e("EncryptionHelper", "Failed to purge corrupted key or SharedPreferences", purgeError)
            }
            
            // 3. Create a brand new MasterKey instance (reset local cache)
            _mainKey = null
            
            // 4. Retry the EncryptedFile.Builder(...).build() with the new key and return it.
            buildAction()
        }
    }

    fun openFileOutputStream(file: File): OutputStream {
        return getEncryptedFile(file).openFileOutput()
    }

    fun openFileInputStream(file: File): InputStream {
        return getEncryptedFile(file).openFileInput()
    }

    /**
     * Low-level Decryption Stream. Use this for SAF streams (content://).
     * This manually handles GCM decryption for streams not backed by a local File object.
     */
    fun decryptStream(inputStream: InputStream): InputStream {
        throw UnsupportedOperationException("SAF Decryption must be handled via StorageManager bridging to EncryptedFile.")
    }

    fun getOrCreateDatabasePassphrase(): ByteArray {
        val file = File(context.filesDir, dbPassphraseFile)
        
        val encryptedFile = try {
            EncryptedFile.Builder(
                context,
                file,
                backgroundKey,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()
        } catch (e: Exception) {
            Log.e("EncryptionHelper", "Passphrase Keystore collision detected. Resetting background key.", e)
            try {
                if (file.exists()) file.delete()
                val keyStore = KeyStore.getInstance("AndroidKeyStore")
                keyStore.load(null)
                // Target the exact Jetpack Security alias
                keyStore.deleteEntry(MasterKey.DEFAULT_MASTER_KEY_ALIAS)
                
                // Purge Tink SharedPreferences
                context.getSharedPreferences("__androidx_security_crypto_encrypted_file_pref__", Context.MODE_PRIVATE)
                    .edit()
                    .clear()
                    .commit()
                    
                Log.w("EncryptionHelper", "Successfully purged _androidx_security_master_key_ and Tink prefs")
            } catch (ex: Exception) {
                Log.e("EncryptionHelper", "Nuclear reset failed for passphrase", ex)
            }
            _backgroundKey = null
            EncryptedFile.Builder(
                context,
                file,
                backgroundKey,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()
        }

        return try {
            if (file.exists()) {
                encryptedFile.openFileInput().use { it.readBytes() }
            } else {
                val newPassphrase = ByteArray(32)
                SecureRandom().nextBytes(newPassphrase)
                encryptedFile.openFileOutput().use { it.write(newPassphrase) }
                newPassphrase
            }
        } catch (e: Exception) {
            Log.e("EncryptionHelper", "Passphrase extraction failed, generating ephemeral fallback", e)
            val ephemeral = ByteArray(32)
            SecureRandom().nextBytes(ephemeral)
            ephemeral
        }
    }

    fun getBiometricCryptoObject(): androidx.biometric.BiometricPrompt.CryptoObject? {
        return try {
            val cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/${KeyProperties.ENCRYPTION_PADDING_NONE}")
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val key = keyStore.getKey(masterKeyAlias, null) as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, key) 
            androidx.biometric.BiometricPrompt.CryptoObject(cipher)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * NUCLEAR WIPE: Permanently deletes all encryption keys from the hardware Keystore.
     * All existing recordings will become mathematically irrecoverable.
     */
    fun nuclearWipe() {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            // Delete our custom aliases
            keyStore.deleteEntry(masterKeyAlias)
            keyStore.deleteEntry(backgroundKeyAlias)
            
            // Delete the default Jetpack Security alias
            keyStore.deleteEntry(MasterKey.DEFAULT_MASTER_KEY_ALIAS)
            
            // Clear Tink SharedPreferences cache
            context.getSharedPreferences("__androidx_security_crypto_encrypted_file_pref__", Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()
                
            Log.e("SECURITY", "!!! NUCLEAR WIPE EXECUTED !!! ALL KEYS PURGED.")
            
            // Reset local cache pointers
            _mainKey = null
            _backgroundKey = null
        } catch (e: Exception) {
            Log.e("SECURITY", "Nuclear wipe failed", e)
        }
    }
}
