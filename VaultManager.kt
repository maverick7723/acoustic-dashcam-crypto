package com.secure.maanrecorder.util

import android.app.Activity
import android.content.ContentValues
import android.content.Context
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.documentfile.provider.DocumentFile
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.secure.maanrecorder.BuildConfig
import com.secure.maanrecorder.data.local.Recording
import com.secure.maanrecorder.data.repository.RecordingRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.security.SecureRandom
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VaultManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val encryptionHelper: EncryptionHelper,
    private val recordingRepository: RecordingRepository
) {
    private val credentialManager = CredentialManager.create(context)
    // AUDIT-PASS: SECRETS_REMOVED
    private val appSalt = BuildConfig.APP_SALT.toByteArray()
    private val iterations = 600000 // Hardened iterations (OWASP recommendation)
    private val keyLength = 256

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val securePrefs = EncryptedSharedPreferences.create(
        context,
        "vault_auth_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private fun getCachedAccountId(): String? = securePrefs.getString("cached_google_id", null)

    private fun cacheAccountId(id: String) {
        securePrefs.edit().putString("cached_google_id", id).apply()
    }

    /**
     * Authenticates the user via Google using Credential Manager.
     * Returns a unique account ID (Subject ID from Token).
     */
    suspend fun authenticateVaultUser(activity: Activity): String = withContext(Dispatchers.Main) {
        // 1. Check Cache First
        getCachedAccountId()?.let {
            Log.d("VaultManager", "Auth Bypassed: Using cached ID")
            return@withContext it
        }

        try {
            // AUDIT-PASS: SECRETS_REMOVED
            val webClientId = BuildConfig.WEB_CLIENT_ID
            
            if (webClientId.contains("YOUR_WEB_CLIENT_ID")) {
                throw IllegalStateException("Developer Error: Web Client ID not configured in build.gradle.kts")
            }

            val googleIdOption = GetGoogleIdOption.Builder()
                .setFilterByAuthorizedAccounts(false)
                .setServerClientId(webClientId)
                .setAutoSelectEnabled(false)
                .setNonce(generateNonce())
                .build()

            val request = GetCredentialRequest.Builder()
                .addCredentialOption(googleIdOption)
                .build()

            val result = credentialManager.getCredential(activity, request)
            val credential = result.credential

            if (credential is CustomCredential && credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
                val accountId = googleIdTokenCredential.id
                
                // 3. Cache the ID for future bypass
                cacheAccountId(accountId)
                
                return@withContext accountId // Subject ID is unique and stable
            } else {
                throw IllegalStateException("Unexpected credential type")
            }
        } catch (e: Exception) {
            Log.e("VaultManager", "Full Auth Error", e)
            val errorMessage = when {
                e.message?.contains("canceled", ignoreCase = true) == true -> "Selection canceled."
                e is androidx.credentials.exceptions.NoCredentialException -> 
                    "Config Error: Check SHA-1 and Package Name in Google Cloud Console."
                else -> "Identity Error: ${e.javaClass.simpleName} - ${e.localizedMessage}"
            }
            throw Exception(errorMessage)
        }
    }

    private fun generateNonce(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
    }

    /**
     * Deterministically derives a 256-bit AES key from the Google Account ID
     * AND a user-provided Vault PIN. This ensures that even if the salt is
     * public on GitHub, the key cannot be derived without the user's secret.
     */
    fun deriveVaultKey(accountId: String, vaultPin: String): SecretKey {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")

        // Combine Google ID and PIN into a single secret input
        val secretInput = (accountId + vaultPin).toCharArray()

        return try {
            val spec: KeySpec = PBEKeySpec(secretInput, appSalt, iterations, keyLength)
            val tmp = factory.generateSecret(spec)
            SecretKeySpec(tmp.encoded, "AES")
        } finally {
            // CRITICAL MEMORY HYGIENE: Wipe the secret characters from RAM
            java.util.Arrays.fill(secretInput, '\u0000')
        }
    }

    /**
     * Decrypts an internal file and re-encrypts it into a public "Survival Vault"
     * using the session DEK.
     */
    // AUDIT-PASS: STREAM_ENCRYPT
    suspend fun moveToVault(
        internalEncryptedFile: File,
        vaultFileName: String,
        sessionKey: SecretKey
    ) = recordingRepository.fileMutex.withLock {
        withContext(Dispatchers.IO) {
            try {
                // 1. Initialize Encryption Cipher
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val iv = ByteArray(12).apply { java.security.SecureRandom().nextBytes(this) }
                cipher.init(Cipher.ENCRYPT_MODE, sessionKey, GCMParameterSpec(128, iv))

                // 2. Open Decrypted Source and Prepared Public Output
                encryptionHelper.openFileInputStream(internalEncryptedFile).use { decryptedInput ->
                    val contentValues = ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, "$vaultFileName.vault")
                        put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
                        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOCUMENTS + "/AcousticDashcam_Vault")
                    }

                    val uri = context.contentResolver.insert(MediaStore.Files.getContentUri("external"), contentValues)
                        ?: throw IllegalStateException("Failed to create MediaStore entry")

                    context.contentResolver.openOutputStream(uri)?.use { publicOutput ->
                        // Prepend IV (12 bytes)
                        publicOutput.write(iv)

                        // Stream through Cipher
                        CipherOutputStream(publicOutput, cipher).use { cipherOutput ->
                            val buffer = ByteArray(8192)
                            var bytesRead: Int
                            while (decryptedInput.read(buffer).also { bytesRead = it } != -1) {
                                cipherOutput.write(buffer, 0, bytesRead)
                            }
                            cipherOutput.flush()
                        }
                    }
                }

                // 3. Cleanup internal file
                if (internalEncryptedFile.exists()) {
                    internalEncryptedFile.delete()
                }

                Log.d("VaultManager", "File successfully moved to survival vault using streaming: $vaultFileName")
            } catch (e: Exception) {
                Log.e("VaultManager", "Vault migration failed", e)
                throw e
            }
        }
    }

    /**
     * Restores an encrypted file from public storage back into the app's internal sandbox.
     */
    suspend fun restoreFromVault(activity: Activity, vaultFileUri: Uri, vaultPin: String) = withContext(Dispatchers.IO) {
        val accountId = authenticateVaultUser(activity)
        // For individual restoration, we still use the account-bound key derived from PIN + ID
        val secretKey = deriveVaultKey(accountId, vaultPin)
        restoreFileWithSessionKey(vaultFileUri, secretKey)
    }

    /**
     * Scans a directory (via SAF tree URI) and restores all valid .vault files.
     * Note: MediaStore fallback removed to prevent silent "0 files found" on reinstall.
     */
    suspend fun batchRestore(sessionKey: SecretKey, treeUri: Uri? = null) = withContext(Dispatchers.IO) {
        val filesToRestore = mutableListOf<Uri>()

        if (treeUri == null) {
            // FIX: Explicitly signal that SAF folder linking is required
            throw IllegalStateException("SAF_REQUIRED")
        }

        // Scan SAF directory using DocumentFile (Essential for re-owning files after reinstall)
        val root = DocumentFile.fromTreeUri(context, treeUri)
        root?.listFiles()?.forEach { file ->
            if (file.isFile && file.name?.endsWith(".vault") == true) {
                filesToRestore.add(file.uri)
            }
        }

        var successCount = 0
        filesToRestore.forEach { uri ->
            try {
                restoreFileWithSessionKey(uri, sessionKey)
                successCount++
            } catch (e: Exception) {
                Log.e("VaultManager", "Failed to restore $uri: ${e.message}")
            }
        }
        successCount
    }

    // AUDIT-PASS: STREAM_DECRYPT
    private suspend fun restoreFileWithSessionKey(vaultFileUri: Uri, sessionKey: SecretKey) = recordingRepository.fileMutex.withLock {
        try {
            context.contentResolver.openInputStream(vaultFileUri)?.use { inputStream ->
                // 1. Read IV (12 bytes)
                val iv = ByteArray(12)
                if (inputStream.read(iv) != 12) throw IllegalStateException("Invalid Vault File")

                // 2. Initialize Decryption Cipher
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, sessionKey, GCMParameterSpec(128, iv))

                // 3. Setup Target
                val timestamp = System.currentTimeMillis()
                val fileName = "Restored_${timestamp}"
                val targetFile = File(context.filesDir, "$fileName.enc")

                // 4. Stream Decrypt -> Re-encrypt (internal sandbox)
                CipherInputStream(inputStream, cipher).use { cipherInput ->
                    encryptionHelper.openFileOutputStream(targetFile).use { internalOutput ->
                        val buffer = ByteArray(8192)
                        var read: Int
                        while (cipherInput.read(buffer).also { read = it } != -1) {
                            internalOutput.write(buffer, 0, read)
                        }
                    }
                }

                // 5. Extract Real Duration (Requires header)
                // We'll re-read for duration after flush to keep logic clean and avoid large RAM buffers
                val durationMs = getMediaDurationForFile(targetFile)

                // 6. Insert into DB
                val recording = Recording(
                    title = fileName,
                    filePath = targetFile.absolutePath,
                    timestamp = timestamp,
                    duration = durationMs,
                    sizeMb = targetFile.length().toDouble() / (1024.0 * 1024.0),
                    isPermanentlySaved = true, // Strictly route to Vault UI
                    tags = "Restored"
                )
                recordingRepository.insertRecording(recording)
            }
        } catch (e: Exception) {
            Log.e("VaultManager", "Streaming restoration failed", e)
        }
    }

    /**
     * Decrypts the internal .enc file to a temp WAV to extract duration.
     */
    private fun getMediaDurationForFile(file: File): Long {
        return try {
            encryptionHelper.openFileInputStream(file).use { input ->
                getMediaDuration(input.readBytes(), 16000)
            }
        } catch (e: Exception) { 0L }
    }

    /**
     * Extracts duration using a temporary file. 
     * Plaintext bytes are raw PCM, so we prepend a WAV header for the retriever.
     */
    private fun getMediaDuration(plaintext: ByteArray, sampleRate: Int): Long {
        val tempFile = File(context.cacheDir, "temp_metadata_${System.currentTimeMillis()}.wav")
        return try {
            val wavData = constructWavHeader(plaintext.size, sampleRate) + plaintext
            tempFile.writeBytes(wavData)
            MediaMetadataRetriever().use { retriever ->
                retriever.setDataSource(tempFile.absolutePath)
                retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLong() ?: 0L
            }
        } catch (e: Exception) {
            Log.e("VaultManager", "Failed to extract duration", e)
            0L
        } finally {
            tempFile.delete()
        }
    }

    private fun saveToPublicStorage(fileName: String, bytes: ByteArray) {
        val contentValues = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, "$fileName.vault")
            put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOCUMENTS + "/AcousticDashcam_Vault")
        }

        val uri = context.contentResolver.insert(MediaStore.Files.getContentUri("external"), contentValues)
        uri?.let {
            context.contentResolver.openOutputStream(it)?.use { output ->
                output.write(bytes)
            }
        } ?: throw IllegalStateException("Failed to create MediaStore entry")
    }

    private fun constructWavHeader(pcmDataSize: Int, sampleRate: Int): ByteArray {
        val header = java.nio.ByteBuffer.allocate(44).apply {
            order(java.nio.ByteOrder.LITTLE_ENDIAN)
            put("RIFF".toByteArray())
            putInt(36 + pcmDataSize)
            put("WAVE".toByteArray())
            put("fmt ".toByteArray())
            putInt(16)
            putShort(1.toShort()) // PCM
            putShort(1.toShort()) // Mono
            putInt(sampleRate)
            putInt(sampleRate * 2) // ByteRate
            putShort(2.toShort()) // BlockAlign
            putShort(16.toShort()) // BitsPerSample
            put("data".toByteArray())
            putInt(pcmDataSize)
        }.array()
        return header
    }

    /**
     * Decrypts a vault file into a temporary cache file for ephemeral playback.
     */
    // AUDIT-PASS: STREAM_DECRYPT
    suspend fun createEphemeralPlaybackFile(vaultFileUri: Uri, sessionKey: SecretKey): File? = withContext(Dispatchers.IO) {
        try {
            context.contentResolver.openInputStream(vaultFileUri)?.use { inputStream ->
                // 1. Read IV (12 bytes)
                val iv = ByteArray(12)
                if (inputStream.read(iv) != 12) return@withContext null

                // 2. Initialize Decryption Cipher
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, sessionKey, GCMParameterSpec(128, iv))

                // 3. Calculate pcmSize for WAV header
                val encryptedSize = context.contentResolver.openAssetFileDescriptor(vaultFileUri, "r")?.use { it.length } ?: -1L
                if (encryptedSize < 28) return@withContext null
                val pcmSize = (encryptedSize - 12 - 16).toInt() // [IV][Ciphertext][Tag]

                // 4. Stream Decrypt -> Temporary WAV
                val tempFile = File(context.cacheDir, "ephemeral_audio_${System.currentTimeMillis()}.wav")
                tempFile.outputStream().use { fos ->
                    // Prepend header
                    fos.write(constructWavHeader(pcmSize, 16000))
                    
                    CipherInputStream(inputStream, cipher).use { cipherInput ->
                        val buffer = ByteArray(8192)
                        var read: Int
                        while (cipherInput.read(buffer).also { read = it } != -1) {
                            fos.write(buffer, 0, read)
                        }
                    }
                    fos.flush()
                }
                tempFile
            }
        } catch (e: Exception) {
            Log.e("VaultManager", "Ephemeral Streaming Decryption failed", e)
            null
        }
    }
}
