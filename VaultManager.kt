package com.secure.maanrecorder.util

import android.app.Activity
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.documentfile.provider.DocumentFile
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
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
    private val appSalt = "MaanDashcam_Secure_Salt_2026".toByteArray()
    private val iterations = 600000 // Hardened iterations (OWASP recommendation)
    private val keyLength = 256

    /**
     * Authenticates the user via Google using Credential Manager.
     * Returns a unique account ID (Subject ID from Token).
     */
    suspend fun authenticateVaultUser(activity: Activity): String? = withContext(Dispatchers.Main) {
        try {
            // NOTE: In production, replace this with your actual Web Client ID from Google Cloud Console
            val googleIdOption = GetGoogleIdOption.Builder()
                .setFilterByAuthorizedAccounts(false)
                .setServerClientId("YOUR_WEB_CLIENT_ID_HERE.apps.googleusercontent.com")
                .setAutoSelectEnabled(false)
                .build()

            val request = GetCredentialRequest.Builder()
                .addCredentialOption(googleIdOption)
                .build()

            val result = credentialManager.getCredential(activity, request)
            val credential = result.credential

            if (credential is CustomCredential && credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
                return@withContext googleIdTokenCredential.id // Subject ID is unique and stable
            }
        } catch (e: Exception) {
            Log.e("VaultManager", "Authentication failed", e)
        }
        null
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
     * using the account-bound identity key.
     */
    suspend fun moveToVault(
        internalEncryptedFile: File, 
        vaultFileName: String, 
        accountId: String,
        vaultPin: String
    ) = recordingRepository.fileMutex.withLock {
        withContext(Dispatchers.IO) {
            var rawBytes: ByteArray? = null
            try {
                val secretKey = deriveVaultKey(accountId, vaultPin)
                
                // 1. Read and Decrypt internal file
                rawBytes = encryptionHelper.openFileInputStream(internalEncryptedFile).use { 
                    it.readBytes() 
                }

                // 2. Re-encrypt with Account-bound Key
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
                
                val encryptedBytes = cipher.doFinal(rawBytes)
                
                // Construct payload: [IV (12 bytes)][Ciphertext]
                val finalPayload = iv + encryptedBytes

                // 3. Save to Public Directory (MediaStore)
                saveToPublicStorage(vaultFileName, finalPayload)
                
                // 4. Cleanup internal file
                if (internalEncryptedFile.exists()) {
                    internalEncryptedFile.delete()
                }
                
                Log.d("VaultManager", "File successfully moved to survival vault: $vaultFileName")
            } catch (e: Exception) {
                Log.e("VaultManager", "Vault migration failed", e)
                throw e
            } finally {
                // SECURE MEMORY HYGIENE: Overwrite plaintext bytes
                rawBytes?.let { java.util.Arrays.fill(it, 0.toByte()) }
            }
        }
    }

    /**
     * Restores an encrypted file from public storage back into the app's internal sandbox.
     */
    suspend fun restoreFromVault(activity: Activity, vaultFileUri: Uri, vaultPin: String) = withContext(Dispatchers.IO) {
        val accountId = authenticateVaultUser(activity) ?: throw IllegalStateException("Identity verification required for restoration")
        restoreFileWithAccountId(vaultFileUri, accountId, vaultPin)
    }

    /**
     * Scans a directory (via SAF tree URI or default) and restores all valid .vault files.
     */
    suspend fun batchRestore(activity: Activity, vaultPin: String, treeUri: Uri? = null) = withContext(Dispatchers.IO) {
        val accountId = authenticateVaultUser(activity) ?: throw IllegalStateException("Identity verification required")
        
        val filesToRestore = mutableListOf<Uri>()
        
        if (treeUri != null) {
            // Scan SAF directory
            val childrenUri = DocumentFile.fromTreeUri(context, treeUri)
            childrenUri?.listFiles()?.forEach { file ->
                if (file.isFile && file.name?.endsWith(".vault") == true) {
                    filesToRestore.add(file.uri)
                }
            }
        } else {
            // Scan default MediaStore/Files location
            val projection = arrayOf(MediaStore.Files.FileColumns._ID, MediaStore.Files.FileColumns.DISPLAY_NAME)
            val selection = "${MediaStore.Files.FileColumns.DISPLAY_NAME} LIKE ?"
            val selectionArgs = arrayOf("%.vault")
            
            context.contentResolver.query(
                MediaStore.Files.getContentUri("external"),
                projection,
                selection,
                selectionArgs,
                null
            )?.use { cursor ->
                val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Files.FileColumns._ID)
                while (cursor.moveToNext()) {
                    val id = cursor.getLong(idColumn)
                    filesToRestore.add(Uri.withAppendedPath(MediaStore.Files.getContentUri("external"), id.toString()))
                }
            }
        }

        var successCount = 0
        filesToRestore.forEach { uri ->
            try {
                restoreFileWithAccountId(uri, accountId, vaultPin)
                successCount++
            } catch (e: Exception) {
                Log.e("VaultManager", "Failed to restore $uri", e)
            }
        }
        successCount
    }

    private suspend fun restoreFileWithAccountId(vaultFileUri: Uri, accountId: String, vaultPin: String) = recordingRepository.fileMutex.withLock {
        var rawBytes: ByteArray? = null
        try {
            val secretKey = deriveVaultKey(accountId, vaultPin)

            // 1. Read identity-encrypted payload
            val encryptedPayload = context.contentResolver.openInputStream(vaultFileUri)?.use { it.readBytes() }
                ?: throw IllegalStateException("Cannot read vault file")

            if (encryptedPayload.size < 28) throw IllegalStateException("File too small to be valid")

            // 2. Decrypt identity payload [IV (12)][Ciphertext]
            val iv = encryptedPayload.sliceArray(0 until 12)
            val ciphertext = encryptedPayload.sliceArray(12 until encryptedPayload.size)
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            rawBytes = cipher.doFinal(ciphertext)

            // 3. Re-ingest into internal sandbox
            val timestamp = System.currentTimeMillis()
            val targetFile = File(context.filesDir, "RESTORED_$timestamp.enc")
            
            encryptionHelper.openFileOutputStream(targetFile).use { output ->
                output.write(rawBytes!!)
            }

            // 4. Insert into DB
            val recording = Recording(
                title = "Restored Evidence",
                filePath = targetFile.absolutePath,
                timestamp = timestamp,
                duration = 0,
                sizeMb = targetFile.length().toDouble() / (1024.0 * 1024.0),
                tags = "Restored"
            )
            recordingRepository.insertRecording(recording)
        } finally {
            // SECURE MEMORY HYGIENE: Overwrite plaintext bytes
            rawBytes?.let { java.util.Arrays.fill(it, 0.toByte()) }
        }
    }

    private fun saveToPublicStorage(fileName: String, bytes: ByteArray) {
        val resolver = context.contentResolver
        val contentValues = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, "$fileName.vault")
            put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOCUMENTS + "/AcousticDashcam_Vault")
        }

        val uri = resolver.insert(MediaStore.Files.getContentUri("external"), contentValues)
        uri?.let {
            resolver.openOutputStream(it)?.use { output ->
                output.write(bytes)
            }
        } ?: throw IllegalStateException("Failed to create MediaStore entry")
    }

    suspend fun signOut() {
        credentialManager.clearCredentialState(ClearCredentialStateRequest())
    }
}
