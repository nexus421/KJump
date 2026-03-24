package bayern.kickner.utils

import kotnexlib.crypto.AES

/**
 * Utility for AES-GCM encryption and decryption.
 * Uses KotNexLib for secure key derivation and cryptographic operations.
 */
object EncryptionUtils {
    /**
     * Decrypts AES-GCM encrypted data using a token-derived key.
     * @param encryptedData The serialized AESData string.
     * @param token The user token for decryption.
     * @return The decrypted plaintext string.
     * @throws Exception if decryption fails or data is corrupted.
     */
    fun decrypt(encryptedData: String, token: CharArray): String {
        if (encryptedData.isBlank()) {
            throw Exception("Encrypted data is empty. Please re-add the server with a valid SSH key.")
        }
        val aesData = try {
            AES.AESData.restore(encryptedData.trim()).getOrThrow()
        } catch (e: Exception) {
            throw Exception("Failed to restore encrypted data structure. Is the data corrupted? (${e.message})")
        }

        return try {
            val tokenString = String(token)
            aesData.decryptAsString(tokenString).getOrThrow()
        } catch (e: Exception) {
            val msg = e.message ?: ""
            if (msg.contains("Tag mismatch", ignoreCase = true)) {
                throw Exception("Wrong token or corrupted data (Tag mismatch).")
            } else {
                throw Exception("Decryption failed: ${e.message}")
            }
        }
    }

    /**
     * Encrypts plaintext data using AES-GCM with a token-derived key.
     * @param data The plaintext string to encrypt.
     * @param token The user token for encryption.
     * @return A serialized AESData string.
     */
    fun encrypt(data: String, token: CharArray): String {
        val aesData = AES.GCM.encryptWithPassword(data, String(token))
        return aesData.toString()
    }
}
