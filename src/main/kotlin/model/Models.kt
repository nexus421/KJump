package bayern.kickner.model

import io.objectbox.annotation.Entity
import io.objectbox.annotation.Id
import kotlinx.serialization.Serializable

/**
 * Represents a user in the system.
 * Used for database storage via ObjectBox.
 */
@Entity
data class User(
    @Id var id: Long = 0,
    var hashedToken: String = "",
    var totpSecret: String = "",
    var createdAt: Long = System.currentTimeMillis()
)

/**
 * Database entity for storing SSH server configurations.
 */
@Entity
data class ServerEntryEntity(
    @Id var id: Long = 0,
    var alias: String = "",
    var ip: String = "",
    var port: Int = 22,
    var user: String = "",
    var encryptedKey: String = ""
)

/**
 * System configuration stored in the database.
 * Used for server-wide settings like the global jump IP.
 *
 * //ToDo: Es muss ein Port angegeben werden KÖNNEN. Default 22. Falls der Host einen anderen Port verwendet.
 */
@Entity
data class SystemConfig(
    @Id var id: Long = 0,
    var globalJumpIp: String = "",
    var apiToken: String = "",
    var port: Int = 8090
)

/**
 * DTO for login requests.
 */
@Serializable
data class LoginRequest(val token: String, val totpCode: String)

/**
 * DTO for login responses.
 */
@Serializable
data class LoginResponse(val apiToken: String)

/**
 * DTO for exchanging server information between client and server.
 * The encryptedKey is removed as the client should never have the key for the target server.
 */
@Serializable
data class ServerEntry(
    val id: Long,
    val alias: String,
    val ip: String,
    val port: Int = 22,
    val user: String,
    val hostIp: String? = null, // Information about the jump host if needed
    val encryptedKey: String? = null // Optional for POST/GET
)

/**
 * Request for preparing an SSH connection via jump host.
 */
@Serializable
data class SshPrepareRequest(val serverId: Long, val token: String)

/**
 * Response with details for the jump host connection.
 */
@Serializable
data class SshPrepareResponse(
    val jumpUser: String,
    val jumpHost: String,
    val jumpHostPrivateKey: String,
    val targetUser: String,
    val targetIp: String,
    val targetPort: Int,
    val remoteKeyPath: String
)
