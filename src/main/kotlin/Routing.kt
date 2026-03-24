package bayern.kickner

import bayern.kickner.db.DatabaseFactory
import bayern.kickner.klogger.debugLog
import bayern.kickner.klogger.errorLog
import bayern.kickner.klogger.infoLog
import bayern.kickner.klogger.warnLog
import bayern.kickner.model.*
import bayern.kickner.utils.EncryptionUtils
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.http.content.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotnexlib.crypto.hashBC
import kotnexlib.external.objectbox.findFirstAndClose
import kotnexlib.isNotNullOrBlank
import java.io.File
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/**
 * Configures the HTTP routes for the application.
 * Includes endpoints for fetching the vault, adding servers, and client downloads.
 */
fun Application.configureRouting() {
    routing {
        post("/auth/login") {
            try {
                val request = call.receive<LoginRequest>()
                debugLog { "Login attempt using token." }

                val userBox = DatabaseFactory.store.boxFor(User::class.java)
                val hashedToken = request.token.hashBC()
                val user = userBox.query(User_.hashedToken.equal(hashedToken)).build().findFirstAndClose()

                if (user != null) {
                    val config = DatabaseFactory.systemConfigBox.all.firstOrNull()
                    if (config != null) {
                        infoLog { "Login successful for user: ${user.username}" }
                        call.respond(LoginResponse(config.apiToken))
                    } else {
                        warnLog { "System configuration missing during login" }
                        call.respond(HttpStatusCode.InternalServerError, "Server configuration missing")
                    }
                } else {
                    warnLog { "Invalid login attempt: Token hash not found." }
                    call.respond(HttpStatusCode.Unauthorized, "Invalid credentials")
                }
            } catch (e: Exception) {
                errorLog(e)
                call.respond(HttpStatusCode.BadRequest, "Invalid request: ${e.message}")
            }
        }

        get("/vault") {
            if (verifyApiToken(call).not()) return@get call.respond(HttpStatusCode.Unauthorized, "Invalid API Token")
            infoLog { "Fetching all servers from vault..." }
            val servers = DatabaseFactory.serverEntryBox.all.map {
                ServerEntry(it.id, it.alias, it.ip, it.port, it.user, getJumpHostIp()) // Use global server IP as hostIp
            }
            infoLog { "Returning ${servers.size} servers." }
            call.respond(servers)
        }

        post("/vault") {
            if (verifyApiToken(call).not()) return@post call.respond(HttpStatusCode.Unauthorized, "Invalid API Token")

            try {
                val entry = call.receive<ServerEntry>()
                infoLog { "Adding new server: Alias='${entry.alias}', User='${entry.user}'" }
                val entity = ServerEntryEntity(
                    alias = entry.alias,
                    ip = entry.ip,
                    port = entry.port,
                    user = entry.user,
                    encryptedKey = entry.encryptedKey ?: ""
                )
                DatabaseFactory.serverEntryBox.put(entity)
                infoLog { "Server '${entry.alias}' added successfully (ID: ${entity.id})" }
                call.respond(HttpStatusCode.Created, "Server added successfully")
            } catch (e: Exception) {
                errorLog("Failed to add server", e)
                call.respond(HttpStatusCode.BadRequest, "Invalid data: ${e.message}")
            }
        }

//        get("/config") {
//            if (verifyApiToken(call).not()) return@get call.respond(HttpStatusCode.Unauthorized, "Invalid API Token")
//            val configBox = DatabaseFactory.store.boxFor(SystemConfig::class.java)
//            val config = configBox.all.firstOrNull() ?: return@get call.respond(
//                HttpStatusCode.NotFound,
//                "No configuration found"
//            )
//            call.respond(config)
//        }
//
//        post("/config") {
//            if (verifyApiToken(call).not()) return@post call.respond(HttpStatusCode.Unauthorized, "Invalid API Token")
//            try {
//                val newConfig = call.receive<SystemConfig>()
//                val configBox = DatabaseFactory.store.boxFor(SystemConfig::class.java)
//                val existingConfig = configBox.all.firstOrNull()
//                if (existingConfig != null) {
//                    newConfig.id = existingConfig.id
//                    // Wenn das API-Token im Request leer ist, behalte das alte bei
//                    if (newConfig.apiToken.isBlank()) {
//                        newConfig.apiToken = existingConfig.apiToken
//                    }
//                }
//                configBox.put(newConfig)
//                infoLog { "System configuration updated." }
//                call.respond(HttpStatusCode.OK, "Configuration updated")
//            } catch (e: Exception) {
//                errorLog("Failed to update config", e)
//                call.respond(HttpStatusCode.BadRequest, "Invalid data: ${e.message}")
//            }
//        }

        post("/prepare") {
            if (verifyApiToken(call).not()) return@post call.respond(HttpStatusCode.Unauthorized, "Invalid API Token")

            try {
                val request = call.receive<SshPrepareRequest>()
                infoLog { "Preparing SSH connection for Server ID: ${request.serverId}" }
                val server = DatabaseFactory.serverEntryBox.get(request.serverId) ?: return@post call.respond(
                    HttpStatusCode.NotFound,
                    "Server not found"
                )

                val decryptedKey = EncryptionUtils.decrypt(server.encryptedKey, request.token.toCharArray())
                val tempKeyFile = File.createTempFile("kjump_ssh_", ".key")
                tempKeyFile.writeText(decryptedKey)

                try {
                    Files.setPosixFilePermissions(tempKeyFile.toPath(), PosixFilePermissions.fromString("rw-------"))
                } catch (_: Exception) {
                    ProcessBuilder("chmod", "600", tempKeyFile.absolutePath).start().waitFor()
                }

                val config = DatabaseFactory.systemConfigBox.all.firstOrNull()
                val jumpUser = System.getProperty("user.name")
                val jumpHost = getJumpHostIp()
                val jumpHostPrivateKey = DatabaseFactory.getJumpHostPrivateKey()

                infoLog { "SSH Prepared: JumpHost=$jumpHost, JumpUser=$jumpUser, RemoteKeyPath=${tempKeyFile.absolutePath}" }

                call.respond(
                    SshPrepareResponse(
                        jumpUser = jumpUser,
                        jumpHost = jumpHost,
                        jumpHostPrivateKey = jumpHostPrivateKey,
                        targetUser = server.user,
                        targetIp = server.ip,
                        targetPort = server.port,
                        remoteKeyPath = tempKeyFile.absolutePath
                    )
                )
            } catch (e: Exception) {
                errorLog("Failed to prepare SSH", e)
                call.respond(HttpStatusCode.BadRequest, "Error: ${e.message}")
            }
        }

        staticFiles("/download", File("clients")) {
            default("kj-client.jar")
        }
    }
}

/**
 * Verifies the API token provided in the request headers.
 */
private fun verifyApiToken(call: ApplicationCall): Boolean {
    val token = call.request.headers["X-API-Token"] ?: return false
    val config = DatabaseFactory.systemConfigBox.all.firstOrNull() ?: return false
    return token == config.apiToken
}

/**
 * Retrieves the configured global IP of this server to be used as a jump host.
 * Falls back to local address if not configured.
 */
private fun getJumpHostIp(): String {
    val config = DatabaseFactory.systemConfigBox.all.firstOrNull()
    return if (config?.globalJumpIp.isNotNullOrBlank()) config.globalJumpIp else InetAddress.getLocalHost().hostAddress
}
