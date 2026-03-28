package bayern.kickner

import bayern.kickner.db.DatabaseFactory
import bayern.kickner.klogger.debugLog
import bayern.kickner.klogger.errorLog
import bayern.kickner.klogger.infoLog
import bayern.kickner.klogger.warnLog
import bayern.kickner.model.*
import bayern.kickner.totp.Totp
import bayern.kickner.utils.EncryptionUtils
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.html.*
import io.ktor.server.http.content.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.html.*
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
    val clientDir = File("client")
    if (!clientDir.exists()) {
        clientDir.mkdirs()
    }
    routing {
        post("/auth/login") {
            try {
                val request = call.receive<LoginRequest>()
                debugLog { "Login attempt using token." }

                val userBox = DatabaseFactory.store.boxFor(User::class.java)
                val hashedToken = request.token.hashBC()
                val user = userBox.query(User_.hashedToken.equal(hashedToken)).build().findFirstAndClose()

                if (user != null) {
                    if (user.totpSecret.isNotBlank() && !Totp.verifyCode(
                            user.totpSecret,
                            request.totpCode
                        )
                    ) {
                        warnLog { "Invalid TOTP code for user." }
                        call.respond(HttpStatusCode.Unauthorized, "Invalid TOTP code")
                        return@post
                    }

                    val config = DatabaseFactory.systemConfigBox.all.firstOrNull()
                    if (config != null) {
                        infoLog { "Login successful." }
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

        get("/client") {
            val dir = File("client")
            if (!dir.exists()) dir.mkdirs()

            val files = dir.listFiles()?.filter { it.isFile } ?: emptyList()
            val jars = files.filter { it.name.endsWith(".jar", true) }
            val natives = files.filter { !it.name.contains(".") }

            val config = DatabaseFactory.systemConfigBox.all.firstOrNull()
            val secret = config?.apiToken ?: "default-secret"
            val a = (1..10).random()
            val b = (1..10).random()
            val ts = System.currentTimeMillis()
            val token = "$ts:${a + b}:$secret".hashBC()

            call.respondHtml {
                head {
                    title { +"KJump Client Download" }
                    style {
                        +".hp { display: none; }"
                    }
                }
                body {
                    h1 { +"KJump Client Download" }
                    p { +"Wählen Sie den gewünschten Client-Typ zum Herunterladen aus:" }

                    if (jars.size > 1) {
                        p {
                            style = "color: orange; font-weight: bold;"
                            +"Warnung: Mehr als eine JAR-Datei im 'client' Ordner gefunden. Die erste wird verwendet (${jars.first().name})."
                        }
                    }
                    if (natives.size > 1) {
                        p {
                            style = "color: orange; font-weight: bold;"
                            +"Warnung: Mehr als eine Native-Datei im 'client' Ordner gefunden. Die erste wird verwendet (${natives.first().name})."
                        }
                    }

                    form(action = "/client/download", method = FormMethod.post) {
                        div {
                            style = "margin-bottom: 10px;"
                            +"Bitte lösen Sie diese Aufgabe: $a + $b = "
                            input(type = InputType.number, name = "answer") {
                                attributes["required"] = "true"
                            }
                        }

                        // Honeypot
                        input(type = InputType.text, name = "email") {
                            classes = setOf("hp")
                        }

                        // Hidden data
                        input(type = InputType.hidden, name = "ts") {
                            value = ts.toString()
                        }
                        input(type = InputType.hidden, name = "token") {
                            value = token
                        }

                        div {
                            if (jars.isEmpty()) {
                                p {
                                    style = "color: red;"
                                    +"Fehler: Keine JAR-Datei gefunden."
                                }
                            } else {
                                button(type = ButtonType.submit) {
                                    name = "type"
                                    value = "jar"
                                    +"JAR Herunterladen (${jars.first().name})"
                                }
                            }
                        }

                        br { }

                        div {
                            if (natives.isEmpty()) {
                                p {
                                    style = "color: red;"
                                    +"Fehler: Keine Native-Datei gefunden."
                                }
                            } else {
                                button(type = ButtonType.submit) {
                                    name = "type"
                                    value = "native"
                                    +"Native Herunterladen (${natives.first().name})"
                                }
                            }
                        }
                    }
                }
            }
        }

        get("/client/download/jar") {
            call.respond(HttpStatusCode.MethodNotAllowed, "Please use the download form at /client")
        }

        get("/client/download/native") {
            call.respond(HttpStatusCode.MethodNotAllowed, "Please use the download form at /client")
        }

        post("/client/download") {
            val params = call.receiveParameters()
            val config = DatabaseFactory.systemConfigBox.all.firstOrNull()
            val secret = config?.apiToken ?: "default-secret"

            val error = validateBotProtection(params, secret)
            if (error != null) {
                call.respond(HttpStatusCode.Forbidden, error)
                return@post
            }

            val type = params["type"] ?: "jar"
            val dir = File("client")
            val file = if (type == "jar") {
                dir.listFiles()?.filter { it.isFile && it.name.endsWith(".jar", true) }?.firstOrNull()
            } else {
                dir.listFiles()?.filter { it.isFile && !it.name.contains(".") }?.firstOrNull()
            }

            if (file != null && file.exists()) {
                call.response.header(
                    HttpHeaders.ContentDisposition,
                    ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, file.name)
                        .toString()
                )
                call.respondFile(file)
            } else {
                call.respond(HttpStatusCode.NotFound, "$type file not found.")
            }
        }
    }
}

private fun validateBotProtection(params: Parameters, secret: String): String? {
    val honeypot = params["email"]
    if (!honeypot.isNullOrEmpty()) return "Bot detected (honeypot)"

    val tsStr = params["ts"] ?: return "Missing timestamp"
    val token = params["token"] ?: return "Missing token"
    val answerStr = params["answer"] ?: return "Missing answer"

    val ts = tsStr.toLongOrNull() ?: return "Invalid timestamp"
    val currentTime = System.currentTimeMillis()

    if (currentTime - ts < 2000) return "You are too fast! (Bot protection)"
    if (currentTime - ts > 10 * 60 * 1000) return "Session expired. Please refresh."

    val answer = answerStr.toIntOrNull() ?: return "Invalid answer format"
    val expectedHash = "$ts:$answer:$secret".hashBC()

    if (token != expectedHash) return "Incorrect math answer"

    return null
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
