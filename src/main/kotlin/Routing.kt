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

            val msg = Messages(call.isGerman())

            call.respondHtml {
                head {
                    title { +msg.title }
                    style {
                        unsafe {
                            +"""
                        body {
                            background-color: #121212;
                            color: #e0e0e0;
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            min-height: 100vh;
                            margin: 0;
                        }
                        .container {
                            background-color: #1e1e1e;
                            padding: 2rem;
                            border-radius: 8px;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
                            max-width: 500px;
                            width: 100%;
                            text-align: center;
                        }
                        h1 { color: #ffffff; margin-bottom: 1.5rem; }
                        p { line-height: 1.6; margin-bottom: 1.5rem; }
                        .warning {
                            background-color: rgba(255, 165, 0, 0.1);
                            border: 1px solid orange;
                            color: orange;
                            padding: 10px;
                            border-radius: 4px;
                            margin-bottom: 1rem;
                            font-weight: bold;
                        }
                        .error {
                            background-color: rgba(255, 0, 0, 0.1);
                            border: 1px solid #f44336;
                            color: #f44336;
                            padding: 10px;
                            border-radius: 4px;
                            margin-bottom: 1rem;
                        }
                        .math-box {
                            background-color: #2d2d2d;
                            padding: 1rem;
                            border-radius: 4px;
                            margin-bottom: 1.5rem;
                        }
                        input[type="number"] {
                            background-color: #333;
                            border: 1px solid #444;
                            color: #fff;
                            padding: 8px;
                            border-radius: 4px;
                            width: 60px;
                            margin-left: 10px;
                        }
                        button {
                            background-color: #2196f3;
                            color: white;
                            border: none;
                            padding: 12px 24px;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 1rem;
                            font-weight: bold;
                            transition: background-color 0.3s;
                            width: 100%;
                            margin-bottom: 10px;
                        }
                        button:hover {
                            background-color: #1976d2;
                        }
                        button:disabled {
                            background-color: #555;
                            cursor: not-allowed;
                        }
                        .hp { display: none; }
                        """.trimIndent()
                        }
                    }
                }
                body {
                    div(classes = "container") {
                        h1 { +msg.title }
                        p { +msg.desc }

                        if (jars.size > 1) {
                            div(classes = "warning") {
                                +"${msg.warnJar} (${jars.first().name})."
                            }
                        }
                        if (natives.size > 1) {
                            div(classes = "warning") {
                                +"${msg.warnNative} (${natives.first().name})."
                            }
                        }

                        form(action = "/client/download", method = FormMethod.post) {
                            div(classes = "math-box") {
                                +"${msg.mathTask}: $a + $b = "
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
                                    div(classes = "error") {
                                        +msg.errorNoJar
                                    }
                                } else {
                                    button(type = ButtonType.submit) {
                                        name = "type"
                                        value = "jar"
                                        +"${msg.downloadJar} (${jars.first().name})"
                                    }
                                }
                            }

                            div {
                                if (natives.isEmpty()) {
                                    div(classes = "error") {
                                        +msg.errorNoNative
                                    }
                                } else {
                                    button(type = ButtonType.submit) {
                                        name = "type"
                                        value = "native"
                                        +"${msg.downloadNative} (${natives.first().name})"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        post("/client/download") {
            val params = call.receiveParameters()
            val msg = Messages(call.isGerman())
            val config = DatabaseFactory.systemConfigBox.all.firstOrNull()
            val secret = config?.apiToken ?: "default-secret"

            val error = validateBotProtection(params, secret, msg)
            if (error != null) {
                call.respond(HttpStatusCode.Forbidden, error)
                return@post
            }

            val type = params["type"] ?: "jar"
            val dir = File("client")
            val file = if (type == "jar") {
                dir.listFiles()?.firstOrNull { it.isFile && it.name.endsWith(".jar", true) }
            } else {
                dir.listFiles()?.firstOrNull { it.isFile && !it.name.contains(".") }
            }

            if (file != null && file.exists()) {
                call.response.header(
                    HttpHeaders.ContentDisposition,
                    ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, file.name)
                        .toString()
                )
                call.respondFile(file)
            } else {
                call.respond(HttpStatusCode.NotFound, "${msg.fileNotFound}: $type")
            }
        }
    }
}

private fun validateBotProtection(params: Parameters, secret: String, msg: Messages): String? {
    val honeypot = params["email"]
    if (honeypot.isNullOrEmpty().not()) return msg.botHoneypot

    val tsStr = params["ts"] ?: return msg.missingTs
    val token = params["token"] ?: return msg.missingToken
    val answerStr = params["answer"] ?: return msg.missingAnswer

    val ts = tsStr.toLongOrNull() ?: return msg.invalidTs
    val currentTime = System.currentTimeMillis()

    if (currentTime - ts < 2000) return msg.tooFast
    if (currentTime - ts > 10 * 60 * 1000) return msg.sessionExpired

    val answer = answerStr.toIntOrNull() ?: return msg.invalidAnswerFormat
    val expectedHash = "$ts:$answer:$secret".hashBC()

    if (token != expectedHash) return msg.incorrectAnswer

    return null
}

private fun ApplicationCall.isGerman() = request.headers["Accept-Language"]?.startsWith("de", true) == true

private class Messages(val isDe: Boolean) {
    val title = "KJump Client Download"
    val desc =
        if (isDe) "Wähle  den gewünschten Client-Typ zum Herunterladen aus:" else "Select the desired client type for download:"
    val warnJar =
        if (isDe) "Warnung: Mehr als eine JAR-Datei im 'client' Ordner gefunden. Die erste wird verwendet" else "Warning: More than one JAR file found in 'client' folder. The first one will be used"
    val warnNative =
        if (isDe) "Warnung: Mehr als eine Native-Datei im 'client' Ordner gefunden. Die erste wird verwendet" else "Warning: More than one native file found in 'client' folder. The first one will be used"
    val mathTask = if (isDe) "Bitte löse diese Aufgabe" else "Please solve this task"
    val errorNoJar = if (isDe) "Fehler: Keine JAR-Datei gefunden." else "Error: No JAR file found."
    val errorNoNative = if (isDe) "Fehler: Keine Native-Datei gefunden." else "Error: No native file found."
    val downloadJar = if (isDe) "JAR Herunterladen" else "Download JAR"
    val downloadNative = if (isDe) "Native Herunterladen" else "Download Native"

    // Bot protection messages
    val botHoneypot = if (isDe) "Bot erkannt" else "Bot detected"
    val missingTs = if (isDe) "Zeitstempel fehlt" else "Missing timestamp"
    val missingToken = if (isDe) "Token fehlt" else "Missing token"
    val missingAnswer = if (isDe) "Antwort fehlt" else "Missing answer"
    val invalidTs = if (isDe) "Ungültiger Zeitstempel" else "Invalid timestamp"
    val tooFast = if (isDe) "Zu schnell! (Bot-Schutz)" else "You are too fast! (Bot protection)"
    val sessionExpired = if (isDe) "Sitzung abgelaufen. Bitte Seite neu laden." else "Session expired. Please refresh."
    val invalidAnswerFormat = if (isDe) "Ungültiges Antwortformat" else "Invalid answer format"
    val incorrectAnswer = if (isDe) "Falsches Ergebnis" else "Incorrect math answer"
    val fileNotFound = if (isDe) "Datei nicht gefunden" else "File not found"
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
