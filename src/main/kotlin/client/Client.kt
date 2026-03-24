package bayern.kickner.client

import bayern.kickner.model.*
import bayern.kickner.utils.EncryptionUtils
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.*
import kotnexlib.fromBase64
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.system.exitProcess

private val client = HttpClient(CIO) {
    install(ContentNegotiation) {
        json()
    }
}


private lateinit var apiToken: String
private lateinit var userToken: String
private lateinit var jumpHost: String

/**
 * CLI Entry point for the K-Jump SSH Client.
 * Handles the main menu loop and user authentication via master token.
 */
fun main() = runBlocking {
    printBanner()

    println("Welcome to K-Jump SSH Client.")
    login()

    while (true) {
        println("\n--- MAIN MENU ---")
        println("1. List & Connect to Servers")
        println("2. Add New SSH Server")
        println("3. Exit")
        print("Selection: ")

        when (readln().trim()) {
            "1" -> listAndConnect(userToken)
            "2" -> addServer(userToken)
            "3" -> {
                println("Goodbye!")
                exitProcess(0)
            }
            else -> println("Invalid selection, please try again.")
        }
    }
}

/**
 * Prints the K-Jump application banner.
 */
fun printBanner() {
    println("""
        |----------------------------------------------------------|
        |                  K-Jump SSH Client                       |
        |----------------------------------------------------------|
    """.trimMargin())
}

/**
 * Fetches the server list from the vault and allows the user to select one for connection.
 * @param token The user token for key decryption.
 */
suspend fun listAndConnect(token: String) {
    println("\n" + "-".repeat(30))
    println("Loading data from server...")
    val servers: List<ServerEntry> = try {
        client.get("$jumpHost/vault") {
            header("X-API-Token", apiToken)
        }.body()
    } catch (e: Exception) {
        println("Error fetching data: ${e.message}")
        return
    }

    if (servers.isEmpty()) return println("No servers found in vault.")

    println("\nAVAILABLE SERVERS")
    println("%-4s | %-20s | %-15s:%-5s".format("ID", "Alias", "IP", "Port"))
    println("-".repeat(55))
    servers.forEach { 
        println("%-4d | %-20s | %-15s:%-5d".format(it.id, it.alias, it.ip, it.port)) 
    }

    print("\nEnter Server ID to connect (or 'q' to return): ")
    val input = readln().trim()
    if (input == "q") return

    val idInput = input.toLongOrNull()
    val selectedServer = servers.find { it.id == idInput }

    if (selectedServer != null) startSsh(selectedServer, token)
    else println("Invalid Server ID.")
}

/**
 * Collects details for a new server, encrypts the private key, and sends it to the server.
 * @param token The user token for key encryption.
 */
suspend fun addServer(token: String) {
    println("\n--- ADD NEW SSH SERVER ---")

    print("Alias (e.g. My-Webserver): ")
    val alias = readln().trim()
    if (alias.isBlank()) return println("Error: Alias cannot be empty.")

    print("IP Address: ")
    val ip = readln().trim()
    if (ip.isBlank() || (ip.contains('.').not() && ip.contains(':').not())) return println("Error: Invalid IP Address")

    print("Port [22]: ")
    val portInput = readln().trim()
    val port = if (portInput.isEmpty()) 22 else portInput.toIntOrNull() ?: 22

    print("Username: ")
    val user = readln().trim()
    if (user.isBlank()) return println("Error: Username cannot be empty.")

    println("SSH Private Key (Paste below and end with an empty line):")
    val keyBuilder = StringBuilder()
    while (true) {
        val line = readln()
        if (line.isEmpty()) break
        keyBuilder.append(line).append("\n")
    }
    val key = keyBuilder.toString().trim() + "\n"

    if (key.isBlank()) return println("Error: SSH Key cannot be empty.")

    // Prepare DTO (id=0 because it's new)
    val encryptedKey = EncryptionUtils.encrypt(key, token.toCharArray())
    val entry = ServerEntry(
        id = 0,
        alias = alias,
        ip = ip,
        port = port,
        user = user,
        encryptedKey = encryptedKey
    )

    val response = client.post("$jumpHost/vault") {
        header("X-API-Token", apiToken)
        contentType(ContentType.Application.Json)
        setBody(entry)
    }

    if (response.status == HttpStatusCode.Created) {
        println("Success: Server added successfully.")
    } else {
        println("Error: ${response.status} - ${response.bodyAsText()}")
    }
}

/**
 * Requests SSH preparation from the server and starts an interactive SSH session via jump host.
 * @param server The server entry containing connection details.
 * @param token The user token for key decryption on the server.
 */
suspend fun startSsh(server: ServerEntry, token: String) = coroutineScope {
    println("Preparing secure connection via jump host...")

    val response = try {
        client.post("$jumpHost/prepare") {
            header("X-API-Token", apiToken)
            contentType(ContentType.Application.Json)
            setBody(SshPrepareRequest(server.id, token))
        }
    } catch (e: Exception) {
        return@coroutineScope println("Error connecting to KJump server: ${e.message}")
    }

    if (response.status != HttpStatusCode.OK) return@coroutineScope println("Error preparing connection: ${response.status} - ${response.bodyAsText()}")

    val prep = response.body<SshPrepareResponse>()

    println("Connecting to ${server.alias} (${server.ip}:${server.port}) via jump host ${prep.jumpHost}...")

    // The host key is sent by the server for us to use as identity file to login to the jump host itself
    val hostKeyFile = File.createTempFile("kjump_host_", ".key")
    hostKeyFile.writeText(prep.jumpHostPrivateKey)
    try {
        Files.setPosixFilePermissions(hostKeyFile.toPath(), PosixFilePermissions.fromString("rw-------"))
    } catch (_: Exception) {
        ProcessBuilder("chmod", "600", hostKeyFile.absolutePath).start().waitFor()
    }

    // Delete the host key after 5 seconds via coroutine
    launch(Dispatchers.IO) {
        delay(5000)
        if (hostKeyFile.exists()) hostKeyFile.delete()
    }

    // The command to run on the jump host: connect to target and ensure the target temp key is deleted afterwards
    val remoteCommand =
        "ssh -tt -o StrictHostKeyChecking=accept-new -i ${prep.remoteKeyPath} -p ${prep.targetPort} ${prep.targetUser}@${prep.targetIp}; rm -v ${prep.remoteKeyPath}"

    val pb = ProcessBuilder(
        "ssh",
        "-tt",
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", hostKeyFile.absolutePath,
        "${prep.jumpUser}@${prep.jumpHost}",
        remoteCommand
    )

    pb.environment().remove("DISPLAY")
    pb.inheritIO()
    val process = pb.start()
    process.waitFor()
    println("\n[SSH Session Ended]")
}

/**
 * Performs login to the server and retrieves the API-Token.
 */
suspend fun login() {
    println("\n--- LOGIN TO K-JUMP SERVER ---")
    print("User Token: ")
    val console = System.console()
    val (host, token) = (if (console != null) String(console.readPassword()) else readln()).let { input ->
        input.fromBase64().split("€")
            .let { "http://" + it[0] + ":8090" to it[1] } //ToDo: Default muss nach der Entwicklung HTTPS sein.
    }

    val response = try {
        client.post("$host/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(token.trim()))
        }
    } catch (e: Exception) {
        println("Error connecting to server for login: ${e.message}")
        exitProcess(1)
    }

    if (response.status == HttpStatusCode.OK) {

        apiToken = response.body<LoginResponse>().apiToken
        userToken = token.trim()
        jumpHost = host.trim()
        println("Login successful!")
    } else {
        println("Login failed: ${response.status} - ${response.bodyAsText()}")
        exitProcess(1)
    }
}
