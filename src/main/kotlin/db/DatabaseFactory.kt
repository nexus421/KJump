package bayern.kickner.db

import bayern.kickner.klogger.errorLog
import bayern.kickner.klogger.infoLog
import bayern.kickner.model.MyObjectBox
import bayern.kickner.model.ServerEntryEntity
import bayern.kickner.model.SystemConfig
import bayern.kickner.model.User
import io.objectbox.Box
import io.objectbox.BoxStore
import kotnexlib.crypto.hashBC
import kotnexlib.toBase64
import java.io.File
import java.security.SecureRandom

/**
 * Handles database initialization and maintenance using ObjectBox.
 */
object DatabaseFactory {

    /**
     * The ObjectBox store instance.
     */
    lateinit var store: BoxStore
        private set

    val systemConfigBox: Box<SystemConfig>
        get() = store.boxFor(SystemConfig::class.java)

    val userBox: Box<User>
        get() = store.boxFor(User::class.java)

    val serverEntryBox: Box<ServerEntryEntity>
        get() = store.boxFor(ServerEntryEntity::class.java)

    /**
     * Initializes the database, sets up the storage directory, and ensures initial data.
     */
    fun init() {
        infoLog { "Initializing Database..." }
        val dbDir = File("kjump-db")
        if (dbDir.exists().not()) {
            infoLog { "Creating database directory: ${dbDir.absolutePath}" }
            dbDir.mkdirs()
        }

        store = MyObjectBox.builder()
            .baseDirectory(dbDir)
            .build()

        infoLog {
            "Database initialized. Found ${store.boxFor(User::class.java).count()} users and ${
                store.boxFor(ServerEntryEntity::class.java).count()
            } server entries."
        }

        val hostIp = ensureConfigInitialized()
        ensureAdminCreated(hostIp)
        ensureHostKeyExists()
    }

    /**
     * Ensures an SSH key pair exists for the jump host.
     * Generates a new one if missing and appends the public key to authorized_keys.
     */
    private fun ensureHostKeyExists() {
        val keyFile = File("kjump-db/id_ed25519")
        if (keyFile.exists().not()) {
            infoLog { "Generating new Jump Host SSH Key pair..." }
            val pb = ProcessBuilder("ssh-keygen", "-t", "ed25519", "-f", keyFile.absolutePath, "-N", "")
            pb.start().waitFor()

            try {
                val pubKey = File(keyFile.absolutePath + ".pub").readText().trim()
                val sshDir = File(System.getProperty("user.home"), ".ssh")
                if (sshDir.exists().not()) sshDir.mkdirs()
                val authFile = File(sshDir, "authorized_keys")

                val currentAuth = if (authFile.exists()) authFile.readText() else ""
                if (currentAuth.contains(pubKey).not()) {
                    authFile.appendText("\n$pubKey\n")
                    infoLog { "Added public key to authorized_keys" }
                }
            } catch (e: Exception) {
                errorLog("Failed to update authorized_keys", e)
            }
        }
    }

    /**
     * Reads the private key for the jump host.
     */
    fun getJumpHostPrivateKey(): String {
        val keyFile = File("kjump-db/id_ed25519")
        if (keyFile.exists().not()) ensureHostKeyExists()
        return keyFile.readText()
    }

    /**
     * Ensures the system configuration is set up (e.g. global server IP).
     *
     * @return The global server IP or hostname.
     */
    private fun ensureConfigInitialized(): String {
        val configBox = store.boxFor(SystemConfig::class.java)
        if (configBox.isEmpty) {
            println("\n" + "=".repeat(60))
            println("FIRST-TIME SETUP: Global Jump IP required.")
            print("Please enter the GLOBAL PUBLIC IP or HOSTNAME of this server: ")
            val ip = readln().trim()

            val config = SystemConfig(
                globalJumpIp = ip,
                apiToken = generateSecureToken()
            )
            configBox.put(config)

            println("Configuration saved. Global Jump IP set to: $ip")
            println("API-Token generated and saved to database.")
            println("=".repeat(60) + "\n")

            infoLog { "Global Jump Host IP set to: $ip" }
        }

        return configBox.all.first().globalJumpIp
    }

    /**
     * Creates an initial admin user if the database is empty.
     */
    private fun ensureAdminCreated(hostIp: String) {
        val userBox = store.boxFor(User::class.java)
        if (userBox.isEmpty) {
            infoLog { "No users found in database. Performing first-time setup..." }

            val adminToken = generateSecureToken()
            val admin = User(
                username = "admin",
                hashedToken = adminToken.hashBC(),
                isAdmin = true
            )
            userBox.put(admin)

            println("\n" + "=".repeat(60))
            println("INITIAL SETUP: Admin user created successfully!")
            println("Username: admin")
            println("Initial Token: $adminToken")
            println("Combined Token for login: ${("$hostIp€$adminToken").toBase64()}") //Used so you only need one token to login!
            println("This is the token you will need to login to the server.")
            println("PLEASE SAVE THIS TOKEN! You will need it to login.")
            println("=".repeat(60) + "\n")

            infoLog { "Initial admin user created successfully." }
        }
    }

    /**
     * Generates a cryptographically secure token.
     */
    private fun generateSecureToken(): String {
        val bytes = ByteArray(64)
        SecureRandom().nextBytes(bytes)
        return bytes.toBase64()
    }
}
