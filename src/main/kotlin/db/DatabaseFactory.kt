package bayern.kickner.db

import bayern.kickner.klogger.errorLog
import bayern.kickner.klogger.infoLog
import bayern.kickner.model.MyObjectBox
import bayern.kickner.model.ServerEntryEntity
import bayern.kickner.model.SystemConfig
import bayern.kickner.model.User
import bayern.kickner.totp.Totp
import io.objectbox.Box
import io.objectbox.BoxStore
import kotlinx.coroutines.*
import kotnexlib.crypto.hashBC
import kotnexlib.toBase64
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.minutes

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
    fun init(port: Int = 8090) {
        if (::store.isInitialized) return
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

        val config = ensureConfigInitialized(port)
        ensureAdminCreated(config.globalJumpIp, config.port)
        ensureHostKeyExists()
        ensureServiceScriptExists()
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
     * @return The system configuration.
     */
    private fun ensureConfigInitialized(port: Int): SystemConfig {
        val configBox = store.boxFor(SystemConfig::class.java)
        if (configBox.isEmpty) {
            println("\n" + "=".repeat(60))
            println("FIRST-TIME SETUP: Global Jump IP required.")
            print("Please enter the GLOBAL PUBLIC IP or HOSTNAME of this server: ")
            val ip = readln().trim()

            val config = SystemConfig(
                globalJumpIp = ip,
                apiToken = generateSecureToken(),
                port = port
            )
            configBox.put(config)

            println("Configuration saved. Global Jump IP set to: $ip (Port: $port)")
            println("API-Token generated and saved to database.")
            println("=".repeat(60) + "\n")

            infoLog { "Global Jump Host IP set to: $ip (Port: $port)" }
        } else {
            val config = configBox.all.first()
            if (config.port != port) {
                println("\n" + "!".repeat(60))
                println("WARNING: Port mismatch!")
                println("The server was started with port $port, but the stored port is ${config.port}.")
                println("Updating database to use port $port.")
                println("!".repeat(60) + "\n")

                infoLog { "Updating port in database from ${config.port} to $port" }
                config.port = port
                configBox.put(config)
            }
        }

        return configBox.all.first()
    }

    /**
     * Creates an initial admin user if the database is empty.
     */
    private fun ensureAdminCreated(hostIp: String, port: Int) {
        val userBox = store.boxFor(User::class.java)
        if (userBox.isEmpty) {
            infoLog { "No users found in database. Performing first-time setup..." }

            val adminToken = generateSecureToken()
            val totpSecret = Totp.generateSecret()
            val admin = User(
                hashedToken = adminToken.hashBC(),
                totpSecret = totpSecret
            )
            userBox.put(admin)

            println("\n" + "=".repeat(60))
            println("INITIAL SETUP: User created successfully!")
            println("Initial Token: $adminToken")
            println("TOTP Secret: $totpSecret")
            println("Combined Token for login: ${("$hostIp:$port€$adminToken").toBase64()}") //Used so you only need one token to login!
            println("This is the token you will need to login to the server.")
            println("PLEASE SAVE THIS TOKEN! You will need it to login.")
            println("=".repeat(60) + "\n")

            infoLog { "Initial user created successfully." }
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

    /**
     * Starts a background task to clean up old temporary SSH key files.
     */
    fun startCleanupTask(scope: CoroutineScope) {
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                try {
                    val tempDir = File(System.getProperty("java.io.tmpdir"))
                    val now = System.currentTimeMillis()
                    val files = tempDir.listFiles { _, name -> name.startsWith("kjump_ssh_") && name.endsWith(".key") }
                    files?.forEach { file ->
                        if (now - file.lastModified() > TimeUnit.MINUTES.toMillis(5)) {
                            if (file.delete()) {
                                infoLog { "Cleaned up old temporary SSH key file: ${file.name}" }
                            }
                        }
                    }
                } catch (e: Exception) {
                    errorLog("Error during temp file cleanup", e)
                }
                delay(10.minutes)
            }
        }
    }

    /**
     * Creates a bash script for systemd service installation if it doesn't exist.
     */
    private fun ensureServiceScriptExists() {
        val scriptFile = File("kjump-service.sh")
        if (scriptFile.exists()) return

        val scriptContent = $$"""
            #!/bin/bash
            
            # K-Jump Service Management Script
            
            SERVICE_NAME="kjump"
            JAR_NAME="kjump_server.jar"
            SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
            WORKING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
            
            if [[ $EUID -ne 0 ]]; then
               echo "This script must be run as root (use sudo)"
               exit 1
            fi
            
            install() {
                if [ ! -f "$WORKING_DIR/$JAR_NAME" ]; then
                    echo "Error: $JAR_NAME not found in $WORKING_DIR"
                    echo "Please ensure this script and $JAR_NAME are in the same directory."
                    exit 1
                fi
            
                echo "Creating systemd service file..."
                
                JAVA_PATH=$(which java)
                if [ -z "$JAVA_PATH" ]; then
                    JAVA_PATH="/usr/bin/java"
                fi
            
                # Detect the actual user who is running sudo
                ACTUAL_USER=${SUDO_USER:-$(logname || echo $USER)}
            
                cat <<EOF > $SERVICE_FILE
            [Unit]
            Description=K-Jump SSH Launcher Service
            After=network.target
            
            [Service]
            Type=simple
            User=$ACTUAL_USER
            WorkingDirectory=$WORKING_DIR
            ExecStart=$JAVA_PATH -jar $WORKING_DIR/$JAR_NAME
            Restart=always
            
            [Install]
            WantedBy=multi-user.target
            EOF
            
                echo "Reloading systemd daemon..."
                systemctl daemon-reload
                echo "Enabling and starting $SERVICE_NAME..."
                systemctl enable $SERVICE_NAME
                systemctl start $SERVICE_NAME
                
                if systemctl is-active --quiet $SERVICE_NAME; then
                    echo "Success: $SERVICE_NAME is now running."
                else
                    echo "Error: $SERVICE_NAME failed to start. Check 'journalctl -u $SERVICE_NAME'"
                fi
            }
            
            uninstall() {
                echo "Stopping $SERVICE_NAME..."
                systemctl stop $SERVICE_NAME
                echo "Disabling $SERVICE_NAME..."
                systemctl disable $SERVICE_NAME
                
                if [ -f "$SERVICE_FILE" ]; then
                    echo "Removing $SERVICE_FILE..."
                    rm "$SERVICE_FILE"
                fi
                
                echo "Reloading systemd daemon..."
                systemctl daemon-reload
                echo "$SERVICE_NAME uninstalled successfully."
            }
            
            case "$1" in
                install)
                    install
                    ;;
                uninstall)
                    uninstall
                    ;;
                *)
                    echo "Usage: $0 {install|uninstall}"
                    exit 1
                    ;;
            esac
        """.trimIndent()

        try {
            scriptFile.writeText(scriptContent)
            scriptFile.setExecutable(true)
            infoLog { "Service installation script created: kjump-service.sh" }
        } catch (e: Exception) {
            errorLog("Failed to create service installation script", e)
        }
    }
}
