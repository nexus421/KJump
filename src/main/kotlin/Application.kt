package bayern.kickner

import bayern.kickner.db.DatabaseFactory
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.infoLog
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.request.*
import org.slf4j.event.Level

/**
 * Entry point for the K-Jump Server.
 * Initializes the embedded Ktor server with CIO engine.
 */
fun main(args: Array<String>) {
    println("""
        
        |----------------------------------------------------------|
        |                  K-Jump SSH Launcher                     |
        |            Secure SSH Management at your tips            |
        |----------------------------------------------------------|
        
    """.trimMargin())

    initLogging()

    val port = args.find { it.startsWith("--port=") }?.substringAfter("=")?.toIntOrNull() ?: 8090

    KLogger.info("Startup") { "Starting K-Jump Server..." }

    DatabaseFactory.init(port)

    embeddedServer(CIO, port = port, host = "0.0.0.0", module = Application::module).start(wait = true)
}

/**
 * Main module of the Ktor application.
 * Installs logging, initializes the database, and configures features.
 */
fun Application.module() {
    install(CallLogging) {
        level = Level.INFO
        filter { call -> call.request.path().startsWith("/") }
    }
    infoLog { "Loading application modules..." }
    DatabaseFactory.init()
    DatabaseFactory.startCleanupTask(this)
    configureAdministration()
    configureSerialization()
    configureRouting()
    val config = DatabaseFactory.systemConfigBox.all.firstOrNull()
    val port = config?.port ?: 8090
    infoLog { "K-Jump Server is ready and listening on http://0.0.0.0:$port" }
}


private fun initLogging() {
    KLogger.configure {
        logToConsole()
    }
}