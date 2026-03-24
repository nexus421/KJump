package bayern.kickner

import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*

/**
 * Configures JSON serialization for Ktor using kotlinx.serialization.
 */
fun Application.configureSerialization() {
    install(ContentNegotiation) {
        json()
    }
}
