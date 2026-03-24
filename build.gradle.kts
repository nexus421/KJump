val ktor_version = "3.4.0"

plugins {
    kotlin("jvm") version "2.3.0"
    id("io.ktor.plugin") version "3.4.0"
    id("org.jetbrains.kotlin.plugin.serialization") version "2.3.0"
    kotlin("kapt") version "2.3.0"
    id("io.objectbox") version "5.2.0"
    application
}

group = "bayern.kickner"
version = "0.0.1"

application {
//    mainClass.set("bayern.kickner.client.ClientKt")
    mainClass.set("bayern.kickner.ApplicationKt")
}

ktor {
    fatJar {
        archiveFileName.set("fat.jar")
    }
}

// @Suppress("DEPRECATION")
// mainClassName = "bayern.kickner.ApplicationKt"

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation("io.github.flaxoos:ktor-server-rate-limiting:2.2.1")
    implementation("io.ktor:ktor-server-core-jvm:$ktor_version")
    implementation("io.ktor:ktor-server-call-logging-jvm:$ktor_version")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:$ktor_version")
    implementation("io.ktor:ktor-serialization-kotlinx-json-jvm:$ktor_version")
    implementation("io.ktor:ktor-server-cio-jvm:$ktor_version")
    implementation("io.ktor:ktor-server-html-builder-jvm:$ktor_version")
    implementation("io.ktor:ktor-client-core-jvm:$ktor_version")
    implementation("io.ktor:ktor-client-cio-jvm:$ktor_version")
    implementation("io.ktor:ktor-client-content-negotiation-jvm:$ktor_version")
    implementation("io.ktor:ktor-serialization-kotlinx-json-jvm:$ktor_version")
    implementation("ch.qos.logback:logback-classic:1.5.31")
    implementation("bayern.kickner:KotNexLib:4.3.0")
    implementation("bayern.kickner:Klogger:0.0.3")

    // ObjectBox
    implementation("io.objectbox:objectbox-kotlin:4.0.0")
    kapt("io.objectbox:objectbox-processor:4.0.0")

    testImplementation("io.ktor:ktor-server-test-host-jvm:$ktor_version")
}