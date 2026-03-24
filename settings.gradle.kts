pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }

    resolutionStrategy {
        eachPlugin {
            // Map the plugin ID to the Maven artifact
            if (requested.id.id == "io.objectbox") {
                useModule("io.objectbox:objectbox-gradle-plugin:${requested.version}")
            }
        }
    }
}
rootProject.name = "KJump"

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven("https://packages.confluent.io/maven/")
        maven {
            name = "nexus421Maven"
            url = uri("https://maven.kickner.bayern/releases")
        }
    }
}
