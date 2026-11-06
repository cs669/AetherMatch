pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://dl.cloudsmith.io/public/libp2p/jvm-libp2p/maven/") }
        maven { url = uri("https://artifacts.consensys.net/public/maven/maven/") }
        maven { url = uri("https://jitpack.io") }
    }
}

rootProject.name = "AetherMatch"
include(":app")
