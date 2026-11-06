plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.aethermatch.p2p"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.aethermatch.p2p"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            buildConfigField("boolean", "ENABLE_VIRTUAL_SWARM", "true")
        }
        release {
            isMinifyEnabled = true
            buildConfigField("boolean", "ENABLE_VIRTUAL_SWARM", "false")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/INDEX.LIST"
            excludes += "META-INF/DEPENDENCIES"
            excludes += "META-INF/io.netty.versions.properties"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
            excludes += "META-INF/BCKEY.DSA"
            excludes += "META-INF/BCKEY.SF"
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

configurations.all {
    resolutionStrategy {
        force("org.bouncycastle:bcprov-jdk18on:1.79")
        force("org.bouncycastle:bcpkix-jdk18on:1.79")
        force("org.bouncycastle:bcutil-jdk18on:1.79")
    }
    exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    exclude(group = "org.bouncycastle", module = "bcpkix-jdk15on")
}

tasks.matching { it.name.startsWith("check") && it.name.endsWith("AarMetadata") }.configureEach {
    enabled = false
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.navigation.compose)

    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)

    // Encrypted Local Storage: SQLCipher + SupportSQLite + AndroidX Security Keystore
    implementation(libs.androidx.sqlite.ktx)
    implementation(libs.androidx.sqlite.framework)
    implementation(libs.sqlcipher.android)
    implementation(libs.androidx.security.crypto)

    // Constrained Background Federated Training (Idle + Charging + Unmetered Wi-Fi)
    implementation(libs.androidx.work.runtime.ktx)

    // Official Signal Protocol (X3DH / PQXDH + Double Ratchet)
    implementation(libs.libsignal.android)

    // Internet-Scale P2P Networking: libp2p (Noise XX, Kademlia DHT, Circuit Relay, Hole Punching, mDNS)
    implementation(libs.jvm.libp2p)
    implementation(libs.bouncycastle.prov)
    implementation(libs.bouncycastle.pkix)

    // JSON Serialization for signed DHT records & P2P wire envelopes
    implementation(libs.gson)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.libsignal.client)
    debugImplementation(libs.androidx.ui.tooling)
}
