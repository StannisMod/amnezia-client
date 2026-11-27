plugins {
    id(libs.plugins.android.library.get().pluginId)
    id(libs.plugins.kotlin.android.get().pluginId)
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "org.amnezia.vpn.util"

    buildFeatures {
        // add BuildConfig class
        buildConfig = true
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    implementation(libs.androidx.core)
    implementation(libs.kotlinx.coroutines)
    implementation(libs.androidx.security.crypto)
}
