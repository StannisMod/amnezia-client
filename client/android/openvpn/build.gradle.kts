plugins {
    id(libs.plugins.android.library.get().pluginId)
    id(libs.plugins.kotlin.android.get().pluginId)
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "org.amnezia.vpn.protocol.openvpn"
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation(project(":utils"))
    testImplementation(project(":protocolApi"))
    compileOnly(project(":utils"))
    compileOnly(project(":protocolApi"))
    implementation(libs.kotlinx.coroutines)
}
