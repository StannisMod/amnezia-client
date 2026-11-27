plugins {
    id(libs.plugins.android.library.get().pluginId)
    id(libs.plugins.kotlin.android.get().pluginId)
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "org.amnezia.vpn.protocol.openvpn"
    // Supplied by the SAME Conan build as libovpn3.so. Never compile the
    // checked-in wrappers, which may silently describe an older native ABI.
    sourceSets.getByName("main").java.setSrcDirs(listOf("generated/java"))
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation(project(":utils"))
    testImplementation(project(":protocolApi"))
    compileOnly(project(":utils"))
    compileOnly(project(":protocolApi"))
    implementation(libs.kotlinx.coroutines)
}
