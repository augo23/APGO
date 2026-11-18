import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The release version, passed in by android/build-apk.sh as -PapgoVersion=X.Y.Z,
// which in turn gets it from build-release.sh (i.e. from the newest git tag).
// A bare `./gradlew assembleDebug` has no release to name, so it falls back to
// the same 1.0.0 the rest of the toolchain uses before any tag exists.
//
// Second source: app/version.properties (versionName=X.Y.Z). It is not in the
// private repo; push-github.sh writes it into the PUBLIC snapshot of each
// release, because F-Droid builds from that snapshot with plain Gradle and
// reads the version from it (see fdroid/org.apgo.app.yml).
val apgoVersionFile: String? = file("version.properties").takeIf { it.isFile }?.let { f ->
    Properties().apply { f.inputStream().use { load(it) } }
        .getProperty("versionName")?.trim()?.takeIf { it.isNotBlank() }
}
val apgoVersion: String =
    (findProperty("apgoVersion") as String?)?.takeIf { it.isNotBlank() }
        ?: apgoVersionFile ?: "1.0.0"
// Tolerant of junk on purpose: a malformed version should still produce an APK
// rather than failing the last step of a long release build.
val apgoParts: List<Int> = apgoVersion.split(".").map { it.toIntOrNull() ?: 0 }

android {
    namespace = "org.apgo.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.apgo.app"
        minSdk = 24
        targetSdk = 34
        // Android will not install an update over an existing install unless
        // versionCode INCREASES, so it has to track the release — putting the
        // version only in the filename leaves every build looking identical to
        // the device. major*10000 + minor*100 + patch stays monotonic across
        // the same ordering git uses, with room for 99 minors and 99 patches.
        // (v1.0.0 -> 10000, comfortably above the hardcoded 1 shipped before.)
        versionCode = apgoParts.getOrElse(0) { 0 } * 10000 +
            apgoParts.getOrElse(1) { 0 } * 100 +
            apgoParts.getOrElse(2) { 0 }
        versionName = apgoVersion
    }

    // Two builds from one source tree:
    //   play   — Google Play: donations through Google Play Billing.
    //   fdroid — F-Droid: no proprietary libraries; donation links only.
    flavorDimensions += "store"
    productFlavors {
        create("play") { dimension = "store" }
        create("fdroid") { dimension = "store" }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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
    }
    composeOptions {
        // Compatible with Kotlin 1.9.24.
        kotlinCompilerExtensionVersion = "1.5.14"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

// Pin every resolved dependency version in gradle.lockfile so builds are
// reproducible and a dependency can't silently change underneath a release.
// After changing dependencies: ./gradlew :app:dependencies --write-locks
dependencyLocking {
    lockAllConfigurations()
}

// Netty is not part of the app: it comes in only through the Android Gradle
// Plugin's own test-device tooling (the _internal-unified-test-platform-*
// configurations, via grpc-netty), which runs on the build machine and never
// ships in an APK. AGP pins 4.1.93.Final, which carries known CVEs (request
// smuggling, hostname-verification and DoS issues), so raise every netty
// module together -- they must stay on one version -- to the patched 4.1 line.
// netty 4.1.x is API-compatible within the line, so grpc-netty keeps working.
val nettyVersion = "4.1.137.Final"
configurations.configureEach {
    resolutionStrategy.eachDependency {
        if (requested.group == "io.netty" && requested.name.startsWith("netty-")) {
            useVersion(nettyVersion)
            because("CVE fixes; netty is build tooling only (AGP test platform)")
        }
    }
}

dependencies {
    // The gomobile-built overlay core (app/libs/overlaymobile.aar), resolved via
    // the flatDir repo declared in settings.gradle.kts.
    implementation(group = "", name = "overlaymobile", ext = "aar")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation(platform("androidx.compose:compose-bom:2024.09.02"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")

    // Biometric / screen-lock app lock (mirrors the iOS Face ID app lock).
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.4")

    // Google Play Billing for in-app gifts to the project.
    "playImplementation"("com.android.billingclient:billing-ktx:7.1.1")

    // ZXing embedded QR scanner (Scan QR to join).
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
