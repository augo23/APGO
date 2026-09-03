plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The release version, passed in by android/build-apk.sh as -PapgoVersion=X.Y.Z,
// which in turn gets it from build-release.sh (i.e. from the newest git tag).
// A bare `./gradlew assembleDebug` has no release to name, so it falls back to
// the same 1.0.0 the rest of the toolchain uses before any tag exists.
val apgoVersion: String =
    (findProperty("apgoVersion") as String?)?.takeIf { it.isNotBlank() } ?: "1.0.0"
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
    implementation("com.android.billingclient:billing-ktx:7.1.1")

    // ZXing embedded QR scanner (Scan QR to join).
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
