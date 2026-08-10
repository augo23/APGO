# APGO for Android

A native Android VPN client (VpnService + Jetpack Compose UI) that runs the same
Go overlay core as the desktop client, compiled to an `.aar` with gomobile. This
is a complete Gradle project that builds to an installable **APK**.

Unlike iOS, Android needs **no paid developer account** — you build an APK and
install it directly (`adb install`, or copy it to the phone and tap it).

## One command build (installs everything)

On a Mac or a Debian/Ubuntu machine:

```
cd android
bash build-apk.sh
```

`build-apk.sh` installs whatever is missing — Go, gomobile, JDK 17, the Android
SDK + NDK, and Gradle — then builds the overlay core and assembles the APK. It's
safe to re-run. When it finishes you get:

```
android/app/build/outputs/apk/debug/app-debug.apk
```

## Put it on your phone

1. Enable **Developer options** on the phone: Settings → About phone → tap
   **Build number** 7 times.
2. In Developer options, turn on **USB debugging**.
3. Plug the phone into the computer, accept the "Allow USB debugging" prompt.
4. Install:
   ```
   adb install -r android/app/build/outputs/apk/debug/app-debug.apk
   ```
   (Or copy the `.apk` to the phone and tap it — allow "install from this
   source" when prompted.)
5. Open APGO, enter the **same network name + PSK** as your other nodes, pick a
   unique last octet, and tap **Connect**. Android shows a one-time VPN consent
   dialog — allow it.

## Project layout

```
android/
├── settings.gradle.kts / build.gradle.kts / gradle.properties
├── build-apk.sh              # installs prereqs, builds core + APK
├── build-aar.sh              # builds the gomobile .aar from ios/core
└── app/
    ├── build.gradle.kts
    ├── libs/overlaymobile.aar         # produced by build-aar.sh
    └── src/main/
        ├── AndroidManifest.xml        # VpnService + permissions
        ├── res/values/…               # strings, theme
        └── java/org/apgo/app/
            ├── MainActivity.kt        # Compose UI: config + Connect
            └── OverlayVpnService.kt   # VpnService: tun -> Go core
```

## How it works

The overlay engine (Noise handshake, sessions, tracker/STUN discovery, endpoint
roaming, admin-key seeding) is the shared Go core in `ios/core` — it's
platform-neutral, so both mobile apps bind the same package. gomobile emits
`org.apgo.overlaymobile.Overlaymobile` with `start(fd, json)` / `stop()`.

`OverlayVpnService` builds the tun with `VpnService.Builder` (overlay IP + route
+ MTU), then hands the tun's file descriptor to `Overlaymobile.start`, which runs
the overlay over it. The node key is stored in the app's private `filesDir`.

## Signing a release APK (optional)

The debug APK is signed with the auto-generated debug key — fine for your own
device. For a shareable/Play build, create a keystore and add a `signingConfig`
to `app/build.gradle.kts`, then run `./gradlew :app:assembleRelease`.

## Notes

- Requires **Gradle 8.7+** and **JDK 17** (the script handles both).
- The first `sdkmanager` run downloads a few hundred MB (SDK platform + NDK).
- gomobile prints `skipping unsupported` warnings for the core's internal API —
  expected; `start`/`stop`/`running` are still exported.
