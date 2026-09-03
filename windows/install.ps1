# APGO Windows installer. Builds the Wintun client + the shared tray app,
# fetches wintun.dll, installs to %LOCALAPPDATA%\APGO, adds a startup shortcut,
# and launches it. No admin needed to install (the client elevates itself via
# UAC at Connect). Invoked by install.cmd.
#
#   -Fresh    also delete the existing node identity and settings (~\.apgo).
#             NOT the default: wiping it gives this machine a brand-new node
#             key, so the mesh sees an unknown device and — on a network with
#             admission control — parks it in "pending approval" until an
#             admin re-approves it. Reinstalling should not silently do that.
#   -SkipGo   never download Go; fail if a suitable Go is not already present.
param(
    [switch]$Fresh,
    [switch]$SkipGo
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # Write-Progress makes downloads
                                              # and Expand-Archive many times
                                              # slower in Windows PowerShell.
$repo = Split-Path -Parent $PSScriptRoot   # windows/ -> repo root
Write-Host "=== APGO Windows installer ===" -ForegroundColor Cyan

# TLS 1.2+ for older PowerShell/.NET so downloads from go.dev / wintun.net work.
# The type is SecurityProtocolType — the old code named a type that does not
# exist, so the whole line threw into its own catch and TLS 1.2 was NEVER
# enabled. On a stock Windows build whose .NET still defaults to TLS 1.0 that
# made every download in this script fail or hang with no explanation.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
} catch {
    Write-Host "  (could not raise the TLS version; downloads may fail on old Windows)"
}

# Download helper. Every download in this script goes through it so that all of
# them get the two things the originals lacked:
#   -UseBasicParsing : Windows PowerShell 5.1's Invoke-WebRequest otherwise
#                      spins up the Internet Explorer engine, which on a
#                      machine where IE's first-run wizard was never completed
#                      either throws or blocks indefinitely. This is the single
#                      most common reason a PowerShell installer "just hangs".
#   -TimeoutSec      : without it a stalled connection waits forever, showing
#                      nothing at all on screen.
function Get-File {
    param([string]$Url, [string]$OutFile, [int]$TimeoutSec = 300)
    Write-Host "  downloading $Url"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSec
    } catch {
        throw "download failed: $Url`n  $($_.Exception.Message)"
    }
    if (-not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -eq 0) {
        throw "download produced an empty file: $Url"
    }
}

# Expand-Archive is very slow on large zips in Windows PowerShell (the Go
# toolchain is ~250 MB and can take minutes with no output, which reads as a
# hang). The .NET extractor does the same job in seconds.
function Expand-Zip {
    param([string]$Zip, [string]$Dest)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    try {
        New-Item -ItemType Directory -Force -Path $Dest | Out-Null
        # Entry by entry rather than ExtractToDirectory: that helper REFUSES a
        # destination that already exists, which is the normal case here (a
        # reinstall, or the APGO folder we just created). Falling back to
        # Expand-Archive in that case would have quietly given up the whole
        # speed-up, on the one archive — the 250 MB Go toolchain — that needs it.
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
        try {
            $root = [System.IO.Path]::GetFullPath($Dest)
            foreach ($entry in $archive.Entries) {
                $target = [System.IO.Path]::GetFullPath((Join-Path $root $entry.FullName))
                # Refuse entries that escape the destination (zip-slip). The
                # archives here are trusted, but an extractor that can write
                # anywhere on disk is not something to leave lying in a repo.
                if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { continue }
                if ($entry.FullName.EndsWith('/')) {
                    New-Item -ItemType Directory -Force -Path $target | Out-Null
                    continue
                }
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
            }
        } finally { $archive.Dispose() }
    } catch {
        Write-Host "  (fast extract unavailable: $($_.Exception.Message); falling back — this is slow)"
        Expand-Archive -Path $Zip -DestinationPath $Dest -Force
    }
}

# --- prerequisites: auto-install Go if missing or too old -------------------
$GoMin    = [version]'1.23.1'
$GoTarget = '1.24.5'
$arch     = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }

function Get-GoVersion {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    # A broken or half-extracted go.exe can hang forever on `go version`, which
    # would stall the installer before it prints anything useful. Run it with a
    # hard deadline instead of trusting it.
    try {
        $p = Start-Process -FilePath $cmd.Source -ArgumentList 'version' -NoNewWindow -PassThru `
                           -RedirectStandardOutput "$env:TEMP\apgo-gover.txt" `
                           -RedirectStandardError  "$env:TEMP\apgo-gover.err"
        if (-not $p.WaitForExit(15000)) {
            try { $p.Kill() } catch {}
            Write-Host "  (the 'go' on PATH did not respond; treating it as unusable)"
            return $null
        }
        $v = Get-Content "$env:TEMP\apgo-gover.txt" -Raw -ErrorAction SilentlyContinue
    } catch { return $null }
    if ($v -match 'go(\d+)\.(\d+)(?:\.(\d+))?') {
        $patch = if ($matches[3]) { $matches[3] } else { '0' }
        return [version]("{0}.{1}.{2}" -f $matches[1], $matches[2], $patch)
    }
    return $null
}

function Install-Go {
    param([string]$Ver)
    $url  = "https://go.dev/dl/go$Ver.windows-$arch.zip"
    $zip  = Join-Path $env:TEMP "go$Ver.zip"
    Write-Host "Downloading Go $Ver ($arch) — this is a large file, please wait..."
    Get-File -Url $url -OutFile $zip
    $dest = Join-Path $env:LOCALAPPDATA 'APGO'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Remove-Item -Recurse -Force (Join-Path $dest 'go') -ErrorAction SilentlyContinue
    Write-Host "Extracting Go to $dest\go ..."
    Expand-Zip -Zip $zip -Dest $dest     # unpacks to $dest\go
    Remove-Item $zip -ErrorAction SilentlyContinue
    $goBin = Join-Path $dest 'go\bin'
    if (-not (Test-Path (Join-Path $goBin 'go.exe'))) {
        throw "Go extraction did not produce $goBin\go.exe"
    }
    $env:PATH = "$goBin;$env:PATH"
    try {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($userPath -notlike "*$goBin*") {
            [Environment]::SetEnvironmentVariable('Path', "$goBin;$userPath", 'User')
        }
    } catch {}
}

$go = Get-GoVersion
if (-not $go -or $go -lt $GoMin) {
    if ($SkipGo) { throw "Go >= $GoMin is required and -SkipGo was given (found: $go)." }
    if ($go) { Write-Host "Found Go $go but need >= $GoMin — installing Go $GoTarget..." }
    else     { Write-Host "Go is not installed — downloading and installing Go $GoTarget..." }
    Install-Go -Ver $GoTarget
    $go = Get-GoVersion
    if (-not $go -or $go -lt $GoMin) {
        throw "Go install failed or is still too old ($go). Install Go $GoTarget from https://go.dev/dl/ manually and re-run."
    }
}
Write-Host "Using Go $go"

$install = Join-Path $env:LOCALAPPDATA 'APGO'
$build   = Join-Path $env:TEMP ("apgo-build-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $build | Out-Null

# Stop any running instance.
#
# The old code ran `taskkill` through `Start-Process -Verb RunAs -Wait`, which
# raises a UAC dialog DURING THE INSTALL and then blocks until it is answered.
# That dialog often opens behind the console window, and nobody expects a UAC
# prompt from an installer that advertises itself as not needing admin — so the
# script sat at "Stopping any running APGO..." indefinitely. That is the hang.
#
# Stop what we can as the current user, and if an elevated client is still
# running, SAY so and carry on: the files we are about to copy are only locked
# if it is, and we detect that below where we can report it properly.
Write-Host "Stopping any running APGO..."
Get-Process -Name 'APGO','overlay-client' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 700
$stillRunning = @(Get-Process -Name 'overlay-client' -ErrorAction SilentlyContinue)
if ($stillRunning.Count -gt 0) {
    Write-Host "  an elevated overlay-client is still running." -ForegroundColor Yellow
    Write-Host "  If the install fails to copy files, disconnect from the APGO tray icon first," -ForegroundColor Yellow
    Write-Host "  or run in an Administrator terminal:  taskkill /F /IM overlay-client.exe" -ForegroundColor Yellow
}

# Node identity and settings are PRESERVED unless -Fresh is given. See the
# param block for why wiping them by default was wrong.
$apgoState = Join-Path $env:USERPROFILE '.apgo'
if ($Fresh) {
    if (Test-Path $apgoState) {
        Write-Host "-Fresh: clearing node identity and settings ($apgoState)..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $apgoState -ErrorAction SilentlyContinue
    }
} elseif (Test-Path $apgoState) {
    Write-Host "Keeping existing settings and node identity in $apgoState (use -Fresh to reset)."
}

try {
    # `go mod tidy` is deliberately NOT run. go.mod and go.sum are committed, so
    # tidy adds nothing but a mandatory network round-trip on every install —
    # one that hangs rather than fails on a restricted or captive network, and
    # that rewrites the user's go.mod as a side effect. `go build` fetches
    # exactly what the build needs.
    Write-Host "Building overlay client (Wintun data plane)..."
    Push-Location (Join-Path $repo 'client')
    try {
        & go build -trimpath -o (Join-Path $build 'overlay-client.exe') .
        if ($LASTEXITCODE) { throw "client build failed (exit $LASTEXITCODE)" }
    } finally { Pop-Location }

    Write-Host "Building tray app (shared desktop module)..."
    Push-Location (Join-Path $repo 'desktop')
    try {
        # Embed the app icon via a .syso resource. Entirely cosmetic, and it
        # needs the network to fetch rsrc — so it must never be able to stop
        # the install. The old version could: `go install ...@latest` with no
        # timeout hangs on a slow or blocked module proxy.
        $syso = Join-Path $repo 'desktop\rsrc_windows.syso'
        $ico  = Join-Path $repo 'windows\app.ico'
        if (Test-Path $ico) {
            try {
                $gopath = (& go env GOPATH)
                $rsrc   = Join-Path $gopath 'bin\rsrc.exe'
                if (-not (Test-Path $rsrc)) {
                    Write-Host "  fetching rsrc (for the exe icon; optional)..."
                    $job = Start-Job { param($p) $env:PATH = $p; & go install github.com/akavel/rsrc@latest } -ArgumentList $env:PATH
                    if (Wait-Job $job -Timeout 90) { Receive-Job $job -ErrorAction SilentlyContinue | Out-Null }
                    else { Stop-Job $job -ErrorAction SilentlyContinue; Write-Host "  (rsrc fetch timed out; skipping the icon)" }
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path $rsrc) {
                    # -arch must match the build target, or the linker rejects
                    # the .syso and the whole tray build fails on ARM64 — a
                    # cosmetic feature breaking the actual product.
                    & $rsrc -ico $ico -arch $arch -o $syso 2>$null
                }
            } catch { Write-Host "  (icon embed skipped: $($_.Exception.Message))" }
        }
        # -H=windowsgui: no console window for the tray app.
        & go build -trimpath -ldflags '-H=windowsgui' -o (Join-Path $build 'APGO.exe') .
        $buildRc = $LASTEXITCODE
        Remove-Item $syso -ErrorAction SilentlyContinue
        if ($buildRc) { throw "tray app build failed (exit $buildRc)" }
    } finally { Pop-Location }

    Write-Host "Fetching wintun.dll..."
    $zip  = Join-Path $env:TEMP 'wintun.zip'
    Get-File -Url 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $zip
    $wdst = Join-Path $env:TEMP 'wintun-extract'
    Remove-Item -Recurse -Force $wdst -ErrorAction SilentlyContinue
    Expand-Zip -Zip $zip -Dest $wdst
    $dll = Join-Path $wdst "wintun\bin\$arch\wintun.dll"
    if (-not (Test-Path $dll)) { throw "wintun.dll for $arch not found in the downloaded archive" }
    Copy-Item $dll (Join-Path $build 'wintun.dll') -Force

    Write-Host "Installing to $install ..."
    New-Item -ItemType Directory -Force -Path $install | Out-Null
    foreach ($f in 'overlay-client.exe','APGO.exe','wintun.dll') {
        try {
            Copy-Item (Join-Path $build $f) $install -Force
        } catch {
            throw "could not replace $install\$f — APGO is probably still running. " +
                  "Disconnect from the tray icon (or run 'taskkill /F /IM overlay-client.exe' " +
                  "in an Administrator terminal) and re-run this installer.`n  $($_.Exception.Message)"
        }
    }

    Write-Host "Adding to startup..."
    $lnk = Join-Path ([Environment]::GetFolderPath('Startup')) 'APGO.lnk'
    $ws  = New-Object -ComObject WScript.Shell
    $sc  = $ws.CreateShortcut($lnk)
    $sc.TargetPath       = Join-Path $install 'APGO.exe'
    $sc.WorkingDirectory = $install
    $sc.Save()

    Write-Host "Launching APGO..."
    Start-Process -FilePath (Join-Path $install 'APGO.exe') -WorkingDirectory $install

    Write-Host ""
    Write-Host "Installed to $install. The APGO tray icon should appear." -ForegroundColor Green
    Write-Host "Click it -> Settings (set the same network name/PSK as your other nodes) -> Connect (UAC prompt)."
    Write-Host ""
    Write-Host "The client adds its own Windows Firewall rule for inbound UDP the first" -ForegroundColor DarkGray
    Write-Host "time it connects (it is elevated at that point; this installer is not)." -ForegroundColor DarkGray
    if (-not $Fresh) {
        Write-Host "Existing settings were kept. Re-run with -Fresh to start from a new node identity." -ForegroundColor DarkGray
    }
}
finally {
    Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue
}
