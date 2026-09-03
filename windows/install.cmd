@echo off
REM APGO Windows installer. Double-click, or run from a terminal:
REM     windows\install.cmd
REM It builds the client + tray app, fetches wintun.dll, installs to
REM %LOCALAPPDATA%\APGO, adds a startup shortcut, and launches it.
REM No admin needed to install; the client elevates via UAC at Connect.
REM
REM Existing settings and node identity in %USERPROFILE%\.apgo are KEPT.
REM To start over from a new node identity:
REM     windows\install.cmd -Fresh
REM
REM -NonInteractive is deliberate: it turns any unexpected prompt into an
REM error instead of a script that waits forever for input nobody can see.

powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
if errorlevel 1 (
    echo.
    echo Install failed. See the error above.
    pause
    exit /b 1
)
