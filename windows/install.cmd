@echo off
REM APGO Windows installer. Double-click, or run from a terminal:
REM     windows\install.cmd
REM It builds the client + tray app, fetches wintun.dll, installs to
REM %LOCALAPPDATA%\APGO, adds a startup shortcut, and launches it.
REM No admin needed to install; the client elevates via UAC at Connect.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if errorlevel 1 (
    echo.
    echo Install failed. See the error above.
    pause
    exit /b 1
)
