@echo off
set AmneziaPath=%~dp0
echo %AmneziaPath%

rem Define directories for logs
set "ORG_DIR=%AppData%\AmneziaVPN.ORG"
set "USER_APP_DIR=%ORG_DIR%\AmneziaVPN"
set "USER_LOG_DIR=%USER_APP_DIR%\log"
set "SYS_APP_DIR=%ProgramData%\AmneziaVPN"
set "SYS_LOG_DIR=%SYS_APP_DIR%\log"
set "SYS_LOG_FILE=%SYS_LOG_DIR%\AmneziaVPN-service.log"

taskkill /IM "AmneziaVPN.exe" /F
rem Restore DNS and join the main service before retiring its native WG link.
powershell -NoProfile -NonInteractive -EncodedCommand @AMNEZIA_WINDOWS_STOP_ENCODED@
if errorlevel 1 exit /b 1
powershell -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; if(Get-Process -Name 'AmneziaVPN-service' -ErrorAction SilentlyContinue){throw 'Unmanaged service process remains; refusing forced termination'}"
if errorlevel 1 exit /b 1
sc query "AmneziaVPN-service" >nul 2>&1
if not errorlevel 1 (
    sc delete "AmneziaVPN-service"
    if errorlevel 1 exit /b 1
)
sc query "AmneziaWGTunnel$AmneziaVPN" >nul 2>&1
if not errorlevel 1 (
    sc delete "AmneziaWGTunnel$AmneziaVPN"
    if errorlevel 1 exit /b 1
)

rem Delete the service log file under ProgramData
if exist "%SYS_LOG_FILE%" del /F /Q "%SYS_LOG_FILE%"
if exist "%SYS_LOG_DIR%" rmdir /S /Q "%SYS_LOG_DIR%"
rem Try to remove application dir if empty
rd "%SYS_APP_DIR%" 2>nul

rem Delete client logs under current user's AppData\Roaming (Organization\Application)
if exist "%USER_LOG_DIR%" rmdir /S /Q "%USER_LOG_DIR%"
rem Try to remove app and org directories if empty
rd "%USER_APP_DIR%" 2>nul
rd "%ORG_DIR%" 2>nul

exit /b 0
