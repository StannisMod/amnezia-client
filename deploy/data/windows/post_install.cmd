@echo off
rem The service, not the GUI, owns DNS/native cleanup. Never force-kill it.
taskkill /IM "AmneziaVPN.exe" /F
powershell -NoProfile -NonInteractive -EncodedCommand @AMNEZIA_WINDOWS_STOP_ENCODED@
if errorlevel 1 exit /b 1
sc query "AmneziaWGTunnel$AmneziaVPN" >nul 2>&1
if not errorlevel 1 (
    sc delete "AmneziaWGTunnel$AmneziaVPN"
    if errorlevel 1 exit /b 1
)
powershell -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; if(Get-Process -Name 'AmneziaVPN-service' -ErrorAction SilentlyContinue){throw 'Unmanaged service process remains; refusing forced termination'}; Start-Service 'AmneziaVPN-service'; (Get-Service 'AmneziaVPN-service').WaitForStatus('Running',(New-TimeSpan -Seconds 30))"
if errorlevel 1 exit /b 1
exit /b 0
