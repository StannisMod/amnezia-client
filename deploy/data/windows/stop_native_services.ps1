$ErrorActionPreference = 'Stop'
# Shared by CMD hooks and embedded pre-payload IFW/MSI operations. Never let
# an installer replace/remove the service while durable DNS cleanup is pending.
function Stop-Native($name) {
    $entry = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {$_.Name -eq $name}
    if (!$entry) { return }
    $process = $null
    try {
        if ($entry.ProcessId -gt 0) {
            $process = Get-Process -Id $entry.ProcessId -ErrorAction Stop
            $null = $process.Handle
        }
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne 'Stopped' -and $service.Status -ne 'StopPending') {
            $service.Stop()
        }
        while ($service.Status -ne 'Stopped') {
            try {
                $service.WaitForStatus('Stopped', (New-TimeSpan -Seconds 5))
            } catch {
                if (!$_.Exception.InnerException -or
                    $_.Exception.InnerException.GetType().FullName -ne 'System.ServiceProcess.TimeoutException') {
                    throw
                }
                $service.Refresh()
                if ($service.Status -ne 'StopPending' -and $service.Status -ne 'Stopped') { throw }
            }
        }
        # SCM can report STOPPED before its final process handle is signaled.
        if ($process) { $process.WaitForExit() }
    } finally {
        if ($process) { $process.Dispose() }
    }
}
Stop-Native 'AmneziaVPN-service'
Stop-Native 'AmneziaWGTunnel$AmneziaVPN'
if (Get-Process -Name 'AmneziaVPN-service' -ErrorAction SilentlyContinue) {
    throw 'Unmanaged service process remains; refusing payload replacement/removal'
}
