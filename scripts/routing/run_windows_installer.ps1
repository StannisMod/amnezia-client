param(
    [Parameter(Mandatory=$true)][ValidateSet('msi','exe')][string]$Kind,
    [Parameter(Mandatory=$true)][string]$Package,
    [switch]$Uninstall,
    [string]$LogPath = 'routing-msi-install.log'
)
$ErrorActionPreference = 'Stop'
if ($Kind -eq 'msi') {
    $program = 'msiexec.exe'
    $operation = if ($Uninstall) { '/x' } else { '/i' }
    $arguments = @($operation, "`"$Package`"", '/qn', '/norestart', '/l*v', "`"$LogPath`"")
} else {
    $program = $Package
    if ($Uninstall) {
        $arguments = @('--default-answer', '--confirm-command', 'purge')
    } else {
        $target = "$env:ProgramFiles/AmneziaVPN"
        $arguments = @('--root', "`"$target`"", '--accept-licenses', '--default-answer', '--confirm-command', 'install')
    }
}
Write-Host "Starting $Kind installer; uninstall=$Uninstall"
# Start-Process -Wait also waits for descendant processes. Installers can start
# the long-lived VPN service, so wait for the installer process itself instead.
$p = Start-Process $program -ArgumentList $arguments -PassThru
if (-not $p.WaitForExit(300000)) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    throw 'Installer process exceeded five minutes'
}
$p.Refresh()
$allowed = @(0,3010)
if ($Uninstall -and $Kind -eq 'msi') { $allowed += 1605 }
if ($p.ExitCode -notin $allowed) { throw "Installer failed: $($p.ExitCode)" }
Write-Host "Installer process completed: $($p.ExitCode)"
