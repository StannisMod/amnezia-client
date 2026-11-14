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
# IFW schedules deletion of its running maintenance executable after exit.
# A short-lived remote test session can otherwise leave that child cleanup
# unfinished and make the next clean installation look like an upgrade.
if ($Uninstall -and $Kind -eq 'exe' -and $p.ExitCode -eq 0) {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Test-Path -LiteralPath $Package -PathType Leaf) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    if (Test-Path -LiteralPath $Package -PathType Leaf) {
        throw 'EXE uninstaller exited successfully but its deferred cleanup did not finish'
    }
}
Write-Host "Installer process completed: $($p.ExitCode)"
