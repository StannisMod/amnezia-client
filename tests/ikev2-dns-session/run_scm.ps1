param([Parameter(Mandatory=$true)][string]$Build)
$ErrorActionPreference = 'Stop'
$name = 'AmneziaDnsStopBarrierFixture'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Refusing pre-existing fixture service' }
$exe = (Resolve-Path (Join-Path $Build 'test_deferred_service.exe')).Path
$state = Join-Path $Build 'fixture-state.json'
$release = Join-Path $Build 'fixture-release'
if ((Test-Path $state) -or (Test-Path $release)) { throw 'Refusing reused fixture state' }
$created = $false
try {
    & sc.exe create $name binPath= "`"$exe`"" start= demand
    if ($LASTEXITCODE -ne 0) { throw 'SCM fixture creation failed' }
    $created = $true
    Start-Service $name
    (Get-Service $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    $before = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($before.ProcessId -eq 0) { throw 'No service PID' }
    & sc.exe stop $name
    if ($LASTEXITCODE -ne 0) { throw 'SCM stop request failed' }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        if ((Test-Path $state) -and ((Get-Content $state -Raw | ConvertFrom-Json).phase -eq 'stop-pending')) { break }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Deferred handler readiness deadline' }
        Start-Sleep -Milliseconds 100
    } while ($true)
    function Checkpoint {
        $text = (& sc.exe queryex $name) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $text -notmatch 'CHECKPOINT\s+:\s+(0x[0-9a-fA-F]+)') {
            throw "Cannot read native SCM checkpoint: $text"
        }
        [Convert]::ToInt32($Matches[1].Substring(2),16)
    }
    $first = Checkpoint
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        Start-Sleep -Milliseconds 100
        $next = Checkpoint
        if ($next -gt $first) { break }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'SCM pending checkpoint did not advance' }
    } while ($true)
    $pending = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($pending.State -ne 'Stop Pending' -or $pending.ProcessId -ne $before.ProcessId) {
        throw 'Service exited/replaced before external join confirmation'
    }
    [IO.File]::WriteAllText($release, 'confirmed fixture join')
    (Get-Service $name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    $after = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($after.ProcessId -ne 0 -or $after.ExitCode -ne 0 -or (Get-Content $state -Raw | ConvertFrom-Json).phase -ne 'joined') {
        throw 'Deferred service did not finish normally after join'
    }
    @{before_pid=$before.ProcessId; pending_pid=$pending.ProcessId; first_checkpoint=$first;
      next_checkpoint=$next; final_state=$after.State; exit_code=$after.ExitCode;
      scope='real SCM/QtService explicit-quit barrier; not native RAS acceptance'} | ConvertTo-Json
} finally {
    if ($created) {
        [IO.File]::WriteAllText($release, 'fixture cleanup join')
        $service = Get-Service $name
        if ($service.Status -ne 'Stopped') {
            if ($service.Status -eq 'Running') { & sc.exe stop $name }
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
        }
        & sc.exe delete $name
    }
}
