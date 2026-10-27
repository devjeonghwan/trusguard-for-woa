#requires -Version 5.1
[CmdletBinding()]
param([switch]$NoLaunch)
$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$identity.Dispose()
if (-not $admin) {
    $arguments = '-NoProfile -ExecutionPolicy RemoteSigned -File "' + $PSCommandPath + '"'
    if ($NoLaunch) { $arguments += ' -NoLaunch' }
    # Windows, rather than this script, obtains the user's administrator approval.
    try {
        $elevated = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Verb RunAs -WindowStyle Normal -ArgumentList $arguments -PassThru
        # Wait only for the setup PowerShell, not the GUI client's lifetime.
        $elevated.WaitForExit()
    } catch {
        [ordered]@{at=(Get-Date -Format o);status='Administrator launch did not start';error=$_.Exception.Message;systemChangesInThisAttempt='none'} |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskRoot 'port\elevation-result.json') -Encoding UTF8
        throw
    }
    if ($elevated.ExitCode -ne 0) { throw "Installation did not complete (exit $($elevated.ExitCode)). Check port\install-result.json." }
    return
}
& (Join-Path $taskRoot 'tools\Test-Port.ps1')
$resultPath = Join-Path $taskRoot 'port\install-result.json'
try {
    $statePath = Join-Path $taskRoot 'port\state\adapter.json'
    if (-not (Test-Path -LiteralPath $statePath)) {
        & (Join-Path $taskRoot 'tools\Adapter.ps1') -Mode Install
    }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($state.Stage -in @('CreatedBeforeAlias','OriginalDisplayNameSaved','AliasWritten','DisplayNameApplied') -or
        ($state.Stage -eq 'AliasInstalled' -and -not $state.DisplayNameApplied)) {
        & (Join-Path $taskRoot 'tools\Adapter.ps1') -Mode Resume
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    }
    if ($state.Stage -ne 'AliasInstalled') { throw "Adapter setup is incomplete: $($state.Stage)" }
    $probeJson = & (Join-Path $taskRoot 'port\tg-woa-probe.exe') --tap $state.NetCfgInstanceId
    if ($LASTEXITCODE -ne 0) { throw "Native TAP query failed: $probeJson" }
    $probe = $probeJson | ConvertFrom-Json
    $adapter = @($probe.adapters | Where-Object { $_.guid -eq $state.NetCfgInstanceId })
    if ($adapter.Count -ne 1 -or -not $adapter[0].trusGuardDescriptionMatch) {
        throw "TrusGuard's required adapter description is not yet visible to GetAdaptersInfo: $probeJson"
    }
    $probeJson | Set-Content -LiteralPath (Join-Path $taskRoot 'port\adapter-probe.json') -Encoding UTF8
    & (Join-Path $taskRoot 'tools\Deploy-Client.ps1') -Mode Install
    [ordered]@{completedAt=(Get-Date -Format o);adapterInstalled=$true;driverProbe='pass';gatewayLogin='not tested';tunnelTraffic='not tested'} |
        ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    if (-not $NoLaunch) { & (Join-Path $taskRoot 'tools\Start-Client.ps1') }
} catch {
    [ordered]@{completedAt=(Get-Date -Format o);error=$_.Exception.Message;recovery='tools\Adapter.ps1 -Mode Inspect; tools\Adapter.ps1 -Mode Remove'} |
        ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Error $_
    exit 1
}
