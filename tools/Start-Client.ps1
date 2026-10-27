[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$identity.Dispose()
if (-not $admin) {
    $arguments = '-NoProfile -ExecutionPolicy RemoteSigned -File "' + $PSCommandPath + '"'
    $elevated = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Verb RunAs -WindowStyle Normal -ArgumentList $arguments -PassThru
    $elevated.WaitForExit()
    if ($elevated.ExitCode -ne 0) { throw "Client launch failed (exit $($elevated.ExitCode))." }
    return
}
$statePath = Join-Path $taskRoot 'port\state\adapter.json'
if (-not (Test-Path -LiteralPath $statePath)) { throw 'Install the experimental ARM64 adapter first with tools\Adapter.ps1 -Mode Install.' }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.Stage -ne 'AliasInstalled') { throw "Adapter setup is incomplete: $($state.Stage). Inspect the recorded adapter before starting." }
$manifest = Get-Content -LiteralPath (Join-Path $taskRoot 'port\client-manifest.json') -Raw | ConvertFrom-Json
foreach ($entry in $manifest.files) {
    $path = Join-Path (Join-Path $taskRoot 'port\client') $entry.name
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.sha256) {
        throw "The original client payload changed: $($entry.name). No client was started."
    }
}
$taskProbeJson = & (Join-Path $taskRoot 'port\tg-woa-probe.exe') --tap $state.NetCfgInstanceId
if ($LASTEXITCODE -ne 0) { throw "The dedicated TAP adapter did not pass the native driver probe: $taskProbeJson" }
$probe = $taskProbeJson | ConvertFrom-Json
$adapter = @($probe.adapters | Where-Object { $_.guid -eq $state.NetCfgInstanceId })
if ($adapter.Count -ne 1 -or -not $adapter[0].trusGuardDescriptionMatch) {
    throw 'The dedicated adapter description is not visible to GetAdaptersInfo as required by TrusGuard.'
}
$taskProbeJson | Set-Content -LiteralPath (Join-Path $taskRoot 'port\adapter-probe.json') -Encoding UTF8
$deploymentPath = Join-Path $taskRoot 'port\state\client.json'
if (-not (Test-Path -LiteralPath $deploymentPath)) { throw 'Deploy the original client with tools\Deploy-Client.ps1 first.' }
$deployment = Get-Content -LiteralPath $deploymentPath -Raw | ConvertFrom-Json
$client = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AhnLab\VPN\SSL VPN'
if ($deployment.Destination -ine $client -or $deployment.Stage -ne 'Deployed') { throw 'Unexpected or incomplete client deployment.' }
foreach ($entry in $manifest.files) {
    if ((Get-FileHash -LiteralPath (Join-Path $client $entry.name) -Algorithm SHA256).Hash -ne $entry.sha256) {
        throw "Deployed client file changed: $($entry.name)"
    }
}
foreach ($name in @('ssl_defaultca.crt','ssl_default.crt','ssl_default.key')) {
    $entry = @($manifest.files | Where-Object name -CEQ $name)
    if ($entry.Count -ne 1 -or (Get-FileHash -LiteralPath (Join-Path (Join-Path $client 'Cert') $name) -Algorithm SHA256).Hash -ne $entry[0].sha256) {
        throw "Required original default certificate is missing or changed: Cert\$name"
    }
}
Write-Output 'Starting the original signed TrusGuard login client. Windows may request administrator approval.'
Write-Output 'Enter gateway and credentials in the client yourself. Do not put passwords in scripts or chat.'
$process = Start-Process -FilePath (Join-Path $client 'tgsvpnL.exe') -WorkingDirectory $client -Verb RunAs -PassThru
[ordered]@{pid=$process.Id;path=$process.Path;launchedAt=(Get-Date -Format o);vpnLogin='user interaction required'} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskRoot 'port\client-launch.json') -Encoding UTF8
