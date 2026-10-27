[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
function Get-PeMachine([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $offset = [BitConverter]::ToInt32($bytes,60)
    [BitConverter]::ToUInt16($bytes,$offset+4)
}
foreach ($spec in @(
    @{Base='port\client';Manifest='port\client-manifest.json'},
    @{Base='port\driver\arm64';Manifest='port\driver\arm64\manifest.json'}
)) {
    $manifest = Get-Content -LiteralPath (Join-Path $taskRoot $spec.Manifest) -Raw | ConvertFrom-Json
    foreach ($file in $manifest.files) {
        $path = Join-Path (Join-Path $taskRoot $spec.Base) $file.name
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.sha256) {
            throw "Hash mismatch: $path"
        }
    }
}
foreach ($name in @('tap0901.sys')) {
    $path = Join-Path $taskRoot "port\driver\arm64\$name"
    if ((Get-PeMachine $path) -ne 0xaa64) { throw "Not an ARM64 PE: $name" }
    if ((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid') { throw "Invalid signature: $name" }
}
$probe = Join-Path $taskRoot 'port\tg-woa-probe.exe'
if ((Get-PeMachine $probe) -ne 0xaa64) { throw 'Probe is not native ARM64.' }
if ((Get-PeMachine (Join-Path $taskRoot 'port\tg-woa-name.exe')) -ne 0xaa64) { throw 'Network naming helper is not native ARM64.' }
if ((Get-PeMachine (Join-Path $taskRoot 'port\tg-woa-device.exe')) -ne 0xaa64) { throw 'Device installation helper is not native ARM64.' }
$taskProbeJson = & $probe
if ($LASTEXITCODE -ne 0) { throw "Native probe failed: $LASTEXITCODE" }
$report = $taskProbeJson | ConvertFrom-Json
if ($report.nativeMachine -ne 0xaa64 -or $report.compiledMachine -ne 0xaa64 -or $report.processMachine -ne 0) {
    throw 'Probe did not run as native ARM64 on ARM64 Windows.'
}
$taskProbeJson | Set-Content -LiteralPath (Join-Path $taskRoot 'port\host-probe.json') -Encoding UTF8
[ordered]@{
    validatedAt=(Get-Date -Format o)
    originalPayloadHashes='pass'
    driverSignatures='pass'
    driverArchitecture='ARM64'
    probeExecution='native ARM64'
    gatewayLogin='not tested'
    tunnelTraffic='not tested'
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskRoot 'port\validation.json') -Encoding UTF8
Write-Output 'PASS: original payload hashes, signed ARM64 driver, native ARM64 probe execution.'
Write-Output 'Gateway login and tunnel traffic remain unverified.'
