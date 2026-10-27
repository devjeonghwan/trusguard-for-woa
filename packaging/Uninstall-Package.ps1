#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$supportRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'TrusGuard-WOA'
$markerPath = Join-Path $supportRoot 'package-installed.json'
if (-not [IO.File]::Exists($markerPath)) { throw 'No TrusGuard WOA package installation is recorded.' }
$marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
if ($marker.Kind -cne 'TrusGuard-WOA-Package' -or $marker.SchemaVersion -ne 1) {
    throw 'The support folder is not a recognized TrusGuard WOA installation.'
}
if ($WhatIfPreference) {
    [void]$PSCmdlet.ShouldProcess($supportRoot,
        'Remove only the recorded TAP adapter and unchanged owned client files; remove only the owned Start Menu shortcut; retain support/state, user certificates/logs and the shared driver package.')
    return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} finally { $identity.Dispose() }
if (-not $admin) {
    $arguments = '-NoProfile -ExecutionPolicy RemoteSigned -File "' + $PSCommandPath + '"'
    $elevated = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Verb RunAs -WindowStyle Normal -ArgumentList $arguments -PassThru
    $elevated.WaitForExit()
    if ($elevated.ExitCode -ne 0) { throw "Uninstall did not complete (exit $($elevated.ExitCode))." }
    return
}
$running = @(Get-Process tgsvpnL,tgsvpnU,tgsvpnE -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) { throw 'Disconnect the VPN and close the TrusGuard client before uninstalling.' }

function Get-Digest([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '') }
    finally { $hash.Dispose(); $stream.Dispose() }
}
foreach ($relative in @('tools/Adapter.ps1','tools/Deploy-Client.ps1')) {
    $entry = @($marker.Files | Where-Object { $_.path -ceq $relative })
    if ($entry.Count -ne 1 -or [string]$entry[0].sha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Missing ownership for uninstall tool: $relative"
    }
    $path = Join-Path $supportRoot $relative.Replace('/', '\')
    $current = $path
    while ($current.Length -ge $supportRoot.Length) {
        if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'An uninstall tool or its containing directory is a reparse path.'
        }
        if ($current.Equals($supportRoot,[StringComparison]::OrdinalIgnoreCase)) { break }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    if ((Get-Digest $path) -ine [string]$entry[0].sha256) { throw "Uninstall tool changed: $relative" }
}
if (-not $PSCmdlet.ShouldProcess($supportRoot, 'Remove the recorded TrusGuard WOA adapter and owned client files')) { return }
$adapterState = Join-Path $supportRoot 'port\state\adapter.json'
$clientState = Join-Path $supportRoot 'port\state\client.json'
if ([IO.File]::Exists($adapterState)) { & (Join-Path $supportRoot 'tools\Adapter.ps1') -Mode Remove }
if ([IO.File]::Exists($clientState)) { & (Join-Path $supportRoot 'tools\Deploy-Client.ps1') -Mode Remove }

$shortcutPath = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'TrusGuard WOA.lnk'
if ($marker.StartMenuShortcut -ieq $shortcutPath -and [IO.File]::Exists($shortcutPath)) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $null
    try {
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $owned = $shortcut.TargetPath -ieq (Join-Path $supportRoot 'Start-TrusGuard.cmd')
    } finally {
        if ($null -ne $shortcut) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
    if ($owned) { [IO.File]::Delete($shortcutPath) }
    else { Write-Warning 'A changed Start Menu shortcut was preserved.' }
}
$marker.Stage = 'Uninstalled'
$marker.UpdatedUtc = [DateTime]::UtcNow.ToString('o')
$temporary = $markerPath + '.tmp'
[IO.File]::WriteAllText($temporary, ($marker | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
[IO.File]::Replace($temporary,$markerPath,[NullString]::Value)
Write-Output 'Recorded adapter and unchanged owned client files removed. Support/state, user data and shared driver package were retained.'
