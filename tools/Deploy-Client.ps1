#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param([ValidateSet('Install','Remove')][string]$Mode='Install')
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$source = Join-Path $taskRoot 'port\client'
$destination = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AhnLab\VPN\SSL VPN'
$statePath = Join-Path $taskRoot 'port\state\client.json'
$manifest = Get-Content -LiteralPath (Join-Path $taskRoot 'port\client-manifest.json') -Raw | ConvertFrom-Json
function Get-FileDigest([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','') }
    finally { $hash.Dispose(); $stream.Dispose() }
}
if ($manifest.files.Count -ne 45) { throw 'Unexpected client file list.' }
foreach ($entry in $manifest.files) {
    if ($entry.name -notmatch '^[a-zA-Z0-9_.-]+$') { throw 'Unsafe client filename.' }
    if ((Get-FileDigest (Join-Path $source $entry.name)) -ne $entry.sha256) {
        throw "Source client file changed: $($entry.name)"
    }
}
function Save-Deployment([object]$Value) {
    [IO.Directory]::CreateDirectory((Split-Path $statePath -Parent)) | Out-Null
    $temporary = $statePath + '.tmp'
    [IO.File]::WriteAllText($temporary,($Value | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
    if ([IO.File]::Exists($statePath)) { [IO.File]::Replace($temporary,$statePath,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$statePath) }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$identity.Dispose()
if (-not $WhatIfPreference -and -not $admin) { throw 'Run from an elevated PowerShell.' }
if ($Mode -eq 'Install') {
    if (Test-Path -LiteralPath $statePath) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.Destination -ine $destination -or $state.Kind -cne 'TrusGuard-WOA-Client') { throw 'Unexpected saved client destination.' }
        foreach ($entry in $manifest.files) {
            if ((Get-FileDigest (Join-Path $destination $entry.name)) -ne $entry.sha256) {
                throw "Previously deployed client changed: $($entry.name)"
            }
        }
        Write-Output "Original client is already deployed: $destination"
    } else {
        if (Test-Path -LiteralPath $destination) { throw "An existing client folder will not be overwritten: $destination" }
        if (-not $PSCmdlet.ShouldProcess($destination,'Deploy 45 unchanged vendor files into the original required resource path')) { return }
        $state = [pscustomobject]@{Kind='TrusGuard-WOA-Client';Destination=$destination;CreatedAt=(Get-Date -Format o);Stage='Deploying';Files=$manifest.files}
        Save-Deployment $state
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        foreach ($entry in $manifest.files) {
            Copy-Item -LiteralPath (Join-Path $source $entry.name) -Destination (Join-Path $destination $entry.name)
        }
        foreach ($name in @('Cert','Log','Tmp')) { New-Item -ItemType Directory -Path (Join-Path $destination $name) -Force | Out-Null }
    }
    # The original installer puts its three default SSL assets in Cert as well.
    # Track only copies made here; preserve all user-created certificates.
    $certificates = @()
    $missing = @()
    foreach ($name in @('ssl_defaultca.crt','ssl_default.crt','ssl_default.key')) {
        $entry = @($manifest.files | Where-Object name -CEQ $name)
        if ($entry.Count -ne 1) { throw "Missing original default asset in manifest: $name" }
        $relative = 'Cert\' + $name
        $path = Join-Path $destination $relative
        $previous = @($state.CertificateFiles | Where-Object name -CEQ $relative)
        if ($previous.Count -gt 1) { throw "Ambiguous certificate ownership: $relative" }
        if (Test-Path -LiteralPath $path) {
            if ((Get-FileDigest $path) -ne $entry[0].sha256) { throw "A different certificate will not be overwritten: $relative" }
            $owned = $previous.Count -eq 1 -and $previous[0].Owned -eq $true
        } else {
            $owned = $true
            $missing += $name
        }
        $certificates += [pscustomobject]@{name=$relative;sha256=$entry[0].sha256;Owned=$owned}
    }
    if (-not $PSCmdlet.ShouldProcess((Join-Path $destination 'Cert'),'Ensure the three unchanged original SSL assets at the exact paths required by the integrity checker')) { return }
    $state | Add-Member -NotePropertyName CertificateFiles -NotePropertyValue $certificates -Force
    $state.Stage = 'DeployingCertificates'
    Save-Deployment $state
    New-Item -ItemType Directory -Path (Join-Path $destination 'Cert') -Force | Out-Null
    foreach ($name in $missing) {
        [IO.File]::Copy((Join-Path $source $name),(Join-Path (Join-Path $destination 'Cert') $name),$false)
    }
    foreach ($entry in $certificates) {
        if ((Get-FileDigest (Join-Path $destination $entry.name)) -ne $entry.sha256) { throw "Default certificate verification failed: $($entry.name)" }
    }
    $state.Stage = 'Deployed'
    Save-Deployment $state
    Write-Output "Deployed original client: $destination"
    return
}
if (-not (Test-Path -LiteralPath $statePath)) { throw 'No recorded client deployment exists.' }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.Destination -ine $destination -or $state.Kind -cne 'TrusGuard-WOA-Client') { throw 'Unexpected saved client destination.' }
# Preflight every file before deleting any. Preserve user-created certificates/logs/settings.
$removeEntries = @($manifest.files)
foreach ($entry in @($state.CertificateFiles)) {
    if ($null -eq $entry) { continue }
    if ($entry.name -notin @('Cert\ssl_defaultca.crt','Cert\ssl_default.crt','Cert\ssl_default.key') -or $entry.Owned -isnot [bool]) {
        throw 'Unexpected default certificate ownership record.'
    }
    $originalName = $entry.name.Substring(5)
    $original = @($manifest.files | Where-Object name -CEQ $originalName)
    if ($original.Count -ne 1 -or $entry.sha256 -ne $original[0].sha256) { throw 'Unexpected default certificate digest in ownership record.' }
    if ($entry.Owned) { $removeEntries += $entry }
}
foreach ($entry in $removeEntries) {
    $path = Join-Path $destination $entry.name
    if ((Test-Path -LiteralPath $path) -and (Get-FileDigest $path) -ne $entry.sha256) {
        throw "Installed file changed; automatic removal stopped: $($entry.name)"
    }
}
if (-not $PSCmdlet.ShouldProcess($destination,'Remove only unchanged files recorded by this deployment, preserving user data and directories')) { return }
foreach ($entry in $removeEntries) {
    $path = Join-Path $destination $entry.name
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
}
$state.Stage = 'OriginalFilesRemoved'
Save-Deployment $state
Write-Output 'Recorded original files removed. User data, directories and deployment record retained.'
