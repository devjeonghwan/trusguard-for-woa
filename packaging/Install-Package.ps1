#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param([switch]$NoLaunch, [switch]$ValidateOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourceRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$supportRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'TrusGuard-WOA'
$manifestName = 'package-manifest.json'
$markerName = 'package-installed.json'

function Get-Digest([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Resolve-PackagePath([string]$Root, [string]$RelativePath) {
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)*$') {
        throw "Unsafe package path: $RelativePath"
    }
    foreach ($segment in $RelativePath.Split('/')) {
        if ($segment -in @('.', '..') -or $segment.EndsWith('.') -or
            $segment -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
            throw "Unsafe package path: $RelativePath"
        }
    }
    if ($RelativePath -match '^(?i:port/state)(/|$)' -or
        $RelativePath -in @($manifestName, $markerName)) {
        throw "Dynamic or reserved path is not allowed in the static manifest: $RelativePath"
    }
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $resolved = [IO.Path]::GetFullPath((Join-Path $Root $RelativePath.Replace('/', '\')))
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Package path escaped its root: $RelativePath"
    }
    return $resolved
}

function Assert-NoReparsePath([string]$Root, [string]$Path) {
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $current = $Path
    while ($current.Length -ge $base.Length) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse paths are not accepted: $current"
            }
        }
        if ($current.Equals($base, [StringComparison]::OrdinalIgnoreCase)) { return }
        $current = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($current)) { break }
    }
    throw 'The package path did not remain beneath its declared root.'
}

function Read-StaticManifest([string]$Root) {
    $path = Join-Path $Root $manifestName
    Assert-NoReparsePath $Root $path
    if (-not [IO.File]::Exists($path)) { throw "Missing package manifest: $path" }
    if ((Get-Item -LiteralPath $path).Length -gt 1MB) { throw 'The package manifest is too large.' }
    $value = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($value.schemaVersion -ne 1 -or @($value.files).Count -lt 10 -or @($value.files).Count -gt 1000) {
        throw 'Unsupported or invalid package manifest.'
    }
    $seen = @{}
    foreach ($entry in $value.files) {
        $relative = [string]$entry.path
        $full = Resolve-PackagePath $Root $relative
        if ($seen.ContainsKey($relative.ToLowerInvariant())) { throw "Duplicate package path: $relative" }
        $seen[$relative.ToLowerInvariant()] = $true
        if ([string]$entry.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Invalid package digest: $relative" }
        Assert-NoReparsePath $Root $full
        if (-not [IO.File]::Exists($full) -or (Get-Digest $full) -ine [string]$entry.sha256) {
            throw "Package file is missing or changed: $relative"
        }
    }
    foreach ($required in @(
        'Install-Package.ps1', 'Install-ARM64.ps1', 'Start-TrusGuard.cmd',
        'tools/Adapter.ps1', 'tools/Deploy-Client.ps1', 'tools/Start-Client.ps1',
        'tools/Test-Port.ps1', 'tools/driver-hashes.json', 'port/client-manifest.json',
        'port/driver/arm64/manifest.json', 'port/tg-woa-probe.exe',
        'port/tg-woa-name.exe', 'port/tg-woa-device.exe'
    )) {
        if (-not $seen.ContainsKey($required.ToLowerInvariant())) { throw "Required package file is not listed: $required" }
    }
    return $value
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally { $identity.Dispose() }
}

function Save-Marker([object]$Marker) {
    $path = Join-Path $supportRoot $markerName
    $temporary = Join-Path $supportRoot ('.package-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporary, ($Marker | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($path)) { [IO.File]::Replace($temporary, $path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $path) }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Add-StartMenuShortcut {
    $programs = [Environment]::GetFolderPath('CommonPrograms')
    $shortcutPath = Join-Path $programs 'TrusGuard WOA.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $null
    try {
        if ([IO.File]::Exists($shortcutPath)) {
            $existing = $shell.CreateShortcut($shortcutPath)
            try {
                if ($existing.TargetPath -ine (Join-Path $supportRoot 'Start-TrusGuard.cmd')) {
                    throw 'An unrelated Start Menu shortcut would be overwritten.'
                }
            } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($existing) }
        }
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = Join-Path $supportRoot 'Start-TrusGuard.cmd'
        $shortcut.WorkingDirectory = $supportRoot
        $shortcut.Description = 'TrusGuard client with ARM64 TAP compatibility'
        $clientIcon = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AhnLab\VPN\SSL VPN\tgsvpnL.exe'
        if ([IO.File]::Exists($clientIcon)) { $shortcut.IconLocation = $clientIcon + ',0' }
        $shortcut.Save()
        return $shortcutPath
    } finally {
        if ($null -ne $shortcut) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
}

$manifest = Read-StaticManifest $sourceRoot
$manifestHash = Get-Digest (Join-Path $sourceRoot $manifestName)
if ($ValidateOnly) {
    [pscustomobject]@{result='Package hashes validated';fileCount=@($manifest.files).Count;manifestSha256=$manifestHash} | ConvertTo-Json
    return
}
if ($WhatIfPreference) {
    [void]$PSCmdlet.ShouldProcess($supportRoot,
        'Validate/copy only listed static files; preserve port/state; run ARM64 setup; create TrusGuard WOA Start Menu shortcut; optionally open the original login client. Existing unrelated installations are refused.')
    [pscustomobject]@{result='Preview only';fileCount=@($manifest.files).Count;destination=$supportRoot;launchClient=(-not $NoLaunch)} | ConvertTo-Json
    return
}
$architecture = try { [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
                catch { if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE } }
if ($architecture -ine 'Arm64') { throw "This package requires Windows ARM64; detected $architecture." }
if (-not (Test-Administrator)) {
    $arguments = '-NoProfile -ExecutionPolicy RemoteSigned -File "' + $PSCommandPath + '"'
    if ($NoLaunch) { $arguments += ' -NoLaunch' }
    $elevated = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Verb RunAs -WindowStyle Normal -ArgumentList $arguments -PassThru
    $elevated.WaitForExit()
    if ($elevated.ExitCode -ne 0) { throw "Package installation failed (exit $($elevated.ExitCode))." }
    return
}

$marker = $null
$knownFiles = @{}
$markerPath = Join-Path $supportRoot $markerName
$statePath = Join-Path $supportRoot 'port\state\adapter.json'
$clientStatePath = Join-Path $supportRoot 'port\state\client.json'
$clientRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AhnLab\VPN\SSL VPN'
if ([IO.Directory]::Exists($supportRoot)) {
    Assert-NoReparsePath $supportRoot $markerPath
    if (-not [IO.File]::Exists($markerPath)) { throw "An unrecognized support folder will not be overwritten: $supportRoot" }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.Kind -cne 'TrusGuard-WOA-Package' -or $marker.SchemaVersion -ne 1) { throw 'Unrecognized installed package marker.' }
    foreach ($entry in @($marker.Files) + @($marker.PreviousFiles)) {
        if ($null -eq $entry) { continue }
        [void](Resolve-PackagePath $supportRoot ([string]$entry.path))
        if ([string]$entry.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid installed-file ownership record.' }
        $key = ([string]$entry.path).ToLowerInvariant()
        if (-not $knownFiles.ContainsKey($key)) { $knownFiles[$key] = @() }
        $knownFiles[$key] += ([string]$entry.sha256).ToUpperInvariant()
    }
}
if ([IO.Directory]::Exists($clientRoot) -and -not [IO.File]::Exists($clientStatePath)) {
    throw 'An existing TrusGuard client is not managed by this package. Its files and active connection were left unchanged.'
}
$differences = @()
foreach ($entry in $manifest.files) {
    $path = Resolve-PackagePath $supportRoot ([string]$entry.path)
    Assert-NoReparsePath $supportRoot $path
    if ([IO.File]::Exists($path)) {
        $actual = Get-Digest $path
        $key = ([string]$entry.path).ToLowerInvariant()
        if ($actual -ine [string]$entry.sha256 -and
            (-not $knownFiles.ContainsKey($key) -or $actual -notin $knownFiles[$key])) {
            throw "A modified support file will not be overwritten: $($entry.path)"
        }
        if ($actual -ine [string]$entry.sha256) { $differences += $entry }
    } else { $differences += $entry }
}
$running = @(Get-Process tgsvpnL,tgsvpnU,tgsvpnE -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    if ($null -ne $marker -and $marker.Stage -ceq 'Installed' -and
        $differences.Count -eq 0 -and [IO.File]::Exists($statePath) -and [IO.File]::Exists($clientStatePath)) {
        Write-Output 'TrusGuard is already installed and running. No files or adapters were changed.'
        return
    }
    throw 'Close the running TrusGuard client before installing or repairing this package. No existing connection was changed.'
}
if (-not $PSCmdlet.ShouldProcess($supportRoot, 'Install the validated ARM64 compatibility package')) { return }

if (-not [IO.Directory]::Exists($supportRoot)) {
    [void][IO.Directory]::CreateDirectory($supportRoot)
    # All elevated scripts and state remain writable only by administrators/SYSTEM.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @(
        @{Sid='S-1-5-18';Rights=[Security.AccessControl.FileSystemRights]::FullControl},
        @{Sid='S-1-5-32-544';Rights=[Security.AccessControl.FileSystemRights]::FullControl},
        @{Sid='S-1-5-32-545';Rights=[Security.AccessControl.FileSystemRights]::ReadAndExecute}
    )) {
        $sid = New-Object Security.Principal.SecurityIdentifier($rule.Sid)
        $access = New-Object Security.AccessControl.FileSystemAccessRule($sid,$rule.Rights,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($access)
    }
    Set-Acl -LiteralPath $supportRoot -AclObject $acl
}
$previousFiles = @()
if ($null -ne $marker) {
    $previousFiles = @($marker.Files) + @($marker.PreviousFiles) | Where-Object { $null -ne $_ } |
        Sort-Object path,sha256 -Unique
}
$installedMarker = [pscustomobject]@{
    Kind='TrusGuard-WOA-Package';SchemaVersion=1;Stage='Copying';
    ManifestSha256=$manifestHash;UpdatedUtc=[DateTime]::UtcNow.ToString('o');
    Files=@($manifest.files);PreviousFiles=@($previousFiles);StartMenuShortcut=$null
}
Save-Marker $installedMarker
try {
    foreach ($entry in $differences) {
        $source = Resolve-PackagePath $sourceRoot ([string]$entry.path)
        $destination = Resolve-PackagePath $supportRoot ([string]$entry.path)
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
        Assert-NoReparsePath $supportRoot $destination
        $temporary = $destination + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        try {
            [IO.File]::Copy($source, $temporary, $false)
            if ((Get-Digest $temporary) -ine [string]$entry.sha256) { throw "Copied file failed hash verification: $($entry.path)" }
            if ([IO.File]::Exists($destination)) { [IO.File]::Replace($temporary,$destination,[NullString]::Value) }
            else { [IO.File]::Move($temporary,$destination) }
        } finally {
            if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        }
    }
    $manifestDestination = Join-Path $supportRoot $manifestName
    $manifestTemporary = $manifestDestination + '.tmp'
    [IO.File]::Copy((Join-Path $sourceRoot $manifestName),$manifestTemporary,$true)
    if ([IO.File]::Exists($manifestDestination)) { [IO.File]::Replace($manifestTemporary,$manifestDestination,[NullString]::Value) }
    else { [IO.File]::Move($manifestTemporary,$manifestDestination) }
    $installedMarker.Stage = 'FilesInstalled'
    Save-Marker $installedMarker
    # A child process contains legacy setup scripts' exit statements. No GUI is
    # launched until persistent state and the Start Menu entry are both saved.
    $global:LASTEXITCODE = 0
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy RemoteSigned `
        -File (Join-Path $supportRoot 'Install-ARM64.ps1') -NoLaunch
    if ($LASTEXITCODE -ne 0) { throw "ARM64 setup failed (exit $LASTEXITCODE). See port\install-result.json under the support folder." }
    $installedMarker.StartMenuShortcut = Add-StartMenuShortcut
    $installedMarker.Stage = 'Installed'
    $installedMarker.UpdatedUtc = [DateTime]::UtcNow.ToString('o')
    Save-Marker $installedMarker
    Write-Output "Installed compatibility files: $supportRoot"
    if (-not $NoLaunch) {
        $global:LASTEXITCODE = 0
        & (Join-Path $supportRoot 'tools\Start-Client.ps1')
        if ($LASTEXITCODE -ne 0) { throw "Client launcher failed (exit $LASTEXITCODE)." }
    }
} catch {
    $installedMarker.Stage = 'InstallFailed'
    $installedMarker.UpdatedUtc = [DateTime]::UtcNow.ToString('o')
    Save-Marker $installedMarker
    throw
}
