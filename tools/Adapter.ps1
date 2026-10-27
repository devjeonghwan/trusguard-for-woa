#requires -Version 5.1
<#
.SYNOPSIS
Stages an experimental ARM64 TAP adapter for the original TrusGuard client.
.DESCRIPTION
Inspect is read-only. Install creates one TAP-Windows6 device, records its exact
identity, then sets that new device's ComponentId and INetCfg display name.
Remove restores those values and removes only the recorded PnP instance.
Install stages the signed driver package/service through Windows PnP. Remove
does not explicitly delete the shared package/service. Signed INF/SYS/CAT files
and the vendor installer are not edited. This does not validate a VPN connection.
.EXAMPLE
.\tools\Adapter.ps1 -Mode Inspect
.EXAMPLE
.\tools\Adapter.ps1 -Mode Install -WhatIf
.EXAMPLE
.\tools\Adapter.ps1 -Mode Install
.EXAMPLE
.\tools\Adapter.ps1 -Mode Resume
.EXAMPLE
.\tools\Adapter.ps1 -Mode Remove -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Inspect', 'Install', 'Resume', 'Remove')]
    [string] $Mode = 'Inspect',
    [string] $DriverDirectory,
    [string] $StatePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:NetClass = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$script:ClassRoot = 'SYSTEM\CurrentControlSet\Control\Class\' + $script:NetClass
$script:AliasComponent = 'tgsvpndrv'
$script:AliasDescription = 'tgsvpn driver 1.0 (ARM64 TAP-Windows6)'
$script:RequiredFiles = @('OemVista.inf', 'tap0901.sys', 'tap0901.cat')
$script:ToolDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:DeviceHelper = Join-Path (Split-Path $script:ToolDirectory -Parent) 'port\tg-woa-device.exe'
if ([string]::IsNullOrWhiteSpace($DriverDirectory)) {
    $DriverDirectory = Join-Path (Split-Path $script:ToolDirectory -Parent) 'port\driver\arm64'
}
if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path (Split-Path $script:ToolDirectory -Parent) 'port\state\adapter.json'
}
$DriverDirectory = [IO.Path]::GetFullPath($DriverDirectory)
$StatePath = [IO.Path]::GetFullPath($StatePath)

function Get-NativeArchitecture {
    try { return [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
    catch {
        if ($env:PROCESSOR_ARCHITEW6432) { return $env:PROCESSOR_ARCHITEW6432 }
        return $env:PROCESSOR_ARCHITECTURE
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally { $identity.Dispose() }
}

function Open-MachineRegistry {
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
}

function Get-ClassRecords {
    $base = Open-MachineRegistry
    $root = $null
    try {
        $root = $base.OpenSubKey($script:ClassRoot)
        if ($null -eq $root) { throw 'The network device class registry key is missing.' }
        foreach ($name in $root.GetSubKeyNames()) {
            if ($name -notmatch '^[0-9]{4}$') { continue }
            $key = $root.OpenSubKey($name)
            if ($null -eq $key) { continue }
            try {
                [pscustomobject]@{
                    ClassKeyName = $name
                    ClassDriver = $script:NetClass + '\' + $name
                    NetCfgInstanceId = [string]$key.GetValue('NetCfgInstanceId', '')
                    ComponentId = [string]$key.GetValue('ComponentId', '')
                    DriverDesc = [string]$key.GetValue('DriverDesc', '')
                }
            }
            finally { $key.Dispose() }
        }
    }
    finally {
        if ($null -ne $root) { $root.Dispose() }
        $base.Dispose()
    }
}

function Get-NetworkSnapshot {
    param([switch] $IncludeNonPresent)
    # PowerShell 5.1 CDXML/property getters can inherit WhatIf and suppress
    # read-only queries. Limit the override to this read-only function scope.
    $WhatIfPreference = $false
    if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) {
        throw 'Get-PnpDevice is required (the Windows PnpDevice module). Use Windows PowerShell 5.1 if unavailable in this host.'
    }
    $pnp = if ($IncludeNonPresent) { @(Get-PnpDevice -Class Net) }
           else { @(Get-PnpDevice -Class Net -PresentOnly) }
    $classes = @(Get-ClassRecords)
    $base = Open-MachineRegistry
    try {
        foreach ($device in $pnp) {
            $enum = $base.OpenSubKey('SYSTEM\CurrentControlSet\Enum\' + $device.InstanceId)
            if ($null -eq $enum) { continue }
            try {
                $driver = [string]$enum.GetValue('Driver', '')
                $class = @($classes | Where-Object { $_.ClassDriver -ieq $driver })
                [pscustomobject]@{
                    InstanceId = [string]$device.InstanceId
                    Status = [string]$device.Status
                    FriendlyName = [string]$device.FriendlyName
                    Service = [string]$enum.GetValue('Service', '')
                    HardwareIds = @($enum.GetValue('HardwareID', @()))
                    ClassDriver = $driver
                    ClassKeyName = if ($class.Count -eq 1) { $class[0].ClassKeyName } else { $null }
                    NetCfgInstanceId = if ($class.Count -eq 1) { $class[0].NetCfgInstanceId } else { $null }
                    ComponentId = if ($class.Count -eq 1) { $class[0].ComponentId } else { $null }
                    DriverDesc = if ($class.Count -eq 1) { $class[0].DriverDesc } else { $null }
                }
            }
            finally { $enum.Dispose() }
        }
    }
    finally { $base.Dispose() }
}

function Assert-Arm64PE {
    param([string] $Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "Not a PE binary: $Path"
    }
    $offset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($offset -lt 64 -or $offset -gt ($bytes.Length - 6) -or
        [BitConverter]::ToUInt32($bytes, $offset) -ne 0x4550 -or
        [BitConverter]::ToUInt16($bytes, $offset + 4) -ne 0xaa64) {
        throw "Expected an ARM64 PE binary: $Path"
    }
}

function Assert-DriverFiles {
    $manifestPath = Join-Path $DriverDirectory 'manifest.json'
    $pinnedPath = Join-Path $script:ToolDirectory 'driver-hashes.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Missing staged hash manifest: $manifestPath"
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if (-not ($manifest.PSObject.Properties.Name -contains 'files')) {
        throw 'Expected manifest.json with a files array of {name, sha256} entries.'
    }
    if (-not (Test-Path -LiteralPath $pinnedPath -PathType Leaf)) {
        throw "Missing trusted driver hash pins: $pinnedPath"
    }
    $pinned = Get-Content -LiteralPath $pinnedPath -Raw | ConvertFrom-Json
    if (-not ($pinned.PSObject.Properties.Name -contains 'files')) {
        throw 'Expected driver-hashes.json with a files array of {name, sha256} entries.'
    }
    foreach ($name in $script:RequiredFiles) {
        $path = Join-Path $DriverDirectory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing staged driver file: $path" }
        $entry = @($manifest.files | Where-Object { $_.name -ceq $name })
        if ($entry.Count -ne 1 -or [string]$entry[0].sha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw "Manifest must contain exactly one valid SHA256 for $name."
        }
        # Get-FileHash in Windows PowerShell 5.1 suppresses an internal
        # ProviderPath getter under inherited WhatIf. Stream bytes directly.
        $algorithm = [Security.Cryptography.SHA256]::Create()
        $stream = [IO.File]::OpenRead($path)
        try { $actualHash = [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
        finally { $stream.Dispose(); $algorithm.Dispose() }
        if ($actualHash -ine [string]$entry[0].sha256) { throw "SHA256 mismatch: $name" }
        $pin = @($pinned.files | Where-Object { $_.name -ceq $name })
        if ($pin.Count -ne 1 -or [string]$pin[0].sha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            $actualHash -ine [string]$pin[0].sha256) {
            throw "Official pinned SHA256 mismatch or missing trusted hash: $name"
        }
        if ($name -ne 'OemVista.inf') {
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            if ($signature.Status -ne 'Valid') {
                throw "Invalid Authenticode signature for ${name}: $($signature.Status) ($($signature.StatusMessage))"
            }
        }
    }
    Assert-Arm64PE $script:DeviceHelper
    Assert-Arm64PE (Join-Path $DriverDirectory 'tap0901.sys')
    $inf = Get-Content -LiteralPath (Join-Path $DriverDirectory 'OemVista.inf') -Raw
    if ($inf -notmatch '(?im)^\s*\[tap0901\.NTARM64\]\s*$' -or
        $inf -notmatch '(?im)^\s*%DeviceDescription%\s*=\s*tap0901\.ndi,\s*root\\tap0901(?:\s*;.*)?\s*$' -or
        $inf -notmatch '(?im)^\s*ClassGUID\s*=\s*\{4d36e972-e325-11ce-bfc1-08002be10318\}\s*$') {
        throw 'The staged INF is not the expected NTARM64 TAP-Windows6 network driver.'
    }
}

function Invoke-Device {
    param([string[]] $Arguments)
    $previousPreference = $ErrorActionPreference
    try {
        # Preserve native stderr as diagnostic output on both PowerShell 5.1 and 7.
        $ErrorActionPreference = 'Continue'
        $output = @(& $script:DeviceHelper @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousPreference }
    $message = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    Write-Verbose $message
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $message }
}

function Invoke-NameHelper {
    param([object] $State, [string] $Name, [switch] $SetName)
    [void](Resolve-StateDevice $State)
    $portDirectory = Split-Path (Split-Path $DriverDirectory -Parent) -Parent
    $helper = Join-Path $portDirectory 'tg-woa-name.exe'
    if (-not [IO.File]::Exists($helper)) { throw "Build the ARM64 INetCfg helper first: $helper" }
    Assert-Arm64PE $helper
    $arguments = if ($SetName) { @('--set-name', $State.NetCfgInstanceId, $Name) }
                 else { @('--get-name', $State.NetCfgInstanceId) }
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $helper @arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousPreference }
    $message = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    if ($exitCode -ne 0) { throw "INetCfg helper failed (exit ${exitCode}): $message" }
    try { $result = $message | ConvertFrom-Json }
    catch { throw "INetCfg helper did not return valid JSON: $message" }
    if ($result.guid -ine $State.NetCfgInstanceId -or $result.stage -cne 'Complete' -or
        $result.displayName -isnot [string] -or $result.displayName.Length -lt 1 -or
        $result.displayName.Length -gt 255 -or $result.hresult -notmatch '^0x[0-7][0-9a-fA-F]{7}$' -or
        ($SetName -and $result.displayName -cne $Name)) {
        throw "INetCfg helper identity or result verification failed: $message"
    }
    return $result
}

function Write-AdapterState {
    param([object] $State)
    $directory = Split-Path $StatePath -Parent
    [void][IO.Directory]::CreateDirectory($directory)
    $temporary = Join-Path $directory ('.adapter-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $json = $State | ConvertTo-Json -Depth 12
        $encoding = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($temporary, $json, $encoding)
        # Windows PowerShell 5.1 coerces plain $null to an empty string for this
        # overload. NullString preserves a real null backup filename on .NET.
        if ([IO.File]::Exists($StatePath)) { [IO.File]::Replace($temporary, $StatePath, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $StatePath) }
    }
    finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Get-OriginalAliasValues {
    param([string] $ClassKeyName)
    $base = Open-MachineRegistry
    $key = $null
    try {
        $key = $base.OpenSubKey($script:ClassRoot + '\' + $ClassKeyName)
        if ($null -eq $key) { throw 'The newly created network-class key disappeared.' }
        $values = [ordered]@{}
        foreach ($name in @('ComponentId', 'DriverDesc')) {
            $exists = @($key.GetValueNames()) -contains $name
            $values[$name] = [pscustomobject]@{
                Exists = $exists
                Kind = if ($exists) { $key.GetValueKind($name).ToString() } else { $null }
                Value = if ($exists) { $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }
            }
        }
        return [pscustomobject]$values
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function Assert-StateShape {
    param([object] $State)
    if ($State.SchemaVersion -ne 1 -or $State.Kind -cne 'TrusGuard-WOA-TAP-Adapter' -or
        $State.InstanceId -notmatch '^ROOT\\NET\\[0-9A-Fa-f]{4}$' -or
        $State.ClassKeyName -notmatch '^[0-9]{4}$' -or
        $State.ClassDriver -ine ($script:NetClass + '\' + $State.ClassKeyName) -or
        $State.Service -ine 'tap0901' -or
        $State.NetCfgInstanceId -notmatch '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$') {
        throw 'The saved adapter state has an unexpected identity or registry path. No changes made.'
    }
    foreach ($name in @('ComponentId', 'DriverDesc')) {
        $saved = $State.OriginalValues.$name
        if ($saved.Exists -isnot [bool] -or
            ($saved.Exists -and ($saved.Kind -notin @('String', 'ExpandString') -or $saved.Value -isnot [string]))) {
            throw "Unexpected original registry value in state: $name"
        }
    }
    if (-not $State.OriginalValues.ComponentId.Exists -or
        $State.OriginalValues.ComponentId.Value -notmatch '^(?:root\\)?tap0901$') {
        throw 'The saved original component is not TAP-Windows6. No changes made.'
    }
    if ($State.PSObject.Properties.Name -contains 'OriginalDisplayName') {
        if ($State.OriginalDisplayName -isnot [string] -or
            $State.OriginalDisplayName.Length -lt 1 -or $State.OriginalDisplayName.Length -gt 255) {
            throw 'The saved original INetCfg display name is invalid.'
        }
    }
    if (($State.PSObject.Properties.Name -contains 'DisplayNameApplied') -and $State.DisplayNameApplied -isnot [bool]) {
        throw 'The saved INetCfg application flag is invalid.'
    }
}

function Resolve-StateDevice {
    param([object] $State)
    Assert-StateShape $State
    $devices = @(Get-NetworkSnapshot -IncludeNonPresent | Where-Object { $_.InstanceId -ieq $State.InstanceId })
    if ($devices.Count -ne 1) { throw 'The recorded PnP instance is missing or ambiguous. State retained; no other adapter will be removed.' }
    $device = $devices[0]
    if ($device.ClassDriver -ine $State.ClassDriver -or
        $device.NetCfgInstanceId -ine $State.NetCfgInstanceId -or
        $device.Service -ine 'tap0901' -or
        -not (@($device.HardwareIds) -icontains 'root\tap0901') -or
        $device.ComponentId -notmatch '^(?:(?:root\\)?tap0901|tgsvpndrv)$') {
        throw 'The saved GUID/PnP/class-key/service/hardware identity no longer matches. No changes made.'
    }
    return $device
}

function Set-AdapterAliases {
    param([object] $State, [switch] $Restore)
    # Revalidate immediately before opening a writable registry handle.
    [void](Resolve-StateDevice $State)
    $base = Open-MachineRegistry
    $key = $null
    try {
        $key = $base.OpenSubKey($script:ClassRoot + '\' + $State.ClassKeyName, $true)
        if ($null -eq $key -or [string]$key.GetValue('NetCfgInstanceId', '') -ine $State.NetCfgInstanceId) {
            throw 'The recorded network-class key changed before mutation.'
        }
        foreach ($name in @('ComponentId', 'DriverDesc')) {
            if ($Restore -or $name -eq 'DriverDesc') {
                $saved = $State.OriginalValues.$name
                if ($saved.Exists) {
                    $kind = [Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind], $saved.Kind)
                    $key.SetValue($name, $saved.Value, $kind)
                }
                else { $key.DeleteValue($name, $false) }
            }
            else {
                $key.SetValue($name, $script:AliasComponent, [Microsoft.Win32.RegistryValueKind]::String)
            }
        }
        $key.Flush()
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function Complete-AdapterCompatibility {
    param([object] $State)
    [void](Resolve-StateDevice $State)
    # A legacy attempt wrote DriverDesc directly. Restore its saved value
    # before INetCfg reads the name, otherwise GetDisplayName may see the alias
    # and skip the Apply operation needed to update the actual interface.
    Set-AdapterAliases $State
    if (-not ($State.PSObject.Properties.Name -contains 'OriginalDisplayName')) {
        $original = Invoke-NameHelper -State $State
        if ($original.displayName -ceq $script:AliasDescription) {
            throw 'The display name is already aliased but no original name was saved. Refusing to guess a rollback value.'
        }
        $State | Add-Member -MemberType NoteProperty -Name OriginalDisplayName -Value $original.displayName
        $State | Add-Member -MemberType NoteProperty -Name DisplayNameApplied -Value $false -Force
        $State.Stage = 'OriginalDisplayNameSaved'
        # Persist the rollback name before the first SetDisplayName operation.
        Write-AdapterState $State
    }
    $State.Stage = 'AliasWritten'
    Write-AdapterState $State
    $named = Invoke-NameHelper -State $State -SetName -Name $script:AliasDescription
    $State | Add-Member -MemberType NoteProperty -Name DisplayNameApplied -Value $true -Force
    $State.Stage = 'DisplayNameApplied'
    $State.RebootRequired = $State.RebootRequired -or ($named.hresult -ieq '0x0004A020')
    Write-AdapterState $State
    if ($named.hresult -ieq '0x0004A020') {
        $restart = Invoke-Device -Arguments @('restart', ('@' + $State.InstanceId))
        if ($restart.ExitCode -notin @(0, 1)) {
            throw "Exact-instance restart failed (exit $($restart.ExitCode)): $($restart.Output)"
        }
        $State.RebootRequired = $State.RebootRequired -or ($restart.ExitCode -eq 1)
    }
    $verified = Resolve-StateDevice $State
    if ($verified.ComponentId -cne $script:AliasComponent) {
        throw 'The engine ComponentId alias did not persist.'
    }
    $State.Stage = 'AliasInstalled'
    Write-AdapterState $State
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This tool requires Windows.' }
$architecture = Get-NativeArchitecture
$admin = Test-Administrator

if ($Mode -eq 'Inspect') {
    $classes = @(Get-ClassRecords)
    [pscustomobject]@{
        Mode = 'Inspect'
        NativeArchitecture = $architecture
        Administrator = $admin
        DriverDirectory = $DriverDirectory
        ManifestPresent = [IO.File]::Exists((Join-Path $DriverDirectory 'manifest.json'))
        RequiredFiles = @($script:RequiredFiles | ForEach-Object {
            [pscustomobject]@{ Name = $_; Exists = [IO.File]::Exists((Join-Path $DriverDirectory $_)) }
        })
        StatePath = $StatePath
        SavedState = if ([IO.File]::Exists($StatePath)) { Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json } else { $null }
        TrusGuardClassEntries = @($classes | Where-Object {
            $_.ComponentId -match '^(?:root\\)?tgsvpndrv$' -or $_.DriverDesc -like '*tgsvpn driver 1.0*'
        })
        PresentNetworkDevices = @(Get-NetworkSnapshot)
        Notice = 'Read-only inventory. No VPN connection or driver compatibility has been tested.'
    } | ConvertTo-Json -Depth 12
    return
}

if ($architecture -ine 'Arm64') { throw "Native Windows ARM64 is required; detected $architecture." }
Assert-DriverFiles
if (-not $WhatIfPreference -and -not $admin) { throw 'Run this mode from an elevated PowerShell session (Run as administrator).' }

if ($Mode -eq 'Install') {
    if ([IO.File]::Exists($StatePath)) { throw "A saved adapter state already exists. Inspect it and use Remove first: $StatePath" }
    $classesBefore = @(Get-ClassRecords)
    $conflicts = @($classesBefore | Where-Object {
        $_.ComponentId -match '^(?:root\\)?tgsvpndrv$' -or $_.DriverDesc -like '*tgsvpn driver 1.0*'
    })
    if ($conflicts.Count -gt 0) {
        throw ('An existing TrusGuard network-class entry would conflict: ' + (($conflicts | ForEach-Object { $_.ClassDriver }) -join ', '))
    }
    $allBefore = @(Get-NetworkSnapshot -IncludeNonPresent)
    $tapConflicts = @($allBefore | Where-Object {
        $_.Service -ieq 'tap0901' -or
        (@($_.HardwareIds) -icontains 'root\tap0901') -or
        (@($_.HardwareIds) -icontains 'tap0901') -or
        $_.ComponentId -match '^(?:root\\)?tap0901$'
    })
    $tapClassConflicts = @($classesBefore | Where-Object { $_.ComponentId -match '^(?:root\\)?tap0901$' })
    $registry = Open-MachineRegistry
    $tapService = $null
    try { $tapService = $registry.OpenSubKey('SYSTEM\CurrentControlSet\Services\tap0901'); $hasTapService = $null -ne $tapService }
    finally {
        if ($null -ne $tapService) { $tapService.Dispose() }
        $registry.Dispose()
    }
    if ($tapConflicts.Count -gt 0 -or $tapClassConflicts.Count -gt 0 -or $hasTapService) {
        throw ('An existing TAP-Windows6 adapter, class entry, or tap0901 service would conflict. Installation refused. Matching instances: ' + (($tapConflicts | ForEach-Object { $_.InstanceId }) -join ', '))
    }
    $before = @(Get-NetworkSnapshot)
    $action = "Run '$script:DeviceHelper install $DriverDirectory\OemVista.inf root\tap0901'; identify exactly one new ROOT\NET\NNNN device; atomically save its GUID/PnP/class identity and original INetCfg display name to '$StatePath'; set only its ComponentId='$script:AliasComponent' and INetCfg display name='$script:AliasDescription'; restart that exact @instance only if INetCfg reports a reboot requirement. Signed driver files remain unchanged."
    if (-not $PSCmdlet.ShouldProcess('One new ARM64 TAP-Windows6 adapter', $action)) { return }
    $state = $null
    $install = Invoke-Device -Arguments @('install', (Join-Path $DriverDirectory 'OemVista.inf'), 'root\tap0901')
    try {
        $candidates = @()
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            $after = @(Get-NetworkSnapshot)
            $candidates = @($after | Where-Object {
                $_.InstanceId -notin @($before.InstanceId) -and
                $_.ClassKeyName -notin @($classesBefore.ClassKeyName) -and
                $_.Service -ieq 'tap0901' -and
                (@($_.HardwareIds) -icontains 'root\tap0901')
            })
            if ($candidates.Count -gt 0) { break }
            Start-Sleep -Milliseconds 500
        }
        if ($candidates.Count -ne 1) {
            $ids = ($candidates | ForEach-Object { $_.InstanceId }) -join ', '
            throw "Could not identify exactly one newly created TAP device (found $($candidates.Count): $ids). No adapter aliases were changed. Device helper exit $($install.ExitCode): $($install.Output)"
        }
        $new = $candidates[0]
        $state = [pscustomobject]@{
            SchemaVersion = 1
            Kind = 'TrusGuard-WOA-TAP-Adapter'
            CreatedUtc = [DateTime]::UtcNow.ToString('o')
            Stage = 'CreatedBeforeAlias'
            InstanceId = $new.InstanceId
            NetCfgInstanceId = $new.NetCfgInstanceId
            ClassKeyName = $new.ClassKeyName
            ClassDriver = $new.ClassDriver
            Service = $new.Service
            HardwareIds = $new.HardwareIds
            OriginalValues = Get-OriginalAliasValues $new.ClassKeyName
            InstallExitCode = $install.ExitCode
            RebootRequired = ($install.ExitCode -eq 1)
        }
        Assert-StateShape $state
        [void](Resolve-StateDevice $state)
        Write-AdapterState $state
        if ($install.ExitCode -notin @(0, 1)) {
            throw "Device installation reported failure after creating a device. State saved for exact rollback. Exit $($install.ExitCode): $($install.Output)"
        }
        Complete-AdapterCompatibility $state
        [pscustomobject]@{
            Result = 'Experimental adapter installed; VPN compatibility remains unverified.'
            InstanceId = $state.InstanceId
            NetCfgInstanceId = $state.NetCfgInstanceId
            StatePath = $StatePath
            RebootRequired = $state.RebootRequired
        } | ConvertTo-Json
    }
    catch {
        if ($null -ne $state -and [IO.File]::Exists($StatePath)) {
            Write-Warning "The exact-device state is retained at '$StatePath'. Use -Mode Remove to restore/remove this recorded adapter."
        }
        throw
    }
    return
}

if ($Mode -eq 'Resume') {
    if (-not [IO.File]::Exists($StatePath)) { throw "No recorded adapter state exists: $StatePath" }
    $resumeState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    $resumeDevice = Resolve-StateDevice $resumeState
    if ($resumeState.Stage -notin @('CreatedBeforeAlias', 'OriginalDisplayNameSaved', 'AliasWritten', 'DisplayNameApplied', 'AliasInstalled')) {
        throw "Cannot resume state stage '$($resumeState.Stage)'. Inspect the state; removal states must not be resumed as an installation."
    }
    $resumeAction = "Revalidate saved GUID/PnP/class/service identity; save the exact GUID's original INetCfg display name if not already recorded; keep ComponentId='$script:AliasComponent' and restore the original DriverDesc at HKLM\$script:ClassRoot\$($resumeState.ClassKeyName); use tg-woa-name.exe --set-name '$($resumeState.NetCfgInstanceId)' '$script:AliasDescription'; restart exact @$($resumeState.InstanceId) only if INetCfg reports a reboot requirement; atomically update '$StatePath'. No driver installation or new adapter creation."
    if (-not $PSCmdlet.ShouldProcess($resumeDevice.InstanceId, $resumeAction)) { return }
    try {
        Complete-AdapterCompatibility $resumeState
        [pscustomobject]@{
            Result = 'Recorded adapter installation resumed; VPN compatibility remains unverified.'
            InstanceId = $resumeState.InstanceId
            NetCfgInstanceId = $resumeState.NetCfgInstanceId
            StatePath = $StatePath
            RebootRequired = $resumeState.RebootRequired
        } | ConvertTo-Json
    }
    catch {
        Write-Warning "The exact-device state is retained at '$StatePath'. Inspect it, retry -Mode Resume, or use -Mode Remove for exact rollback."
        throw
    }
    return
}

if (-not [IO.File]::Exists($StatePath)) { throw "No recorded adapter state exists: $StatePath" }
$savedState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
$recorded = Resolve-StateDevice $savedState
$removeAction = "Restore the recorded original INetCfg display name (when saved) for exact GUID $($savedState.NetCfgInstanceId), then restore saved ComponentId/DriverDesc only at HKLM\$script:ClassRoot\$($savedState.ClassKeyName); run '$script:DeviceHelper remove @$($savedState.InstanceId)'; delete this state file only after disappearance is verified. Leave shared driver store/service and every other adapter untouched."
if (-not $PSCmdlet.ShouldProcess($recorded.InstanceId, $removeAction)) { return }
if ($savedState.PSObject.Properties.Name -contains 'OriginalDisplayName') {
    $restoredName = Invoke-NameHelper -State $savedState -SetName -Name $savedState.OriginalDisplayName
    $savedState.RebootRequired = $savedState.RebootRequired -or ($restoredName.hresult -ieq '0x0004A020')
}
Set-AdapterAliases $savedState -Restore
$savedState.Stage = 'AliasesRestoredBeforeRemove'
Write-AdapterState $savedState
$remove = Invoke-Device -Arguments @('remove', ('@' + $savedState.InstanceId))
if ($remove.ExitCode -notin @(0, 1)) {
    throw "Device removal failed; original aliases restored and state retained. Exit $($remove.ExitCode): $($remove.Output)"
}
$remaining = @()
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    $remaining = @(Get-NetworkSnapshot -IncludeNonPresent | Where-Object { $_.InstanceId -ieq $savedState.InstanceId })
    if ($remaining.Count -eq 0) { break }
    Start-Sleep -Milliseconds 500
}
if ($remaining.Count -gt 0) {
    $savedState.Stage = 'RemovalPending'
    $savedState.RebootRequired = ($remove.ExitCode -eq 1)
    Write-AdapterState $savedState
    throw "The recorded instance is still enumerated after remove (exit $($remove.ExitCode)). State retained. Reboot may be required; inspect before retrying."
}
[IO.File]::Delete($StatePath)
[pscustomobject]@{
    Result = 'Only the recorded TAP adapter was removed. Shared driver package/service retained.'
    InstanceId = $savedState.InstanceId
    RebootRequired = ($remove.ExitCode -eq 1)
} | ConvertTo-Json
