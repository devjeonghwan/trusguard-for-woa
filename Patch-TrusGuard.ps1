#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position=0)][string]$InputPath,
    [Parameter(Position=1)][string]$OutputPath,
    [switch]$Force,
    [switch]$KeepWork
)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows is required.' }
$repo = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($InputPath)) { $InputPath = Join-Path $repo 'tgsvpn_setup_x64.exe' }
$inputFile = [IO.Path]::GetFullPath($InputPath)
if (-not [IO.File]::Exists($inputFile)) { throw "Place your original tgsvpn_setup_x64.exe here or pass -InputPath: $inputFile" }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path ([IO.Path]::GetDirectoryName($inputFile)) ([IO.Path]::GetFileNameWithoutExtension($inputFile) + '_patched.exe')
}
$outputFile = [IO.Path]::GetFullPath($OutputPath)
if ($inputFile -ieq $outputFile) { throw 'Input and output must be different files.' }
if ([IO.Path]::GetExtension($outputFile) -ine '.exe') { throw 'OutputPath must end in .exe.' }
if ([IO.File]::Exists($outputFile) -and -not $Force) { throw "Output exists; use -Force to replace it: $outputFile" }

function Get-Digest([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','') }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Assert-NoReparsePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($current)) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Use a local path without junctions or symbolic links: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}
function Assert-Arm64([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 77 -or $bytes[1] -ne 90) { throw "Not a PE file: $Path" }
    $offset = [BitConverter]::ToInt32($bytes,60)
    if ($offset -lt 64 -or $offset -gt ($bytes.Length-6) -or [BitConverter]::ToUInt32($bytes,$offset) -ne 0x4550 -or
        [BitConverter]::ToUInt16($bytes,$offset+4) -ne 0xaa64) { throw "Expected ARM64 helper: $Path" }
}
function Copy-PayloadFile([string]$Source,[string]$Relative) {
    $target = Join-Path $payload $Relative
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    [IO.File]::Copy($Source,$target,$false)
}

# Limit compatibility changes to the original version actually validated.
Assert-NoReparsePath $inputFile
Assert-NoReparsePath $outputFile
$installerHash = '71EF2F4D0AD0E1F70B46CEA7A4A25025BF827EDA0E0F1DFC4933FC9D098EC0DA'
if ((Get-Digest $inputFile) -cne $installerHash) {
    throw 'Unsupported installer. This patcher supports the inspected TrusGuard 3.0.9.1 x64 package only.'
}
if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) { throw 'Windows tar.exe is required.' }
$pins = Get-Content -LiteralPath (Join-Path $repo 'tools\driver-hashes.json') -Raw | ConvertFrom-Json
foreach ($pin in $pins.files) {
    if ($pin.name -notin @('OemVista.inf','tap0901.sys','tap0901.cat')) { throw 'Unexpected driver pin.' }
    $path = Join-Path (Join-Path $repo 'vendor\tap-windows6\arm64') $pin.name
    if ((Get-Digest $path) -ine $pin.sha256) { throw "Bundled driver hash mismatch: $($pin.name)" }
    if ($pin.name -ne 'OemVista.inf' -and (Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid') {
        throw "Bundled driver signature is invalid: $($pin.name)"
    }
}
if (@($pins.files).Count -ne 3) { throw 'Three official driver files are required.' }
$helpers = Get-Content -LiteralPath (Join-Path $repo 'assets\arm64\manifest.json') -Raw | ConvertFrom-Json
$helperNames = @('tg-woa-probe.exe','tg-woa-name.exe','tg-woa-device.exe','tg-woa-sfx.exe')
foreach ($name in $helperNames) {
    $pin = @($helpers.files | Where-Object name -CEQ $name)
    $path = Join-Path (Join-Path $repo 'assets\arm64') $name
    if ($pin.Count -ne 1 -or (Get-Digest $path) -ine $pin[0].sha256) { throw "Helper hash mismatch: $name" }
    Assert-Arm64 $path
}

$workRoot = [IO.Path]::GetFullPath((Join-Path $repo 'build'))
Assert-NoReparsePath $workRoot
[void][IO.Directory]::CreateDirectory($workRoot)
$work = Join-Path $workRoot ('patch-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$payload = Join-Path $work 'payload'
$client = Join-Path $payload 'port\client'
[void][IO.Directory]::CreateDirectory($client)
try {
    Write-Output 'Extracting the user-provided original client...'
    $entries = @(& tar.exe -tf $inputFile)
    if ($LASTEXITCODE -ne 0 -or $entries.Count -ne 45 -or @($entries | Where-Object { $_ -notmatch '^[a-zA-Z0-9_.-]+$' }).Count -or
        @($entries | Sort-Object -Unique).Count -ne $entries.Count) { throw 'Unexpected installer archive layout.' }
    & tar.exe -xf $inputFile -C $client
    if ($LASTEXITCODE -ne 0) { throw 'Original installer extraction failed.' }
    $clientFiles = @($entries | Sort-Object | ForEach-Object {
        [ordered]@{name=$_;sha256=(Get-Digest (Join-Path $client $_))}
    })
    [ordered]@{installerSha256=$installerHash;files=$clientFiles} | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $payload 'port\client-manifest.json') -Encoding UTF8

    foreach ($name in @('Install-ARM64.ps1','Start-TrusGuard.cmd','LICENSE')) {
        Copy-PayloadFile (Join-Path $repo $name) $name
    }
    foreach ($name in @('Install-Package.ps1','Uninstall-Package.ps1')) {
        Copy-PayloadFile (Join-Path (Join-Path $repo 'packaging') $name) $name
    }
    foreach ($name in @('Adapter.ps1','Deploy-Client.ps1','Start-Client.ps1','Test-Port.ps1','driver-hashes.json')) {
        Copy-PayloadFile (Join-Path (Join-Path $repo 'tools') $name) ('tools\' + $name)
    }
    foreach ($name in @('tg-woa-probe.exe','tg-woa-name.exe','tg-woa-device.exe')) {
        Copy-PayloadFile (Join-Path (Join-Path $repo 'assets\arm64') $name) ('port\' + $name)
    }
    foreach ($pin in $pins.files) {
        Copy-PayloadFile (Join-Path (Join-Path $repo 'vendor\tap-windows6\arm64') $pin.name) ('port\driver\arm64\' + $pin.name)
    }
    $pins | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $payload 'port\driver\arm64\manifest.json') -Encoding UTF8
    foreach ($name in @('COPYING','COPYRIGHT.GPL','COPYRIGHT.MIT','NOTICE.md','source\tap-windows6-9.27.0.zip')) {
        Copy-PayloadFile (Join-Path (Join-Path $repo 'vendor\tap-windows6') $name) ('licenses\tap-windows6\' + $name)
    }
    $manifestEntries = @(Get-ChildItem -LiteralPath $payload -File -Recurse | Sort-Object FullName | ForEach-Object {
        [ordered]@{path=$_.FullName.Substring($payload.Length+1).Replace('\','/');sha256=(Get-Digest $_.FullName)}
    })
    [ordered]@{schemaVersion=1;files=$manifestEntries} | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $payload 'package-manifest.json') -Encoding UTF8

    Write-Output 'Building the ARM64 self-extracting installer...'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = Join-Path $work 'payload.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($payload,$zip,[IO.Compression.CompressionLevel]::Optimal,$false)
    $temporaryExe = Join-Path $work 'patched.exe'
    $output = [IO.File]::Create($temporaryExe)
    try {
        foreach ($path in @((Join-Path $repo 'assets\arm64\tg-woa-sfx.exe'),$zip)) {
            $stream = [IO.File]::OpenRead($path)
            try { $stream.CopyTo($output) } finally { $stream.Dispose() }
        }
        $magic = [Text.Encoding]::ASCII.GetBytes('TGWOA-SFX-ZIP-v1')
        $length = [BitConverter]::GetBytes([UInt64](Get-Item -LiteralPath $zip).Length)
        $hexDigest = Get-Digest $zip
        $digest = New-Object byte[] 32
        for ($i=0; $i -lt 32; $i++) { $digest[$i]=[Convert]::ToByte($hexDigest.Substring($i*2,2),16) }
        $output.Write($magic,0,$magic.Length)
        $output.Write($length,0,$length.Length)
        $output.Write($digest,0,$digest.Length)
    } finally { $output.Dispose() }
    $outputDirectory = [IO.Path]::GetDirectoryName($outputFile)
    Assert-NoReparsePath $outputFile
    [void][IO.Directory]::CreateDirectory($outputDirectory)
    $sibling = Join-Path $outputDirectory ('.tgwoa-output-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::Copy($temporaryExe,$sibling,$false)
        Assert-NoReparsePath $outputFile
        if ([IO.File]::Exists($outputFile)) {
            if (-not $Force) { throw "Output already exists: $outputFile" }
            # Replace the directory entry rather than truncating a hardlinked input.
            [IO.File]::Replace($sibling,$outputFile,[NullString]::Value)
        } else { [IO.File]::Move($sibling,$outputFile) }
    } finally {
        if ([IO.File]::Exists($sibling)) { [IO.File]::Delete($sibling) }
    }
    Write-Output "Created: $outputFile"
    Write-Output "SHA256: $(Get-Digest $outputFile)"
    Write-Output 'The original installer was not modified. No driver or application was installed during this build.'
} finally {
    if ($KeepWork) { Write-Output "Work directory retained: $work" }
    elseif ([IO.Directory]::Exists($work)) {
        $resolved = [IO.Path]::GetFullPath($work)
        Assert-NoReparsePath $resolved
        $expectedPrefix = $workRoot.TrimEnd('\') + '\patch-'
        $item = Get-Item -LiteralPath $resolved
        if (-not $resolved.StartsWith($expectedPrefix,[StringComparison]::OrdinalIgnoreCase) -or
            $item.Name -notmatch '^patch-[0-9a-f]{32}$' -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Refusing to clean an unexpected work directory.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
