[CmdletBinding()]
param(
    [string]$VisualStudio = 'C:\Program Files\Microsoft Visual Studio\2022\Community',
    [string]$WindowsSdk = 'C:\Program Files (x86)\Windows Kits\10'
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$msvc = Get-ChildItem -LiteralPath "$VisualStudio\VC\Tools\MSVC" -Directory |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
$sdk = Get-ChildItem -LiteralPath "$WindowsSdk\Include" -Directory |
    Where-Object Name -Match '^\d+\.\d+\.\d+\.\d+$' |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $msvc -or -not $sdk) { throw 'Visual C++ ARM64 tools and Windows SDK are required.' }
$hostName = if ($env:PROCESSOR_ARCHITECTURE -ieq 'ARM64') { 'Hostarm64' } else { 'Hostx64' }
$compiler = "$($msvc.FullName)\bin\$hostName\arm64\cl.exe"
if (-not (Test-Path -LiteralPath $compiler)) { throw "ARM64 compiler not found: $compiler" }
$oldInclude = $env:INCLUDE
$oldLib = $env:LIB
try {
    $env:INCLUDE = "$($msvc.FullName)\include;$WindowsSdk\Include\$($sdk.Name)\ucrt;$WindowsSdk\Include\$($sdk.Name)\shared;$WindowsSdk\Include\$($sdk.Name)\um"
    $env:LIB = "$($msvc.FullName)\lib\arm64;$WindowsSdk\Lib\$($sdk.Name)\ucrt\arm64;$WindowsSdk\Lib\$($sdk.Name)\um\arm64"
    $build = New-Item -ItemType Directory -Path "$taskRoot\build\native" -Force
    $assets = New-Item -ItemType Directory -Path "$taskRoot\assets\arm64" -Force
    $specs = @(
        @{Name='tg-woa-probe';Source='tools\tg-woa-probe.cpp';Libraries=@('iphlpapi.lib')},
        @{Name='tg-woa-name';Source='tools\tg-woa-name.cpp';Libraries=@('ole32.lib','uuid.lib')},
        @{Name='tg-woa-device';Source='tools\tg-woa-device.cpp';Libraries=@('setupapi.lib','newdev.lib','cfgmgr32.lib','advapi32.lib')},
        @{Name='tg-woa-sfx';Source='packaging\bootstrap.cpp';Libraries=@('bcrypt.lib')}
    )
    foreach ($spec in $specs) {
        $arguments = @('/nologo','/W4','/WX','/EHsc','/std:c++17','/MT','/O2','/DUNICODE','/D_UNICODE',
            (Join-Path $taskRoot $spec.Source),('/Fo' + (Join-Path $build.FullName ($spec.Name + '.obj'))),
            ('/Fe' + (Join-Path $assets.FullName ($spec.Name + '.exe'))),'/link','/MACHINE:ARM64') + $spec.Libraries
        & $compiler @arguments
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed: $($spec.Name) ($LASTEXITCODE)" }
    }
    [ordered]@{files=@($specs | ForEach-Object {
        [ordered]@{name=($_.Name + '.exe');sha256=(Get-FileHash -LiteralPath (Join-Path $assets.FullName ($_.Name + '.exe')) -Algorithm SHA256).Hash}
    })} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $assets.FullName 'manifest.json') -Encoding UTF8
} finally {
    $env:INCLUDE = $oldInclude
    $env:LIB = $oldLib
}
