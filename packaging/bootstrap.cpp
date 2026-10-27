#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#if !defined(_M_ARM64)
#error Build this self-extracting bootstrap for native Windows ARM64.
#endif

namespace {
constexpr char footerMagic[17] = "TGWOA-SFX-ZIP-v1";
constexpr std::uint64_t footerBytes = 56;
constexpr std::uint64_t maximumZipBytes = 256ULL * 1024 * 1024;

[[noreturn]] void fail(const char* operation, DWORD code = GetLastError()) {
    throw std::runtime_error(std::string(operation) + " (code " + std::to_string(code) + ")");
}

struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE input = INVALID_HANDLE_VALUE) : value(input) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value); }
};

struct Sha256 {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<unsigned char> object;
    Sha256() {
        NTSTATUS result = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (result < 0) fail("BCryptOpenAlgorithmProvider", static_cast<DWORD>(result));
        DWORD bytes = 0, returned = 0;
        result = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&bytes), sizeof bytes, &returned, 0);
        if (result < 0) { BCryptCloseAlgorithmProvider(algorithm, 0); algorithm = nullptr; fail("BCryptGetProperty", static_cast<DWORD>(result)); }
        object.resize(bytes);
        result = BCryptCreateHash(algorithm, &hash, object.data(), bytes, nullptr, 0, 0);
        if (result < 0) { BCryptCloseAlgorithmProvider(algorithm, 0); algorithm = nullptr; fail("BCryptCreateHash", static_cast<DWORD>(result)); }
    }
    ~Sha256() {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    void update(unsigned char* data, DWORD size) {
        const NTSTATUS result = BCryptHashData(hash, data, size, 0);
        if (result < 0) fail("BCryptHashData", static_cast<DWORD>(result));
    }
    std::array<unsigned char, 32> finish() {
        std::array<unsigned char, 32> digest{};
        const NTSTATUS result = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
        if (result < 0) fail("BCryptFinishHash", static_cast<DWORD>(result));
        return digest;
    }
};

std::wstring executablePath() {
    std::vector<wchar_t> path(32768);
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) fail("GetModuleFileNameW");
    return std::wstring(path.data(), length);
}

std::wstring absolutePath(const wchar_t* input) {
    const DWORD needed = GetFullPathNameW(input, 0, nullptr, nullptr);
    if (!needed || needed > 32768) fail("GetFullPathNameW");
    std::vector<wchar_t> path(needed);
    const DWORD length = GetFullPathNameW(input, needed, path.data(), nullptr);
    if (!length || length >= needed) fail("GetFullPathNameW");
    return std::wstring(path.data(), length);
}

std::wstring temporaryDirectory() {
    std::vector<wchar_t> base(32768);
    const DWORD length = GetTempPathW(static_cast<DWORD>(base.size()), base.data());
    if (!length || length >= base.size()) fail("GetTempPathW");
    for (unsigned int attempt = 0; attempt < 8; ++attempt) {
        std::array<unsigned char, 16> random{};
        const NTSTATUS result = BCryptGenRandom(nullptr, random.data(),
            static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (result < 0) fail("BCryptGenRandom", static_cast<DWORD>(result));
        std::wstring path(base.data(), length);
        path += L"TrusGuard-WOA-";
        constexpr wchar_t hex[] = L"0123456789abcdef";
        for (unsigned char value : random) { path += hex[value >> 4]; path += hex[value & 15]; }
        if (CreateDirectoryW(path.c_str(), nullptr)) return path;
        if (GetLastError() != ERROR_ALREADY_EXISTS) fail("CreateDirectoryW temporary directory");
    }
    fail("CreateDirectoryW random directory", ERROR_ALREADY_EXISTS);
}

void seek(HANDLE file, std::uint64_t offset) {
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) fail("SetFilePointerEx");
}

void readExact(HANDLE file, unsigned char* output, DWORD size) {
    DWORD returned = 0;
    if (!ReadFile(file, output, size, &returned, nullptr)) fail("ReadFile");
    if (returned != size) fail("ReadFile truncated package", ERROR_HANDLE_EOF);
}

void writeExact(HANDLE file, const unsigned char* input, DWORD size) {
    DWORD returned = 0;
    if (!WriteFile(file, input, size, &returned, nullptr)) fail("WriteFile");
    if (returned != size) fail("WriteFile incomplete", ERROR_WRITE_FAULT);
}

std::wstring quoteArgument(const std::wstring& value) {
    // CommandLineToArgvW / Microsoft CRT quoting, including trailing backslashes.
    std::wstring output = L"\"";
    size_t slashes = 0;
    for (wchar_t character : value) {
        if (character == L'\\') { ++slashes; continue; }
        if (character == L'\"') {
            output.append(slashes * 2 + 1, L'\\');
            output += L'\"';
        } else {
            output.append(slashes, L'\\');
            output += character;
        }
        slashes = 0;
    }
    output.append(slashes * 2, L'\\');
    output += L'\"';
    return output;
}

constexpr char extractor[] = R"PS1(param(
    [Parameter(Mandatory=$true)][string]$ZipPath,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][ValidateSet('Verify','Extract','Install')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $sha = [Security.Cryptography.SHA256]::Create()
    $inputFile = [IO.File]::OpenRead($ZipPath)
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($inputFile))).Replace('-','') }
    finally { $inputFile.Dispose(); $sha.Dispose() }
    if ($actual -ine $ExpectedSha256) { throw 'Payload ZIP changed before extraction.' }

    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if ($root -notmatch '^[A-Za-z]:\\') { throw 'Extraction requires a local drive path.' }
    $prefix = $root + '\'
    if ($Action -ne 'Verify' -and (Test-Path -LiteralPath $root)) { throw 'Extraction destination already exists.' }
    $names = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $files = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $directories = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $items = New-Object 'Collections.Generic.List[object]'
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        if ($archive.Entries.Count -lt 1 -or $archive.Entries.Count -gt 4096) { throw 'Unexpected ZIP entry count.' }
        [long]$total = 0
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\','/')
            $isDirectory = $name.EndsWith('/')
            if ($name.Length -gt 240 -or $name -notmatch '^[A-Za-z0-9_. /-]+$' -or $name.StartsWith('/')) {
                throw 'Unsafe ZIP entry name.'
            }
            $trimmed = $name.TrimEnd('/')
            if (-not $names.Add($trimmed)) { throw 'Duplicate ZIP entry.' }
            $segments = $trimmed.Split('/')
            foreach ($segment in $segments) {
                if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.' -or $segment -eq '..' -or
                    $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
                    $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CLOCK\$|CONIN\$|CONOUT\$)(?:\.|$)') {
                    throw 'Unsafe ZIP path component.'
                }
            }
            $type = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if (($type -ne 0 -and $type -ne 0x8000 -and $type -ne 0x4000) -or
                ($entry.ExternalAttributes -band 0x400) -ne 0) { throw 'ZIP link or reparse entry rejected.' }
            if ($entry.Length -lt 0 -or $entry.Length -gt 134217728 -or ($isDirectory -and $entry.Length -ne 0)) {
                throw 'ZIP entry size is outside limits.'
            }
            $total += $entry.Length
            if ($total -gt 536870912) { throw 'ZIP unpacked size is outside limits.' }
            $relative = $trimmed.Replace('/','\')
            $path = [IO.Path]::GetFullPath([IO.Path]::Combine($root,$relative))
            if (-not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'ZIP path escaped extraction root.' }
            if ($isDirectory) { [void]$directories.Add($relative) } else { [void]$files.Add($relative) }
            $parent = [IO.Path]::GetDirectoryName($relative)
            while (-not [string]::IsNullOrEmpty($parent)) {
                [void]$directories.Add($parent)
                $parent = [IO.Path]::GetDirectoryName($parent)
            }
            $items.Add([pscustomobject]@{Entry=$entry;Path=$path;Directory=$isDirectory})
        }
        foreach ($path in $files) { if ($directories.Contains($path)) { throw 'ZIP file/directory collision.' } }
        if (-not $files.Contains('Install-Package.ps1')) { throw 'Installer entry script is missing.' }

        if ($Action -ne 'Verify') { [void][IO.Directory]::CreateDirectory($root) }
        [long]$writtenTotal = 0
        $buffer = New-Object byte[] 65536
        foreach ($item in $items) {
            if ($item.Directory) {
                if ($Action -ne 'Verify') { [void][IO.Directory]::CreateDirectory($item.Path) }
                continue
            }
            $source = $item.Entry.Open()
            $target = $null
            try {
                if ($Action -ne 'Verify') {
                    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($item.Path))
                    $target = New-Object IO.FileStream($item.Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                }
                [long]$written = 0
                while (($count = $source.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $written += $count
                    $writtenTotal += $count
                    if ($written -gt $item.Entry.Length -or $writtenTotal -gt 536870912) { throw 'ZIP decompression exceeded declared limits.' }
                    if ($null -ne $target) { $target.Write($buffer,0,$count) }
                }
                if ($written -ne $item.Entry.Length) { throw 'Truncated ZIP entry.' }
            } finally {
                if ($null -ne $target) { $target.Dispose() }
                $source.Dispose()
            }
        }
    } finally { $archive.Dispose() }
    if ($Action -eq 'Verify') {
        Write-Output 'Verified payload ZIP. No installation was performed.'
    } elseif ($Action -eq 'Extract') {
        Write-Output ('Extracted payload to: ' + $root)
    } else {
        $global:LASTEXITCODE = 0
        & ([IO.Path]::Combine($root,'Install-Package.ps1'))
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
)PS1";

int run(int argc, wchar_t** argv) {
    std::wstring action = L"Install";
    std::wstring destination;
    if (argc == 2 && (wcscmp(argv[1], L"--help") == 0 || wcscmp(argv[1], L"/?") == 0)) {
        puts("Usage: tgsvpn_setup_x64_patched.exe [--verify | --extract <new-directory>]");
        return 0;
    }
    if (argc == 2 && wcscmp(argv[1], L"--verify") == 0) action = L"Verify";
    else if (argc == 3 && wcscmp(argv[1], L"--extract") == 0) { action = L"Extract"; destination = absolutePath(argv[2]); }
    else if (argc != 1) { fputs("Invalid arguments. Use --help.\n", stderr); return 2; }

    const std::wstring self = executablePath();
    Handle input(CreateFileW(self.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (input.value == INVALID_HANDLE_VALUE) fail("Open bootstrap executable");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(input.value, &size)) fail("GetFileSizeEx");
    if (size.QuadPart < static_cast<LONGLONG>(footerBytes + 64)) fail("Package footer missing", ERROR_INVALID_DATA);
    std::array<unsigned char, footerBytes> footer{};
    seek(input.value, static_cast<std::uint64_t>(size.QuadPart) - footerBytes);
    readExact(input.value, footer.data(), static_cast<DWORD>(footer.size()));
    if (memcmp(footer.data(), footerMagic, 16) != 0) fail("Package magic mismatch", ERROR_INVALID_DATA);
    std::uint64_t zipBytes = 0;
    memcpy(&zipBytes, footer.data() + 16, sizeof zipBytes);
    if (!zipBytes || zipBytes > maximumZipBytes || zipBytes > static_cast<std::uint64_t>(size.QuadPart) - footerBytes - 64) {
        fail("Package ZIP length invalid", ERROR_INVALID_DATA);
    }

    const std::wstring work = temporaryDirectory();
    if (destination.empty()) destination = work + L"\\payload";
    const std::wstring zipPath = work + L"\\payload.zip";
    const std::wstring scriptPath = work + L"\\extract.ps1";
    {
        Handle zip(CreateFileW(zipPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (zip.value == INVALID_HANDLE_VALUE) fail("Create payload ZIP");
        seek(input.value, static_cast<std::uint64_t>(size.QuadPart) - footerBytes - zipBytes);
        std::vector<unsigned char> buffer(1024 * 1024);
        Sha256 hash;
        std::uint64_t remaining = zipBytes;
        while (remaining) {
            const DWORD chunk = static_cast<DWORD>(remaining < buffer.size() ? remaining : buffer.size());
            readExact(input.value, buffer.data(), chunk);
            hash.update(buffer.data(), chunk);
            writeExact(zip.value, buffer.data(), chunk);
            remaining -= chunk;
        }
        const auto digest = hash.finish();
        if (memcmp(digest.data(), footer.data() + 24, digest.size()) != 0) fail("Package SHA256 mismatch", ERROR_CRC);
    }
    {
        Handle script(CreateFileW(scriptPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (script.value == INVALID_HANDLE_VALUE) fail("Create extraction script");
        writeExact(script.value, reinterpret_cast<const unsigned char*>(extractor), static_cast<DWORD>(sizeof extractor - 1));
    }
    std::wstring digestHex;
    constexpr wchar_t hex[] = L"0123456789ABCDEF";
    for (size_t i = 24; i < footer.size(); ++i) { digestHex += hex[footer[i] >> 4]; digestHex += hex[footer[i] & 15]; }
    std::vector<wchar_t> windows(32768);
    const UINT windowsLength = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    if (!windowsLength || windowsLength >= windows.size()) fail("GetWindowsDirectoryW");
    const std::wstring powershell = std::wstring(windows.data(), windowsLength) + L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    std::wstring command = quoteArgument(powershell) + L" -NoProfile -ExecutionPolicy RemoteSigned -File " + quoteArgument(scriptPath)
        + L" -ZipPath " + quoteArgument(zipPath) + L" -Destination " + quoteArgument(destination)
        + L" -Action " + quoteArgument(action) + L" -ExpectedSha256 " + quoteArgument(digestHex);
    STARTUPINFOW startup{}; startup.cb = sizeof startup;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(powershell.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr, work.c_str(), &startup, &process)) {
        fail("Start PowerShell extractor");
    }
    Handle thread(process.hThread);
    Handle child(process.hProcess);
    if (WaitForSingleObject(child.value, INFINITE) != WAIT_OBJECT_0) fail("Wait for package operation");
    DWORD exitCode = 1;
    if (!GetExitCodeProcess(child.value, &exitCode)) fail("Get package exit code");
    std::wcout << L"Package working files: " << work << L'\n';
    return static_cast<int>(exitCode);
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try { return run(argc, argv); }
    catch (const std::exception& error) { std::cerr << "TrusGuard ARM64 package: " << error.what() << '\n'; return 1; }
}
