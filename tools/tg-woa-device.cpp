// Native device setup helper for the single dedicated TAP-Windows6 adapter.
// Uses Windows SDK APIs directly; it does not redistribute DevCon.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>
#include <stdexcept>

#if !defined(_M_ARM64)
#error Build this helper for native Windows ARM64.
#endif

namespace {
constexpr GUID networkClass = {
    0x4d36e972, 0xe325, 0x11ce,
    {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}
};
constexpr wchar_t targetHardware[] = L"root\\tap0901";
constexpr wchar_t targetService[] = L"tap0901";

struct Error {
    const wchar_t* operation;
    DWORD code;
};

[[noreturn]] void fail(const wchar_t* operation, DWORD code = GetLastError()) {
    throw Error{operation, code ? code : ERROR_GEN_FAILURE};
}

class DeviceSet {
public:
    explicit DeviceSet(HDEVINFO value) : value_(value) {
        if (value == INVALID_HANDLE_VALUE) fail(L"Create device information set");
    }
    ~DeviceSet() { SetupDiDestroyDeviceInfoList(value_); }
    DeviceSet(const DeviceSet&) = delete;
    DeviceSet& operator=(const DeviceSet&) = delete;
    operator HDEVINFO() const { return value_; }
private:
    HDEVINFO value_;
};

struct Property {
    bool present = false;
    DWORD type = 0;
    std::vector<wchar_t> characters;
};

Property readProperty(HDEVINFO set, SP_DEVINFO_DATA& device, DWORD property) {
    DWORD type = 0, bytes = 0;
    if (SetupDiGetDeviceRegistryPropertyW(set, &device, property, &type,
                                          nullptr, 0, &bytes)) {
        fail(L"Read empty device property", ERROR_INVALID_DATA);
    }
    const DWORD error = GetLastError();
    if (error == ERROR_INVALID_DATA || error == ERROR_FILE_NOT_FOUND) return {};
    if (error != ERROR_INSUFFICIENT_BUFFER) fail(L"Read device property size", error);
    if (bytes < sizeof(wchar_t) || bytes > 65536 || bytes % sizeof(wchar_t)) {
        fail(L"Validate device property length", ERROR_INVALID_DATA);
    }
    Property result;
    result.characters.resize(bytes / sizeof(wchar_t) + 2, L'\0');
    if (!SetupDiGetDeviceRegistryPropertyW(set, &device, property, &type,
            reinterpret_cast<PBYTE>(result.characters.data()), bytes, &bytes)) {
        fail(L"Read device property");
    }
    result.present = true;
    result.type = type;
    return result;
}

bool hardwareMatches(HDEVINFO set, SP_DEVINFO_DATA& device) {
    const Property property = readProperty(set, device, SPDRP_HARDWAREID);
    if (!property.present) return false;
    if (property.type != REG_MULTI_SZ) fail(L"Validate hardware ID type", ERROR_INVALID_DATA);
    const wchar_t* cursor = property.characters.data();
    const wchar_t* end = cursor + property.characters.size();
    while (cursor < end && *cursor) {
        const size_t length = wcsnlen_s(cursor, static_cast<size_t>(end - cursor));
        if (length == static_cast<size_t>(end - cursor)) {
            fail(L"Validate hardware ID terminator", ERROR_INVALID_DATA);
        }
        if (_wcsicmp(cursor, targetHardware) == 0 || _wcsicmp(cursor, L"tap0901") == 0) return true;
        cursor += length + 1;
    }
    return false;
}

bool serviceMatches(HDEVINFO set, SP_DEVINFO_DATA& device) {
    const Property property = readProperty(set, device, SPDRP_SERVICE);
    if (!property.present) return false;
    if (property.type != REG_SZ) fail(L"Validate service property type", ERROR_INVALID_DATA);
    return _wcsicmp(property.characters.data(), targetService) == 0;
}

std::wstring instanceId(HDEVINFO set, SP_DEVINFO_DATA& device) {
    wchar_t buffer[MAX_DEVICE_ID_LEN]{};
    if (!SetupDiGetDeviceInstanceIdW(set, &device, buffer, ARRAYSIZE(buffer), nullptr)) {
        fail(L"Get device instance ID");
    }
    return buffer;
}

bool validInstance(const wchar_t* identifier) {
    constexpr wchar_t prefix[] = L"ROOT\\NET\\";
    constexpr size_t prefixLength = ARRAYSIZE(prefix) - 1;
    if (wcslen(identifier) != prefixLength + 4 ||
        _wcsnicmp(identifier, prefix, prefixLength) != 0) return false;
    for (size_t i = prefixLength; i < prefixLength + 4; ++i) {
        const wchar_t ch = identifier[i];
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
              (ch >= L'A' && ch <= L'F'))) return false;
    }
    return true;
}

void assertAdministrator() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
        fail(L"Create administrator SID");
    }
    BOOL member = FALSE;
    const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
    const DWORD error = checked ? ERROR_SUCCESS : GetLastError();
    FreeSid(administrators);
    if (!checked) fail(L"Check administrator token", error);
    if (!member) fail(L"Administrator approval required", ERROR_ELEVATION_REQUIRED);
}

void assertNoDriverService() {
    HKEY key = nullptr;
    const LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\tap0901", 0,
        KEY_READ | KEY_WOW64_64KEY, &key);
    if (status == ERROR_SUCCESS) {
        RegCloseKey(key);
        fail(L"Existing TAP-Windows6 service conflicts with a new adapter", ERROR_ALREADY_EXISTS);
    }
    if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) {
        fail(L"Inspect existing TAP-Windows6 service", static_cast<DWORD>(status));
    }
}

// Include non-present devices. Updating a shared hardware ID must never reach
// another application's adapter, including an unplugged/hidden one.
void assertOnlyMatchingDevice(const std::wstring& allowed = L"", bool requireAllowed = true) {
    DeviceSet set(SetupDiGetClassDevsW(&networkClass, nullptr, nullptr, 0));
    size_t allowedCount = 0;
    for (DWORD index = 0;; ++index) {
        SP_DEVINFO_DATA device{};
        device.cbSize = sizeof(device);
        if (!SetupDiEnumDeviceInfo(set, index, &device)) {
            const DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) break;
            fail(L"Enumerate network devices", error);
        }
        if (!hardwareMatches(set, device) && !serviceMatches(set, device)) continue;
        const std::wstring actual = instanceId(set, device);
        if (allowed.empty() || _wcsicmp(actual.c_str(), allowed.c_str()) != 0) {
            fail(L"Existing TAP-Windows6 device conflicts with installation", ERROR_ALREADY_EXISTS);
        }
        ++allowedCount;
    }
    if (!allowed.empty() && requireAllowed && allowedCount != 1) {
        fail(L"Verify newly registered TAP device", ERROR_NO_SUCH_DEVINST);
    }
}

void assertTarget(HDEVINFO set, SP_DEVINFO_DATA& device, const std::wstring& expected,
                  bool requireService = true) {
    if (!IsEqualGUID(device.ClassGuid, networkClass) ||
        _wcsicmp(instanceId(set, device).c_str(), expected.c_str()) != 0 ||
        !validInstance(expected.c_str()) || !hardwareMatches(set, device) ||
        (requireService && !serviceMatches(set, device))) {
        fail(L"Exact TAP device identity validation", ERROR_INVALID_DATA);
    }
}

bool rebootRequired(HDEVINFO set, SP_DEVINFO_DATA& device) {
    SP_DEVINSTALL_PARAMS_W parameters{};
    parameters.cbSize = sizeof(parameters);
    if (!SetupDiGetDeviceInstallParamsW(set, &device, &parameters)) fail(L"Read device install status");
    return (parameters.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
}

void removeDevice(HDEVINFO set, SP_DEVINFO_DATA& device) {
    SP_REMOVEDEVICE_PARAMS parameters{};
    parameters.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    parameters.ClassInstallHeader.InstallFunction = DIF_REMOVE;
    parameters.Scope = DI_REMOVEDEVICE_GLOBAL;
    parameters.HwProfile = 0;
    if (!SetupDiSetClassInstallParamsW(set, &device, &parameters.ClassInstallHeader,
                                      sizeof(parameters))) {
        fail(L"Set exact-device removal parameters");
    }
    if (!SetupDiCallClassInstaller(DIF_REMOVE, set, &device)) fail(L"Remove exact TAP device");
}

std::wstring validateInf(const wchar_t* input) {
    // Only local fully-qualified paths are accepted; no wildcards or UNC input.
    if (wcslen(input) < 4 || input[1] != L':' || input[2] != L'\\' ||
        !((input[0] >= L'A' && input[0] <= L'Z') || (input[0] >= L'a' && input[0] <= L'z'))) {
        fail(L"INF must be a fully-qualified local path", ERROR_BAD_PATHNAME);
    }
    const DWORD needed = GetFullPathNameW(input, 0, nullptr, nullptr);
    if (!needed || needed > 32768) fail(L"Resolve INF path");
    std::vector<wchar_t> path(needed + 1, L'\0');
    const DWORD written = GetFullPathNameW(input, static_cast<DWORD>(path.size()), path.data(), nullptr);
    if (!written || written >= path.size()) fail(L"Resolve INF path", ERROR_BAD_PATHNAME);
    const wchar_t* basename = wcsrchr(path.data(), L'\\');
    if (!basename || _wcsicmp(basename + 1, L"OemVista.inf") != 0) {
        fail(L"Expected the staged OemVista.inf", ERROR_INVALID_NAME);
    }
    const DWORD attributes = GetFileAttributesW(path.data());
    if (attributes == INVALID_FILE_ATTRIBUTES) fail(L"Inspect staged INF");
    if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
        fail(L"INF must be a regular local file", ERROR_INVALID_DATA);
    }
    GUID infClass{};
    wchar_t className[128]{};
    if (!SetupDiGetINFClassW(path.data(), &infClass, className, ARRAYSIZE(className), nullptr)) {
        fail(L"Read INF network class");
    }
    if (!IsEqualGUID(infClass, networkClass)) fail(L"INF must target the network device class", ERROR_CLASS_MISMATCH);
    return path.data();
}

int install(const wchar_t* path) {
    const std::wstring inf = validateInf(path);
    assertNoDriverService();
    assertOnlyMatchingDevice();
    DeviceSet set(SetupDiCreateDeviceInfoList(&networkClass, nullptr));
    SP_DEVINFO_DATA device{};
    device.cbSize = sizeof(device);
    if (!SetupDiCreateDeviceInfoW(set, L"Net", &networkClass, L"TAP-Windows Adapter V9",
            nullptr, DICD_GENERATE_ID, &device)) {
        fail(L"Create dedicated TAP device information");
    }
    // The explicit NUL plus the string terminator form the REG_MULTI_SZ end.
    constexpr wchar_t hardwareIds[] = L"root\\tap0901\0";
    if (!SetupDiSetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID,
            reinterpret_cast<const BYTE*>(hardwareIds), sizeof(hardwareIds))) {
        fail(L"Set dedicated TAP hardware ID");
    }
    std::wstring created = instanceId(set, device);
    if (!validInstance(created.c_str())) fail(L"Validate generated ROOT NET instance", ERROR_INVALID_DATA);
    bool registered = false;
    try {
        // Repeat the conflict check immediately before publishing the devnode.
        assertNoDriverService();
        assertOnlyMatchingDevice(created, false);
        // A class installer can partially register a devnode before reporting
        // failure, so make the exact freshly allocated identity rollbackable.
        registered = true;
        if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, &device)) fail(L"Register dedicated TAP device");
        created = instanceId(set, device);
        assertTarget(set, device, created, false);
        assertOnlyMatchingDevice(created);
        BOOL restart = FALSE;
        if (!UpdateDriverForPlugAndPlayDevicesW(nullptr, targetHardware, inf.c_str(),
                                                INSTALLFLAG_FORCE, &restart)) {
            fail(L"Install signed TAP driver");
        }
        assertTarget(set, device, created);
        const bool needsReboot = restart != FALSE || rebootRequired(set, device);
        registered = false; // Ownership is now handed back to the caller's state file.
        wprintf(L"Installed dedicated TAP device %ls.%ls\n", created.c_str(),
                needsReboot ? L" Restart required." : L"");
        return needsReboot ? 1 : 0;
    } catch (...) {
        if (registered) {
            try {
                // Roll back only the exact devnode allocated by this invocation.
                assertTarget(set, device, created, false);
                removeDevice(set, device);
            } catch (const Error& cleanup) {
                fwprintf(stderr, L"Rollback of %ls failed at %ls (Win32 %lu).\n",
                         created.c_str(), cleanup.operation, cleanup.code);
            } catch (...) {
                fwprintf(stderr, L"Rollback of the newly created TAP device failed.\n");
            }
        }
        throw;
    }
}

int change(const wchar_t* identifier, bool remove) {
    if (!identifier || identifier[0] != L'@' || !validInstance(identifier + 1)) {
        fail(L"Expected one exact @ROOT\\NET\\NNNN instance", ERROR_INVALID_NAME);
    }
    const std::wstring expected = identifier + 1;
    DeviceSet set(SetupDiCreateDeviceInfoList(&networkClass, nullptr));
    SP_DEVINFO_DATA device{};
    device.cbSize = sizeof(device);
    if (!SetupDiOpenDeviceInfoW(set, expected.c_str(), nullptr, 0, &device)) fail(L"Open exact TAP device");
    assertTarget(set, device, expected);
    if (remove) {
        removeDevice(set, device);
    } else {
        SP_PROPCHANGE_PARAMS parameters{};
        parameters.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        parameters.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        parameters.StateChange = DICS_PROPCHANGE;
        parameters.Scope = DICS_FLAG_GLOBAL;
        parameters.HwProfile = 0;
        if (!SetupDiSetClassInstallParamsW(set, &device, &parameters.ClassInstallHeader,
                                          sizeof(parameters))) {
            fail(L"Set exact-device restart parameters");
        }
        if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, set, &device)) fail(L"Restart exact TAP device");
    }
    const bool restart = rebootRequired(set, device);
    wprintf(L"%ls %ls.%ls\n", remove ? L"Removed" : L"Restarted", expected.c_str(),
            restart ? L" Restart required." : L"");
    return restart ? 1 : 0;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && wcscmp(argv[1], L"--version") == 0) {
        puts("tg-woa-device 1.0 (ARM64)");
        return 0;
    }
    const bool installing = argc == 4 && wcscmp(argv[1], L"install") == 0 &&
                            _wcsicmp(argv[3], targetHardware) == 0;
    const bool restarting = argc == 3 && wcscmp(argv[1], L"restart") == 0;
    const bool removing = argc == 3 && wcscmp(argv[1], L"remove") == 0;
    if (!installing && !restarting && !removing) {
        fputs("Usage:\n  tg-woa-device install C:\\path\\OemVista.inf root\\tap0901\n"
              "  tg-woa-device restart @ROOT\\NET\\NNNN\n"
              "  tg-woa-device remove @ROOT\\NET\\NNNN\n"
              "  tg-woa-device --version\n", stderr);
        return 2;
    }
    try {
        assertAdministrator();
        return installing ? install(argv[2]) : change(argv[2], removing);
    } catch (const Error& error) {
        fwprintf(stderr, L"%ls failed (Win32 %lu).\n", error.operation, error.code);
    } catch (const std::exception&) {
        fputs("The native device helper could not complete the operation.\n", stderr);
    } catch (...) {
        fputs("Unexpected native device helper failure.\n", stderr);
    }
    return 2;
}
