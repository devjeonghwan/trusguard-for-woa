#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#if !defined(_M_ARM64)
#error Build this diagnostic for native Windows ARM64.
#endif

static std::string json(const char* text) {
    std::string out = "\"";
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
        if (*p == '"' || *p == '\\') { out += '\\'; out += *p; }
        else if (*p < 32 || *p >= 127) {
            char escaped[7]; sprintf_s(escaped, "\\u%04x", *p); out += escaped;
        } else out += *p;
    }
    return out + '"';
}

static bool valid_guid(const wchar_t* value) {
    if (wcslen(value) != 38 || value[0] != L'{' || value[37] != L'}') return false;
    for (size_t i = 1; i < 37; ++i) {
        if (i == 9 || i == 14 || i == 19 || i == 24) { if (value[i] != L'-') return false; }
        else if (!((value[i] >= L'0' && value[i] <= L'9') ||
                   (value[i] >= L'a' && value[i] <= L'f') ||
                   (value[i] >= L'A' && value[i] <= L'F'))) return false;
    }
    return true;
}

static DWORD query(HANDLE device, DWORD code, void* output, DWORD size, DWORD* returned) {
    OVERLAPPED op{};
    op.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!op.hEvent) return GetLastError();
    BOOL ok = DeviceIoControl(device, code, output, size, output, size, returned, &op);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (error == ERROR_IO_PENDING) {
        const DWORD wait = WaitForSingleObject(op.hEvent, 5000);
        if (wait != WAIT_OBJECT_0) {
            CancelIoEx(device, &op);
            GetOverlappedResult(device, &op, returned, TRUE);
            error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_GEN_FAILURE;
        } else error = GetOverlappedResult(device, &op, returned, FALSE) ? ERROR_SUCCESS : GetLastError();
    }
    CloseHandle(op.hEvent);
    return error;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 1 && !(argc == 3 && wcscmp(argv[1], L"--tap") == 0 && valid_guid(argv[2]))) {
        fputs("Usage: tg-woa-probe.exe [--tap {adapter-guid}]\n", stderr);
        return 2;
    }
    USHORT process = 0, native = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &native)) return 3;
    printf("{\"nativeMachine\":%u,\"processMachine\":%u,\"compiledMachine\":43620,", native, process);
    ULONG size = 0;
    DWORD status = GetAdaptersInfo(nullptr, &size);
    std::vector<unsigned char> storage(size);
    IP_ADAPTER_INFO* first = storage.empty() ? nullptr : reinterpret_cast<IP_ADAPTER_INFO*>(storage.data());
    if (status == ERROR_BUFFER_OVERFLOW) status = GetAdaptersInfo(first, &size);
    printf("\"adapterEnumerationError\":%lu,\"adapters\":[", status == ERROR_NO_DATA ? 0UL : status);
    bool comma = false;
    if (status == NO_ERROR) for (auto p = first; p; p = p->Next) {
        if (comma) putchar(','); comma = true;
        printf("{\"guid\":%s,\"description\":%s,\"trusGuardDescriptionMatch\":%s}",
               json(p->AdapterName).c_str(), json(p->Description).c_str(),
               strstr(p->Description, "tgsvpn driver 1.0") ? "true" : "false");
    }
    putchar(']');
    int result = status != NO_ERROR && status != ERROR_NO_DATA ? 4 : 0;
    if (argc == 3) {
        std::wstring path = L"\\\\.\\Global\\"; path += argv[2]; path += L".tap";
        HANDLE device = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, nullptr);
        DWORD openError = device == INVALID_HANDLE_VALUE ? GetLastError() : 0;
        printf(",\"tap\":{\"openError\":%lu", openError);
        if (device != INVALID_HANDLE_VALUE) {
            ULONG version[3]{}; DWORD returned = 0;
            DWORD error = query(device, 0x220008, version, sizeof version, &returned);
            printf(",\"versionError\":%lu,\"versionBytes\":%lu,\"version\":[%lu,%lu,%lu]", error, returned, version[0], version[1], version[2]);
            if (error || returned < sizeof version) result = 5;
            ULONG mtu = 0; returned = 0;
            error = query(device, 0x22000c, &mtu, sizeof mtu, &returned);
            printf(",\"mtuError\":%lu,\"mtuBytes\":%lu,\"mtu\":%lu", error, returned, mtu);
            if (error || returned < sizeof mtu) result = 5;
            CloseHandle(device);
        } else result = 5;
        putchar('}');
    }
    puts("}");
    return result;
}
