#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <netcfgx.h>
#include <cstdio>
#include <cwchar>
#include <string>

#if !defined(_M_ARM64)
#error Build this helper for native Windows ARM64.
#endif

namespace {

// Enumerate only adapters, never protocol, service, or client components.
constexpr GUID networkClass = {
    0x4d36e972, 0xe325, 0x11ce,
    {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}
};

bool canonicalGuid(const wchar_t* value) {
    if (wcslen(value) != 38 || value[0] != L'{' || value[37] != L'}') return false;
    for (size_t i = 1; i < 37; ++i) {
        if (i == 9 || i == 14 || i == 19 || i == 24) {
            if (value[i] != L'-') return false;
        } else if (!((value[i] >= L'0' && value[i] <= L'9') ||
                     (value[i] >= L'a' && value[i] <= L'f') ||
                     (value[i] >= L'A' && value[i] <= L'F'))) return false;
    }
    return true;
}

std::string json(const std::wstring& value) {
    // Escaping every non-ASCII UTF-16 code unit preserves Unicode without
    // depending on the console code page. Surrogate pairs stay paired.
    std::string output = "\"";
    for (wchar_t ch : value) {
        if (ch == L'"' || ch == L'\\') {
            output += '\\';
            output += static_cast<char>(ch);
        } else if (ch < 32 || ch >= 127) {
            char escaped[7];
            sprintf_s(escaped, "\\u%04x", static_cast<unsigned int>(ch));
            output += escaped;
        } else {
            output += static_cast<char>(ch);
        }
    }
    return output + '"';
}

struct Configuration {
    INetCfg* config = nullptr;
    INetCfgLock* lock = nullptr;
    IEnumNetCfgComponent* enumerator = nullptr;
    INetCfgComponent* component = nullptr;
    bool initialized = false;
    bool locked = false;

    HRESULT close(HRESULT result) {
        if (component) { component->Release(); component = nullptr; }
        if (enumerator) { enumerator->Release(); enumerator = nullptr; }
        if (initialized) {
            const HRESULT cleanup = config->Uninitialize();
            initialized = false;
            if (SUCCEEDED(result) && FAILED(cleanup)) result = cleanup;
        }
        if (locked) {
            const HRESULT cleanup = lock->ReleaseWriteLock();
            locked = false;
            if (SUCCEEDED(result) && FAILED(cleanup)) result = cleanup;
        }
        if (lock) { lock->Release(); lock = nullptr; }
        if (config) { config->Release(); config = nullptr; }
        return result;
    }

    ~Configuration() { close(S_OK); }
};

HRESULT selectAdapter(Configuration& session, const GUID& wanted) {
    HRESULT result = session.config->EnumComponents(&networkClass, &session.enumerator);
    if (FAILED(result)) return result;
    for (;;) {
        INetCfgComponent* candidate = nullptr;
        ULONG fetched = 0;
        result = session.enumerator->Next(1, &candidate, &fetched);
        if (FAILED(result)) {
            if (candidate) candidate->Release();
            return result;
        }
        if (!fetched) {
            if (candidate) candidate->Release();
            break;
        }
        if (!candidate) return E_UNEXPECTED;
        GUID actual{};
        result = candidate->GetInstanceGuid(&actual);
        if (FAILED(result)) { candidate->Release(); return result; }
        if (IsEqualGUID(actual, wanted)) {
            if (session.component) {
                candidate->Release();
                return HRESULT_FROM_WIN32(ERROR_DUP_NAME);
            }
            session.component = candidate;
        } else {
            candidate->Release();
        }
    }
    return session.component ? S_OK : HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

HRESULT readName(INetCfgComponent* component, std::wstring& output) {
    LPWSTR allocated = nullptr;
    const HRESULT result = component->GetDisplayName(&allocated);
    if (SUCCEEDED(result)) {
        if (!allocated) return E_UNEXPECTED;
        output = allocated;
    }
    CoTaskMemFree(allocated);
    return result;
}

HRESULT run(bool write, const GUID& wanted, const wchar_t* requested,
            std::wstring& current, std::wstring& previous, const char*& stage) {
    Configuration session;
    stage = "CoCreateInstance";
    HRESULT result = CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER,
        IID_INetCfg, reinterpret_cast<void**>(&session.config));
    if (FAILED(result)) return result;
    if (write) {
        stage = "QueryInterface";
        result = session.config->QueryInterface(IID_INetCfgLock,
            reinterpret_cast<void**>(&session.lock));
        if (FAILED(result)) return result;
        LPWSTR holder = nullptr;
        stage = "AcquireWriteLock";
        result = session.lock->AcquireWriteLock(5000, L"TrusGuard WOA dedicated adapter name", &holder);
        CoTaskMemFree(holder);
        // S_FALSE is a timeout, not permission to continue without the lock.
        if (result == S_FALSE) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        if (FAILED(result)) return result;
        session.locked = true;
    }
    stage = "Initialize";
    result = session.config->Initialize(nullptr);
    if (FAILED(result)) return result;
    session.initialized = true;
    stage = "EnumComponents";
    result = selectAdapter(session, wanted);
    if (FAILED(result)) return result;
    stage = "GetDisplayName";
    result = readName(session.component, current);
    if (FAILED(result)) return result;
    previous = current;
    HRESULT applied = S_OK;
    if (write && current != requested) {
        stage = "SetDisplayName";
        result = session.component->SetDisplayName(requested);
        if (FAILED(result)) {
            session.config->Cancel();
            return result;
        }
        stage = "Apply";
        result = session.config->Apply();
        if (FAILED(result)) {
            session.config->Cancel();
            return result;
        }
        applied = result; // Preserve NETCFG_S_REBOOT and other success statuses.
        stage = "VerifyDisplayName";
        result = readName(session.component, current);
        if (FAILED(result)) return result;
        if (current != requested) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }
    stage = "Cleanup";
    const HRESULT closed = session.close(applied);
    if (SUCCEEDED(closed)) stage = "Complete";
    return closed;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    const bool get = argc == 3 && wcscmp(argv[1], L"--get-name") == 0;
    const bool set = argc == 4 && wcscmp(argv[1], L"--set-name") == 0;
    HRESULT result = E_INVALIDARG;
    std::wstring identifier;
    std::wstring current;
    std::wstring previous;
    const char* stage = "Arguments";
    if ((get || set) && canonicalGuid(argv[2]) &&
        (!set || (wcslen(argv[3]) > 0 && wcslen(argv[3]) <= 255))) {
        identifier = argv[2];
        GUID wanted{};
        result = CLSIDFromString(argv[2], &wanted);
        if (SUCCEEDED(result)) {
            stage = "CoInitializeEx";
            result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (SUCCEEDED(result)) {
                result = run(set, wanted, set ? argv[3] : L"", current, previous, stage);
                CoUninitialize();
            }
        }
    } else {
        fputs("Usage: tg-woa-name.exe --get-name {adapter-guid}\n"
              "       tg-woa-name.exe --set-name {adapter-guid} \"description\"\n", stderr);
    }
    char hr[11];
    sprintf_s(hr, "0x%08lX", static_cast<unsigned long>(result));
    printf("{\"guid\":%s,\"displayName\":%s,\"previousDisplayName\":%s,\"hresult\":\"%s\",\"stage\":\"%s\"}\n",
        json(identifier).c_str(), json(current).c_str(), json(previous).c_str(), hr, stage);
    return FAILED(result) ? 1 : 0;
}
