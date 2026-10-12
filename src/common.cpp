#include "common.hpp"
#include <cstring>

namespace su {
namespace {
struct Key {
    HKEY h = nullptr;
    ~Key() { if (h) RegCloseKey(h); }
};
HRESULT Set(HKEY key, const wchar_t* name, DWORD type, const void* value, DWORD size) {
    LONG rc = RegSetValueExW(key, name, 0, type, static_cast<const BYTE*>(value), size);
    return rc == ERROR_SUCCESS ? S_OK : Error(rc);
}
HRESULT Read(HKEY key, const wchar_t* name, DWORD type, void* value, DWORD size) {
    DWORD actualType = 0, actualSize = size;
    LONG rc = RegQueryValueExW(key, name, nullptr, &actualType, static_cast<BYTE*>(value), &actualSize);
    if (rc != ERROR_SUCCESS) return Error(rc);
    return actualType == type && actualSize == size ? S_OK : Error(ERROR_INVALID_DATA);
}
HRESULT String(HKEY key, const wchar_t* name, std::wstring& out) {
    DWORD size = 0, type = 0;
    LONG rc = RegQueryValueExW(key, name, nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS) return Error(rc);
    if (type != REG_SZ || size < sizeof(wchar_t) || size > 4096 || size % sizeof(wchar_t)) return Error(ERROR_INVALID_DATA);
    std::vector<wchar_t> value(size / sizeof(wchar_t));
    rc = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(value.data()), &size);
    if (rc != ERROR_SUCCESS) return Error(rc);
    if (value.back() != 0) return Error(ERROR_INVALID_DATA);
    out.assign(value.data());
    return S_OK;
}
HRESULT SetString(HKEY key, const wchar_t* name, const std::wstring& value) {
    return Set(key, name, REG_SZ, value.c_str(), static_cast<DWORD>((value.size()+1)*sizeof(wchar_t)));
}
HRESULT SidString(PSID sid, std::wstring& value) {
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) return Error();
    value = text;
    LocalFree(text);
    return S_OK;
}
HRESULT TokenSid(HANDLE token, std::wstring& sid) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (!size) return Error();
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) return Error();
    return SidString(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, sid);
}
bool WtsText(DWORD session, WTS_INFO_CLASS type, std::wstring& out) {
    LPWSTR text = nullptr; DWORD size = 0;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, type, &text, &size)) return false;
    if (text && size >= sizeof(wchar_t)) out = text;
    WTSFreeMemory(text);
    return !out.empty();
}
}

ConfigLock::ConfigLock(const wchar_t* name,DWORD timeout) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) return;
    SECURITY_ATTRIBUTES sa{sizeof(sa), descriptor, FALSE};
    Handle h(CreateMutexW(&sa, FALSE, name));
    LocalFree(descriptor);
    mutex_.put()[0] = h.release();
    if (!mutex_.get()) return;
    DWORD result = WaitForSingleObject(mutex_.get(), timeout);
    acquired_ = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
}

std::uint64_t Now() {
    FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER value{}; value.LowPart = ft.dwLowDateTime; value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}
std::uint64_t RandomId() {
    std::uint64_t id = 0;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&id), sizeof(id), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return 0;
    return id;
}
bool IsSystem() {
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.put())) return false;
    std::wstring sid;
    return SUCCEEDED(TokenSid(token.get(), sid)) && sid == L"S-1-5-18";
}
int LockState(DWORD session) {
    LPWSTR buffer = nullptr; DWORD size = 0;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSSessionInfoEx, &buffer, &size)) return -1;
    int state = -1;
    if (size >= sizeof(WTSINFOEXW)) {
        const auto* info = reinterpret_cast<const WTSINFOEXW*>(buffer);
        if (info->Level == 1) {
            LONG flags=info->Data.WTSInfoExLevel1.SessionFlags;
            if (flags == WTS_SESSIONSTATE_LOCK) state=1;
            else if (flags == WTS_SESSIONSTATE_UNLOCK) state=0;
        }
    }
    WTSFreeMemory(buffer);
    return state;
}
bool IsLocked(DWORD session) { return LockState(session) == 1; }
HRESULT ConsoleIdentity(Identity& identity, bool verifyToken) {
    DWORD session = WTSGetActiveConsoleSessionId();
    if (session == kInvalidSession) return Error(ERROR_NO_SUCH_LOGON_SESSION);
    Identity candidate;
    if (!WtsText(session, WTSUserName, candidate.user) || !WtsText(session, WTSDomainName, candidate.domain)) return Error(ERROR_NO_SUCH_USER);
    wchar_t machine[MAX_COMPUTERNAME_LENGTH+1]{}; DWORD machineSize = ARRAYSIZE(machine);
    if (!GetComputerNameW(machine, &machineSize)) return Error();
    // Version 0.1 intentionally accepts only local SAM users, not Microsoft/Entra/AD accounts.
    if (_wcsicmp(candidate.domain.c_str(), machine) != 0) return Error(ERROR_NOT_SUPPORTED);
    std::wstring qualified = candidate.domain + L"\\" + candidate.user;
    DWORD sidSize = 0, domainSize = 0; SID_NAME_USE use{};
    LookupAccountNameW(nullptr, qualified.c_str(), nullptr, &sidSize, nullptr, &domainSize, &use);
    if (!sidSize || !domainSize) return Error();
    std::vector<BYTE> sid(sidSize); std::vector<wchar_t> domain(domainSize);
    if (!LookupAccountNameW(nullptr, qualified.c_str(), sid.data(), &sidSize, domain.data(), &domainSize, &use)) return Error();
    if (use != SidTypeUser || _wcsicmp(domain.data(), machine) != 0) return Error(ERROR_NOT_SUPPORTED);
    HRESULT hr = SidString(sid.data(), candidate.sid);
    if (FAILED(hr)) return hr;
    if (verifyToken) {
        // WTSQueryUserToken requires SeTcbPrivilege even for a SYSTEM scheduler job.
        Handle processToken;
        if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,processToken.put())) return Error();
        TOKEN_PRIVILEGES privilege{};
        privilege.PrivilegeCount=1;
        if (!LookupPrivilegeValueW(nullptr,SE_TCB_NAME,&privilege.Privileges[0].Luid)) return Error();
        privilege.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        SetLastError(ERROR_SUCCESS);
        if (!AdjustTokenPrivileges(processToken.get(),FALSE,&privilege,0,nullptr,nullptr)) return Error();
        DWORD privilegeError=GetLastError();
        if (privilegeError != ERROR_SUCCESS) return Error(privilegeError);
        Handle token;
        if (!WTSQueryUserToken(session, token.put())) return Error();
        std::wstring actualSid;
        hr = TokenSid(token.get(), actualSid);
        if (FAILED(hr)) return hr;
        if (candidate.sid != actualSid) return Error(ERROR_ACCESS_DENIED);
    }
    identity = std::move(candidate);
    return S_OK;
}
HRESULT ValidatePassword(const Identity& identity, const Secret& password) {
    if (password.empty()) return Error(ERROR_INVALID_PASSWORD);
    Handle token;
    if (!LogonUserW(identity.user.c_str(), identity.domain.c_str(), password.data(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, token.put())) return Error();
    std::wstring sid;
    HRESULT hr = TokenSid(token.get(), sid);
    return FAILED(hr) ? hr : (sid == identity.sid ? S_OK : Error(ERROR_ACCESS_DENIED));
}
HRESULT Encrypt(const Secret& password, std::vector<BYTE>& encrypted) {
    if (password.empty() || password.count() > 513) return Error(ERROR_INVALID_PASSWORD);
    DATA_BLOB input{static_cast<DWORD>(password.count()*sizeof(wchar_t)), reinterpret_cast<BYTE*>(const_cast<wchar_t*>(password.data()))};
    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"ScheduledUnlock password", nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &output)) return Error();
    encrypted.assign(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return S_OK;
}
HRESULT Decrypt(const std::vector<BYTE>& encrypted, Secret& password) {
    if (encrypted.empty() || encrypted.size() > 16384) return Error(ERROR_INVALID_DATA);
    DATA_BLOB input{static_cast<DWORD>(encrypted.size()), const_cast<BYTE*>(encrypted.data())}, output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) return Error();
    bool valid = output.cbData >= 2*sizeof(wchar_t) && output.cbData <= 513*sizeof(wchar_t) && output.cbData % sizeof(wchar_t) == 0;
    if (valid) valid = reinterpret_cast<wchar_t*>(output.pbData)[output.cbData/sizeof(wchar_t)-1] == 0;
    if (valid) {
        Secret temp(output.cbData/sizeof(wchar_t));
        CopyMemory(temp.data(), output.pbData, output.cbData);
        password = std::move(temp);
    }
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    return valid && !password.empty() ? S_OK : Error(ERROR_INVALID_DATA);
}
HRESULT ReadConfigUnlocked(Config& config) {
    Key key;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, KEY_READ | KEY_WOW64_64KEY, &key.h);
    if (rc != ERROR_SUCCESS) return Error(rc);
    Config c;
    HRESULT hr = Read(key.h, L"Generation", REG_QWORD, &c.generation, sizeof(c.generation));
    if (FAILED(hr) || !c.generation) return Error(ERROR_NOT_FOUND);
    if (FAILED(hr = String(key.h, L"User", c.identity.user)) || FAILED(hr = String(key.h, L"Domain", c.identity.domain)) || FAILED(hr = String(key.h, L"Sid", c.identity.sid))) return hr;
    DWORD size = 0, type = 0;
    rc = RegQueryValueExW(key.h, L"Password", nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS) return Error(rc);
    if (type != REG_BINARY || !size || size > 16384) return Error(ERROR_INVALID_DATA);
    c.encrypted.resize(size);
    rc = RegQueryValueExW(key.h, L"Password", nullptr, &type, c.encrypted.data(), &size);
    if (rc != ERROR_SUCCESS) return Error(rc);
    DWORD wake = 0, daily = 0, suspended = 0;
    if (FAILED(hr = Read(key.h,L"Hour",REG_DWORD,&c.hour,sizeof(c.hour))) || FAILED(hr = Read(key.h,L"Minute",REG_DWORD,&c.minute,sizeof(c.minute))) || FAILED(hr = Read(key.h,L"Wake",REG_DWORD,&wake,sizeof(wake))) || FAILED(hr = Read(key.h,L"Daily",REG_DWORD,&daily,sizeof(daily))) || FAILED(hr = Read(key.h,L"Suspended",REG_DWORD,&suspended,sizeof(suspended)))) return hr;
    if (c.hour > 23 || c.minute > 59 || c.identity.user.empty() || c.identity.domain.empty() || c.identity.sid.empty()) return Error(ERROR_INVALID_DATA);
    c.wake = wake != 0; c.daily = daily != 0; c.suspended = suspended != 0;
    config = std::move(c);
    return S_OK;
}
HRESULT SaveConfigUnlocked(const Config& c) {
    Key key;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,kRegPath,0,KEY_WRITE | KEY_WOW64_64KEY,&key.h);
    if (rc != ERROR_SUCCESS) return Error(rc);
    if (!c.generation || c.encrypted.empty()) return Error(ERROR_INVALID_DATA);
    // Fail closed during a partial update. Generation is committed last.
    RegDeleteValueW(key.h, L"Generation"); RegDeleteValueW(key.h, L"Pending");
    HRESULT hr;
    DWORD wake = c.wake, daily = c.daily, suspended = c.suspended;
    if (FAILED(hr=SetString(key.h,L"User",c.identity.user)) || FAILED(hr=SetString(key.h,L"Domain",c.identity.domain)) || FAILED(hr=SetString(key.h,L"Sid",c.identity.sid)) || FAILED(hr=Set(key.h,L"Password",REG_BINARY,c.encrypted.data(),static_cast<DWORD>(c.encrypted.size()))) || FAILED(hr=Set(key.h,L"Hour",REG_DWORD,&c.hour,sizeof(c.hour))) || FAILED(hr=Set(key.h,L"Minute",REG_DWORD,&c.minute,sizeof(c.minute))) || FAILED(hr=Set(key.h,L"Wake",REG_DWORD,&wake,sizeof(wake))) || FAILED(hr=Set(key.h,L"Daily",REG_DWORD,&daily,sizeof(daily))) || FAILED(hr=Set(key.h,L"Suspended",REG_DWORD,&suspended,sizeof(suspended)))) return hr;
    return Set(key.h,L"Generation",REG_QWORD,&c.generation,sizeof(c.generation));
}
HRESULT ClearConfigUnlocked() {
    Key key;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,kRegPath,0,KEY_WRITE | KEY_WOW64_64KEY,&key.h);
    if (rc != ERROR_SUCCESS) return Error(rc);
    // Delete the revision first so any concurrent read becomes ineligible.
    const wchar_t* names[] = {L"Generation",L"Pending",L"Password",L"User",L"Domain",L"Sid",L"Hour",L"Minute",L"Wake",L"Daily",L"Suspended"};
    for (auto name : names) {
        rc = RegDeleteValueW(key.h, name);
        if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) return Error(rc);
    }
    return S_OK;
}
bool PendingUnlocked(DWORD session, Config& config, Request& request) {
    if (session == kInvalidSession || session != WTSGetActiveConsoleSessionId()) return false;
    if (FAILED(ReadConfigUnlocked(config)) || config.suspended) return false;
    Key key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,kRegPath,0,KEY_READ | KEY_WOW64_64KEY,&key.h) != ERROR_SUCCESS) return false;
    if (FAILED(Read(key.h,L"Pending",REG_BINARY,&request,sizeof(request)))) return false;
    if (!Eligible(request,Now(),session,config.generation,IsLocked(session))) return false;
    Identity current;
    return SUCCEEDED(ConsoleIdentity(current,false)) && current.sid == config.identity.sid;
}
HRESULT WriteRequestUnlocked(const Request& request) {
    Key key;
    LONG rc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,kRegPath,0,KEY_WRITE | KEY_WOW64_64KEY,&key.h);
    if (rc != ERROR_SUCCESS) return Error(rc);
    return Set(key.h,L"Pending",REG_BINARY,&request,sizeof(request));
}
HRESULT ClearRequestUnlocked() {
    Key key;
    LONG rc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,kRegPath,0,KEY_WRITE | KEY_WOW64_64KEY,&key.h);
    if (rc != ERROR_SUCCESS) return Error(rc);
    rc=RegDeleteValueW(key.h,L"Pending");
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND ? S_OK : Error(rc);
}
void StatusUnlocked(const wchar_t* text, bool suspend) {
    Key key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,kRegPath,0,KEY_WRITE | KEY_WOW64_64KEY,&key.h) != ERROR_SUCCESS) return;
    SetString(key.h,L"Status",text);
    std::uint64_t now=Now(); Set(key.h,L"StatusTime",REG_QWORD,&now,sizeof(now));
    if (suspend) { DWORD one=1; Set(key.h,L"Suspended",REG_DWORD,&one,sizeof(one)); RegDeleteValueW(key.h,L"Pending"); }
}
std::wstring ReadStatus() {
    ConfigLock guard;
    if (!guard.acquired()) return L"暂时无法读取状态。";
    Key key; std::wstring value;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,kRegPath,0,KEY_READ | KEY_WOW64_64KEY,&key.h) == ERROR_SUCCESS) String(key.h,L"Status",value);
    return value.empty() ? L"尚未设置。" : value;
}
std::wstring ErrorText(HRESULT hr) {
    LPWSTR message=nullptr;
    DWORD code = HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : static_cast<DWORD>(hr);
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,code,0,reinterpret_cast<LPWSTR>(&message),0,nullptr);
    std::wstring text = message ? message : L"操作失败。";
    if (message) LocalFree(message);
    wchar_t suffix[32]{}; swprintf_s(suffix,ARRAYSIZE(suffix),L" (0x%08lX)",static_cast<unsigned long>(hr));
    text += suffix;
    return text;
}
bool ProviderInstalled() {
    HKEY key=nullptr;
    std::wstring path=L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" + std::wstring(kClsidText);
    LONG rc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),0,KEY_READ | KEY_WOW64_64KEY,&key);
    if (key) RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}
bool InstalledExecutable(const std::wstring& path) {
    Key key; std::wstring expected;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,kRegPath,0,KEY_READ | KEY_WOW64_64KEY,&key.h) != ERROR_SUCCESS) return false;
    return SUCCEEDED(String(key.h,L"ExePath",expected)) && _wcsicmp(path.c_str(),expected.c_str()) == 0;
}
}
