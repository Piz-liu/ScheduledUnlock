#include "common.hpp"
#include <credentialprovider.h>
#include <wincred.h>
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>
#include <atomic>
#include <new>
#include <memory>
#include <cwchar>

// Credential packing follows Microsoft's MIT-licensed V2 Credential Provider sample.
// See THIRD_PARTY_NOTICES.md and LICENSE-Microsoft.txt.
namespace {
std::atomic<long> g_objects{0};

HRESULT CopyText(const wchar_t* text, PWSTR* output) {
    if (!output) return E_POINTER;
    *output=nullptr;
    const std::size_t bytes=(wcslen(text)+1)*sizeof(wchar_t);
    auto* value=static_cast<PWSTR>(CoTaskMemAlloc(bytes));
    if (!value) return E_OUTOFMEMORY;
    CopyMemory(value,text,bytes); *output=value;
    return S_OK;
}
HRESULT NegotiatePackage(ULONG* package) {
    LSA_HANDLE lsa=nullptr;
    NTSTATUS status=LsaConnectUntrusted(&lsa);
    if (status < 0) return su::Error(LsaNtStatusToWinError(status));
    char name[]="Negotiate";
    LSA_STRING text{static_cast<USHORT>(strlen(name)),static_cast<USHORT>(sizeof(name)),name};
    status=LsaLookupAuthenticationPackage(lsa,&text,package);
    LsaDeregisterLogonProcess(lsa);
    return status < 0 ? su::Error(LsaNtStatusToWinError(status)) : S_OK;
}
HRESULT ProtectPassword(const su::Secret& input, su::Secret& output) {
    if (input.empty()) return su::Error(ERROR_INVALID_PASSWORD);
    su::Secret copy(input.count());
    CopyMemory(copy.data(),input.data(),input.count()*sizeof(wchar_t));
    DWORD count=0;
    CRED_PROTECTION_TYPE type=CredUnprotected;
    if (CredProtectW(FALSE,copy.data(),static_cast<DWORD>(wcslen(copy.data())+1),nullptr,&count,&type)) return E_UNEXPECTED;
    DWORD error=GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER || count == 0 || count > 4096) return su::Error(error);
    su::Secret protectedValue(count);
    if (!CredProtectW(FALSE,copy.data(),static_cast<DWORD>(wcslen(copy.data())+1),protectedValue.data(),&count,&type)) return su::Error();
    output=std::move(protectedValue);
    return S_OK;
}
HRESULT Pack(const su::Config& config, const su::Secret& password,
             CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
             CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) {
    ULONG package=0;
    HRESULT hr=NegotiatePackage(&package);
    if (FAILED(hr)) return hr;
    su::Secret protectedValue;
    if (FAILED(hr=ProtectPassword(password,protectedValue))) return hr;
    const wchar_t* strings[]={config.identity.domain.c_str(),config.identity.user.c_str(),protectedValue.data()};
    USHORT lengths[3]{};
    DWORD total=sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    for (unsigned i=0;i<3;++i) {
        std::size_t bytes=wcslen(strings[i])*sizeof(wchar_t);
        if (bytes > 65534) return su::Error(ERROR_ARITHMETIC_OVERFLOW);
        lengths[i]=static_cast<USHORT>(bytes); total+=lengths[i];
    }
    auto* buffer=static_cast<BYTE*>(CoTaskMemAlloc(total));
    if (!buffer) return E_OUTOFMEMORY;
    ZeroMemory(buffer,total);
    auto* logon=reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buffer);
    logon->Logon.MessageType=scenario == CPUS_UNLOCK_WORKSTATION ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;
    // Winlogon supplies LogonId when an existing session is unlocked.
    UNICODE_STRING* targets[]={&logon->Logon.LogonDomainName,&logon->Logon.UserName,&logon->Logon.Password};
    DWORD offset=sizeof(*logon);
    for (unsigned i=0;i<3;++i) {
        targets[i]->Length=targets[i]->MaximumLength=lengths[i];
        CopyMemory(buffer+offset,strings[i],lengths[i]);
        targets[i]->Buffer=reinterpret_cast<PWSTR>(static_cast<ULONG_PTR>(offset));
        offset+=lengths[i];
    }
    serialization->ulAuthenticationPackage=package;
    serialization->clsidCredentialProvider=su::kClsid;
    serialization->cbSerialization=total;
    serialization->rgbSerialization=buffer;
    return S_OK;
}

class Credential final: public ICredentialProviderCredential2 {
    std::atomic<ULONG> refs_{1};
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
    DWORD session_;
    std::wstring sid_;
    std::uint64_t attemptedGeneration_=0;
public:
    Credential(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD session,std::wstring sid):
        scenario_(scenario),session_(session),sid_(std::move(sid)) { ++g_objects; }
    ~Credential() { --g_objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(ICredentialProviderCredential) || iid == __uuidof(ICredentialProviderCredential2)) *out=static_cast<ICredentialProviderCredential2*>(this);
        if (!*out) return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG n=--refs_; if (!n) delete this; return n; }
    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE UnAdvise() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetSelected(BOOL* automatic) override try {
        if (!automatic) return E_POINTER;
        *automatic=FALSE;
        su::ConfigLock guard; su::Config config; su::Request request;
        if (guard.acquired() && su::PendingUnlocked(session_,config,request) && config.identity.sid == sid_) *automatic=TRUE;
        return S_OK;
    } catch (const std::bad_alloc&) { return E_OUTOFMEMORY; } catch (...) { return E_FAIL; }
    HRESULT STDMETHODCALLTYPE SetDeselected() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldState(DWORD field,CREDENTIAL_PROVIDER_FIELD_STATE* state,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override {
        if (!state || !interactive) return E_POINTER;
        if (field > 1) return E_INVALIDARG;
        *state=CPFS_DISPLAY_IN_BOTH; *interactive=CPFIS_NONE; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetStringValue(DWORD field,PWSTR* text) override {
        if (field > 1) return E_INVALIDARG;
        return CopyText(field == 0 ? L"定时解锁" : L"正在验证本地账户…",text);
    }
    HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD,HBITMAP* bitmap) override { if (bitmap) *bitmap=nullptr; return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD,BOOL* checked,PWSTR* label) override { if (checked) *checked=FALSE; if (label) *label=nullptr; return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD,DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD,DWORD*,DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD,DWORD,PWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetStringValue(DWORD,PCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD,BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD,DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetUserSid(PWSTR* sid) override { return CopyText(sid_.c_str(),sid); }

    HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,PWSTR* statusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* icon) override try {
        if (!response || !serialization || !statusText || !icon) return E_POINTER;
        *response=CPGSR_NO_CREDENTIAL_NOT_FINISHED; *statusText=nullptr; *icon=CPSI_NONE;
        ZeroMemory(serialization,sizeof(*serialization));
        su::Config config;
        std::uint64_t deadline=0;
        {
            su::ConfigLock guard; su::Request request;
            if (!guard.acquired() || !su::PendingUnlocked(session_,config,request) || config.identity.sid != sid_) return S_OK;
            // Consume under the same mutex before credential submission. No retry/replay.
            HRESULT hr=su::ClearRequestUnlocked();
            if (FAILED(hr)) return hr;
            attemptedGeneration_=config.generation;
            deadline=request.expires;
        }
        su::Secret password;
        HRESULT hr=su::Decrypt(config.encrypted,password);
        if (SUCCEEDED(hr)) hr=Pack(config,password,scenario_,serialization);
        if (FAILED(hr)) {
            su::ConfigLock guard;
            su::Config current;
            if (guard.acquired() && SUCCEEDED(su::ReadConfigUnlocked(current)) && current.generation == attemptedGeneration_)
                su::StatusUnlocked(L"解锁组件无法读取或提交凭据，已暂停。请重新保存设置。",true);
            return hr;
        }
        // The user could disable or replace the configuration during DPAPI/LSA work.
        {
            su::ConfigLock guard; su::Config current;
            su::Identity currentUser;
            if (!guard.acquired() || FAILED(su::ReadConfigUnlocked(current)) || current.suspended || current.generation != config.generation || su::Now() >= deadline || !su::IsLocked(session_) || session_ != WTSGetActiveConsoleSessionId() || FAILED(su::ConsoleIdentity(currentUser,false)) || currentUser.sid != config.identity.sid) {
                SecureZeroMemory(serialization->rgbSerialization,serialization->cbSerialization);
                CoTaskMemFree(serialization->rgbSerialization); ZeroMemory(serialization,sizeof(*serialization));
                return S_OK;
            }
        }
        *response=CPGSR_RETURN_CREDENTIAL_FINISHED;
        return S_OK;
    } catch (...) {
        if (serialization && serialization->rgbSerialization) {
            SecureZeroMemory(serialization->rgbSerialization,serialization->cbSerialization);
            CoTaskMemFree(serialization->rgbSerialization);
            ZeroMemory(serialization,sizeof(*serialization));
        }
        if (response) *response=CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS status,NTSTATUS substatus,PWSTR* text,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override try {
        if (!text || !icon) return E_POINTER;
        *text=nullptr; *icon=CPSI_NONE;
        su::ConfigLock guard; su::Config current;
        if (guard.acquired() && attemptedGeneration_ && SUCCEEDED(su::ReadConfigUnlocked(current)) && current.generation == attemptedGeneration_) {
            if (status == 0 && substatus == 0) su::StatusUnlocked(L"上次定时解锁成功。");
            else {
                su::StatusUnlocked(L"Windows 拒绝了登录凭据，自动解锁已暂停。请重新输入账户密码。",true);
                *icon=CPSI_ERROR;
                CopyText(L"自动解锁已暂停。请使用正常登录方式进入桌面后更新密码。",text);
            }
        }
        return S_OK;
    } catch (...) { return E_FAIL; }
};

// A detached watcher owns only this state and a marshalled event interface.
// UnAdvise must never join a thread making a synchronous COM callback into LogonUI.
struct WatchState {
    su::Handle stop{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    DWORD session=su::kInvalidSession;
    UINT_PTR context=0;
    IStream* stream=nullptr;
    HMODULE module=nullptr;
    ~WatchState() {
        if (stream) { CoReleaseMarshalData(stream); stream->Release(); }
        if (module) FreeLibrary(module);
    }
};
DWORD WINAPI WatchThread(void* opaque) {
    std::unique_ptr<std::shared_ptr<WatchState>> holder(static_cast<std::shared_ptr<WatchState>*>(opaque));
    auto state=*holder;
    HRESULT initialized=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if (SUCCEEDED(initialized)) {
        su::ComPtr<ICredentialProviderEvents> events;
        IStream* stream=std::exchange(state->stream,nullptr);
        HRESULT hr=CoGetInterfaceAndReleaseStream(stream,__uuidof(ICredentialProviderEvents),reinterpret_cast<void**>(events.put()));
        if (SUCCEEDED(hr)) {
            std::uint64_t lastNonce=0;
            while (WaitForSingleObject(state->stop.get(),500) == WAIT_TIMEOUT) {
                try {
                std::uint64_t nonce=0;
                {
                    su::ConfigLock guard; su::Config config; su::Request request;
                    if (guard.acquired() && su::PendingUnlocked(state->session,config,request)) nonce=request.nonce;
                }
                if (nonce && nonce != lastNonce) {
                    lastNonce=nonce;
                    if (WaitForSingleObject(state->stop.get(),0) == WAIT_OBJECT_0) break;
                    if (FAILED(events->CredentialsChanged(state->context))) break;
                }
                } catch (...) { break; }
            }
        }
        events.put(); // Release the COM proxy before leaving its apartment.
        CoUninitialize();
    }
    HMODULE module=std::exchange(state->module,nullptr);
    holder.reset(); state.reset();
    --g_objects;
    // The watcher pins the DLL until its last instruction has finished executing.
    FreeLibraryAndExitThread(module,0);
    return 0;
}

class Provider final: public ICredentialProvider, public ICredentialProviderSetUserArray {
    std::atomic<ULONG> refs_{1};
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_=CPUS_INVALID;
    DWORD session_=su::kInvalidSession;
    Credential* credential_=nullptr;
    std::wstring credentialSid_;
    std::shared_ptr<WatchState> watcher_;
    void StopWatch() { if (watcher_) { SetEvent(watcher_->stop.get()); watcher_.reset(); } }
public:
    Provider() { ++g_objects; ProcessIdToSessionId(GetCurrentProcessId(),&session_); }
    ~Provider() { StopWatch(); if (credential_) credential_->Release(); --g_objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(ICredentialProvider)) *out=static_cast<ICredentialProvider*>(this);
        else if (iid == __uuidof(ICredentialProviderSetUserArray)) *out=static_cast<ICredentialProviderSetUserArray*>(this);
        if (!*out) return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG n=--refs_; if (!n) delete this; return n; }
    HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD) override {
        if (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) return E_NOTIMPL;
        scenario_=scenario;
        if (credential_) { credential_->Release(); credential_=nullptr; credentialSid_.clear(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetUserArray(ICredentialProviderUserArray*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents* events,UINT_PTR context) override try {
        if (!events) return E_POINTER;
        StopWatch();
        auto state=std::make_shared<WatchState>();
        if (!state->stop.get()) return su::Error();
        state->session=session_; state->context=context;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,reinterpret_cast<LPCWSTR>(&WatchThread),&state->module)) return su::Error();
        HRESULT hr=CoMarshalInterThreadInterfaceInStream(__uuidof(ICredentialProviderEvents),events,&state->stream);
        if (FAILED(hr)) return hr;
        auto* holder=new(std::nothrow) std::shared_ptr<WatchState>(state);
        if (!holder) return E_OUTOFMEMORY;
        ++g_objects;
        su::Handle thread(CreateThread(nullptr,0,WatchThread,holder,0,nullptr));
        if (!thread.get()) { --g_objects; delete holder; return su::Error(); }
        watcher_=std::move(state);
        return S_OK;
    } catch (const std::bad_alloc&) { return E_OUTOFMEMORY; } catch (...) { return E_FAIL; }
    HRESULT STDMETHODCALLTYPE UnAdvise() override { StopWatch(); return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* count) override { if (!count) return E_POINTER; *count=2; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD index,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out) override {
        if (!out) return E_POINTER;
        *out=nullptr; if (index > 1) return E_INVALIDARG;
        auto* field=static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        if (!field) return E_OUTOFMEMORY;
        ZeroMemory(field,sizeof(*field)); field->dwFieldID=index;
        field->cpft=index == 0 ? CPFT_LARGE_TEXT : CPFT_SMALL_TEXT;
        HRESULT hr=CopyText(index == 0 ? L"定时解锁" : L"状态",&field->pszLabel);
        if (FAILED(hr)) { CoTaskMemFree(field); return hr; }
        *out=field; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* count,DWORD* defaultIndex,BOOL* automatic) override try {
        if (!count || !defaultIndex || !automatic) return E_POINTER;
        *count=0; *defaultIndex=CREDENTIAL_PROVIDER_NO_DEFAULT; *automatic=FALSE;
        if (scenario_ == CPUS_INVALID) return S_OK;
        su::ConfigLock guard; su::Config config; su::Request request;
        if (!guard.acquired() || !su::PendingUnlocked(session_,config,request)) return S_OK;
        if (!credential_ || credentialSid_ != config.identity.sid) {
            if (credential_) { credential_->Release(); credential_=nullptr; }
            credential_=new(std::nothrow) Credential(scenario_,session_,config.identity.sid);
            if (!credential_) return E_OUTOFMEMORY;
            credentialSid_=config.identity.sid;
        }
        *count=1; *defaultIndex=0; *automatic=TRUE;
        return S_OK;
    } catch (const std::bad_alloc&) { return E_OUTOFMEMORY; } catch (...) { return E_FAIL; }
    HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD index,ICredentialProviderCredential** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (index != 0 || !credential_) return E_INVALIDARG;
        return credential_->QueryInterface(__uuidof(ICredentialProviderCredential),reinterpret_cast<void**>(out));
    }
};

class Factory final: public IClassFactory {
    std::atomic<ULONG> refs_{1};
public:
    Factory() { ++g_objects; }
    ~Factory() { --g_objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
        *out=static_cast<IClassFactory*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG n=--refs_; if (!n) delete this; return n; }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer,REFIID iid,void** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* provider=new(std::nothrow) Provider();
        if (!provider) return E_OUTOFMEMORY;
        HRESULT hr=provider->QueryInterface(iid,out); provider->Release(); return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override { if (lock) ++g_objects; else --g_objects; return S_OK; }
};
}

extern "C" HRESULT WINAPI DllCanUnloadNow() { return g_objects.load() == 0 ? S_OK : S_FALSE; }
extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID clsid,REFIID iid,void** out) {
    if (!out) return E_POINTER;
    *out=nullptr;
    if (clsid != su::kClsid) return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory=new(std::nothrow) Factory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT hr=factory->QueryInterface(iid,out); factory->Release(); return hr;
}
