#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <wtsapi32.h>
#include <wincrypt.h>
#include <sddl.h>
#include <bcrypt.h>
#include <string>
#include <cstdint>
#include <vector>
#include <utility>
#include "core.hpp"

namespace su {
inline constexpr wchar_t kRegPath[] = L"SOFTWARE\\ScheduledUnlock";
inline constexpr wchar_t kClsidText[] = L"{A8255267-5B6C-4F76-9827-83FE0A09F593}";
inline constexpr GUID kClsid = {0xa8255267,0x5b6c,0x4f76,{0x98,0x27,0x83,0xfe,0x0a,0x09,0xf5,0x93}};
inline constexpr wchar_t kDailyTask[] = L"ScheduledUnlock-Daily";
inline constexpr wchar_t kTestTask[] = L"ScheduledUnlock-Test";

inline HRESULT Error(DWORD e = GetLastError()) {
    return HRESULT_FROM_WIN32(e ? e : ERROR_GEN_FAILURE);
}

template<class T> class ComPtr {
    T* ptr_ = nullptr;
public:
    ComPtr() = default;
    ~ComPtr() { if (ptr_) ptr_->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T* operator->() const { return ptr_; }
    T* get() const { return ptr_; }
    T** put() { if (ptr_) ptr_->Release(); ptr_ = nullptr; return &ptr_; }
};

class Handle {
    HANDLE h_ = nullptr;
public:
    explicit Handle(HANDLE h = nullptr): h_(h) {}
    ~Handle() { if (h_ && h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return h_; }
    HANDLE* put() { if (h_) CloseHandle(h_); h_ = nullptr; return &h_; }
    HANDLE release() { return std::exchange(h_, nullptr); }
};

// Password storage is move-only and wiped before its allocation is released.
class Secret {
    std::vector<wchar_t> value_;
public:
    explicit Secret(std::size_t count = 1): value_(count, L'\0') {}
    ~Secret() { clear(); }
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&& other) noexcept: value_(std::move(other.value_)) {}
    Secret& operator=(Secret&& other) noexcept {
        clear(); value_ = std::move(other.value_); return *this;
    }
    void clear() { if (!value_.empty()) SecureZeroMemory(value_.data(), value_.size() * sizeof(wchar_t)); }
    wchar_t* data() { return value_.data(); }
    const wchar_t* data() const { return value_.data(); }
    std::size_t count() const { return value_.size(); }
    bool empty() const { return value_.empty() || value_[0] == 0; }
};

class ConfigLock {
    Handle mutex_;
    bool acquired_ = false;
public:
    explicit ConfigLock(const wchar_t* name=L"Global\\ScheduledUnlock.Config.v1", DWORD timeout=3000);
    ~ConfigLock() { if (acquired_) ReleaseMutex(mutex_.get()); }
    bool acquired() const { return acquired_; }
};

struct Identity { std::wstring user, domain, sid; };
struct Config {
    Identity identity;
    std::vector<BYTE> encrypted;
    std::uint64_t generation = 0;
    DWORD hour = 8, minute = 30;
    bool wake = false, daily = false, suspended = false;
};

std::uint64_t Now();
std::uint64_t RandomId();
bool IsSystem();
int LockState(DWORD session); // -1 unknown, 0 unlocked, 1 locked
bool IsLocked(DWORD session);
HRESULT ConsoleIdentity(Identity& identity, bool verifyToken);
HRESULT ValidatePassword(const Identity& identity, const Secret& password);
HRESULT Encrypt(const Secret& password, std::vector<BYTE>& encrypted);
HRESULT Decrypt(const std::vector<BYTE>& encrypted, Secret& password);
// All *Unlocked functions require ConfigLock held by the caller.
HRESULT ReadConfigUnlocked(Config& config);
HRESULT SaveConfigUnlocked(const Config& config);
HRESULT ClearConfigUnlocked();
bool PendingUnlocked(DWORD session, Config& config, Request& request);
HRESULT WriteRequestUnlocked(const Request& request);
HRESULT ClearRequestUnlocked();
void StatusUnlocked(const wchar_t* text, bool suspend = false);
std::wstring ReadStatus();
std::wstring ErrorText(HRESULT hr);
bool ProviderInstalled();
bool InstalledExecutable(const std::wstring& path);
}
