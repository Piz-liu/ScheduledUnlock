#include "common.hpp"
#include "tasks.hpp"
#include <commctrl.h>
#include <shellapi.h>
#include <cwchar>
#include <cstdlib>

namespace {
enum { Password=100, Time=101, Wake=102, Save=103, Test=104, Disable=105, Status=106, Refresh=107 };
HWND window=nullptr,passwordBox=nullptr,timePicker=nullptr,wakeBox=nullptr,statusBox=nullptr;
HFONT font=nullptr,titleFont=nullptr;
su::Identity identity;
std::wstring exePath;
bool busy=false;
int scale=96;
int D(int value) { return MulDiv(value,scale,96); }

void ShowError(HRESULT hr,const wchar_t* context) {
    std::wstring message=context;
    message+=L"\n\n"; message+=su::ErrorText(hr);
    MessageBoxW(window,message.c_str(),L"定时解锁",MB_OK | MB_ICONERROR);
}
void RefreshStatus() {
    auto text=su::ReadStatus();
    SetWindowTextW(statusBox,text.c_str());
}
void Buttons(bool enabled) {
    for (int id : {Save,Test,Disable}) EnableWindow(GetDlgItem(window,id),enabled);
    busy=!enabled;
}
su::Secret InputPassword() {
    int length=GetWindowTextLengthW(passwordBox);
    su::Secret value(static_cast<std::size_t>(length)+1);
    GetWindowTextW(passwordBox,value.data(),length+1);
    return value;
}
void ClearPasswordBox() { SetWindowTextW(passwordBox,L""); }

HRESULT Prepare(su::Config& config,bool daily) {
    HRESULT hr=su::ConsoleIdentity(identity,false);
    if (FAILED(hr)) return hr;
    if (!su::ProviderInstalled()) return su::Error(ERROR_SERVICE_NOT_ACTIVE);
    su::Config old;
    {
        su::ConfigLock guard;
        if (!guard.acquired()) return su::Error(ERROR_TIMEOUT);
        su::ReadConfigUnlocked(old);
    }
    config.identity=identity;
    config.generation=su::RandomId();
    if (!config.generation) return E_FAIL;
    SYSTEMTIME time{};
    if (DateTime_GetSystemtime(timePicker,&time) != GDT_VALID) return E_INVALIDARG;
    config.hour=time.wHour; config.minute=time.wMinute;
    config.wake=SendMessageW(wakeBox,BM_GETCHECK,0,0) == BST_CHECKED;
    config.daily=daily || (old.generation && old.daily);
    config.suspended=false;
    auto password=InputPassword();
    if (password.empty()) {
        if (!old.generation || old.identity.sid != identity.sid) return su::Error(ERROR_INVALID_PASSWORD);
        if (FAILED(hr=su::Decrypt(old.encrypted,password))) return hr;
    }
    // Validate exactly once on a save/test, before persisting any new credentials.
    if (FAILED(hr=su::ValidatePassword(identity,password))) return hr;
    return su::Encrypt(password,config.encrypted);
}
void SaveOrTest(bool test) {
    if (busy) return;
    Buttons(false);
    su::Config config;
    HRESULT hr=Prepare(config,!test);
    if (SUCCEEDED(hr)) {
        // Disable the previous revision before replacing scheduler tasks. No partial activation.
        su::ConfigLock guard;
        if (!guard.acquired()) hr=su::Error(ERROR_TIMEOUT);
        else {
            config.suspended=true;
            hr=su::SaveConfigUnlocked(config);
        }
    }
    if (SUCCEEDED(hr)) hr=su::DeleteTasks();
    if (SUCCEEDED(hr) && config.daily) hr=su::RegisterTask(config,exePath,false);
    if (SUCCEEDED(hr) && test) hr=su::RegisterTask(config,exePath,true);
    if (SUCCEEDED(hr)) {
        su::ConfigLock guard;
        if (!guard.acquired()) hr=su::Error(ERROR_TIMEOUT);
        else {
            config.suspended=false;
            hr=su::SaveConfigUnlocked(config);
            if (SUCCEEDED(hr)) {
                if (test) su::StatusUnlocked(L"测试已安排：请现在按 Win + L，60 秒后尝试解锁。");
                else {
                    wchar_t text[120]{};
                    swprintf_s(text,ARRAYSIZE(text),L"已启用：每天 %02lu:%02lu 尝试解锁。电脑须已登录并处于锁屏状态。",config.hour,config.minute);
                    su::StatusUnlocked(text);
                }
            }
        }
    }
    ClearPasswordBox(); Buttons(true); RefreshStatus();
    if (FAILED(hr)) ShowError(hr,L"没有完成设置。请检查账户密码和安装状态。");
    else if (test) MessageBoxW(window,L"请在接下来 60 秒内按 Win + L 锁屏。\n\n测试只执行一次；每日计划按界面中设定的时间运行。",L"测试已安排",MB_OK | MB_ICONINFORMATION);
}
void DisableAll() {
    if (busy) return;
    Buttons(false);
    HRESULT cleared;
    {
        su::ConfigLock guard;
        cleared=guard.acquired() ? su::ClearConfigUnlocked() : su::Error(ERROR_TIMEOUT);
        if (SUCCEEDED(cleared)) su::StatusUnlocked(L"已停用。已清除保存的密码和解锁请求。");
    }
    HRESULT removed=su::DeleteTasks();
    ClearPasswordBox(); Buttons(true); RefreshStatus();
    if (FAILED(cleared)) ShowError(cleared,L"未能清除设置。");
    else if (FAILED(removed)) ShowError(removed,L"密码已清除，但未能删除定时任务。可使用卸载程序继续清理。");
}
HWND Control(const wchar_t* kind,const wchar_t* text,DWORD style,int x,int y,int width,int height,int id=0) {
    HWND control=CreateWindowExW(wcscmp(kind,L"EDIT") == 0 ? WS_EX_CLIENTEDGE : 0,kind,text,WS_CHILD | WS_VISIBLE | style,D(x),D(y),D(width),D(height),window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
    SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
    return control;
}
void CreateControls() {
    font=CreateFontW(-D(16),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    titleFont=CreateFontW(-D(26),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    HWND title=Control(L"STATIC",L"定时解锁",0,28,22,500,44);
    SendMessageW(title,WM_SETFONT,reinterpret_cast<WPARAM>(titleFont),TRUE);
    Control(L"STATIC",L"让已锁屏的 Windows 在指定时间回到桌面。",0,30,76,570,28);
    Control(L"STATIC",L"当前账户",0,30,122,100,28);
    std::wstring account=identity.domain+L"\\"+identity.user;
    Control(L"EDIT",account.c_str(),ES_READONLY | ES_AUTOHSCROLL,148,118,450,32);
    Control(L"STATIC",L"账户密码",0,30,174,100,28);
    passwordBox=Control(L"EDIT",L"",WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,148,170,450,32,Password);
    SendMessageW(passwordBox,EM_SETLIMITTEXT,512,0);
    Control(L"STATIC",L"首次输入密码；已保存后留空可沿用。",0,148,211,450,25);
    Control(L"STATIC",L"每天解锁时间",0,30,256,115,30);
    timePicker=Control(DATETIMEPICK_CLASSW,L"",WS_TABSTOP | DTS_TIMEFORMAT | DTS_UPDOWN,148,252,130,34,Time);
    DateTime_SetFormat(timePicker,L"HH:mm");
    wakeBox=Control(L"BUTTON",L"允许唤醒睡眠中的电脑",WS_TABSTOP | BS_AUTOCHECKBOX,148,308,450,30,Wake);
    Control(L"BUTTON",L"启用并保存",WS_TABSTOP | BS_DEFPUSHBUTTON,30,368,160,40,Save);
    Control(L"BUTTON",L"60 秒后测试",WS_TABSTOP | BS_PUSHBUTTON,208,368,160,40,Test);
    Control(L"BUTTON",L"停用并清除密码",WS_TABSTOP | BS_PUSHBUTTON,386,368,212,40,Disable);
    statusBox=Control(L"STATIC",L"",0,30,435,570,70,Status);
    Control(L"BUTTON",L"刷新状态",WS_TABSTOP | BS_PUSHBUTTON,480,514,118,32,Refresh);
    Control(L"STATIC",L"仅支持本地账户密码。电脑关机时不会执行。",0,30,563,570,28);
    su::Config config;
    SYSTEMTIME time{}; GetLocalTime(&time); time.wHour=8; time.wMinute=30; time.wSecond=0;
    {
        su::ConfigLock guard;
        if (guard.acquired() && SUCCEEDED(su::ReadConfigUnlocked(config))) {
            time.wHour=static_cast<WORD>(config.hour); time.wMinute=static_cast<WORD>(config.minute);
            SendMessageW(wakeBox,BM_SETCHECK,config.wake ? BST_CHECKED : BST_UNCHECKED,0);
        }
    }
    DateTime_SetSystemtime(timePicker,GDT_VALID,&time);
    RefreshStatus();
    SetTimer(window,1,3000,nullptr);
}
LRESULT CALLBACK WindowProc(HWND hwnd,UINT message,WPARAM w,LPARAM l) {
    switch (message) {
    case WM_CREATE: window=hwnd; CreateControls(); return 0;
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case Save: SaveOrTest(false); break;
        case Test: SaveOrTest(true); break;
        case Disable: DisableAll(); break;
        case Refresh: RefreshStatus(); break;
        }
        return 0;
    case WM_TIMER: if (!busy) RefreshStatus(); return 0;
    case WM_DESTROY:
        KillTimer(hwnd,1); DeleteObject(font); DeleteObject(titleFont); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd,message,w,l);
}

int RequestUnlock(std::uint64_t expectedGeneration) {
    // Scheduler jobs must run as SYSTEM. No command-line passwords or arbitrary target users.
    if (!su::IsSystem()) return ERROR_ACCESS_DENIED;
    su::ConfigLock singleWorker(L"Global\\ScheduledUnlock.Worker.v1",0);
    if (!singleWorker.acquired()) return ERROR_ALREADY_EXISTS;
    std::vector<wchar_t> path(32768);
    DWORD length=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if (!length || length >= path.size() || !su::InstalledExecutable(std::wstring(path.data(),length))) return ERROR_ACCESS_DENIED;
    su::Config config;
    DWORD session=WTSGetActiveConsoleSessionId();
    su::Request request;
    {
        su::ConfigLock guard;
        if (!guard.acquired()) return ERROR_TIMEOUT;
        if (FAILED(su::ReadConfigUnlocked(config)) || config.suspended || config.generation != expectedGeneration) return ERROR_CANCELLED;
        int locked=su::LockState(session);
        if (locked < 0) { su::StatusUnlocked(L"无法读取当前锁屏状态，已跳过本次解锁。"); return ERROR_GEN_FAILURE; }
        if (!locked) { su::StatusUnlocked(L"已跳过：到点时电脑没有处于锁屏状态。"); return 0; }
        su::Identity actual;
        HRESULT hr=su::ConsoleIdentity(actual,true);
        if (FAILED(hr)) { su::StatusUnlocked(L"无法验证当前登录会话，已跳过本次解锁。"); return HRESULT_CODE(hr); }
        if (actual.sid != config.identity.sid) { su::StatusUnlocked(L"已跳过：当前登录账户与设置的账户不同。"); return 0; }
        request.session=session; request.generation=config.generation; request.nonce=su::RandomId();
        request.issued=su::Now(); request.expires=request.issued+su::kRequestLifetime;
        if (!request.nonce) return ERROR_GEN_FAILURE;
        hr=su::WriteRequestUnlocked(request);
        if (FAILED(hr)) return HRESULT_CODE(hr);
        su::StatusUnlocked(L"正在请求解锁；请求将在 90 秒后过期。");
    }
    while (su::Now() < request.expires) {
        Sleep(500);
        su::ConfigLock guard; su::Config current;
        if (!guard.acquired()) continue;
        if (FAILED(su::ReadConfigUnlocked(current)) || current.generation != expectedGeneration) return ERROR_CANCELLED;
        if (current.suspended) return ERROR_LOGON_FAILURE;
        if (session != WTSGetActiveConsoleSessionId()) { su::ClearRequestUnlocked(); su::StatusUnlocked(L"已取消：当前桌面会话发生了变化。"); return ERROR_CANCELLED; }
        if (su::LockState(session) == 0) {
            su::ClearRequestUnlocked(); su::StatusUnlocked(L"电脑已回到桌面。"); return 0;
        }
    }
    su::ConfigLock guard; su::Config current;
    if (guard.acquired() && SUCCEEDED(su::ReadConfigUnlocked(current)) && current.generation == expectedGeneration && !current.suspended) {
        su::ClearRequestUnlocked();
        su::StatusUnlocked(L"请求已过期，未完成自动解锁。请正常登录后查看说明或重新测试。");
    }
    return ERROR_TIMEOUT;
}
}

int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int show) try {
    int count=0; LPWSTR* args=CommandLineToArgvW(GetCommandLineW(),&count);
    if (args && count == 3 && wcscmp(args[1],L"--request") == 0) {
        wchar_t* end=nullptr;
        unsigned long long revision=wcstoull(args[2],&end,10);
        bool valid=end && *end == 0 && revision != 0;
        LocalFree(args);
        return valid ? RequestUnlock(revision) : ERROR_INVALID_PARAMETER;
    }
    if (args) LocalFree(args);
    HRESULT initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return 1;
    HRESULT hr=su::ConsoleIdentity(identity,false);
    if (FAILED(hr)) {
        MessageBoxW(nullptr,L"本版本需要已登录的 Windows 本地账户。\n微软账户、公司账户、远程桌面会话暂不支持。",L"定时解锁",MB_OK | MB_ICONERROR);
        CoUninitialize(); return 1;
    }
    if (!su::ProviderInstalled()) {
        MessageBoxW(nullptr,L"请先解压完整软件包，并运行 Install.cmd 安装。",L"定时解锁",MB_OK | MB_ICONINFORMATION);
        CoUninitialize(); return 1;
    }
    std::vector<wchar_t> path(32768);
    DWORD pathLength=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if (!pathLength || pathLength >= path.size()) { CoUninitialize(); return 1; }
    exePath.assign(path.data(),pathLength);
    DWORD ownSession=su::kInvalidSession; ProcessIdToSessionId(GetCurrentProcessId(),&ownSession);
    if (!su::InstalledExecutable(exePath) || ownSession != WTSGetActiveConsoleSessionId()) {
        MessageBoxW(nullptr,L"请在电脑本地桌面打开安装程序创建的“定时解锁”快捷方式。",L"定时解锁",MB_OK | MB_ICONINFORMATION);
        CoUninitialize(); return 1;
    }
    HDC screen=GetDC(nullptr); scale=GetDeviceCaps(screen,LOGPIXELSX); ReleaseDC(nullptr,screen);
    INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_DATE_CLASSES | ICC_STANDARD_CLASSES}; InitCommonControlsEx(&controls);
    WNDCLASSW klass{}; klass.lpfnWndProc=WindowProc; klass.hInstance=instance; klass.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    klass.hIcon=LoadIconW(nullptr,IDI_APPLICATION); klass.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1); klass.lpszClassName=L"ScheduledUnlock.Window";
    RegisterClassW(&klass);
    RECT rect{0,0,D(630),D(620)}; AdjustWindowRectEx(&rect,WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,FALSE,0);
    HWND hwnd=CreateWindowExW(0,klass.lpszClassName,L"定时解锁 · 本地账户",WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,CW_USEDEFAULT,CW_USEDEFAULT,rect.right-rect.left,rect.bottom-rect.top,nullptr,nullptr,instance,nullptr);
    if (!hwnd) { CoUninitialize(); return 1; }
    ShowWindow(hwnd,show); UpdateWindow(hwnd);
    MSG message{};
    while (GetMessageW(&message,nullptr,0,0) > 0) {
        if (!IsDialogMessageW(hwnd,&message)) { TranslateMessage(&message); DispatchMessageW(&message); }
    }
    CoUninitialize(); return static_cast<int>(message.wParam);
} catch (...) {
    if (!su::IsSystem()) MessageBoxW(nullptr,L"程序遇到了无法处理的错误。请重新打开设置窗口。",L"定时解锁",MB_OK | MB_ICONERROR);
    return ERROR_GEN_FAILURE;
}
