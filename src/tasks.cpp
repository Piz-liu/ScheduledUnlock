#include "tasks.hpp"
#include <taskschd.h>
#include <oleauto.h>

namespace su {
namespace {
struct Text {
    BSTR b;
    explicit Text(const wchar_t* s):b(SysAllocString(s)) {}
    ~Text() { SysFreeString(b); }
    operator BSTR() const { return b; }
};
struct Value {
    VARIANT v;
    Value() { VariantInit(&v); }
    explicit Value(const wchar_t* s) { VariantInit(&v); v.vt=VT_BSTR; v.bstrVal=SysAllocString(s); }
    ~Value() { VariantClear(&v); }
};
HRESULT Connect(ComPtr<ITaskService>& service,ComPtr<ITaskFolder>& folder) {
    HRESULT hr=CoCreateInstance(CLSID_TaskScheduler,nullptr,CLSCTX_INPROC_SERVER,IID_ITaskService,reinterpret_cast<void**>(service.put()));
    if (FAILED(hr)) return hr;
    Value empty;
    if (FAILED(hr=service->Connect(empty.v,empty.v,empty.v,empty.v))) return hr;
    Text root(L"\\");
    return service->GetFolder(root,folder.put());
}
std::wstring Boundary(const Config& c,bool test) {
    SYSTEMTIME time{};
    if (test) {
        ULARGE_INTEGER ticks{}; ticks.QuadPart=Now()+60*kTicksPerSecond;
        FILETIME utc{ticks.LowPart,ticks.HighPart}, local{};
        FileTimeToLocalFileTime(&utc,&local); FileTimeToSystemTime(&local,&time);
    } else {
        GetLocalTime(&time); time.wHour=static_cast<WORD>(c.hour); time.wMinute=static_cast<WORD>(c.minute); time.wSecond=0;
    }
    wchar_t value[40]{};
    swprintf_s(value,ARRAYSIZE(value),L"%04u-%02u-%02uT%02u:%02u:%02u",time.wYear,time.wMonth,time.wDay,time.wHour,time.wMinute,time.wSecond);
    return value;
}
}
HRESULT RegisterTask(const Config& config,const std::wstring& exe,bool test) {
    ComPtr<ITaskService> service; ComPtr<ITaskFolder> folder;
    HRESULT hr=Connect(service,folder);
    if (FAILED(hr)) return hr;
    ComPtr<ITaskDefinition> task;
    if (FAILED(hr=service->NewTask(0,task.put()))) return hr;
    ComPtr<IRegistrationInfo> info;
    if (FAILED(hr=task->get_RegistrationInfo(info.put()))) return hr;
    Text author(L"ScheduledUnlock"),description(L"解锁已登录且正在锁屏的本地账户；不执行开机自动登录。");
    if (FAILED(hr=info->put_Author(author)) || FAILED(hr=info->put_Description(description))) return hr;
    ComPtr<IPrincipal> principal;
    if (FAILED(hr=task->get_Principal(principal.put()))) return hr;
    Text system(L"S-1-5-18");
    if (FAILED(hr=principal->put_UserId(system)) || FAILED(hr=principal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT)) || FAILED(hr=principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST))) return hr;
    ComPtr<ITaskSettings> settings;
    if (FAILED(hr=task->get_Settings(settings.put()))) return hr;
    Text timeout(L"PT2M");
    if (FAILED(hr=settings->put_Enabled(VARIANT_TRUE)) || FAILED(hr=settings->put_StartWhenAvailable(VARIANT_FALSE)) || FAILED(hr=settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE)) || FAILED(hr=settings->put_StopIfGoingOnBatteries(VARIANT_FALSE)) || FAILED(hr=settings->put_WakeToRun(config.wake ? VARIANT_TRUE : VARIANT_FALSE)) || FAILED(hr=settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW)) || FAILED(hr=settings->put_ExecutionTimeLimit(timeout))) return hr;
    ComPtr<ITriggerCollection> triggers;
    if (FAILED(hr=task->get_Triggers(triggers.put()))) return hr;
    ComPtr<ITrigger> trigger;
    if (FAILED(hr=triggers->Create(test ? TASK_TRIGGER_TIME : TASK_TRIGGER_DAILY,trigger.put()))) return hr;
    Text boundary(Boundary(config,test).c_str());
    if (FAILED(hr=trigger->put_StartBoundary(boundary)) || FAILED(hr=trigger->put_Enabled(VARIANT_TRUE))) return hr;
    if (!test) {
        ComPtr<IDailyTrigger> daily;
        if (FAILED(hr=trigger->QueryInterface(IID_IDailyTrigger,reinterpret_cast<void**>(daily.put()))) || FAILED(hr=daily->put_DaysInterval(1))) return hr;
    }
    ComPtr<IActionCollection> actions;
    if (FAILED(hr=task->get_Actions(actions.put()))) return hr;
    ComPtr<IAction> action;
    if (FAILED(hr=actions->Create(TASK_ACTION_EXEC,action.put()))) return hr;
    ComPtr<IExecAction> execute;
    if (FAILED(hr=action->QueryInterface(IID_IExecAction,reinterpret_cast<void**>(execute.put())))) return hr;
    std::wstring arguments=L"--request " + std::to_wstring(config.generation);
    Text path(exe.c_str()), args(arguments.c_str());
    if (FAILED(hr=execute->put_Path(path)) || FAILED(hr=execute->put_Arguments(args))) return hr;
    Value user(L"S-1-5-18"),empty,acl(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    ComPtr<IRegisteredTask> registered;
    Text name(test ? kTestTask : kDailyTask);
    return folder->RegisterTaskDefinition(name,task.get(),TASK_CREATE_OR_UPDATE,user.v,empty.v,TASK_LOGON_SERVICE_ACCOUNT,acl.v,registered.put());
}
HRESULT DeleteTasks() {
    ComPtr<ITaskService> service; ComPtr<ITaskFolder> folder;
    HRESULT hr=Connect(service,folder);
    if (FAILED(hr)) return hr;
    HRESULT first=S_OK;
    for (auto name : {kDailyTask,kTestTask}) {
        Text text(name); hr=folder->DeleteTask(text,0);
        if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) && SUCCEEDED(first)) first=hr;
    }
    return first;
}
}
