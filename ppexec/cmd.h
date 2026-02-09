#pragma once
#define NOMINMAX
#include <windows.h>
#include <newdev.h>
#include <algorithm>
#include <stdio.h>
#include <string>
#include <vector>
#include <atomic>



// Assumes your project provides:
//   - g_log.Printf(LogLevel::..., SKW(L"..."), ...)
//   - SKW(...) macro
//   - LogLevel enum
// If not, include the соответствующие заголовки до cmd.h.

//
// Minimal dynamic WinAPI resolver (GetProcAddress-based).
// NOTE: This uses the imports GetModuleHandleW/LoadLibraryW/GetProcAddress to bootstrap.
// All other WinAPI calls below go through resolved function pointers.
//
namespace cmd_dyn
{
    inline HMODULE Module(const wchar_t* name)
    {
        HMODULE m = ::GetModuleHandleW(name);
        if (!m) m = ::LoadLibraryW(name);
        return m;
    }

    template <class T>
    inline T Proc(const wchar_t* module, const char* name)
    {
        HMODULE m = Module(module);
        if (!m) return nullptr;
        return reinterpret_cast<T>(::GetProcAddress(m, name));
    }

    // kernel32
    using PFN_GetLastError = DWORD(WINAPI*)();
    using PFN_CloseHandle = BOOL(WINAPI*)(HANDLE);
    using PFN_CreatePipe = BOOL(WINAPI*)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
    using PFN_SetHandleInformation = BOOL(WINAPI*)(HANDLE, DWORD, DWORD);
    using PFN_GetStdHandle = HANDLE(WINAPI*)(DWORD);
    using PFN_CreateProcessW = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    using PFN_ReadFile = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using PFN_MultiByteToWideChar = int  (WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int);
    using PFN_OpenProcess = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
    using PFN_QueryFullProcessImageNameW = BOOL(WINAPI*)(HANDLE, DWORD, LPWSTR, PDWORD);
    using PFN_CreateEventW = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
    using PFN_CreateThread = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using PFN_SetEvent = BOOL(WINAPI*)(HANDLE);
    using PFN_WaitForSingleObject = DWORD(WINAPI*)(HANDLE, DWORD);

    struct Kernel32
    {
        PFN_GetLastError               GetLastError = nullptr;
        PFN_CloseHandle                CloseHandle = nullptr;
        PFN_CreatePipe                 CreatePipe = nullptr;
        PFN_SetHandleInformation       SetHandleInformation = nullptr;
        PFN_GetStdHandle               GetStdHandle = nullptr;
        PFN_CreateProcessW             CreateProcessW = nullptr;
        PFN_ReadFile                   ReadFile = nullptr;
        PFN_MultiByteToWideChar        MultiByteToWideChar = nullptr;
        PFN_OpenProcess                OpenProcess = nullptr;
        PFN_QueryFullProcessImageNameW QueryFullProcessImageNameW = nullptr;
        PFN_CreateEventW               CreateEventW = nullptr;
        PFN_CreateThread               CreateThread = nullptr;
        PFN_SetEvent                   SetEvent = nullptr;
        PFN_WaitForSingleObject        WaitForSingleObject = nullptr;

        bool Resolve()
        {
            if (GetLastError) return true;

            GetLastError = Proc<PFN_GetLastError>(L"kernel32.dll", "GetLastError");
            CloseHandle = Proc<PFN_CloseHandle>(L"kernel32.dll", "CloseHandle");
            CreatePipe = Proc<PFN_CreatePipe>(L"kernel32.dll", "CreatePipe");
            SetHandleInformation = Proc<PFN_SetHandleInformation>(L"kernel32.dll", "SetHandleInformation");
            GetStdHandle = Proc<PFN_GetStdHandle>(L"kernel32.dll", "GetStdHandle");
            CreateProcessW = Proc<PFN_CreateProcessW>(L"kernel32.dll", "CreateProcessW");
            ReadFile = Proc<PFN_ReadFile>(L"kernel32.dll", "ReadFile");
            MultiByteToWideChar = Proc<PFN_MultiByteToWideChar>(L"kernel32.dll", "MultiByteToWideChar");
            OpenProcess = Proc<PFN_OpenProcess>(L"kernel32.dll", "OpenProcess");
            QueryFullProcessImageNameW = Proc<PFN_QueryFullProcessImageNameW>(L"kernel32.dll", "QueryFullProcessImageNameW");
            CreateEventW = Proc<PFN_CreateEventW>(L"kernel32.dll", "CreateEventW");
            CreateThread = Proc<PFN_CreateThread>(L"kernel32.dll", "CreateThread");
            SetEvent = Proc<PFN_SetEvent>(L"kernel32.dll", "SetEvent");
            WaitForSingleObject = Proc<PFN_WaitForSingleObject>(L"kernel32.dll", "WaitForSingleObject");

            return GetLastError && CloseHandle && CreatePipe && SetHandleInformation && GetStdHandle &&
                CreateProcessW && ReadFile && MultiByteToWideChar && OpenProcess && QueryFullProcessImageNameW &&
                CreateEventW && CreateThread && SetEvent && WaitForSingleObject;
        }
    };

    inline Kernel32& K32()
    {
        static Kernel32 g{};
        (void)g.Resolve();
        return g;
    }
}

struct ExecResult {
    bool ok = false;
    DWORD win32Error = 0;
    PROCESS_INFORMATION pi{};
    HANDLE hRead = NULL;   // read-end of stdout/stderr
    HANDLE hWrite = NULL;  // (parent holds write-end before closing it)
};

static inline std::wstring BuildCmdLine(const std::wstring& exePath, const std::wstring& args)
{
    std::wstring cmd = L"\"" + exePath + L"\"";
    if (!args.empty()) { cmd += L" "; cmd += args; }
    return cmd;
}

inline ExecResult CreateSuspendedWithPipe(
    const std::wstring& exePath,
    const std::wstring& args
)
{
    ExecResult r;

    auto& k32 = cmd_dyn::K32();
    if (!k32.Resolve()) {
        r.win32Error = ERROR_PROC_NOT_FOUND;
        return r;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hRead = NULL, hWrite = NULL;
    if (!k32.CreatePipe(&hRead, &hWrite, &sa, 0)) {
        r.win32Error = k32.GetLastError();
        return r;
    }
    k32.SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = k32.GetStdHandle(STD_INPUT_HANDLE);

    std::wstring cmdLine = BuildCmdLine(exePath, args);
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');

    DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

    BOOL ok = k32.CreateProcessW(
        exePath.c_str(),
        buf.data(),
        NULL, NULL,
        TRUE,        // inherit handles for pipe
        flags,
        NULL,
        NULL,
        &si,
        &r.pi
    );

    if (!ok) {
        r.win32Error = k32.GetLastError();
        k32.CloseHandle(hRead);
        k32.CloseHandle(hWrite);
        ZeroMemory(&r.pi, sizeof(r.pi));
        return r;
    }

    // Close write-end in parent so ReadFile gets EOF when child closes.
    k32.CloseHandle(hWrite);

    r.ok = true;
    r.hRead = hRead;
    r.hWrite = NULL;
    return r;
}

inline std::wstring ReadAllPipeTextAndClose(HANDLE hRead)
{
    std::wstring out;
    if (!hRead) return out;

    auto& k32 = cmd_dyn::K32();
    if (!k32.Resolve()) {
        return out;
    }

    DWORD read = 0;
    char buf[4096];

    while (k32.ReadFile(hRead, buf, (DWORD)(sizeof(buf) - 1), &read, NULL) && read) {
        buf[read] = 0;

        int wlen = k32.MultiByteToWideChar(CP_OEMCP, 0, buf, (int)read, NULL, 0);
        if (wlen > 0) {
            std::wstring wtmp((size_t)wlen, L'\0');
            k32.MultiByteToWideChar(CP_OEMCP, 0, buf, (int)read, &wtmp[0], wlen);
            out += wtmp;
        }
    }

    k32.CloseHandle(hRead);
    return out;
}

inline bool GetProcessNameByPid(
    DWORD pid,
    std::wstring& outProcessName
)
{
    outProcessName.clear();

    auto& k32 = cmd_dyn::K32();
    if (!k32.Resolve())
        return false;

    HANDLE hProcess = k32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );
    if (!hProcess)
        return false;

    wchar_t path[MAX_PATH];
    DWORD size = ARRAYSIZE(path);

    bool ok = k32.QueryFullProcessImageNameW(
        hProcess,
        0,          // full path
        path,
        &size
    ) ? true : false;

    k32.CloseHandle(hProcess);

    if (!ok)
        return false;

    const wchar_t* name = wcsrchr(path, L'\\');
    outProcessName = name ? (name + 1) : path;
    return true;
}

struct ShellLaunchResult
{
    bool started = false;
    DWORD pid = 0;
    DWORD win32Error = 0;
};

// Launches interactive cmd.exe / powershell.exe and prints status via g_log.
// Returns PID (if started) and GetLastError code on failure.
inline ShellLaunchResult LaunchInteractiveShellWithPidWatcher(
    bool usePowerShell,                 // false = cmd.exe, true = powershell.exe
    const std::wstring& extraArgs,       // extra args (single line)
    HANDLE* outProcessHandle = nullptr,  // optional: return hProcess
    HANDLE* outThreadHandle = nullptr    // optional: return hThread
)
{
    ShellLaunchResult result{};

    auto& k32 = cmd_dyn::K32();
    if (!k32.Resolve()) {
        result.win32Error = ERROR_PROC_NOT_FOUND;
        return result;
    }

    HANDLE hStartedEvent = k32.CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hStartedEvent) {
        result.win32Error = k32.GetLastError();
        return result;
    }

    std::atomic<DWORD>  sharedPid{ 0 };
    std::atomic<DWORD>  sharedErr{ 0 };
    std::atomic<HANDLE> sharedProc{ NULL };
    std::atomic<HANDLE> sharedThread{ NULL };

    struct Ctx {
        bool usePowerShell;
        std::wstring args;
        HANDLE startedEvent;
        std::atomic<DWORD>* pid;
        std::atomic<DWORD>* err;
        std::atomic<HANDLE>* proc;
        std::atomic<HANDLE>* thr;
    } ctx{
        usePowerShell,
        extraArgs,
        hStartedEvent,
        &sharedPid,
        &sharedErr,
        &sharedProc,
        &sharedThread
    };

    auto launchProc = [](LPVOID param) -> DWORD
        {
            Ctx* c = (Ctx*)param;

            STARTUPINFOW si{};
            si.cb = sizeof(si);

            PROCESS_INFORMATION pi{};

            std::wstring exe = c->usePowerShell
                ? L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                : L"C:\\Windows\\System32\\cmd.exe";

            std::wstring args = c->args;
            if (c->usePowerShell) {
                if (args.find(L"-NoExit") == std::wstring::npos)
                    args = L"-NoExit " + args;
            }

            std::wstring cmdLine = BuildCmdLine(exe, args);
            std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
            buf.push_back(L'\0');

            auto& k32local = cmd_dyn::K32();

            BOOL ok = k32local.CreateProcessW(
                exe.c_str(),
                buf.data(),
                nullptr,
                nullptr,
                TRUE,
                0,
                nullptr,
                nullptr,
                &si,
                &pi
            );

            if (!ok) {
                c->err->store(k32local.GetLastError(), std::memory_order_relaxed);
                k32local.SetEvent(c->startedEvent);
                return 0;
            }

            c->pid->store(pi.dwProcessId, std::memory_order_relaxed);
            c->proc->store(pi.hProcess, std::memory_order_relaxed);
            c->thr->store(pi.hThread, std::memory_order_relaxed);
            k32local.SetEvent(c->startedEvent);
            return 0;
        };

    HANDLE hLaunchThread = k32.CreateThread(nullptr, 0, launchProc, &ctx, 0, nullptr);
    if (!hLaunchThread) {
        result.win32Error = k32.GetLastError();
        k32.CloseHandle(hStartedEvent);
        return result;
    }

    // Watcher: waits until launch thread signals startedEvent, then logs result.
    struct WatchCtx {
        HANDLE startedEvent;
        std::atomic<DWORD>* pid;
        std::atomic<DWORD>* err;
    } wctx{ hStartedEvent, &sharedPid, &sharedErr };

    auto watchProc = [](LPVOID param) -> DWORD
        {
            WatchCtx* w = (WatchCtx*)param;
            auto& k32local = cmd_dyn::K32();
            k32local.WaitForSingleObject(w->startedEvent, INFINITE);

            DWORD pid = w->pid->load(std::memory_order_relaxed);
            DWORD err = w->err->load(std::memory_order_relaxed);

            if (pid != 0) {
                g_log.Printf(LogLevel::Info, SKW(L"[!] cmd::LaunchInteractiveShellWithPidWatcher() Info: Shell started. PID=%lu\n"), pid);
            }
            else {
                g_log.Printf(LogLevel::Error, SKW(L"[!] cmd::LaunchInteractiveShellWithPidWatcher() Error: Shell start failed. GetLastError=%lu\n"), err);
            }
            return 0;
        };

    HANDLE hWatchThread = k32.CreateThread(nullptr, 0, watchProc, &wctx, 0, nullptr);
    if (!hWatchThread) {
        result.win32Error = k32.GetLastError();
        // continue anyway
    }

    // wait for started
    k32.WaitForSingleObject(hStartedEvent, INFINITE);

    DWORD pid = sharedPid.load(std::memory_order_relaxed);
    DWORD err = sharedErr.load(std::memory_order_relaxed);

    if (pid != 0) {
        result.started = true;
        result.pid = pid;
    }
    else {
        result.started = false;
        result.win32Error = (err != 0) ? err : ERROR_GEN_FAILURE;
    }

    // cleanup
    k32.CloseHandle(hLaunchThread);
    if (hWatchThread) k32.CloseHandle(hWatchThread);
    k32.CloseHandle(hStartedEvent);

    HANDLE hp = sharedProc.load(std::memory_order_relaxed);
    HANDLE ht = sharedThread.load(std::memory_order_relaxed);

    if (result.started) {
        if (outProcessHandle) *outProcessHandle = hp; else if (hp) k32.CloseHandle(hp);
        if (outThreadHandle)  *outThreadHandle = ht; else if (ht) k32.CloseHandle(ht);
    }
    else {
        if (hp) k32.CloseHandle(hp);
        if (ht) k32.CloseHandle(ht);
    }

    return result;
}

