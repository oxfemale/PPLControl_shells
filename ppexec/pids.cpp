#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <winnt.h>
#include <tlhelp32.h>
#include "crypt.h"
#include "pids.h"
#include "Controller.h"
#include "service.h"





typedef DWORD(WINAPI* PFN_GetCurrentProcessId)();
typedef HMODULE(WINAPI* PFN_GetModuleHandleW)(LPCWSTR);
typedef FARPROC(WINAPI* PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef DWORD(WINAPI* PFN_GetLastError)();
typedef UINT(WINAPI* PFN_GetWindowsDirectoryW)(LPWSTR, UINT);
typedef UINT(WINAPI* PFN_GetSystemDirectoryW)(LPWSTR, UINT);
typedef DWORD(WINAPI* PFN_GetCurrentDirectoryW)(DWORD, LPWSTR);
typedef DWORD(WINAPI* PFN_GetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef BOOL(WINAPI* PFN_CopyFileW)(LPCWSTR, LPCWSTR, BOOL);
typedef DWORD(WINAPI* PFN_GetFileAttributesW)(LPCWSTR);
typedef BOOL(WINAPI* PFN_CreateDirectoryW)(LPCWSTR, LPSECURITY_ATTRIBUTES);
typedef HANDLE(WINAPI* PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* PFN_CloseHandle)(HANDLE);
typedef BOOL(WINAPI* PFN_DeleteFileW)(LPCWSTR);
typedef DWORD(WINAPI* PFN_GetFullPathNameW)(LPCWSTR, DWORD, LPWSTR, LPWSTR*);
typedef DWORD(WINAPI* PFN_FormatMessageW)(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*);
typedef BOOL(WINAPI* PFN_LocalFree)(HLOCAL);
typedef HANDLE(WINAPI* PFN_GetCurrentProcess)();
typedef DWORD(WINAPI* PFN_GetFileSize)(HANDLE, LPDWORD);
typedef BOOL(WINAPI* PFN_IsWow64Process)(HANDLE, PBOOL);
typedef BOOL(WINAPI* PFN_GetProcessInformation)(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);
typedef DWORD(WINAPI* PFN_GetProcessId)(HANDLE);
typedef BOOL(WINAPI* PFN_GetProcessTimes)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
typedef DWORD(WINAPI* PFN_GetTickCount)();


template<typename FuncType>
FuncType GetKernel32Function(const char* funcName)
{
    static HMODULE hKernel32 = nullptr;
    static PFN_GetProcAddress pGetProcAddress = nullptr;

    if (!hKernel32)
    {
        hKernel32 = GetModuleHandleW(SKW(L"kernel32.dll"));
        if (!hKernel32)
        {
            g_log.Printf(LogLevel::Error, SKW(L"[!] pids::GetKernel32Function() Error: Failed to get kernel32.dll handle\n"));
            return nullptr;
        }

        pGetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel32, SKA("GetProcAddress"));
        if (!pGetProcAddress)
        {
            g_log.Printf(LogLevel::Error, SKW(L"[!] pids::GetKernel32Function() Error: Failed to get GetProcAddress function\n"));
            return nullptr;
        }
    }

    return (FuncType)pGetProcAddress(hKernel32, funcName);
}

template<typename FuncType>
FuncType GetAdvapi32Function(const char* funcName)
{
    static HMODULE hAdvapi32 = nullptr;
    static PFN_GetProcAddress pGetProcAddress = nullptr;

    if (!hAdvapi32)
    {
        PFN_GetModuleHandleW pGetModuleHandleW = GetKernel32Function<PFN_GetModuleHandleW>("GetModuleHandleW");
        if (!pGetModuleHandleW) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] pids::GetAdvapi32Function() Failed to get GetModuleHandleW function\n"));
            return nullptr;
        }

        hAdvapi32 = pGetModuleHandleW(SKW(L"advapi32.dll"));
        if (!hAdvapi32)
        {

            auto pLoadLibraryW = GetKernel32Function<HMODULE(WINAPI*)(LPCWSTR)>("LoadLibraryW");
            if (pLoadLibraryW) hAdvapi32 = pLoadLibraryW(L"advapi32.dll");
            if (!hAdvapi32) {
                g_log.Printf(LogLevel::Error, SKW(L"[!] pids::GetAdvapi32Function() Failed to get advapi32.dll handle\n"));
                return nullptr;
            }
        }

        pGetProcAddress = GetKernel32Function<PFN_GetProcAddress>("GetProcAddress");
        if (!pGetProcAddress) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] pids::GetAdvapi32Function() Failed to get GetProcAddress function\n"));
            return nullptr;
        }
    }

    return (FuncType)pGetProcAddress(hAdvapi32, funcName);
}


namespace parents
{
    typedef HANDLE(WINAPI* PFN_CreateToolhelp32Snapshot)(DWORD, DWORD);
    typedef BOOL(WINAPI* PFN_Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL(WINAPI* PFN_Process32NextW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL(WINAPI* PFN_CloseHandle)(HANDLE);

    typedef HANDLE(WINAPI* PFN_OpenProcess)(DWORD, BOOL, DWORD);
    typedef BOOL(WINAPI* PFN_QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
    typedef DWORD(WINAPI* PFN_GetLastError)(VOID);

    typedef BOOL(WINAPI* PFN_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
    typedef BOOL(WINAPI* PFN_GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
    typedef BOOL(WINAPI* PFN_LookupAccountSidW)(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);

    static bool QueryTokenUserName(
        HANDLE hProcess,
        std::wstring& outUserDomain,
        std::wstring& outUserName
    )
    {
        outUserDomain.clear();
        outUserName.clear();

        auto pOpenProcessToken = GetAdvapi32Function<PFN_OpenProcessToken>(SKA("OpenProcessToken"));
        auto pGetTokenInformation = GetAdvapi32Function<PFN_GetTokenInformation>(SKA("GetTokenInformation"));
        auto pLookupAccountSidW = GetAdvapi32Function<PFN_LookupAccountSidW>(SKA("LookupAccountSidW"));
        auto pCloseHandle = GetKernel32Function<PFN_CloseHandle>(SKA("CloseHandle"));
        auto pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

        if (!pOpenProcessToken || !pGetTokenInformation || !pLookupAccountSidW || !pCloseHandle)
            return false;

        HANDLE hToken = nullptr;
        if (!pOpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            DWORD e = pGetLastError ? pGetLastError() : 0;
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::QueryTokenUserName() OpenProcessToken failed: %s\n"),
                GetErrorStringOut(e).c_str());
            return false;
        }

        DWORD cb = 0;
        pGetTokenInformation(hToken, TokenUser, nullptr, 0, &cb);
        if (cb == 0)
        {
            pCloseHandle(hToken);
            return false;
        }

        std::vector<BYTE> buf(cb);
        if (!pGetTokenInformation(hToken, TokenUser, buf.data(), (DWORD)buf.size(), &cb))
        {
            DWORD e = pGetLastError ? pGetLastError() : 0;
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::QueryTokenUserName() GetTokenInformation(TokenUser) failed: %s\n"),
                GetErrorStringOut(e).c_str());
            pCloseHandle(hToken);
            return false;
        }

        auto ptu = reinterpret_cast<TOKEN_USER*>(buf.data());
        if (!ptu || !ptu->User.Sid)
        {
            pCloseHandle(hToken);
            return false;
        }

        wchar_t name[256] = {};
        wchar_t domain[256] = {};
        DWORD cchName = (DWORD)(sizeof(name) / sizeof(name[0]));
        DWORD cchDomain = (DWORD)(sizeof(domain) / sizeof(domain[0]));
        SID_NAME_USE use = SidTypeUnknown;

        if (!pLookupAccountSidW(nullptr, ptu->User.Sid, name, &cchName, domain, &cchDomain, &use))
        {
            DWORD e = pGetLastError ? pGetLastError() : 0;
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::QueryTokenUserName() LookupAccountSidW failed: %s\n"),
                GetErrorStringOut(e).c_str());
            pCloseHandle(hToken);
            return false;
        }

        pCloseHandle(hToken);

        outUserName = name;
        outUserDomain = domain;
        return true;
    }

    static bool QueryProcessFullPath(HANDLE hProcess, std::wstring& outPath)
    {
        outPath.clear();

        auto pQueryFullProcessImageNameW =
            GetKernel32Function<PFN_QueryFullProcessImageNameW>(SKA("QueryFullProcessImageNameW"));
        auto pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

        if (!pQueryFullProcessImageNameW)
            return false;

        wchar_t buf[MAX_PATH * 4] = {};
        DWORD cch = (DWORD)(sizeof(buf) / sizeof(buf[0]));

        if (!pQueryFullProcessImageNameW(hProcess, 0, buf, &cch))
        {
            DWORD e = pGetLastError ? pGetLastError() : 0;
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::QueryProcessFullPath() QueryFullProcessImageNameW failed: %s\n"),
                GetErrorStringOut(e).c_str());
            return false;
        }

        outPath.assign(buf, cch);
        return true;
    }


    static DWORD GetParentPidToolhelp(DWORD pid)
    {
        auto pCreateToolhelp32Snapshot =
            GetKernel32Function<PFN_CreateToolhelp32Snapshot>(SKA("CreateToolhelp32Snapshot"));
        auto pProcess32FirstW =
            GetKernel32Function<PFN_Process32FirstW>(SKA("Process32FirstW"));
        auto pProcess32NextW =
            GetKernel32Function<PFN_Process32NextW>(SKA("Process32NextW"));
        auto pCloseHandle =
            GetKernel32Function<PFN_CloseHandle>(SKA("CloseHandle"));

        if (!pCreateToolhelp32Snapshot || !pProcess32FirstW || !pProcess32NextW || !pCloseHandle)
            return 0;

        HANDLE hSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        DWORD ppid = 0;
        if (pProcess32FirstW(hSnap, &pe))
        {
            do {
                if (pe.th32ProcessID == pid)
                {
                    ppid = pe.th32ParentProcessID;
                    break;
                }
                pe.dwSize = sizeof(pe);
            } while (pProcess32NextW(hSnap, &pe));
        }

        pCloseHandle(hSnap);
        return ppid;
    }

    
    bool PrintParentProcessInfo(DWORD pid)
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] pids::PrintParentProcessInfo() Target PID: %lu\n"), pid);

        DWORD ppid = GetParentPidToolhelp(pid);
        if (ppid == 0)
        {
            g_log.Printf(LogLevel::Error, SKW(L"[!] pids::PrintParentProcessInfo() Failed to find parent PID for %lu\n"), pid);
            return false;
        }

        g_log.Printf(LogLevel::Info, SKW(L"[i] pids::PrintParentProcessInfo() Parent PID: %lu\n"), ppid);

        auto pOpenProcess = GetKernel32Function<PFN_OpenProcess>(SKA("OpenProcess"));
        auto pCloseHandle = GetKernel32Function<PFN_CloseHandle>(SKA("CloseHandle"));
        auto pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

        if (!pOpenProcess || !pCloseHandle)
        {
            g_log.Printf(LogLevel::Error, SKW(L"[!] pids::PrintParentProcessInfo() OpenProcess/CloseHandle not available\n"));
            return false;
        }

        HANDLE hParent = pOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
        if (!hParent)
        {
            DWORD e = pGetLastError ? pGetLastError() : 0;
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::PrintParentProcessInfo() OpenProcess(PPID=%lu) failed: %s\n"),
                ppid, GetErrorStringOut(e).c_str());
            return true;
        }

        std::wstring parentPath;
        QueryProcessFullPath(hParent, parentPath);

        std::wstring dom, user;
        QueryTokenUserName(hParent, dom, user);

        if (!parentPath.empty())
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i] pids::PrintParentProcessInfo() Parent Image: %ws\n"), parentPath.c_str());
        }
        else
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::PrintParentProcessInfo() Parent Image: <unknown>\n"));
        }

        if (!user.empty())
        {
            if (!dom.empty())
                g_log.Printf(LogLevel::Info, SKW(L"[i] pids::PrintParentProcessInfo() Parent User: %ws\\%ws\n"), dom.c_str(), user.c_str());
            else
                g_log.Printf(LogLevel::Info, SKW(L"[i] pids::PrintParentProcessInfo() Parent User: %ws\n"), user.c_str());
        }
        else
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::PrintParentProcessInfo() Parent User: <unknown>\n"));
        }

        pCloseHandle(hParent);
        return true;
    }
}


// ==============================================
// Функции для получения PID
// ==============================================

// Основная функция получения PID текущего процесса
DWORD GetCurrentProcessID()
{
    g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::GetCurrentProcessID() Getting current process ID\n"));

    PFN_GetCurrentProcessId pGetCurrentProcessId = GetKernel32Function<PFN_GetCurrentProcessId>(SKA("GetCurrentProcessId"));

    if (!pGetCurrentProcessId)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] pids::GetCurrentProcessID() Error: Failed to load GetCurrentProcessId function\n"));
        return 0;
    }

    DWORD pid = pGetCurrentProcessId();
    g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::GetCurrentProcessID() Current PID: %lu\n"), pid);
    return pid;
}

// Альтернативная версия через GetCurrentProcess + GetProcessId (если доступна)
DWORD GetCurrentProcessIDAlternative()
{
    g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::GetCurrentProcessIDAlternative() Getting PID via alternative method\n"));

    typedef DWORD(WINAPI* PFN_GetProcessId)(HANDLE);
    typedef HANDLE(WINAPI* PFN_GetCurrentProcess)();

    PFN_GetProcessId pGetProcessId = GetKernel32Function<PFN_GetProcessId>(SKA("GetProcessId"));
    PFN_GetCurrentProcess pGetCurrentProcess = GetKernel32Function<PFN_GetCurrentProcess>(SKA("GetCurrentProcess"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (pGetProcessId && pGetCurrentProcess)
    {
        HANDLE hProcess = pGetCurrentProcess();
        if (hProcess && hProcess != INVALID_HANDLE_VALUE)
        {
            DWORD pid = pGetProcessId(hProcess);
            g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::GetCurrentProcessIDAlternative() PID via GetProcessId: %lu\n"), pid);
            return pid;
        }
        else if (pGetLastError)
        {
            DWORD error = pGetLastError();
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::GetCurrentProcessIDAlternative() Warning: Failed to get current process handle: %s\n"), GetErrorStringOut(error).c_str());
        }
    }
    else
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::GetCurrentProcessIDAlternative() Warning: GetProcessId not available, falling back\n"));
    }

    return GetCurrentProcessID();
}

// Функция получения PID с детальным выводом
DWORD GetCurrentProcessIDWithInfo(bool verbose = false)
{
    g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::GetCurrentProcessIDWithInfo() Getting process info (verbose: %s)\n"), verbose ? L"true" : L"false");

    DWORD pid = GetCurrentProcessID();

    if (pid == 0)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] pids::GetCurrentProcessIDWithInfo() Error: Failed to get process ID\n"));
        return 0;
    }

    if (verbose)
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] pids::GetCurrentProcessIDWithInfo() Current Process ID: %lu\n"), pid);

        PFN_GetModuleFileNameW pGetModuleFileNameW = GetKernel32Function<PFN_GetModuleFileNameW>(SKA("GetModuleFileNameW"));
        PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

        if (pGetModuleFileNameW)
        {
            wchar_t exePath[MAX_PATH] = { 0 };
            DWORD pathLen = pGetModuleFileNameW(nullptr, exePath, MAX_PATH);
            if (pathLen > 0)
            {
                g_log.Printf(LogLevel::Info, SKW(L"[i] pids::GetCurrentProcessIDWithInfo() Executable path: %s\n"), exePath);

                std::wstring pathStr = exePath;
                size_t lastSlash = pathStr.find_last_of(L"\\/");
                if (lastSlash != std::wstring::npos)
                {
                    std::wstring exeName = pathStr.substr(lastSlash + 1);
                    g_log.Printf(LogLevel::Info, SKW(L"[i] pids::GetCurrentProcessIDWithInfo() Executable name: %s\n"), exeName.c_str());
                }
            }
            else if (pGetLastError)
            {
                DWORD error = pGetLastError();
                g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::GetCurrentProcessIDWithInfo() Warning: Failed to get module filename: %s\n"), GetErrorStringOut(error).c_str());
            }
        }
    }

    return pid;
}




namespace pids
{
    typedef BOOL(WINAPI* PFN_IsWow64Process)(HANDLE, PBOOL);
    typedef BOOL(WINAPI* PFN_IsWow64Process2)(HANDLE, USHORT*, USHORT*);
    typedef VOID(WINAPI* PFN_GetNativeSystemInfo)(LPSYSTEM_INFO);
    typedef HANDLE(WINAPI* PFN_GetCurrentProcess)(VOID);
    typedef DWORD(WINAPI* PFN_GetLastError)(VOID);

    static FARPROC GetProcFromEither(const char* name)
    {
        HMODULE hK32 = ::GetModuleHandleW(SKW(L"kernel32.dll"));
        HMODULE hKBase = ::GetModuleHandleW(SKW(L"kernelbase.dll"));

        FARPROC p = nullptr;
        if (hK32)   p = ::GetProcAddress(hK32, name);
        if (!p && hKBase) p = ::GetProcAddress(hKBase, name);
        return p;
    }

    bool IsCurrentProcess64Bit()
    {
        g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::IsCurrentProcess64Bit() Checking process architecture\n"));

        auto pGetCurrentProcess = (PFN_GetCurrentProcess)GetProcFromEither(SKA("GetCurrentProcess"));
        auto pGetLastError = (PFN_GetLastError)GetProcFromEither(SKA("GetLastError"));

        if (!pGetCurrentProcess) {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::IsCurrentProcess64Bit() GetCurrentProcess not available\n"));
            return false;
        }

        HANDLE hProcess = pGetCurrentProcess();

        auto pIsWow64Process2 = (PFN_IsWow64Process2)GetProcFromEither(SKA("IsWow64Process2"));
        if (pIsWow64Process2)
        {
            USHORT processMachine = 0;
            USHORT nativeMachine = 0;

            if (pIsWow64Process2(hProcess, &processMachine, &nativeMachine))
            {
                const bool isWow64 = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN);
                const bool is64OS = (nativeMachine == IMAGE_FILE_MACHINE_AMD64 ||
                    nativeMachine == IMAGE_FILE_MACHINE_ARM64);

                const bool is64Proc = (is64OS && !isWow64);

                g_log.Printf(LogLevel::Info, SKW(L"[i] pids::IsCurrentProcess64Bit() IsWow64Process2: native=0x%04x process=0x%04x => %s\n"),
                    nativeMachine, processMachine, is64Proc ? SKW(L"64-bit") : SKW(L"32-bit"));

                return is64Proc;
            }
            else if (pGetLastError)
            {
                DWORD e = pGetLastError();
                g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::IsCurrentProcess64Bit() IsWow64Process2 failed: %s\n"),
                    GetErrorStringOut(e).c_str());
            }
        }

        auto pIsWow64Process = (PFN_IsWow64Process)GetProcFromEither(SKA("IsWow64Process"));
        auto pGetNativeSystemInfo = (PFN_GetNativeSystemInfo)GetProcFromEither(SKA("GetNativeSystemInfo"));

        if (pIsWow64Process)
        {
            BOOL isWow64 = FALSE;
            if (pIsWow64Process(hProcess, &isWow64))
            {
                if (isWow64) {
                    g_log.Printf(LogLevel::Info, SKW(L"[i] pids::IsCurrentProcess64Bit() Process is 32-bit (WOW64)\n"));
                    return false;
                }

                SYSTEM_INFO si{};
                if (pGetNativeSystemInfo) pGetNativeSystemInfo(&si);
                else ::GetSystemInfo(&si);

                const bool is64OS =
                    (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);

                const bool is64Proc = is64OS;
                g_log.Printf(LogLevel::Info, SKW(L"[i] pids::IsCurrentProcess64Bit() OS is %s => Process is %s\n"),
                    is64OS ? SKW(L"64-bit") : SKW(L"32-bit"),
                    is64Proc ? SKW(L"64-bit") : SKW(L"32-bit"));

                return is64Proc;
            }
            else if (pGetLastError)
            {
                DWORD e = pGetLastError();
                g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::IsCurrentProcess64Bit() IsWow64Process failed: %s\n"),
                    GetErrorStringOut(e).c_str());
            }
        }
        else
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::IsCurrentProcess64Bit() IsWow64Process not available\n"));
        }

        g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::IsCurrentProcess64Bit() Assuming 32-bit (fallback)\n"));
        return false;
    }
}


// Функция сравнения PID с другим процессом
bool IsSameProcess(DWORD otherPid)
{
    g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::IsSameProcess() Checking if PID %lu is current process\n"), otherPid);

    DWORD currentPid = GetCurrentProcessID();
    bool result = (currentPid == otherPid);

    if (result)
    {
        g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::IsSameProcess() PID %lu matches current process\n"), otherPid);
    }
    else
    {
        g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::IsSameProcess() PID %lu is different from current PID %lu\n"), otherPid, currentPid);
    }

    return result;
}

// Функция проверки, запущен ли процесс с повышенными правами
bool IsCurrentProcessElevated()
{
    g_log.Printf(LogLevel::Debug, SKW(L"[i] pids::IsCurrentProcessElevated() Checking process elevation\n"));

    typedef BOOL(WINAPI* PFN_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
    typedef BOOL(WINAPI* PFN_GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

    PFN_GetModuleHandleW pGetModuleHandleW = GetKernel32Function<PFN_GetModuleHandleW>(SKA("GetModuleHandleW"));
    PFN_GetProcAddress pGetProcAddress = GetKernel32Function<PFN_GetProcAddress>(SKA("GetProcAddress"));
    PFN_CloseHandle pCloseHandle = GetKernel32Function<PFN_CloseHandle>(SKA("CloseHandle"));
    PFN_GetCurrentProcess pGetCurrentProcess = GetKernel32Function<PFN_GetCurrentProcess>(SKA("GetCurrentProcess"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pGetModuleHandleW || !pGetProcAddress || !pCloseHandle || !pGetCurrentProcess || !pGetLastError)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] pids::IsCurrentProcessElevated() Error: Failed to load kernel32 functions\n"));
        return false;
    }

    HMODULE hAdvapi32 = pGetModuleHandleW(SKW(L"advapi32.dll"));
    if (!hAdvapi32)
    {
        auto pLoadLibraryW = GetKernel32Function<HMODULE(WINAPI*)(LPCWSTR)>(SKA("LoadLibraryW"));
        if (pLoadLibraryW) hAdvapi32 = pLoadLibraryW(SKW(L"advapi32.dll"));
        if (!hAdvapi32) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] pids::IsCurrentProcessElevated() Error: Failed to load advapi32.dll\n"));
            return false;
        }
    }

    PFN_OpenProcessToken pOpenProcessToken = (PFN_OpenProcessToken)pGetProcAddress(hAdvapi32, SKA("OpenProcessToken"));
    PFN_GetTokenInformation pGetTokenInformation = (PFN_GetTokenInformation)pGetProcAddress(hAdvapi32, SKA("GetTokenInformation"));

    if (!pOpenProcessToken || !pGetTokenInformation)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] pids::IsCurrentProcessElevated() Error: Failed to load token functions\n"));
        return false;
    }

    HANDLE hToken = nullptr;
    if (!pOpenProcessToken(pGetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] pids::IsCurrentProcessElevated() Error: OpenProcessToken failed: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);

    BOOL result = pGetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size);
    DWORD error = pGetLastError();

    if (hToken)
    {
        pCloseHandle(hToken);
    }

    if (!result)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] pids::IsCurrentProcessElevated() Error: GetTokenInformation failed: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    bool isElevated = elevation.TokenIsElevated != 0;
    g_log.Printf(LogLevel::Info, SKW(L"[i] pids::IsCurrentProcessElevated() Process elevation: %s\n"),
        isElevated ? SKW(L"Elevated (Admin)") : SKW(L"Not elevated"));

    return isElevated;
}


void PrintProcessInfo()
{
    DWORD pid = GetCurrentProcessIDWithInfo(true);
    if (pid == 0)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] pids::PrintProcessInfo() Error: Failed to get process ID\n"));
        return;
    }

    bool is64bit = pids::IsCurrentProcess64Bit();
    g_log.Printf(LogLevel::Info, SKW(L"[i] pids::PrintProcessInfo() Process architecture: %s\n"), is64bit ? L"64-bit" : L"32-bit");


    bool isElevated = IsCurrentProcessElevated();
    g_log.Printf(LogLevel::Info, SKW(L"[i] pids::PrintProcessInfo() Process elevation: %s\n"), isElevated ? L"Elevated (Admin)" : L"Not elevated");

    PFN_GetTickCount pGetTickCount = GetKernel32Function<PFN_GetTickCount>(SKA("GetTickCount"));
    if (pGetTickCount)
    {
        DWORD ticks = pGetTickCount();
        g_log.Printf(LogLevel::Info, SKW(L"[i] pids::PrintProcessInfo() System uptime: %lu ms\n"), ticks);
    }

}

void DemonstratePIDUsage()
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] pids::DemonstratePIDUsage() Demonstrating PID usage\n"));

    DWORD myPid = GetCurrentProcessID();

    if (myPid == 0)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] pids::DemonstratePIDUsage() Failed to get current process ID\n"));
        return;
    }

    g_log.Printf(LogLevel::Info, SKW(L"[i] pids::DemonstratePIDUsage() My Process ID: %lu\n"), myPid);

    if (IsSameProcess(myPid))
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] pids::DemonstratePIDUsage() This is definitely my process!\n"));
    }

    wchar_t pidStr[64];
    swprintf_s(pidStr, SKW(L"PID: %lu (0x%08lX)"), myPid, myPid);
    g_log.Printf(LogLevel::Info, SKW(L"[i] pids::DemonstratePIDUsage() Formatted: %s\n"), pidStr);

    if (myPid == 0)
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::DemonstratePIDUsage() Warning: PID is 0 (System Idle Process)\n"));
    }
    else if (myPid == 4)
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] pids::DemonstratePIDUsage() Warning: PID is 4 (System Process)\n"));
    }
    else if (myPid < 100)
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] pids::DemonstratePIDUsage() Info: PID is less than 100 (likely system process)\n"));
    }
    else
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] pids::DemonstratePIDUsage() Info: Normal user process PID\n"));
    }
}


