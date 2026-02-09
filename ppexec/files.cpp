#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include "crypt.h"
#include "Controller.h"
#include "files.h"
#include "service.h"


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


typedef BOOL(WINAPI* PFN_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI* PFN_GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);


typedef int(WINAPI* PFN_MessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);


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
            g_log.Printf(LogLevel::Error, SKW(L"[!] files::GetKernel32Function() Error: Failed to get kernel32.dll handle\n"));
            return nullptr;
        }

        pGetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
        if (!pGetProcAddress)
        {
            g_log.Printf(LogLevel::Error, SKW(L"[!] files::GetKernel32Function() Error: Failed to get GetProcAddress function\n"));
            return nullptr;
        }
    }

    return (FuncType)pGetProcAddress(hKernel32, funcName);
}


// Получение указателя на функцию из произвольной DLL
template<typename FuncType>
FuncType GetFunctionFromDll(const wchar_t* dllName, const char* funcName)
{
    HMODULE hModule = GetModuleHandleW(dllName);
    if (!hModule)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::GetFunctionFromDll() Error: Failed to get module handle for %s\n"), dllName);
        return nullptr;
    }

    PFN_GetProcAddress pGetProcAddress = GetKernel32Function<PFN_GetProcAddress>("GetProcAddress");
    if (!pGetProcAddress) return nullptr;

    return (FuncType)pGetProcAddress(hModule, funcName);
}


std::wstring GetErrorString(DWORD errorCode = 0)
{
    return GetErrorStringOut(errorCode);
}


bool CheckAndCopyDriverFile(const std::wstring& driverFileName)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Processing driver file: %s\n"), driverFileName.c_str());

    if (driverFileName.empty())
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Driver file name is empty\n"));
        return false;
    }

    PFN_GetWindowsDirectoryW pGetWindowsDirectoryW = GetKernel32Function<PFN_GetWindowsDirectoryW>(SKA("GetWindowsDirectoryW"));
    PFN_GetSystemDirectoryW pGetSystemDirectoryW = GetKernel32Function<PFN_GetSystemDirectoryW>(SKA("GetSystemDirectoryW"));
    PFN_GetCurrentDirectoryW pGetCurrentDirectoryW = GetKernel32Function<PFN_GetCurrentDirectoryW>(SKA("GetCurrentDirectoryW"));
    PFN_GetModuleFileNameW pGetModuleFileNameW = GetKernel32Function<PFN_GetModuleFileNameW>(SKA("GetModuleFileNameW"));
    PFN_CopyFileW pCopyFileW = GetKernel32Function<PFN_CopyFileW>(SKA("CopyFileW"));
    PFN_GetFileAttributesW pGetFileAttributesW = GetKernel32Function<PFN_GetFileAttributesW>(SKA("GetFileAttributesW"));
    PFN_CreateDirectoryW pCreateDirectoryW = GetKernel32Function<PFN_CreateDirectoryW>(SKA("CreateDirectoryW"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pGetWindowsDirectoryW || !pGetSystemDirectoryW || !pGetCurrentDirectoryW ||
        !pGetModuleFileNameW || !pCopyFileW || !pGetFileAttributesW || !pGetLastError)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Failed to load required functions from kernel32.dll\n"));
        return false;
    }

    wchar_t systemDir[MAX_PATH] = { 0 };
    wchar_t windowsDir[MAX_PATH] = { 0 };

    if (pGetSystemDirectoryW(systemDir, MAX_PATH) == 0)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Failed to get system directory: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    if (pGetWindowsDirectoryW(windowsDir, MAX_PATH) == 0)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Failed to get windows directory: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    std::wstring targetDriverPath = std::wstring(systemDir) + SKW(L"\\drivers\\") + driverFileName;
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Target path: %s\n"), targetDriverPath.c_str());


    DWORD fileAttributes = pGetFileAttributesW(targetDriverPath.c_str());
    if (fileAttributes != INVALID_FILE_ATTRIBUTES &&
        !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Info: Driver file already exists\n"));
        return true;
    }

    g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Info: Driver file not found in system directory\n"));

    wchar_t currentExePath[MAX_PATH] = { 0 };
    if (pGetModuleFileNameW(nullptr, currentExePath, MAX_PATH) == 0)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Failed to get current executable path: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    std::wstring currentExeDir = currentExePath;
    size_t lastSlash = currentExeDir.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos)
    {
        currentExeDir = currentExeDir.substr(0, lastSlash + 1);
    }
    else
    {
        currentExeDir = L".\\";
    }

    std::wstring sourceDriverPath = currentExeDir + driverFileName;
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Source path: %s\n"), sourceDriverPath.c_str());


    DWORD sourceAttributes = pGetFileAttributesW(sourceDriverPath.c_str());
    if (sourceAttributes == INVALID_FILE_ATTRIBUTES ||
        (sourceAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Source driver file not found\n"));
        g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Info: Please ensure %s is in the same directory as the executable\n"), driverFileName.c_str());
        return false;
    }

    std::wstring driversDir = std::wstring(systemDir) + SKW(L"\\drivers");
    DWORD driversDirAttributes = pGetFileAttributesW(driversDir.c_str());

    if (driversDirAttributes == INVALID_FILE_ATTRIBUTES)
    {
        // Каталог не существует, создаем его
        g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Creating drivers directory...\n"));

        if (pCreateDirectoryW && !pCreateDirectoryW(driversDir.c_str(), nullptr))
        {
            DWORD error = pGetLastError();
            if (error != ERROR_ALREADY_EXISTS)
            {
                g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Failed to create drivers directory: %s\n"), GetErrorStringOut(error).c_str());
                return false;
            }
            else
            {
                g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Info: Drivers directory already exists\n"));
            }
        }
        else
        {
            g_log.Printf(LogLevel::Good, SKW(L"[i] files::CheckAndCopyDriverFile() Good: Drivers directory created\n"));
        }
    }
    else if (!(driversDirAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Path exists but is not a directory: %s\n"), driversDir.c_str());
        return false;
    }

    g_log.Printf(LogLevel::Info, SKW(L"[i] files::CheckAndCopyDriverFile() Copying driver file...\n"));

    if (!pCopyFileW(sourceDriverPath.c_str(), targetDriverPath.c_str(), FALSE))
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Failed to copy driver file: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    fileAttributes = pGetFileAttributesW(targetDriverPath.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES ||
        (fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::CheckAndCopyDriverFile() Error: Failed to verify copied file\n"));
        return false;
    }

    g_log.Printf(LogLevel::Good, SKW(L"[i] files::CheckAndCopyDriverFile() Good: Driver file successfully copied\n"));
    return true;
}


bool VerifyDriverFile(const std::wstring& driverFileName)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::VerifyDriverFile() Verifying driver file: %s\n"), driverFileName.c_str());

    if (driverFileName.empty())
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::VerifyDriverFile() Error: Driver file name is empty\n"));
        return false;
    }

    PFN_GetSystemDirectoryW pGetSystemDirectoryW = GetKernel32Function<PFN_GetSystemDirectoryW>(SKA("GetSystemDirectoryW"));
    PFN_GetFileAttributesW pGetFileAttributesW = GetKernel32Function<PFN_GetFileAttributesW>(SKA("GetFileAttributesW"));
    PFN_CreateFileW pCreateFileW = GetKernel32Function<PFN_CreateFileW>(SKA("CreateFileW"));
    PFN_CloseHandle pCloseHandle = GetKernel32Function<PFN_CloseHandle>(SKA("CloseHandle"));
    PFN_GetFileSize pGetFileSize = GetKernel32Function<PFN_GetFileSize>(SKA("GetFileSize"));

    if (!pGetSystemDirectoryW || !pGetFileAttributesW)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::VerifyDriverFile() Error: Failed to load required functions\n"));
        return false;
    }

    wchar_t systemDir[MAX_PATH] = { 0 };
    if (pGetSystemDirectoryW(systemDir, MAX_PATH) == 0)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::VerifyDriverFile() Error: Failed to get system directory\n"));
        return false;
    }

    std::wstring driverPath = std::wstring(systemDir) + L"\\drivers\\" + driverFileName;
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::VerifyDriverFile() Checking path: %s\n"), driverPath.c_str());

    DWORD attributes = pGetFileAttributesW(driverPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[i] files::VerifyDriverFile() Warning: Driver file not found\n"));
        return false;
    }

    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::VerifyDriverFile() Error: Path is a directory, not a file\n"));
        return false;
    }

   
    DWORD fileSize = 0;
    if (pCreateFileW && pCloseHandle && pGetFileSize)
    {
        HANDLE hFile = pCreateFileW(driverPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile != INVALID_HANDLE_VALUE)
        {
            fileSize = pGetFileSize(hFile, nullptr);
            pCloseHandle(hFile);
            g_log.Printf(LogLevel::Good, SKW(L"[i] files::VerifyDriverFile() Good: Driver file exists, size: %lu bytes\n"), fileSize);
        }
        else
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i] files::VerifyDriverFile() Info: Driver file exists (cannot read size)\n"));
        }
    }
    else
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] files::VerifyDriverFile() Info: Driver file exists\n"));
    }

    return true;
}


// Функция для проверки прав администратора
bool IsRunningAsAdmin()
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::IsRunningAsAdmin() Checking administrator privileges\n"));

    PFN_GetModuleHandleW pGetModuleHandleW = GetKernel32Function<PFN_GetModuleHandleW>(SKA("GetModuleHandleW"));
    PFN_GetProcAddress pGetProcAddress = GetKernel32Function<PFN_GetProcAddress>(SKA("GetProcAddress"));

    if (!pGetModuleHandleW || !pGetProcAddress)
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] files::IsRunningAsAdmin() Warning: Failed to get basic functions for admin check\n"));
        return false;
    }

    HMODULE hAdvapi32 = pGetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi32)
    {
        auto pLoadLibraryW = GetKernel32Function<HMODULE(WINAPI*)(LPCWSTR)>(SKA("LoadLibraryW"));
        if (pLoadLibraryW) hAdvapi32 = pLoadLibraryW(SKW(L"advapi32.dll"));
        if (!hAdvapi32){
            g_log.Printf(LogLevel::Warn, SKW(L"[!] files::IsRunningAsAdmin() Warning: Failed to load advapi32.dll\n"));
            return false;
        }
    }

    PFN_OpenProcessToken pOpenProcessToken = (PFN_OpenProcessToken)pGetProcAddress(hAdvapi32, SKA("OpenProcessToken"));
    PFN_GetTokenInformation pGetTokenInformation = (PFN_GetTokenInformation)pGetProcAddress(hAdvapi32, SKA("GetTokenInformation"));
    PFN_CloseHandle pCloseHandle = GetKernel32Function<PFN_CloseHandle>(SKA("CloseHandle"));
    PFN_GetCurrentProcess pGetCurrentProcess = GetKernel32Function<PFN_GetCurrentProcess>(SKA("GetCurrentProcess"));

    if (!pOpenProcessToken || !pGetTokenInformation || !pCloseHandle || !pGetCurrentProcess)
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] files::IsRunningAsAdmin() Warning: Failed to get admin check functions\n"));
        return false;
    }

    HANDLE hToken = nullptr;
    if (!pOpenProcessToken(pGetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] files::IsRunningAsAdmin() Warning: Failed to open process token\n"));
        return false;
    }

    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);

    BOOL result = pGetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size);
    pCloseHandle(hToken);

    if (result && elevation.TokenIsElevated)
    {
        g_log.Printf(LogLevel::Good, SKW(L"[i] files::IsRunningAsAdmin() Good: Running with administrator privileges\n"));
        return true;
    }
    else
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] files::IsRunningAsAdmin() Warning: Not running as administrator\n"));
        return false;
    }
}

void ShowMessage(const std::wstring& title, const std::wstring& message)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::ShowMessage() Showing message: %s - %s\n"), title.c_str(), message.c_str());
}


// Функция удаления драйвера
bool DeleteDriverFile(const std::wstring& driverFileName)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::DeleteDriverFile() Deleting driver file: %s\n"), driverFileName.c_str());

    if (driverFileName.empty())
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::DeleteDriverFile() Error: Driver file name is empty\n"));
        return false;
    }

    PFN_GetSystemDirectoryW pGetSystemDirectoryW = GetKernel32Function<PFN_GetSystemDirectoryW>(SKA("GetSystemDirectoryW"));
    PFN_DeleteFileW pDeleteFileW = GetKernel32Function<PFN_DeleteFileW>(SKA("DeleteFileW"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pGetSystemDirectoryW || !pDeleteFileW || !pGetLastError)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::DeleteDriverFile() Error: Failed to load required functions\n"));
        return false;
    }

    wchar_t systemDir[MAX_PATH] = { 0 };
    if (pGetSystemDirectoryW(systemDir, MAX_PATH) == 0)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] files::DeleteDriverFile() Error: Failed to get system directory: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    std::wstring driverPath = std::wstring(systemDir) + SKW(L"\\drivers\\") + driverFileName;
    g_log.Printf(LogLevel::Info, SKW(L"[i] files::DeleteDriverFile() Target path: %s\n"), driverPath.c_str());

    if (pDeleteFileW(driverPath.c_str()))
    {
        g_log.Printf(LogLevel::Good, SKW(L"[i] files::DeleteDriverFile() Good: Driver file deleted successfully\n"));
        return true;
    }
    else
    {
        DWORD error = pGetLastError();
        if (error == ERROR_FILE_NOT_FOUND)
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i] files::DeleteDriverFile() Info: Driver file not found (already deleted)\n"));
            return true;
        }

        g_log.Printf(LogLevel::Error, SKW(L"[!] files::DeleteDriverFile() Error: Failed to delete driver file: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }
}

