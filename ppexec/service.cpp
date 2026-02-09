#include <windows.h>
#include <stdio.h>
#include <string>
#include"service.h"
#include "crypt.h"
#include "dynapi.h"
#include "Controller.h"

//HMODULE hAdvapi32 = nullptr;

using PFN_QueryServiceStatusEx = BOOL(WINAPI*)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
using PFN_GetTickCount64 = ULONGLONG(WINAPI*)();
using PFN_Sleep = VOID(WINAPI*)(DWORD);
typedef HMODULE(WINAPI* PFN_GetModuleHandleW)(LPCWSTR);
typedef FARPROC(WINAPI* PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef DWORD(WINAPI* PFN_GetLastError)();
typedef DWORD(WINAPI* PFN_FormatMessageW)(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*);
typedef BOOL(WINAPI* PFN_LocalFree)(HLOCAL);
typedef BOOL(WINAPI* PFN_CloseHandle)(HANDLE);
typedef BOOL(WINAPI* PFN_DeleteFileW)(LPCWSTR);
typedef DWORD(WINAPI* PFN_GetFileAttributesW)(LPCWSTR);
typedef BOOL(WINAPI* PFN_MoveFileExW)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE(WINAPI* PFN_OpenSCManagerW)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE(WINAPI* PFN_OpenServiceW)(SC_HANDLE, LPCWSTR, DWORD);
typedef BOOL(WINAPI* PFN_CloseServiceHandle)(SC_HANDLE);
typedef BOOL(WINAPI* PFN_QueryServiceConfigW)(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
typedef BOOL(WINAPI* PFN_DeleteService)(SC_HANDLE);
typedef BOOL(WINAPI* PFN_ControlService)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
typedef BOOL(WINAPI* PFN_QueryServiceStatus)(SC_HANDLE, LPSERVICE_STATUS);
typedef BOOL(WINAPI* PFN_ChangeServiceConfigW)(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL(WINAPI* PFN_StartServiceW)(SC_HANDLE, DWORD, LPCWSTR*);

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
            g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetKernel32Function() Error: Failed to get kernel32.dll handle\n"));
            return nullptr;
        }

        pGetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel32, SKA("GetProcAddress"));
        if (!pGetProcAddress)
        {
            g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetKernel32Function() Error: Failed to get GetProcAddress function\n"));
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
			g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetAdvapi32Function() Failed to get GetModuleHandleW function\n"));
            return nullptr;
        }

        hAdvapi32 = pGetModuleHandleW(SKW(L"advapi32.dll"));
        if (!hAdvapi32)
        {

            auto pLoadLibraryW = GetKernel32Function<HMODULE(WINAPI*)(LPCWSTR)>("LoadLibraryW");
            if (pLoadLibraryW) hAdvapi32 = pLoadLibraryW(L"advapi32.dll");
            if (!hAdvapi32) {
                g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetAdvapi32Function() Failed to get advapi32.dll handle\n"));
                return nullptr;
            }
        }

        pGetProcAddress = GetKernel32Function<PFN_GetProcAddress>("GetProcAddress");
        if (!pGetProcAddress) {
			g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetAdvapi32Function() Failed to get GetProcAddress function\n"));
            return nullptr;
        }
    }

    return (FuncType)pGetProcAddress(hAdvapi32, funcName);
}

// Функция для получения текстового описания ошибки
std::wstring GetErrorStringOut(DWORD errorCode)
{
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));
    PFN_FormatMessageW pFormatMessageW = GetKernel32Function<PFN_FormatMessageW>(SKA("FormatMessageW"));
    PFN_LocalFree pLocalFree = GetKernel32Function<PFN_LocalFree>(SKA("LocalFree"));

    if (!pGetLastError || !pFormatMessageW || !pLocalFree)
        return SKW(L"Failed to get error message functions");

    if (errorCode == 0) errorCode = pGetLastError();

    wchar_t* buffer = nullptr;
    DWORD size = pFormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errorCode, 0, (LPWSTR)&buffer, 0, nullptr);

    std::wstring result;
    if (size && buffer)
    {
        result = std::wstring(buffer, size);
        // Убираем переводы строк
        while (!result.empty() && (result.back() == L'\n' || result.back() == L'\r'))
            result.pop_back();
        pLocalFree(buffer);
    }
    else
    {
        wchar_t errorCodeStr[32];
        swprintf_s(errorCodeStr, SKW(L"Unknown error (%lu)"), errorCode);
        result = errorCodeStr;
    }

    return result;
}


// Функция для остановки сервиса
bool StopService(const std::wstring& serviceName)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] service::StopService() Stopping service: %s\n"), serviceName.c_str());

    PFN_OpenSCManagerW pOpenSCManagerW = GetAdvapi32Function<PFN_OpenSCManagerW>(SKA("OpenSCManagerW"));
    PFN_OpenServiceW pOpenServiceW = GetAdvapi32Function<PFN_OpenServiceW>(SKA("OpenServiceW"));
    PFN_CloseServiceHandle pCloseServiceHandle = GetAdvapi32Function<PFN_CloseServiceHandle>(SKA("CloseServiceHandle"));
    PFN_ControlService pControlService = GetAdvapi32Function<PFN_ControlService>(SKA("ControlService"));
    PFN_QueryServiceStatus pQueryServiceStatus = GetAdvapi32Function<PFN_QueryServiceStatus>(SKA("QueryServiceStatus"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pOpenSCManagerW || !pOpenServiceW || !pCloseServiceHandle ||
        !pControlService || !pQueryServiceStatus || !pGetLastError)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::StopService() Error: Failed to load service control functions\n"));
        return false;
    }

    SC_HANDLE scm = pOpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[*] service::StopService() Error: Failed to open service manager: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    SC_HANDLE service = pOpenServiceW(scm, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service)
    {
        DWORD error = pGetLastError();

        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i] service::StopService() Info: Service does not exist: %s\n"), serviceName.c_str());
            pCloseServiceHandle(scm);
            return true;
        }

        g_log.Printf(LogLevel::Error, (L"[!] service::StopService() Error: Failed to open service: %s\n"), GetErrorStringOut(error).c_str());
        pCloseServiceHandle(scm);
        return false;
    }


    SERVICE_STATUS serviceStatus;
    if (!pQueryServiceStatus(service, &serviceStatus))
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Warn, (L"[!] service::StopService() Warning: Failed to query service status: %s\n"), GetErrorStringOut(error).c_str());
    }
    else if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] service::StopService() Info: Service is already stopped\n"));
        pCloseServiceHandle(service);
        pCloseServiceHandle(scm);
        return true;
    }


    SERVICE_STATUS stopStatus;
    if (!pControlService(service, SERVICE_CONTROL_STOP, &stopStatus))
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, (L"[!] service::StopService() Error: Failed to stop service: %s\n"), GetErrorStringOut(error).c_str());
        pCloseServiceHandle(service);
        pCloseServiceHandle(scm);
        return false;
    }

    g_log.Printf(LogLevel::Info, SKW(L"[i] service::StopService() Service stop requested\n"));

    for (int i = 0; i < 30; i++)
    {
        if (!pQueryServiceStatus(service, &serviceStatus))
            break;

        if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
        {
            g_log.Printf(LogLevel::Good, SKW(L"[i] service::StopService() Good: Service stopped successfully\n"));
            break;
        }

        if (i == 29)
        g_log.Printf(LogLevel::Warn, SKW(L"[i] service::StopService() Warning: Service may still be stopping\n"));
        else
            Sleep(1000);
    }

    pCloseServiceHandle(service);
    pCloseServiceHandle(scm);
    return true;
}

// Функция для получения пути к файлу драйвера из сервиса
std::wstring GetServiceDriverPath(const std::wstring& serviceName)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] service::GetServiceDriverPath() Getting driver path for service: %s\n"), serviceName.c_str());

    PFN_OpenSCManagerW pOpenSCManagerW = GetAdvapi32Function<PFN_OpenSCManagerW>(SKA("OpenSCManagerW"));
    PFN_OpenServiceW pOpenServiceW = GetAdvapi32Function<PFN_OpenServiceW>(SKA("OpenServiceW"));
    PFN_CloseServiceHandle pCloseServiceHandle = GetAdvapi32Function<PFN_CloseServiceHandle>(SKA("CloseServiceHandle"));
    PFN_QueryServiceConfigW pQueryServiceConfigW = GetAdvapi32Function<PFN_QueryServiceConfigW>(SKA("QueryServiceConfigW"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));
    PFN_LocalFree pLocalFree = GetKernel32Function<PFN_LocalFree>(SKA("LocalFree"));

    if (!pOpenSCManagerW || !pOpenServiceW || !pCloseServiceHandle ||
        !pQueryServiceConfigW || !pGetLastError || !pLocalFree)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetServiceDriverPath() Error: Failed to load service functions\n"));
        return L"";
    }

    SC_HANDLE scm = pOpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetServiceDriverPath() Error: Failed to open service manager: %s\n"), GetErrorStringOut(error).c_str());
        return L"";
    }

    SC_HANDLE service = pOpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_CONFIG);
    if (!service)
    {
        DWORD error = pGetLastError();

        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i] service::GetServiceDriverPath() Info: Service does not exist: %s\n"), serviceName.c_str());
            pCloseServiceHandle(scm);
            return L"";
        }

        g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetServiceDriverPath() Error: Failed to open service: %s\n"), GetErrorStringOut(error).c_str());
        pCloseServiceHandle(scm);
        return L"";
    }

    DWORD bytesNeeded = 0;
    pQueryServiceConfigW(service, nullptr, 0, &bytesNeeded);

    if (bytesNeeded == 0)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetServiceDriverPath() Error: Failed to get service config size: %s\n"), GetErrorStringOut(error).c_str());
        pCloseServiceHandle(service);
        pCloseServiceHandle(scm);
        return L"";
    }

    QUERY_SERVICE_CONFIGW* serviceConfig = (QUERY_SERVICE_CONFIGW*)LocalAlloc(LPTR, bytesNeeded);
    if (!serviceConfig)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetServiceDriverPath() Error: Failed to allocate memory for service config\n"));
        pCloseServiceHandle(service);
        pCloseServiceHandle(scm);
        return L"";
    }

    if (!pQueryServiceConfigW(service, serviceConfig, bytesNeeded, &bytesNeeded))
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::GetServiceDriverPath() Error: Failed to query service config: %s\n"), GetErrorStringOut(error).c_str());
        pLocalFree(serviceConfig);
        pCloseServiceHandle(service);
        pCloseServiceHandle(scm);
        return L"";
    }

    std::wstring driverPath;
    if (serviceConfig->lpBinaryPathName)
    {
        driverPath = serviceConfig->lpBinaryPathName;

        if (driverPath.length() >= 2 &&
            driverPath[0] == L'"' &&
            driverPath[driverPath.length() - 1] == L'"')
        {
            driverPath = driverPath.substr(1, driverPath.length() - 2);
        }

        g_log.Printf(LogLevel::Info, SKW(L"[i] service::GetServiceDriverPath() Info: Service driver path: %s\n"), driverPath.c_str());
    }
    else
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] service::GetServiceDriverPath() Warning: Service has no binary path\n"));
    }


    pLocalFree(serviceConfig);
    pCloseServiceHandle(service);
    pCloseServiceHandle(scm);

    return driverPath;
}

// Функция для удаления файла драйвера
bool DeleteDriverFileNow(const std::wstring& driverPath)
{
    if (driverPath.empty())
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteDriverFileNow() Info: No driver file to delete\n"));
        return true;
    }

    g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteDriverFileNow() Deleting driver file: %s\n"), driverPath.c_str());

    PFN_DeleteFileW pDeleteFileW = GetKernel32Function<PFN_DeleteFileW>(SKA("DeleteFileW"));
    PFN_GetFileAttributesW pGetFileAttributesW = GetKernel32Function<PFN_GetFileAttributesW>(SKA("GetFileAttributesW"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));
    PFN_MoveFileExW pMoveFileExW = GetKernel32Function<PFN_MoveFileExW>(SKA("MoveFileExW"));

    if (!pDeleteFileW || !pGetFileAttributesW || !pGetLastError)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteDriverFileNow() Error: Failed to load file functions\n"));
        return false;
    }

    DWORD fileAttributes = pGetFileAttributesW(driverPath.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES)
    {
        DWORD error = pGetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteDriverFileNow() Info: Driver file not found: %s\n"), driverPath.c_str());
            return true;
        }

        g_log.Printf(LogLevel::Warn, SKW(L"[!] service::DeleteDriverFileNow() Warning: Failed to check file attributes: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    if (fileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteDriverFileNow() Error: Path is a directory, not a file: %s\n"), driverPath.c_str());
        return false;
    }

    if (pDeleteFileW(driverPath.c_str()))
    {
        g_log.Printf(LogLevel::Good, SKW(L"[+] service::DeleteDriverFileNow() Good: Driver file deleted successfully\n"));
        return true;
    }

    DWORD error = pGetLastError();

    if (error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED)
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] service::DeleteDriverFileNow() Warning: File is in use, scheduling delete on reboot...\n"));

        if (pMoveFileExW)
        {
            if (pMoveFileExW(driverPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
            {
                g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteDriverFileNow() Info: File scheduled for deletion on next reboot\n"));
                return true;
            }
            else
            {
                DWORD moveError = pGetLastError();
                g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteDriverFileNow() Error: Failed to schedule delete on reboot: %s\n"), GetErrorStringOut(moveError).c_str());
            }
        }
    }

    g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteDriverFileNow() Error: Failed to delete driver file: %s\n"), GetErrorStringOut(error).c_str());
    return false;
}

// Функция для удаления сервиса
bool DeleteServiceByName(const std::wstring& serviceName)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteServiceByName() Deleting service: %s\n"), serviceName.c_str());

    // Загружаем необходимые функции
    PFN_OpenSCManagerW pOpenSCManagerW = GetAdvapi32Function<PFN_OpenSCManagerW>(SKA("OpenSCManagerW"));
    PFN_OpenServiceW pOpenServiceW = GetAdvapi32Function<PFN_OpenServiceW>(SKA("OpenServiceW"));
    PFN_CloseServiceHandle pCloseServiceHandle = GetAdvapi32Function<PFN_CloseServiceHandle>(SKA("CloseServiceHandle"));
    PFN_DeleteService pDeleteService = GetAdvapi32Function<PFN_DeleteService>(SKA("DeleteService"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pOpenSCManagerW || !pOpenServiceW || !pCloseServiceHandle ||
        !pDeleteService || !pGetLastError)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteServiceByName() Error: Failed to load service deletion functions\n"));
        return false;
    }

    SC_HANDLE scm = pOpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteServiceByName() Error: Failed to open service manager: %s\n"), GetErrorStringOut(error).c_str());
        return false;
    }

    SC_HANDLE service = pOpenServiceW(scm, serviceName.c_str(), DELETE);
    if (!service)
    {
        DWORD error = pGetLastError();

        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteServiceByName() Info: Service does not exist: %s\n"), serviceName.c_str());
            pCloseServiceHandle(scm);
            return true;
        }

        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteServiceByName() Error: Failed to open service for deletion: %s\n"), GetErrorStringOut(error).c_str());
        pCloseServiceHandle(scm);
        return false;
    }

    if (!pDeleteService(service))
    {
        DWORD error = pGetLastError();

        if (error == ERROR_SERVICE_MARKED_FOR_DELETE || error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteServiceByName() Info: Service already marked for deletion or does not exist\n"));
            pCloseServiceHandle(service);
            pCloseServiceHandle(scm);
            return true;
        }

        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteServiceByName() Error: Failed to delete service: %s\n"), GetErrorStringOut(error).c_str());
        pCloseServiceHandle(service);
        pCloseServiceHandle(scm);
        return false;
    }

    g_log.Printf(LogLevel::Good, SKW(L"[+] service::DeleteServiceByName() Good: Service deleted successfully: %s\n"), serviceName.c_str());

    pCloseServiceHandle(service);
    pCloseServiceHandle(scm);
    return true;
}


// Основная функция удаления сервиса и файла драйвера
bool DeleteServiceAndDriver(const std::wstring& serviceName, bool deleteDriverFile)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteServiceAndDriver() Deleting Service: %s\n"), serviceName.c_str());

    bool overallSuccess = true;

    std::wstring driverPath;
    if (deleteDriverFile)
    {
        driverPath = GetServiceDriverPath(serviceName);
        if (driverPath.empty())
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] service::DeleteServiceAndDriver() Warning: Could not get driver path for service\n"));
        }
    }

    if (!StopService(serviceName))
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] service::DeleteServiceAndDriver() Warning: Failed to stop service (continuing anyway)\n"));
        overallSuccess = false;
    }

    if (!DeleteServiceByName(serviceName))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DeleteServiceAndDriver() Error: Failed to delete service\n"));
        overallSuccess = false;
    }

    if (deleteDriverFile && !driverPath.empty())
    {
        if (!DeleteDriverFileNow(driverPath))
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] service::DeleteServiceAndDriver() Warning: Failed to delete driver file\n"));
            overallSuccess = false;
        }
    }
    else if (deleteDriverFile)
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] service::DeleteServiceAndDriver() Info: No driver file to delete (path not available)\n"));
    }

    if (overallSuccess)
        g_log.Printf(LogLevel::Good, SKW(L"[+] service::DeleteServiceAndDriver() Good: Service removal completed successfully\n"));
    else
        g_log.Printf(LogLevel::Warn, SKW(L"[!] service::DeleteServiceAndDriver() Warning: Service removal completed with warnings/errors\n"));


    return overallSuccess;
}


// Функция проверки существования сервиса
bool DoesServiceExist(const std::wstring& serviceName)
{
    PFN_OpenSCManagerW pOpenSCManagerW = GetAdvapi32Function<PFN_OpenSCManagerW>(SKA("OpenSCManagerW"));
    PFN_OpenServiceW pOpenServiceW = GetAdvapi32Function<PFN_OpenServiceW>(SKA("OpenServiceW"));
    PFN_CloseServiceHandle pCloseServiceHandle = GetAdvapi32Function<PFN_CloseServiceHandle>(SKA("CloseServiceHandle"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pOpenSCManagerW ) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoesServiceExist() Failed load api OpenSCManagerW \n"));
        return false;
    }
    if (!pOpenServiceW) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoesServiceExist() Failed load api  OpenServiceW \n"));
        return false;
    }
    if (!pCloseServiceHandle) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoesServiceExist() Failed load api CloseServiceHandle\n"));
        return false;
    }
    if (!pGetLastError) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoesServiceExist() Failed load api GetLastError\n"));
        return false;
    }

    SC_HANDLE scm = pOpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
		DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoesServiceExist() Failed OpenSCManagerW(SC_MANAGER_CONNECT) Service: %ws, %ws\n"), serviceName.c_str(), GetErrorStringOut(error).c_str());
        return false;
    }

    SC_HANDLE service = pOpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!service)
    {
        DWORD error = pGetLastError();
        pCloseServiceHandle(scm);
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoesServiceExist() Failed OpenServiceW(SERVICE_QUERY_STATUS) Service: %ws, %ws\n"), serviceName.c_str(), GetErrorStringOut(error).c_str());
        return (error != ERROR_SERVICE_DOES_NOT_EXIST);
    }

    pCloseServiceHandle(service);
    pCloseServiceHandle(scm);
    return true;
}

// Функция запуска сервиса
// Возвращаемые коды:
// 1 - OpenSCManagerW failed
// 2 - OpenServiceW failed
// 3 - CloseServiceHandle failed
// 4 - StartServiceW failed
// 5 - Service started successfully or already running
DWORD DoStartService(const std::wstring& serviceName)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] service::DoStartService() Starting service: %s\n"), serviceName.c_str());

    PFN_OpenSCManagerW pOpenSCManagerW = GetAdvapi32Function<PFN_OpenSCManagerW>(SKA("OpenSCManagerW"));
    PFN_OpenServiceW pOpenServiceW = GetAdvapi32Function<PFN_OpenServiceW>(SKA("OpenServiceW"));
    PFN_CloseServiceHandle pCloseServiceHandle = GetAdvapi32Function<PFN_CloseServiceHandle>(SKA("CloseServiceHandle"));
    PFN_StartServiceW pStartServiceW = GetAdvapi32Function<PFN_StartServiceW>(SKA("StartServiceW"));
    PFN_GetLastError pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pOpenSCManagerW || !pOpenServiceW || !pCloseServiceHandle || !pStartServiceW || !pGetLastError)
    {
		g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoStartService() Error: Failed to load service control functions\n"));
        return 1;
    }

    SC_HANDLE scm = pOpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoStartService() Error: Failed to open service manager\n"));
        return 2;
    }

    SC_HANDLE service = pOpenServiceW(scm, serviceName.c_str(), SERVICE_START);
    if (!service)
    {
        pCloseServiceHandle(scm);
		g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoStartService() Error: Failed to open service: %s\n"), serviceName.c_str());
        return 3;
    }

    // Пытаемся запустить сервис
    BOOL result = pStartServiceW(service, 0, nullptr);
    DWORD error = pGetLastError();

    pCloseServiceHandle(service);
    pCloseServiceHandle(scm);

    if (!result && error != ERROR_SERVICE_ALREADY_RUNNING)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::DoStartService() Error: Failed to start service: %s\n"), GetErrorStringOut(error).c_str());
        return 4;
    }

    if (error == ERROR_SERVICE_ALREADY_RUNNING)
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] service::DoStartService() Info: Service is already running\n"));
    }
    else
    {
        g_log.Printf(LogLevel::Good, SKW(L"[+] service::DoStartService() Good: Service started successfully\n"));
    }

    return 5;
}

static DWORD WaitForServiceState(
    SC_HANDLE svc,
    DWORD desiredState,
    DWORD timeoutMs,
    PFN_QueryServiceStatusEx pQueryServiceStatusEx,
    PFN_GetTickCount64 pGetTickCount64,
    PFN_Sleep pSleep
)
{
    if (!pQueryServiceStatusEx || !pGetTickCount64 || !pSleep)
    {
		g_log.Printf(LogLevel::Error, SKW(L"[!] service::WaitForServiceState() Error: Invalid function pointers provided\n"));
        return ERROR_PROC_NOT_FOUND;
    }

    ULONGLONG start = pGetTickCount64();
    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;

    for (;;)
    {
        if (!pQueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp),
            sizeof(ssp),
            &bytesNeeded))
        {
			g_log.Printf(LogLevel::Error, SKW(L"[!] service::WaitForServiceState() Error: Failed to query service status\n"));
            return GetLastError();
        }

        if (ssp.dwCurrentState == desiredState)
        {
			g_log.Printf(LogLevel::Info, SKW(L"[i] service::WaitForServiceState() Info: Service reached desired state: %lu\n"), desiredState);
            return ERROR_SUCCESS;
        }

        if (timeoutMs != INFINITE)
        {
            ULONGLONG now = pGetTickCount64();
            ULONGLONG elapsed = now - start;
            if (elapsed >= timeoutMs)
            {
				g_log.Printf(LogLevel::Error, SKW(L"[!] service::WaitForServiceState() Error: Timeout waiting for service to reach desired state: %lu\n"), desiredState);
                return ERROR_TIMEOUT;
            }
        }

        DWORD waitHint = ssp.dwWaitHint;
        DWORD sleepMs = 200;
        if (waitHint >= 1000)
        {
            sleepMs = waitHint / 10;
            if (sleepMs < 200) sleepMs = 200;
            if (sleepMs > 1000) sleepMs = 1000;
        }

        pSleep(sleepMs);
    }
}

// Возврат: ERROR_SUCCESS (0) если ок, иначе Win32 error code
DWORD RestartService(const std::wstring& serviceName, DWORD timeoutMs)
{
    g_log.Printf(LogLevel::Info, SKW(L"[i] service::RestartService() Restarting service: %s\n"), serviceName.c_str());

    auto pOpenSCManagerW = GetAdvapi32Function<PFN_OpenSCManagerW>(SKA("OpenSCManagerW"));
    auto pOpenServiceW = GetAdvapi32Function<PFN_OpenServiceW>(SKA("OpenServiceW"));
    auto pCloseServiceHandle = GetAdvapi32Function<PFN_CloseServiceHandle>(SKA("CloseServiceHandle"));
    auto pQueryServiceStatusEx = GetAdvapi32Function<PFN_QueryServiceStatusEx>(SKA("QueryServiceStatusEx"));
    auto pControlService = GetAdvapi32Function<PFN_ControlService>(SKA("ControlService"));
    auto pStartServiceW = GetAdvapi32Function<PFN_StartServiceW>(SKA("StartServiceW"));

    auto pGetTickCount64 = GetKernel32Function<PFN_GetTickCount64>(SKA("GetTickCount64"));
    auto pSleep = GetKernel32Function<PFN_Sleep>(SKA("Sleep"));
    auto pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pOpenSCManagerW || !pOpenServiceW || !pCloseServiceHandle ||
        !pQueryServiceStatusEx || !pControlService || !pStartServiceW ||
        !pGetTickCount64 || !pSleep || !pGetLastError)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Failed to load required functions\n"));
        return ERROR_PROC_NOT_FOUND;
    }

    SC_HANDLE scm = pOpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        DWORD error = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Failed to open service manager: %s\n"), GetErrorStringOut(error).c_str());
        return error;
    }

    SC_HANDLE svc = pOpenServiceW(
        scm,
        serviceName.c_str(),
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP
    );

    if (!svc)
    {
        DWORD e = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Failed to open service: %s\n"), GetErrorStringOut(e).c_str());
        pCloseServiceHandle(scm);
        return e;
    }

    DWORD ret = ERROR_SUCCESS;

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;
    if (!pQueryServiceStatusEx(
        svc,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp),
        sizeof(ssp),
        &bytesNeeded))
    {
        ret = pGetLastError();
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Failed to query service status: %s\n"), GetErrorStringOut(ret).c_str());
        pCloseServiceHandle(svc);
        pCloseServiceHandle(scm);
        return ret;
    }

    if (ssp.dwCurrentState != SERVICE_STOPPED)
    {
        if ((ssp.dwControlsAccepted & SERVICE_ACCEPT_STOP) == 0)
        {
            ret = ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
            g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Service cannot accept stop control\n"));
            pCloseServiceHandle(svc);
            pCloseServiceHandle(scm);
            return ret;
        }

        g_log.Printf(LogLevel::Info, SKW(L"[i] service::RestartService() Stopping service...\n"));
        SERVICE_STATUS ss{};
        if (!pControlService(svc, SERVICE_CONTROL_STOP, &ss))
        {
            DWORD e = pGetLastError();
            if (e != ERROR_SERVICE_NOT_ACTIVE)
            {
                g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Failed to stop service: %s\n"), GetErrorStringOut(e).c_str());
                pCloseServiceHandle(svc);
                pCloseServiceHandle(scm);
                return e;
            }
        }

        ret = WaitForServiceState(svc, SERVICE_STOPPED, timeoutMs, pQueryServiceStatusEx, pGetTickCount64, pSleep);
        if (ret != ERROR_SUCCESS)
        {
            g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Timeout waiting for service to stop: %s\n"), GetErrorStringOut(ret).c_str());
            pCloseServiceHandle(svc);
            pCloseServiceHandle(scm);
            return ret;
        }
        g_log.Printf(LogLevel::Good, SKW(L"[+] service::RestartService() Service stopped successfully\n"));
    }
    else
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] service::RestartService() Service is already stopped\n"));
    }

    g_log.Printf(LogLevel::Info, SKW(L"[i] service::RestartService() Starting service...\n"));
    if (!pStartServiceW(svc, 0, nullptr))
    {
        DWORD e = pGetLastError();
        // если уже запущен (редко после stop, но пусть будет)
        if (e != ERROR_SERVICE_ALREADY_RUNNING)
        {
            g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Failed to start service: %s\n"), GetErrorStringOut(e).c_str());
            pCloseServiceHandle(svc);
            pCloseServiceHandle(scm);
            return e;
        }
        g_log.Printf(LogLevel::Info, SKW(L"[i] service::RestartService() Service already running\n"));
    }

    ret = WaitForServiceState(svc, SERVICE_RUNNING, timeoutMs, pQueryServiceStatusEx, pGetTickCount64, pSleep);
    if (ret != ERROR_SUCCESS)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] service::RestartService() Error: Timeout waiting for service to start: %s\n"), GetErrorStringOut(ret).c_str());
    }
    else
    {
        g_log.Printf(LogLevel::Good, SKW(L"[+] service::RestartService() Service started successfully\n"));
    }

    pCloseServiceHandle(svc);
    pCloseServiceHandle(scm);
    return ret;
}


// Возврат:
//  - ERROR_SUCCESS (0)             => сервис запущен (SERVICE_RUNNING)
//  - ERROR_SERVICE_NOT_ACTIVE (1062)=> сервис НЕ запущен (STOPPED)
//  - иначе Win32 error code         => ошибки доступа/не найден и т.п.
DWORD IsServiceRunning(const std::wstring& serviceName)
{
    auto pOpenSCManagerW = GetAdvapi32Function<PFN_OpenSCManagerW>(SKA("OpenSCManagerW"));
    auto pOpenServiceW = GetAdvapi32Function<PFN_OpenServiceW>(SKA("OpenServiceW"));
    auto pCloseServiceHandle = GetAdvapi32Function<PFN_CloseServiceHandle>(SKA("CloseServiceHandle"));
    auto pQueryServiceStatusEx = GetAdvapi32Function<PFN_QueryServiceStatusEx>(SKA("QueryServiceStatusEx"));
    auto pGetLastError = GetKernel32Function<PFN_GetLastError>(SKA("GetLastError"));

    if (!pOpenSCManagerW || !pOpenServiceW || !pCloseServiceHandle || !pQueryServiceStatusEx || !pGetLastError)
    {
		g_log.Printf(LogLevel::Error, SKW(L"[!] service::IsServiceRunning() Error: Failed to load required functions\n"));
        return ERROR_PROC_NOT_FOUND;
    }

    SC_HANDLE scm = pOpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
		g_log.Printf(LogLevel::Error, SKW(L"[!] service::IsServiceRunning() Error: Failed to open service manager: %s\n"), GetErrorStringOut(pGetLastError()).c_str());
        return pGetLastError();
    }

    SC_HANDLE svc = pOpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!svc)
    {
        DWORD e = pGetLastError();
        pCloseServiceHandle(scm);
		g_log.Printf(LogLevel::Error, SKW(L"[!] service::IsServiceRunning() Error: Failed to open service: %s\n"), GetErrorStringOut(e).c_str());
        return e;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;

    if (!pQueryServiceStatusEx(
        svc,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp),
        sizeof(ssp),
        &bytesNeeded))
    {
        DWORD e = pGetLastError();
        pCloseServiceHandle(svc);
        pCloseServiceHandle(scm);
		g_log.Printf(LogLevel::Error, SKW(L"[!] service::IsServiceRunning() Error: Failed to query service status: %s\n"), GetErrorStringOut(e).c_str());
        return e;
    }

    pCloseServiceHandle(svc);
    pCloseServiceHandle(scm);

    if (ssp.dwCurrentState == SERVICE_RUNNING)
    {
		g_log.Printf(LogLevel::Info, SKW(L"[i] service::IsServiceRunning() Info: Service is running\n"));
        return ERROR_SUCCESS;
    }


    if (ssp.dwCurrentState == SERVICE_STOPPED)
    {
		g_log.Printf(LogLevel::Info, SKW(L"[i] service::IsServiceRunning() Info: Service is stopped\n"));
        return ERROR_SERVICE_NOT_ACTIVE;
    }

	g_log.Printf(LogLevel::Info, SKW(L"[i] service::IsServiceRunning() Info: Service is in state %u\n"), ssp.dwCurrentState);
    return ERROR_SERVICE_REQUEST_TIMEOUT;
}

