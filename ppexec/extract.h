#pragma once
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <stdio.h>
#include "crypt.h"
#include "Controller.h"

//const std::wstring svcName = L"jango.service";
//const std::wstring outName = L"NeacSafe64.inf";
//const WORD RES_ID_TESTDAT = 101;
//const std::wstring outName = L"NeacSafe64.sys";
//const WORD RES_ID_TESTDAT = 102;
DWORD extract(WORD RES_ID_TESTDAT, std::wstring outName, std::wstring svcName);

// Возвращает true если процесс создан, и (опционально) отдаёт PID.
bool RunInstallDriver(DWORD* outPid /*=nullptr*/);

// Install INF section "DefaultInstall" using SetupAPI function SetupInstallFromInfSectionW
bool InstallInfSection_DefaultInstall_132(const std::wstring& infPath);

// Get directory of current exe (with trailing backslash removed)
std::wstring GetCurrentExeDirectory();

// Check if a service exists (read-only)
bool ServiceExists(const std::wstring& svcName);
