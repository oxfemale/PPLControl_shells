#pragma once
#include <windows.h>

namespace pids
{
    bool IsCurrentProcess64Bit();
}

namespace parents
{
    bool IsCurrentProcess64Bit();
    bool PrintParentProcessInfo(DWORD pid);
}

// Основная функция получения PID текущего процесса
DWORD GetCurrentProcessID();

// Функция получения PID с детальным выводом
void PrintProcessInfo();

void DemonstratePIDUsage();
