#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

// Проверка и копирование драйвера
bool CheckAndCopyDriverFile(const std::wstring& driverFileName);

// Проверка прав администратора
bool IsRunningAsAdmin();

// Функция удаления драйвера
bool DeleteDriverFile(const std::wstring& driverFileName);

// Функция проверки существования драйвера
bool VerifyDriverFile(const std::wstring& driverFileName);
