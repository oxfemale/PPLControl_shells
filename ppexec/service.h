#include<windows.h>

bool DeleteServiceAndDriver(const std::wstring& serviceName, bool deleteDriverFile = true);

// Функция для остановки сервиса
bool StopService(const std::wstring& serviceName);

// Функция проверки существования сервиса
bool DoesServiceExist(const std::wstring& serviceName);

// Функция запуска сервиса
// Возвращаемые коды:
// 1 - OpenSCManagerW failed
// 2 - OpenServiceW failed
// 3 - CloseServiceHandle failed
// 4 - StartServiceW failed
// 5 - Service started successfully or already running
DWORD DoStartService(const std::wstring& serviceName);


// Возврат:
//  - ERROR_SUCCESS (0)             => сервис запущен (SERVICE_RUNNING)
//  - ERROR_SERVICE_NOT_ACTIVE (1062)=> сервис НЕ запущен (STOPPED)
//  - иначе Win32 error code         => ошибки доступа/не найден и т.п.
DWORD IsServiceRunning(const std::wstring& serviceName);

// Возврат: ERROR_SUCCESS (0) если ок, иначе Win32 error code
DWORD RestartService(const std::wstring& serviceName, DWORD timeoutMs /*например 30000*/);

// Функция для получения текстового описания ошибки
std::wstring GetErrorStringOut(DWORD errorCode = 0);
