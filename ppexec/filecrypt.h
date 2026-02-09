#pragma once
#pragma once
#include <windows.h>
#include <string>

// Расшифровать "зашифрованный файл" (в нашем формате FCRY) прямо из памяти и сохранить на диск.
// outPath — полный путь файла назначения.
// Возвращает true если успешно.
bool FcryDecryptBufferToFile(const BYTE* encryptedBlob, DWORD encryptedBlobSize, const std::wstring& outPath);

// (опционально) удобно для лога
std::wstring Win32ErrorToStringW(DWORD err);
