#pragma once
#include <windows.h>

namespace dynapi
{
    // Call once at startup (or rely on EnsureInitialized() before usage)
    bool Initialize();
    void Uninitialize(); // optional (clears pointers)
    bool IsInitialized();
    bool EnsureInitialized(); // Initialize() if not yet done

    // --- Function pointer typedefs ---
    using PFN_HeapReAlloc = LPVOID(WINAPI*)(HANDLE, DWORD, LPVOID, SIZE_T);
    using PFN_HeapFree = BOOL(WINAPI*)(HANDLE, DWORD, LPVOID);
    using PFN_GetProcessHeap = HANDLE(WINAPI*)(VOID);
    using PFN_HeapAlloc = LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T);

    using PFN_LoadLibraryW = HMODULE(WINAPI*)(LPCWSTR);
    using PFN_FreeLibrary = BOOL(WINAPI*)(HMODULE);

    using PFN_CloseHandle = BOOL(WINAPI*)(HANDLE);

    using PFN_CreateFileW = HANDLE(WINAPI*)(
        LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

    using PFN_DeviceIoControl = BOOL(WINAPI*)(
        HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

    using PFN_GetStdHandle = HANDLE(WINAPI*)(DWORD);
    using PFN_GetConsoleMode = BOOL(WINAPI*)(HANDLE, LPDWORD);
    using PFN_SetConsoleMode = BOOL(WINAPI*)(HANDLE, DWORD);

    using PFN_GetModuleFileNameW = DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD);

    using PFN_FormatMessageW = DWORD(WINAPI*)(
        DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*);

    using PFN_LocalFree = HLOCAL(WINAPI*)(HLOCAL);

    using PFN_GetFileSizeEx = BOOL(WINAPI*)(HANDLE, PLARGE_INTEGER);

    using PFN_WriteFile = BOOL(WINAPI*)(
        HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

    using PFN_OutputDebugStringW = VOID(WINAPI*)(LPCWSTR);

    using PFN_GetConsoleScreenBufferInfo = BOOL(WINAPI*)(HANDLE, PCONSOLE_SCREEN_BUFFER_INFO);

    using PFN_SetConsoleTextAttribute = BOOL(WINAPI*)(HANDLE, WORD);

    using PFN_WriteConsoleW = BOOL(WINAPI*)(
        HANDLE, const VOID*, DWORD, LPDWORD, LPVOID);

    // --- Extern pointers (defined in dynapi.cpp) ---
    extern PFN_HeapReAlloc                 pHeapReAlloc;
    extern PFN_HeapFree                    pHeapFree;
    extern PFN_GetProcessHeap              pGetProcessHeap;
    extern PFN_HeapAlloc                   pHeapAlloc;
    extern PFN_LoadLibraryW                pLoadLibraryW;
    extern PFN_FreeLibrary                 pFreeLibrary;
    extern PFN_CloseHandle                 pCloseHandle;
    extern PFN_CreateFileW                 pCreateFileW;
    extern PFN_DeviceIoControl             pDeviceIoControl;
    extern PFN_GetStdHandle                pGetStdHandle;
    extern PFN_GetConsoleMode              pGetConsoleMode;
    extern PFN_SetConsoleMode              pSetConsoleMode;
    extern PFN_GetModuleFileNameW          pGetModuleFileNameW;
    extern PFN_FormatMessageW              pFormatMessageW;
    extern PFN_LocalFree                   pLocalFree;
    extern PFN_GetFileSizeEx               pGetFileSizeEx;
    extern PFN_WriteFile                   pWriteFile;
    extern PFN_OutputDebugStringW          pOutputDebugStringW;
    extern PFN_GetConsoleScreenBufferInfo  pGetConsoleScreenBufferInfo;
    extern PFN_SetConsoleTextAttribute     pSetConsoleTextAttribute;
    extern PFN_WriteConsoleW               pWriteConsoleW;

} // namespace dynapi


// -----------------------------------------------------------------------------
// OPTIONAL: if you want to call WinAPI names directly (HeapAlloc(...), etc.)
// define DYNAPI_REPLACE_WINAPI before including this header in ALL .cpp files.
// Example: add /D DYNAPI_REPLACE_WINAPI in Project -> C/C++ -> Preprocessor.
// -----------------------------------------------------------------------------
#ifdef DYNAPI_REPLACE_WINAPI
#define HeapReAlloc                 dynapi::pHeapReAlloc
#define HeapFree                    dynapi::pHeapFree
#define GetProcessHeap              dynapi::pGetProcessHeap
#define HeapAlloc                   dynapi::pHeapAlloc
#define LoadLibraryW                dynapi::pLoadLibraryW
#define FreeLibrary                 dynapi::pFreeLibrary
#define CloseHandle                 dynapi::pCloseHandle
#define CreateFileW                 dynapi::pCreateFileW
#define DeviceIoControl             dynapi::pDeviceIoControl
#define GetStdHandle                dynapi::pGetStdHandle
#define GetConsoleMode              dynapi::pGetConsoleMode
#define SetConsoleMode              dynapi::pSetConsoleMode
#define GetModuleFileNameW          dynapi::pGetModuleFileNameW
#define FormatMessageW              dynapi::pFormatMessageW
#define LocalFree                   dynapi::pLocalFree
#define GetFileSizeEx               dynapi::pGetFileSizeEx
#define WriteFile                   dynapi::pWriteFile
#define OutputDebugStringW          dynapi::pOutputDebugStringW
#define GetConsoleScreenBufferInfo  dynapi::pGetConsoleScreenBufferInfo
#define SetConsoleTextAttribute     dynapi::pSetConsoleTextAttribute
#define WriteConsoleW               dynapi::pWriteConsoleW
#endif
