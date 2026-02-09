#include "dynapi.h"
#include <atomic>
#include "crypt.h"

namespace dynapi
{
    
    PFN_HeapReAlloc                 pHeapReAlloc = nullptr;
    PFN_HeapFree                    pHeapFree = nullptr;
    PFN_GetProcessHeap              pGetProcessHeap = nullptr;
    PFN_HeapAlloc                   pHeapAlloc = nullptr;
    PFN_LoadLibraryW                pLoadLibraryW = nullptr;
    PFN_FreeLibrary                 pFreeLibrary = nullptr;
    PFN_CloseHandle                 pCloseHandle = nullptr;
    PFN_CreateFileW                 pCreateFileW = nullptr;
    PFN_DeviceIoControl             pDeviceIoControl = nullptr;
    PFN_GetStdHandle                pGetStdHandle = nullptr;
    PFN_GetConsoleMode              pGetConsoleMode = nullptr;
    PFN_SetConsoleMode              pSetConsoleMode = nullptr;
    PFN_GetModuleFileNameW          pGetModuleFileNameW = nullptr;
    PFN_FormatMessageW              pFormatMessageW = nullptr;
    PFN_LocalFree                   pLocalFree = nullptr;
    PFN_GetFileSizeEx               pGetFileSizeEx = nullptr;
    PFN_WriteFile                   pWriteFile = nullptr;
    PFN_OutputDebugStringW          pOutputDebugStringW = nullptr;
    PFN_GetConsoleScreenBufferInfo  pGetConsoleScreenBufferInfo = nullptr;
    PFN_SetConsoleTextAttribute     pSetConsoleTextAttribute = nullptr;
    PFN_WriteConsoleW               pWriteConsoleW = nullptr;

    static std::atomic<bool> g_inited{ false };
    static HMODULE g_hKernel32 = nullptr;

    static FARPROC Resolve(HMODULE mod, const char* name)
    {
        if (!mod || !name) return nullptr;
        return ::GetProcAddress(mod, name);
    }

    bool Initialize()
    {
        bool expected = false;
        if (!g_inited.compare_exchange_strong(expected, true))
            return true;

        g_hKernel32 = ::GetModuleHandleW(SKW(L"kernel32.dll"));
        if (!g_hKernel32)
            g_hKernel32 = ::LoadLibraryW(SKW(L"kernel32.dll"));
        if (!g_hKernel32) {
            g_inited.store(false);
            return false;
        }

        pHeapFree = reinterpret_cast<PFN_HeapFree>(Resolve(g_hKernel32, SKA("HeapFree")));
        pGetProcessHeap = reinterpret_cast<PFN_GetProcessHeap>(Resolve(g_hKernel32, SKA("GetProcessHeap")));
        pHeapAlloc = reinterpret_cast<PFN_HeapAlloc>(Resolve(g_hKernel32, SKA("HeapAlloc")));

        pLoadLibraryW = reinterpret_cast<PFN_LoadLibraryW>(Resolve(g_hKernel32, SKA("LoadLibraryW")));
        pFreeLibrary = reinterpret_cast<PFN_FreeLibrary>(Resolve(g_hKernel32, SKA("FreeLibrary")));

        pCloseHandle = reinterpret_cast<PFN_CloseHandle>(Resolve(g_hKernel32, SKA("CloseHandle")));

        pCreateFileW = reinterpret_cast<PFN_CreateFileW>(Resolve(g_hKernel32, SKA("CreateFileW")));
        pDeviceIoControl = reinterpret_cast<PFN_DeviceIoControl>(Resolve(g_hKernel32, SKA("DeviceIoControl")));

        pGetStdHandle = reinterpret_cast<PFN_GetStdHandle>(Resolve(g_hKernel32, SKA("GetStdHandle")));
        pGetConsoleMode = reinterpret_cast<PFN_GetConsoleMode>(Resolve(g_hKernel32, SKA("GetConsoleMode")));
        pSetConsoleMode = reinterpret_cast<PFN_SetConsoleMode>(Resolve(g_hKernel32, SKA("SetConsoleMode")));

        pGetModuleFileNameW = reinterpret_cast<PFN_GetModuleFileNameW>(Resolve(g_hKernel32, SKA("GetModuleFileNameW")));
        pFormatMessageW = reinterpret_cast<PFN_FormatMessageW>(Resolve(g_hKernel32, SKA("FormatMessageW")));
        pLocalFree = reinterpret_cast<PFN_LocalFree>(Resolve(g_hKernel32, SKA("LocalFree")));

        pGetFileSizeEx = reinterpret_cast<PFN_GetFileSizeEx>(Resolve(g_hKernel32, SKA("GetFileSizeEx")));
        pWriteFile = reinterpret_cast<PFN_WriteFile>(Resolve(g_hKernel32, SKA("WriteFile")));

        pOutputDebugStringW = reinterpret_cast<PFN_OutputDebugStringW>(Resolve(g_hKernel32, SKA("OutputDebugStringW")));

        pGetConsoleScreenBufferInfo = reinterpret_cast<PFN_GetConsoleScreenBufferInfo>(Resolve(g_hKernel32, SKA("GetConsoleScreenBufferInfo")));
        pSetConsoleTextAttribute = reinterpret_cast<PFN_SetConsoleTextAttribute>(Resolve(g_hKernel32, SKA("SetConsoleTextAttribute")));

        pWriteConsoleW = reinterpret_cast<PFN_WriteConsoleW>(Resolve(g_hKernel32, SKA("WriteConsoleW")));
        
        pHeapReAlloc = reinterpret_cast<PFN_HeapReAlloc>(Resolve(g_hKernel32, SKA("HeapReAlloc")));


        if (!pGetProcessHeap || !pHeapAlloc || !pHeapFree ||
            !pLoadLibraryW || !pFreeLibrary || !pHeapReAlloc ||
            !pCloseHandle || !pCreateFileW || !pDeviceIoControl ||
            !pGetStdHandle || !pGetConsoleMode || !pSetConsoleMode ||
            !pGetModuleFileNameW || !pFormatMessageW || !pLocalFree ||
            !pGetFileSizeEx || !pWriteFile ||
            !pOutputDebugStringW ||
            !pGetConsoleScreenBufferInfo || !pSetConsoleTextAttribute ||
            !pWriteConsoleW)
        {
            Uninitialize();
            return false;
        }

        return true;
    }

    void Uninitialize()
    {
        pHeapReAlloc = nullptr;
        pHeapFree = nullptr;
        pGetProcessHeap = nullptr;
        pHeapAlloc = nullptr;
        pLoadLibraryW = nullptr;
        pFreeLibrary = nullptr;
        pCloseHandle = nullptr;
        pCreateFileW = nullptr;
        pDeviceIoControl = nullptr;
        pGetStdHandle = nullptr;
        pGetConsoleMode = nullptr;
        pSetConsoleMode = nullptr;
        pGetModuleFileNameW = nullptr;
        pFormatMessageW = nullptr;
        pLocalFree = nullptr;
        pGetFileSizeEx = nullptr;
        pWriteFile = nullptr;
        pOutputDebugStringW = nullptr;
        pGetConsoleScreenBufferInfo = nullptr;
        pSetConsoleTextAttribute = nullptr;
        pWriteConsoleW = nullptr;

        g_hKernel32 = nullptr;
        g_inited.store(false);
    }

    bool IsInitialized()
    {
        return g_inited.load();
    }

    bool EnsureInitialized()
    {
        return IsInitialized() ? true : Initialize();
    }

}
