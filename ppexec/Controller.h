#pragma once

#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <winsvc.h>
#include <string>
#include <vector>
#include <sstream>
#include <tlhelp32.h>
#include <iostream>
#include <map>
#include<fltuser.h>
#include<emmintrin.h>
#include<winnt.h>
#include "dynapi.h"
#include "crypt.h"


extern BYTE Key[33];
extern PVOID  SSDT_Items[0x1000];
extern HANDLE hPort;

HANDLE connect_driver();

PVOID get_proc_base(HANDLE hPort, DWORD Pid);

DWORD read_proc_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, PVOID Out);

DWORD write_proc_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, PVOID In);

BOOL protect_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, DWORD NewProtect);

BOOL update_state(HANDLE hPort, BYTE FunctionId, BYTE State);

BOOL kernel_write_data(HANDLE hPort, PVOID Dst, PVOID Src, DWORD Size);

BOOL kernel_read_data(HANDLE hPort, PVOID Dst, PVOID Src, DWORD Size);

BOOL kill_process(HANDLE hPort, DWORD Pid);

BOOL get_ssdt_items(HANDLE hPort, PVOID Out, DWORD Size);

PVOID find_krnl_images(PVOID PsLoadedModuleList, const wchar_t* name);

DWORD get_export_rva(const char* funcName);

DWORD parse_export_rva(const BYTE* moduleBase, const char* funcName);

void encrypt(unsigned int* buffer, unsigned int idx);

void encode_payload(PBYTE key, PBYTE buffer, SIZE_T size);




enum class Offset
{
	KernelPsInitialSystemProcess,
	ProcessActiveProcessLinks,
	ProcessUniqueProcessId,
	ProcessProtection,
	ProcessSignatureLevel,
	ProcessSectionSignatureLevel
};

class OffsetFinder
{
public:
	OffsetFinder();
	~OffsetFinder();
	DWORD GetOffset(Offset Name);
	BOOL FindAllOffsets();

private:
	HMODULE _KernelModule;
	std::map<Offset, DWORD> _OffsetMap;

private:
	BOOL FindKernelPsInitialSystemProcessOffset();
	BOOL FindProcessActiveProcessLinksOffset();
	BOOL FindProcessUniqueProcessIdOffset();
	BOOL FindProcessProtectionOffset();
	BOOL FindProcessSignatureLevelOffset();
	BOOL FindProcessSectionSignatureLevelOffset();
};



#define CASE_STR( c ) case c: return UTILS_STR_##c

class Utils
{
public:
	static ULONG_PTR GetKernelBaseAddress();
	static ULONG_PTR GetKernelAddress(ULONG_PTR Base, DWORD Offset);
	static UCHAR GetProtectionLevel(UCHAR Protection);
	static UCHAR GetSignerType(UCHAR Protection);
	static UCHAR GetProtection(UCHAR ProtectionLevel, UCHAR SignerType);
	static LPCWSTR GetProtectionLevelAsString(UCHAR ProtectionLevel);
	static LPCWSTR GetSignerTypeAsString(UCHAR SignerType);
	static UCHAR GetProtectionLevelFromString(LPCWSTR ProtectionLevel);
	static UCHAR GetSignerTypeFromString(LPCWSTR SignerType);
	static UCHAR GetSignatureLevel(UCHAR SignerType);
	static UCHAR GetSectionSignatureLevel(UCHAR SignerType);
	static LPCWSTR GetSignatureLevelAsString(UCHAR SignatureLevel);
};


typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone = 0,      // 0
	PsProtectedSignerAuthenticode,  // 1
	PsProtectedSignerCodeGen,       // 2
	PsProtectedSignerAntimalware,   // 3
	PsProtectedSignerLsa,           // 4
	PsProtectedSignerWindows,       // 5
	PsProtectedSignerWinTcb,        // 6
	PsProtectedSignerWinSystem,     // 7
	PsProtectedSignerApp,           // 8
	PsProtectedSignerMax            // 9
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;




#define RTC64_IOCTL_MEMORY_READ 0x80002048
#define RTC64_IOCTL_MEMORY_WRITE 0x8000204c

struct RTC64_MSR_READ {
	DWORD Register;
	DWORD ValueHigh;
	DWORD ValueLow;
};

struct RTC64_MEMORY_READ {
	BYTE Pad0[8];
	DWORD64 Address;
	BYTE Pad1[8];
	DWORD Size;
	DWORD Value;
	BYTE Pad3[16];
};

struct RTC64_MEMORY_WRITE {
	BYTE Pad0[8];
	DWORD64 Address;
	BYTE Pad1[8];
	DWORD Size;
	DWORD Value;
	BYTE Pad3[16];
};


#ifdef _WIN64
#define RTC_DEVICE_NAME_W RTC64_DEVICE_NAME_W
#else
#define RTC_DEVICE_NAME_W RTC32_DEVICE_NAME_W
#endif

#ifdef _WIN64
#define RTC_MSR_READ RTC64_MSR_READ
#define RTC_MEMORY_READ RTC64_MEMORY_READ
#define RTC_MEMORY_WRITE RTC64_MEMORY_WRITE
#else
#error RTCore driver 32-bit structures not defined
#endif

#ifdef _WIN64
#define RTC_IOCTL_MEMORY_READ RTC64_IOCTL_MEMORY_READ
#define RTC_IOCTL_MEMORY_WRITE RTC64_IOCTL_MEMORY_WRITE
#else
#error RTCore driver IOCTLs not defined
#endif

class RTCore
{
public:
	RTCore();
	~RTCore();
	BOOL Read8(ULONG_PTR Address, PBYTE Value);
	BOOL Read16(ULONG_PTR Address, PWORD Value);
	BOOL Read32(ULONG_PTR Address, PDWORD Value);
	BOOL Read64(ULONG_PTR Address, PDWORD64 Value);
	BOOL ReadPtr(ULONG_PTR Address, PULONG_PTR Value);
	BOOL Write8(ULONG_PTR Address, BYTE Value);
	BOOL Write16(ULONG_PTR Address, WORD Value);
	BOOL Write32(ULONG_PTR Address, DWORD Value);
	BOOL Write64(ULONG_PTR Address, DWORD64 Value);

private:
	LPWSTR _DeviceName;
	HANDLE _DeviceHandle;

private:
	BOOL Initialize();
	BOOL Read(ULONG_PTR Address, DWORD ValueSize, PDWORD Value);
	BOOL Write(ULONG_PTR Address, DWORD ValueSize, DWORD Value);
    
};

typedef struct _CTRL_PROCESS_ENTRY
{
	ULONG_PTR KernelAddress;
	DWORD Pid;
	UCHAR ProtectionLevel;
	UCHAR SignerType;
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
} CTRL_PROCESS_ENTRY, *PCTRL_PROCESS_ENTRY;

typedef struct _CTRL_PROCESS_INFO
{
	DWORD NumberOfEntries;
	CTRL_PROCESS_ENTRY Entries[ANYSIZE_ARRAY];
} CTRL_PROCESS_INFO, *PCTRL_PROCESS_INFO;

class Controller
{
public:
	Controller();
	Controller(RTCore* rtc, OffsetFinder* of);
	BOOL ListProtectedProcesses();
	BOOL GetProcessProtection(DWORD Pid);
	BOOL SetProcessProtection(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType);
	BOOL GetProcessSignatureLevels(DWORD Pid);
	BOOL SetProcessSignatureLevels(DWORD Pid, LPCWSTR SignerType);
	BOOL ProtectProcess(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType);
	BOOL UnprotectProcess(DWORD Pid);

private:
	RTCore* _rtc;
	OffsetFinder* _of;

private:
	BOOL GetInitialSystemProcessAddress(PULONG_PTR Addr);
	BOOL GetProcessKernelAddress(DWORD Pid, PULONG_PTR Addr);
	BOOL GetProcessList(PCTRL_PROCESS_INFO *List);
	BOOL GetProcessProtection(ULONG_PTR Addr, PUCHAR Protection);
	BOOL SetProcessProtection(ULONG_PTR Addr, UCHAR Protection);
	BOOL GetProcessSignatureLevel(ULONG_PTR Addr, PUCHAR SignatureLevel);
	BOOL SetProcessSignatureLevel(ULONG_PTR Addr, UCHAR SignatureLevel);
	BOOL GetProcessSectionSignatureLevel(ULONG_PTR Addr, PUCHAR SectionSignatureLevel);
	BOOL SetProcessSectionSignatureLevel(ULONG_PTR Addr, UCHAR SectionSignatureLevel);
};



enum class LogLevel { Debug, Info, Warn, Error, Good, Alert };

static void EnableVirtualTerminal()
{
    HANDLE hOut = dynapi::pGetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr)
        return;

    DWORD mode = 0;
    if (!dynapi::pGetConsoleMode(hOut, &mode))
        return;

    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    dynapi::pSetConsoleMode(hOut, mode);
}

static const wchar_t* LogLevelTag(LogLevel lv)
{
    switch (lv) {
    case LogLevel::Debug: return SKW(L"DBG");
    case LogLevel::Info:  return SKW(L"INFO");
    case LogLevel::Warn:  return SKW(L"WARN");
    case LogLevel::Error: return SKW(L"ERR");
    case LogLevel::Good:  return SKW(L"GOOD");
    case LogLevel::Alert: return SKW(L"ALERT");
    default:              return SKW(L"LOG");
    }
}

static const WORD LogLevelColor(LogLevel lv)
{
    switch (lv) {
    case LogLevel::Debug: return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case LogLevel::Info:  return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case LogLevel::Warn:  return FOREGROUND_RED | FOREGROUND_GREEN;
    case LogLevel::Error: return FOREGROUND_RED | FOREGROUND_INTENSITY;
    case LogLevel::Good:  return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case LogLevel::Alert:  return FOREGROUND_RED | FOREGROUND_INTENSITY;
    default:              return FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}

static std::wstring GetSelfDir()
{
    std::vector<wchar_t> buf(512);
    for (;;) {
        DWORD n = dynapi::pGetModuleFileNameW(nullptr, buf.data(), (DWORD)buf.size());
        if (n == 0) return L"";
        if (n < buf.size() - 1) break;
        buf.resize(buf.size() * 2);
    }
    std::wstring full(buf.data());
    size_t pos = full.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L"";
    return full.substr(0, pos);
}

static std::wstring Win32ErrorToStringW(DWORD err)
{
    if (err == 0) return L"OK";
    LPWSTR buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = dynapi::pFormatMessageW(flags, nullptr, err, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring s = (len && buf) ? std::wstring(buf, len) : SKW(L"(no message)");
    if (buf) dynapi::pLocalFree(buf);
    while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n')) s.pop_back();
    return s;
}

class Logger
{
public:
    Logger() = default;

    void InitDefault()
    {
        // ❗ НЕ создаём файл, если debug выключен
        //if (!glob_DebugFlag) return;

        std::wstring dir = GetSelfDir();
        if (dir.empty()) dir = L".";
        m_logPath = dir + SKW(L"\\ppexec.log");

        m_hLog = dynapi::pCreateFileW(
            m_logPath.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        // UTF-16LE BOM
        if (m_hLog != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz{};
            if (dynapi::pGetFileSizeEx(m_hLog, &sz) && sz.QuadPart == 0) {
                const wchar_t bom = 0xFEFF;
                DWORD wr = 0;
                dynapi::pWriteFile(m_hLog, &bom, sizeof(bom), &wr, nullptr);
            }
        }else{
            wprintf(SKW(L"[-_-] Controller::InitDefault() CreateFileW failed: %lu (%s)\n"),
                GetLastError(),
                Win32ErrorToStringW(GetLastError()).c_str()
			);
		}
    }

    void Close()
    {
        if (m_hLog != INVALID_HANDLE_VALUE) {
            dynapi::pCloseHandle(m_hLog);
            m_hLog = INVALID_HANDLE_VALUE;
        }
    }

    void Write(LogLevel lv, const std::wstring& msg)
    {
        std::wstring line = L"[";
        line += LogLevelTag(lv);
        line += L"] ";
        line += msg;
        if (line.empty() || (line.back() != L'\n' && line.back() != L'\r'))
            line += L"\r\n";

        // Debug output — ВСЕГДА
        dynapi::pOutputDebugStringW(line.c_str());

        // Console — ВСЕГДА
        WriteToConsole(lv, line);

        // File — ТОЛЬКО если debug=true
        //if (glob_DebugFlag)
        WriteToFile(lv, line);
    }

    void Printf(LogLevel lv, const wchar_t* fmt, ...)
    {
        if (!fmt) return;
        va_list ap;
        va_start(ap, fmt);
        std::wstring s = VFormat(fmt, ap);
        va_end(ap);
        Write(lv, s);
    }

    const std::wstring& LogPath() const { return m_logPath; }

private:
    static std::wstring VFormat(const wchar_t* fmt, va_list ap)
    {
        va_list ap2;
        va_copy(ap2, ap);
        int need = _vscwprintf(fmt, ap2);
        va_end(ap2);
        if (need <= 0) return L"";
        std::wstring out;
        out.resize((size_t)need);
        vswprintf_s(out.data(), out.size() + 1, fmt, ap);
        return out;
    }

    void WriteToFile(LogLevel lv, const std::wstring& line)
    {
        if (m_hLog == INVALID_HANDLE_VALUE) {
            InitDefault();
            if (m_hLog == INVALID_HANDLE_VALUE) {
                wprintf(SKW(L"[-_-] Controller::WriteToFile() INVALID_HANDLE_VALUE to file write.\n"));
                return;
            }
        }

        if (LogLevel::Debug == lv) {
            if (glob_debug_out != 1) return;
        }

        DWORD wr = 0;
        dynapi::pWriteFile(
            m_hLog,
            line.data(),
            (DWORD)(line.size() * sizeof(wchar_t)),
            &wr,
            nullptr
        );
    }

    static bool IsConsoleHandle(HANDLE h)
    {
        if (!h || h == INVALID_HANDLE_VALUE) return false;
        DWORD mode = 0;
        return dynapi::pGetConsoleMode(h, &mode) != 0;
    }

    static void WriteToConsole(LogLevel lv, const std::wstring& line)
    {
        if (LogLevel::Debug == lv) {
            if (glob_debug_out != 1) return;
        }

        HANDLE hOut = dynapi::pGetStdHandle(STD_OUTPUT_HANDLE);
        if (IsConsoleHandle(hOut)) {
            CONSOLE_SCREEN_BUFFER_INFO csbi{};
            dynapi::pGetConsoleScreenBufferInfo(hOut, &csbi);
            WORD oldColor = csbi.wAttributes;
            dynapi::pSetConsoleTextAttribute(hOut, LogLevelColor(lv));
            DWORD wr = 0;
            dynapi::pWriteConsoleW(hOut, line.c_str(), (DWORD)line.size(), &wr, nullptr);
            dynapi::pSetConsoleTextAttribute(hOut, oldColor);
            return;
        }

        if (hOut && hOut != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            dynapi::pWriteFile(hOut, line.c_str(), (DWORD)(line.size() * sizeof(wchar_t)), &wr, nullptr);
        }
    }

private:
    HANDLE m_hLog = INVALID_HANDLE_VALUE;
    std::wstring m_logPath;
};

static Logger g_log;

class LogLineBuilder
{
public:
    LogLineBuilder(LogLevel lv) : m_lv(lv) {}
    ~LogLineBuilder() { g_log.Write(m_lv, m_ss.str()); }

    template<typename T>
    LogLineBuilder& operator<<(const T& v)
    {
        m_ss << v;
        return *this;
    }

private:
    LogLevel m_lv;
    std::wstringstream m_ss;
};

#define LOGD() LogLineBuilder(LogLevel::Debug)
#define LOGI() LogLineBuilder(LogLevel::Info)
#define LOGW() LogLineBuilder(LogLevel::Warn)
#define LOGE() LogLineBuilder(LogLevel::Error)

bool SafeCloseHandle(HANDLE* ph, DWORD* outLastError /*=nullptr*/);

