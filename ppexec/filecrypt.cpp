#define _CRT_SECURE_NO_WARNINGS
#include "filecrypt.h"
#include <windows.h>
#include <string>
#include <wincrypt.h>
#include <vector>
#include <cstdio>
#include "crypt.h"
#include "Controller.h"

//#pragma comment(lib, "advapi32.lib")



std::wstring Win32ErrorToStringWfilecrypt(DWORD err)
{
    typedef DWORD(WINAPI* PFN_FormatMessageW)(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*);
    typedef HLOCAL(WINAPI* PFN_LocalFree)(HLOCAL);

    HMODULE hK32 = ::GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::Win32ErrorToStringWfilecrypt() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return SKW(L"(unknown error)");
    }

    PFN_FormatMessageW pFormatMessageW = (PFN_FormatMessageW)::GetProcAddress(hK32, SKA("FormatMessageW"));
    PFN_LocalFree pLocalFree = (PFN_LocalFree)::GetProcAddress(hK32, SKA("LocalFree"));

    if (!pFormatMessageW || !pLocalFree) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::Win32ErrorToStringWfilecrypt() GetProcAddress(FormatMessageW, LocalFree) Failed, error.\n"));
        return SKW(L"(unknown error)");
    }

    wchar_t* buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = pFormatMessageW(flags,nullptr,err,0,(LPWSTR)&buf,0,nullptr);
    std::wstring s = (len && buf) ? std::wstring(buf, buf + len) : SKW(L"(unknown error)");

    if (buf) pLocalFree(buf);

    return s;
}

static bool WriteExact(HANDLE h, const void* p, DWORD cb)
{
    typedef BOOL(WINAPI* PFN_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

    HMODULE hK32 = ::GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::WriteExact() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return false;
    }

    PFN_WriteFile pWriteFile = (PFN_WriteFile)::GetProcAddress(hK32, SKA("WriteFile"));
    if (!pWriteFile) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::WriteExact() GetProcAddress(WriteFile) Failed, error.\n"));
        return false;
    }

    const BYTE* b = (const BYTE*)p;
    DWORD wr = 0;

    while (cb)
    {
        if (!pWriteFile(h, b, cb, &wr, nullptr)) {
            g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::WriteExact() WriteFile() Failed, error: %lu (%s)\n"), GetLastError(), Win32ErrorToStringWfilecrypt(GetLastError()).c_str());
            return false;
        }

        if (wr == 0) {
			g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::WriteExact() WriteFile() wrote 0 bytes, unexpected.\n"));
            return false;
        }

        b += wr;
        cb -= wr;
    }
    return true;
}

static bool ConstantTimeEq32(const BYTE a[32], const BYTE b[32])
{
    BYTE x = 0;
    for (int i = 0; i < 32; ++i) x |= (a[i] ^ b[i]);
    return x == 0;
}


static BYTE g_Passphrase[64];
static DWORD g_PassphraseLen = 0;

static BYTE g_Salt[16];
static DWORD g_SaltLen = 0;

static BYTE g_EncKeyRaw[32];
static BYTE g_MacKeyRaw[32];

static void ClearSecrets()
{
    SecureZeroMemory(g_Passphrase, sizeof(g_Passphrase));
    SecureZeroMemory(g_Salt, sizeof(g_Salt));
    SecureZeroMemory(g_EncKeyRaw, sizeof(g_EncKeyRaw));
    SecureZeroMemory(g_MacKeyRaw, sizeof(g_MacKeyRaw));
    g_PassphraseLen = 0;
    g_SaltLen = 0;
}

static void InitPassphraseDemo()
{
    const char* demo = SKA("DEMO-PASS-CHANGE-ME-TO-REAL-SECRET");
    g_PassphraseLen = (DWORD)lstrlenA(demo);
    if (g_PassphraseLen > sizeof(g_Passphrase)) g_PassphraseLen = sizeof(g_Passphrase);
    memcpy(g_Passphrase, demo, g_PassphraseLen);
}



static bool DeriveKeySHA256(
    HCRYPTPROV hProv,
    const BYTE* pass, DWORD passLen,
    const BYTE* salt, DWORD saltLen,
    const char* purpose,
    BYTE out32[32]
)
{
    typedef BOOL(WINAPI* PFN_CryptCreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
    typedef BOOL(WINAPI* PFN_CryptHashData)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
    typedef BOOL(WINAPI* PFN_CryptGetHashParam)(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
    typedef BOOL(WINAPI* PFN_CryptDestroyHash)(HCRYPTHASH);
    typedef int   (WINAPI* PFN_lstrlenA)(LPCSTR);

    HMODULE hAdv = ::GetModuleHandleW(SKW(L"advapi32.dll"));
    if (!hAdv) hAdv = ::LoadLibraryW(SKW(L"advapi32.dll"));
    if (!hAdv) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::DeriveKeySHA256() LoadLibraryW(advapi32.dll) Failed, error.\n"));
        return false;
    }

    HMODULE hK32 = ::GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::DeriveKeySHA256() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return false;
    }

    PFN_CryptCreateHash    pCryptCreateHash = (PFN_CryptCreateHash)::GetProcAddress(hAdv, SKA("CryptCreateHash"));
    PFN_CryptHashData      pCryptHashData = (PFN_CryptHashData)::GetProcAddress(hAdv, SKA("CryptHashData"));
    PFN_CryptGetHashParam  pCryptGetHashParam = (PFN_CryptGetHashParam)::GetProcAddress(hAdv, SKA("CryptGetHashParam"));
    PFN_CryptDestroyHash   pCryptDestroyHash = (PFN_CryptDestroyHash)::GetProcAddress(hAdv, SKA("CryptDestroyHash"));
    PFN_lstrlenA           plstrlenA = (PFN_lstrlenA)::GetProcAddress(hK32, SKA("lstrlenA"));

    if (!pCryptCreateHash || !pCryptHashData || !pCryptGetHashParam || !pCryptDestroyHash || !plstrlenA)
    {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::DeriveKeySHA256() GetProcAddress(CryptCreateHash, CryptHashData, CryptGetHashParam, CryptDestroyHash, lstrlenA) Failed, error.\n"));
        return false;
    }

    HCRYPTHASH hHash = 0;
    if (!pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::DeriveKeySHA256() CryptCreateHash(CALG_SHA_256) Failed, error: %lu (%s)\n"), GetLastError(), Win32ErrorToStringWfilecrypt(GetLastError()).c_str());
        return false;
    }

    bool ok = false;
    do
    {
        if (passLen && !pCryptHashData(hHash, pass, passLen, 0)) break;
        if (saltLen && !pCryptHashData(hHash, salt, saltLen, 0)) break;

        const BYTE* purp = (const BYTE*)purpose;
        DWORD purpLen = (DWORD)plstrlenA(purpose);
        if (purpLen && !pCryptHashData(hHash, purp, purpLen, 0)) break;

        DWORD cb = 32;
        if (!pCryptGetHashParam(hHash, HP_HASHVAL, out32, &cb, 0)) break;
        if (cb != 32) break;

        ok = true;
    } while (0);

    pCryptDestroyHash(hHash);
    return ok;
}

static bool ImportAes256Key(HCRYPTPROV hProv, const BYTE key32[32], HCRYPTKEY& outKey)
{
    typedef BOOL(WINAPI* PFN_CryptImportKey)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);

    HMODULE hAdv = ::GetModuleHandleW(SKW(L"advapi32.dll"));
    if (!hAdv) hAdv = ::LoadLibraryW(SKW(L"advapi32.dll"));
    if (!hAdv) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::ImportAes256Key() LoadLibraryW(advapi32.dll) Failed, error.\n"));
        return false;
    }

    PFN_CryptImportKey pCryptImportKey = (PFN_CryptImportKey)::GetProcAddress(hAdv, SKA("CryptImportKey"));
    if (!pCryptImportKey) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::ImportAes256Key() GetProcAddress(CryptImportKey) Failed, error.\n"));
        return false;
    }

    // PLAINTEXTKEYBLOB for AES256
    struct KEYBLOB
    {
        BLOBHEADER hdr;
        DWORD dwKeySize;
        BYTE  key[32];
    } blob{};

    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_AES_256;
    blob.dwKeySize = 32;
    memcpy(blob.key, key32, 32);

    outKey = 0;
    return pCryptImportKey(hProv, (const BYTE*)&blob, (DWORD)sizeof(blob), 0, 0, &outKey) != FALSE;
}

static bool ImportHmacSha256Key(HCRYPTPROV hProv, const BYTE key32[32], HCRYPTKEY& outKey)
{
    typedef BOOL(WINAPI* PFN_CryptImportKey)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);

    HMODULE hAdv = ::GetModuleHandleW(SKW(L"advapi32.dll"));
    if (!hAdv) hAdv = ::LoadLibraryW(SKW(L"advapi32.dll"));
    if (!hAdv) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::ImportHmacSha256Key() LoadLibraryW(advapi32.dll) Failed, error.\n"));
        return false;
    }

    PFN_CryptImportKey pCryptImportKey = (PFN_CryptImportKey)::GetProcAddress(hAdv, SKA("CryptImportKey"));
    if (!pCryptImportKey) {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::ImportHmacSha256Key() GetProcAddress(CryptImportKey) Failed, error.\n"));
        return false;
    }

    struct HMACKEYBLOB
    {
        BLOBHEADER hdr;
        DWORD dwKeySize;
        BYTE  key[32];
    } blob{};

    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_RC2; // carrier
    blob.dwKeySize = 32;
    memcpy(blob.key, key32, 32);

    outKey = 0;
    return pCryptImportKey(
        hProv,
        (const BYTE*)&blob,
        (DWORD)sizeof(blob),
        0,
        CRYPT_IPSEC_HMAC_KEY,
        &outKey
    ) != FALSE;
}


static bool CreateHmacSha256(
    HCRYPTPROV hProv,
    const BYTE macKey32[32],
    HCRYPTHASH& outHash,
    HCRYPTKEY& outKeyCarrier
)
{
    typedef BOOL(WINAPI* PFN_CryptCreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
    typedef BOOL(WINAPI* PFN_CryptDestroyKey)(HCRYPTKEY);
    typedef BOOL(WINAPI* PFN_CryptSetHashParam)(HCRYPTHASH, DWORD, const BYTE*, DWORD);
    typedef BOOL(WINAPI* PFN_CryptDestroyHash)(HCRYPTHASH);

    outHash = 0;
    outKeyCarrier = 0;

    if (!ImportHmacSha256Key(hProv, macKey32, outKeyCarrier))
    {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::CreateHmacSha256() ImportHmacSha256Key() Failed, error.\n"));
        return false;
    }

    HMODULE hAdv = ::GetModuleHandleW(SKW(L"advapi32.dll"));
    if (!hAdv) hAdv = ::LoadLibraryW(SKW(L"advapi32.dll"));
    if (!hAdv)
    {
        outKeyCarrier = 0;
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::CreateHmacSha256() LoadLibraryW(advapi32.dll) Failed, error.\n"));
        return false;
    }

    PFN_CryptCreateHash   pCryptCreateHash = (PFN_CryptCreateHash)::GetProcAddress(hAdv, SKA("CryptCreateHash"));
    PFN_CryptDestroyKey   pCryptDestroyKey = (PFN_CryptDestroyKey)::GetProcAddress(hAdv, SKA("CryptDestroyKey"));
    PFN_CryptSetHashParam pCryptSetHashParam = (PFN_CryptSetHashParam)::GetProcAddress(hAdv, SKA("CryptSetHashParam"));
    PFN_CryptDestroyHash  pCryptDestroyHash = (PFN_CryptDestroyHash)::GetProcAddress(hAdv, SKA("CryptDestroyHash"));

    if (!pCryptCreateHash || !pCryptDestroyKey || !pCryptSetHashParam || !pCryptDestroyHash)
    {
        if (pCryptDestroyKey && outKeyCarrier) pCryptDestroyKey(outKeyCarrier);
        outKeyCarrier = 0;
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::CreateHmacSha256() GetProcAddress(CryptCreateHash, CryptDestroyKey, CryptSetHashParam, CryptDestroyHash) Failed, error.\n"));
        return false;
    }

    if (!pCryptCreateHash(hProv, CALG_HMAC, outKeyCarrier, 0, &outHash))
    {
        pCryptDestroyKey(outKeyCarrier);
        outKeyCarrier = 0;
        outHash = 0;
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::CreateHmacSha256() CryptCreateHash(CALG_HMAC) Failed, error: %lu (%s)\n"), GetLastError(), Win32ErrorToStringWfilecrypt(GetLastError()).c_str());
        return false;
    }

    HMAC_INFO info{};
    info.HashAlgid = CALG_SHA_256;

    if (!pCryptSetHashParam(outHash, HP_HMAC_INFO, (const BYTE*)&info, 0))
    {
        pCryptDestroyHash(outHash);
        pCryptDestroyKey(outKeyCarrier);
        outHash = 0;
        outKeyCarrier = 0;
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::CreateHmacSha256() CryptSetHashParam(HP_HMAC_INFO) Failed, error: %lu (%s)\n"), GetLastError(), Win32ErrorToStringWfilecrypt(GetLastError()).c_str());
        return false;
    }

    return true;
}


#pragma pack(push, 1)
struct FCRY_HEADER_FIXED
{
    BYTE  Magic[4];     // "FCRY"
    DWORD Version;      // 1
    DWORD SaltLen;      // 16
    DWORD IvLen;        // 16
    ULONGLONG OriginalSize;
};
#pragma pack(pop)

static const BYTE  kMagic[4] = { 'F','C','R','Y' };
static const DWORD kVersion = 1;
static const DWORD kSaltLen = 16;
static const DWORD kIvLen = 16;
static const DWORD kTagLen = 32;


bool FcryDecryptBufferToFile(const BYTE* encryptedBlob, DWORD encryptedBlobSize, const std::wstring& outPath)
{
    if (!encryptedBlob || encryptedBlobSize == 0)
    {
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() Invalid parameters.\n"));
        return false;
    }

    ClearSecrets();
    InitPassphraseDemo();

    typedef BOOL(WINAPI* PFN_CryptAcquireContextW)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
    typedef BOOL(WINAPI* PFN_CryptReleaseContext)(HCRYPTPROV, DWORD);
    typedef BOOL(WINAPI* PFN_CryptSetKeyParam)(HCRYPTKEY, DWORD, const BYTE*, DWORD);
    typedef BOOL(WINAPI* PFN_CryptHashData)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
    typedef BOOL(WINAPI* PFN_CryptGetHashParam)(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
    typedef BOOL(WINAPI* PFN_CryptGetKeyParam)(HCRYPTKEY, DWORD, BYTE*, DWORD*, DWORD);
    typedef BOOL(WINAPI* PFN_CryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
    typedef BOOL(WINAPI* PFN_CryptDestroyHash)(HCRYPTHASH);
    typedef BOOL(WINAPI* PFN_CryptDestroyKey)(HCRYPTKEY);

    typedef HMODULE(WINAPI* PFN_LoadLibraryW)(LPCWSTR);
    typedef HMODULE(WINAPI* PFN_GetModuleHandleW)(LPCWSTR);
    typedef FARPROC(WINAPI* PFN_GetProcAddress)(HMODULE, LPCSTR);

    typedef HANDLE(WINAPI* PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL(WINAPI* PFN_CloseHandle)(HANDLE);
    typedef BOOL(WINAPI* PFN_DeleteFileW)(LPCWSTR);
    typedef BOOL(WINAPI* PFN_MoveFileExW)(LPCWSTR, LPCWSTR, DWORD);


    HMODULE hK32 = ::GetModuleHandleW(SKW(L"kernel32.dll"));
    if (!hK32) { 
        ClearSecrets();
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() GetModuleHandleW(kernel32.dll) Failed, error.\n"));
        return false; 
    }
    
    PFN_GetModuleHandleW pGetModuleHandleW = (PFN_GetModuleHandleW)::GetProcAddress(hK32, SKA("GetModuleHandleW"));
    PFN_GetProcAddress   pGetProcAddress = (PFN_GetProcAddress)::GetProcAddress(hK32, SKA("GetProcAddress"));
    PFN_LoadLibraryW     pLoadLibraryW = (PFN_LoadLibraryW)::GetProcAddress(hK32, SKA("LoadLibraryW"));

    if (!pGetModuleHandleW || !pGetProcAddress || !pLoadLibraryW)
    {
        ClearSecrets();
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() GetProcAddress(GetModuleHandleW, GetProcAddress, LoadLibraryW) Failed, error.\n"));
        return false;
    }


    PFN_CreateFileW       pCreateFileW = (PFN_CreateFileW)pGetProcAddress(hK32, SKA("CreateFileW"));
	if (!pCreateFileW) g_log.Printf(LogLevel::Alert, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() GetProcAddress(CreateFileW) returned nullptr.\n"));
    PFN_CloseHandle       pCloseHandle = (PFN_CloseHandle)pGetProcAddress(hK32, SKA("CloseHandle"));
	if (!pCloseHandle) g_log.Printf(LogLevel::Alert, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() GetProcAddress(CloseHandle) returned nullptr.\n"));
    PFN_DeleteFileW       pDeleteFileW = (PFN_DeleteFileW)pGetProcAddress(hK32, SKA("DeleteFileW"));
	if (!pDeleteFileW) g_log.Printf(LogLevel::Alert, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() GetProcAddress(DeleteFileW) returned nullptr.\n"));
    PFN_MoveFileExW       pMoveFileExW = (PFN_MoveFileExW)pGetProcAddress(hK32, SKA("MoveFileExW"));
	if (!pMoveFileExW) g_log.Printf(LogLevel::Alert, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() GetProcAddress(MoveFileExW) returned nullptr.\n"));

    if (!pCreateFileW || !pCloseHandle || !pDeleteFileW || !pMoveFileExW )
    {
        ClearSecrets();
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() GetProcAddress(CreateFileW, CloseHandle, DeleteFileW, MoveFileExW, SecureZeroMemory) Failed, error.\n"));
        return false;
    }


    HMODULE hAdv = pGetModuleHandleW(SKW(L"advapi32.dll"));
    if (!hAdv) hAdv = pLoadLibraryW(SKW(L"advapi32.dll"));
    if (!hAdv)
    {
        ClearSecrets();
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() LoadLibraryW(advapi32.dll) Failed, error.\n"));
        return false;
    }

    PFN_CryptAcquireContextW pCryptAcquireContextW = (PFN_CryptAcquireContextW)pGetProcAddress(hAdv, SKA("CryptAcquireContextW"));
    PFN_CryptReleaseContext  pCryptReleaseContext = (PFN_CryptReleaseContext)pGetProcAddress(hAdv, SKA("CryptReleaseContext"));
    PFN_CryptSetKeyParam     pCryptSetKeyParam = (PFN_CryptSetKeyParam)pGetProcAddress(hAdv, SKA("CryptSetKeyParam"));
    PFN_CryptHashData        pCryptHashData = (PFN_CryptHashData)pGetProcAddress(hAdv, SKA("CryptHashData"));
    PFN_CryptGetHashParam    pCryptGetHashParam = (PFN_CryptGetHashParam)pGetProcAddress(hAdv, SKA("CryptGetHashParam"));
    PFN_CryptGetKeyParam     pCryptGetKeyParam = (PFN_CryptGetKeyParam)pGetProcAddress(hAdv, SKA("CryptGetKeyParam"));
    PFN_CryptDecrypt         pCryptDecrypt = (PFN_CryptDecrypt)pGetProcAddress(hAdv, SKA("CryptDecrypt"));
    PFN_CryptDestroyHash     pCryptDestroyHash = (PFN_CryptDestroyHash)pGetProcAddress(hAdv, SKA("CryptDestroyHash"));
    PFN_CryptDestroyKey      pCryptDestroyKey = (PFN_CryptDestroyKey)pGetProcAddress(hAdv, SKA("CryptDestroyKey"));
    

    if (!pCryptAcquireContextW || !pCryptReleaseContext || !pCryptSetKeyParam ||
        !pCryptHashData || !pCryptGetHashParam || !pCryptGetKeyParam ||
        !pCryptDecrypt || !pCryptDestroyHash || !pCryptDestroyKey)
    {
        ClearSecrets();
		g_log.Printf(LogLevel::Error, SKW(L"[!] filecrypt::FcryDecryptBufferToFile() GetProcAddress(CryptAcquireContextW, CryptReleaseContext, CryptSetKeyParam, CryptHashData, CryptGetHashParam, CryptGetKeyParam, CryptDecrypt, CryptDestroyHash, CryptDestroyKey) Failed, error.\n"));
        return false;
    }

    bool ok = false;

    HCRYPTPROV hProv = 0;
    HCRYPTKEY  hAesKey = 0;
    HCRYPTKEY  hMacCarrier = 0;
    HCRYPTHASH hMac = 0;

    HANDLE hTmp = INVALID_HANDLE_VALUE;
    std::wstring tmpPath = outPath + SKW(L".tmp");

    do
    {
        if (encryptedBlobSize < (DWORD)(sizeof(FCRY_HEADER_FIXED) + kSaltLen + kIvLen + kTagLen))
            break;

        const BYTE* p = encryptedBlob;
        DWORD remaining = encryptedBlobSize;

        auto consume = [&](DWORD n) -> const BYTE*
            {
                if (n > remaining) return nullptr;
                const BYTE* ret = p;
                p += n;
                remaining -= n;
                return ret;
            };

        const BYTE* hdrPtr = consume((DWORD)sizeof(FCRY_HEADER_FIXED));
        if (!hdrPtr) break;

        FCRY_HEADER_FIXED hdr{};
        memcpy(&hdr, hdrPtr, sizeof(hdr));

        if (memcmp(hdr.Magic, kMagic, 4) != 0) break;
        if (hdr.Version != kVersion) break;
        if (hdr.SaltLen != kSaltLen || hdr.IvLen != kIvLen) break;

        const BYTE* saltPtr = consume(kSaltLen);
        const BYTE* ivPtr = consume(kIvLen);
        if (!saltPtr || !ivPtr) break;

        memcpy(g_Salt, saltPtr, kSaltLen);
        g_SaltLen = kSaltLen;

        BYTE iv[16];
        memcpy(iv, ivPtr, kIvLen);

        if (remaining < kTagLen) break;
        DWORD cipherLen = remaining - kTagLen;

        const BYTE* cipherPtr = consume(cipherLen);
        const BYTE* tagPtr = consume(kTagLen);
        if (!cipherPtr || !tagPtr) break;

        if (!pCryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            break;

        if (!DeriveKeySHA256(hProv, g_Passphrase, g_PassphraseLen, g_Salt, g_SaltLen, SKA("ENC"), g_EncKeyRaw))
            break;
        if (!DeriveKeySHA256(hProv, g_Passphrase, g_PassphraseLen, g_Salt, g_SaltLen, SKA("MAC"), g_MacKeyRaw))
            break;

        if (!ImportAes256Key(hProv, g_EncKeyRaw, hAesKey))
            break;

        DWORD mode = CRYPT_MODE_CBC;
        if (!pCryptSetKeyParam(hAesKey, KP_MODE, (BYTE*)&mode, 0))
            break;
        if (!pCryptSetKeyParam(hAesKey, KP_IV, iv, 0))
            break;

        if (!CreateHmacSha256(hProv, g_MacKeyRaw, hMac, hMacCarrier))
            break;

        // HMAC(header + salt + iv + ciphertext)
        if (!pCryptHashData(hMac, (BYTE*)&hdr, (DWORD)sizeof(hdr), 0)) break;
        if (!pCryptHashData(hMac, (BYTE*)saltPtr, kSaltLen, 0)) break;
        if (!pCryptHashData(hMac, (BYTE*)ivPtr, kIvLen, 0)) break;
        if (cipherLen && !pCryptHashData(hMac, (BYTE*)cipherPtr, cipherLen, 0)) break;

        BYTE calcTag[32];
        DWORD calcTagLen = 32;
        //SecureZeroMemory(calcTag, sizeof(calcTag));
        volatile BYTE* v = (volatile BYTE*)calcTag;
        for (SIZE_T i = 0; i < sizeof(calcTag); ++i) v[i] = 0;

        if (!pCryptGetHashParam(hMac, HP_HASHVAL, calcTag, &calcTagLen, 0) || calcTagLen != 32)
            break;

        if (!ConstantTimeEq32(calcTag, tagPtr))
            break;

        // temp file
        hTmp = pCreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hTmp == INVALID_HANDLE_VALUE)
            break;

        DWORD blockBits = 0, cb = sizeof(blockBits);
        if (!pCryptGetKeyParam(hAesKey, KP_BLOCKLEN, (BYTE*)&blockBits, &cb, 0))
            break;

        DWORD blockBytes = blockBits / 8;
        if (blockBytes == 0 || blockBytes > 32) break;

        const DWORD CHUNK = 1u * 1024u * 1024u;
        std::vector<BYTE> buf;
        buf.resize(CHUNK + blockBytes);

        DWORD off = 0;
        while (off < cipherLen)
        {
            DWORD take = (cipherLen - off > CHUNK) ? CHUNK : (cipherLen - off);
            memcpy(buf.data(), cipherPtr + off, take);
            off += take;

            BOOL finalBlock = (off == cipherLen) ? TRUE : FALSE;

            DWORD dataLen = take;
            if (!pCryptDecrypt(hAesKey, 0, finalBlock, 0, buf.data(), &dataLen))
            {
                ok = false;
                break;
            }

            if (!WriteExact(hTmp, buf.data(), dataLen))
            {
                ok = false;
                break;
            }

            if (finalBlock)
            {
                ok = true;
                break;
            }
        }

        if (!ok) break;

        pCloseHandle(hTmp);
        hTmp = INVALID_HANDLE_VALUE;

        pDeleteFileW(outPath.c_str());
        if (!pMoveFileExW(tmpPath.c_str(), outPath.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            ok = false;
            break;
        }

        ok = true;

    } while (0);

    if (!ok)
    {
        if (hTmp != INVALID_HANDLE_VALUE) pCloseHandle(hTmp);
        pDeleteFileW(tmpPath.c_str());
    }

    if (hMac)        pCryptDestroyHash(hMac);
    if (hMacCarrier) pCryptDestroyKey(hMacCarrier);
    if (hAesKey)     pCryptDestroyKey(hAesKey);
    if (hProv)       pCryptReleaseContext(hProv, 0);

    ClearSecrets();
    return ok;
}
