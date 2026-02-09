// filecrypt.cpp : WinAPI-only crypto (CryptoAPI) AES-256-CBC + HMAC-SHA256
// Build: cl /EHsc /W4 filecrypt.cpp advapi32.lib

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>

#include <string>
#include <vector>
#include <cstdio>

#pragma comment(lib, "advapi32.lib")

// ---------------------------- Helpers ----------------------------

static std::wstring Win32ErrorToStringW(DWORD err)
{
    wchar_t* buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, err, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring s = (len && buf) ? std::wstring(buf, buf + len) : L"(unknown error)";
    if (buf) LocalFree(buf);
    return s;
}

static bool ReadExact(HANDLE h, void* p, DWORD cb)
{
    BYTE* b = (BYTE*)p;
    DWORD got = 0;
    while (cb)
    {
        if (!ReadFile(h, b, cb, &got, nullptr)) return false;
        if (got == 0) return false;
        b += got;
        cb -= got;
    }
    return true;
}

static bool WriteExact(HANDLE h, const void* p, DWORD cb)
{
    const BYTE* b = (const BYTE*)p;
    DWORD wr = 0;
    while (cb)
    {
        if (!WriteFile(h, b, cb, &wr, nullptr)) return false;
        if (wr == 0) return false;
        b += wr;
        cb -= wr;
    }
    return true;
}

static bool GetFileSizeU64(HANDLE h, ULONGLONG& outSize)
{
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(h, &li)) return false;
    outSize = (ULONGLONG)li.QuadPart;
    return true;
}

static std::wstring MakeOutPathCrypted(const std::wstring& inPath)
{
    // Insert "_crypted" before extension
    size_t slash = inPath.find_last_of(L"\\/");

    size_t dot = inPath.find_last_of(L'.');
    if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash))
    {
        return inPath + L"_crypted";
    }

    return inPath.substr(0, dot) + L"_crypted" + inPath.substr(dot);
}

static std::wstring MakeOutPathDecrypted(const std::wstring& inPath)
{
    // If filename has "_crypted" right before extension, remove it; else add "_decrypted"
    size_t slash = inPath.find_last_of(L"\\/");
    size_t dot = inPath.find_last_of(L'.');
    size_t nameStart = (slash == std::wstring::npos) ? 0 : slash + 1;

    std::wstring base;
    std::wstring ext;

    if (dot == std::wstring::npos || dot < nameStart)
    {
        base = inPath;
        ext = L"";
        dot = inPath.size();
    }
    else
    {
        base = inPath.substr(0, dot);
        ext = inPath.substr(dot);
    }

    const std::wstring suff = L"_crypted";
    if (base.size() >= suff.size() && base.compare(base.size() - suff.size(), suff.size(), suff) == 0)
    {
        return base.substr(0, base.size() - suff.size()) + ext;
    }
    return base + L"_decrypted" + ext;
}

static bool ConstantTimeEq32(const BYTE a[32], const BYTE b[32])
{
    BYTE x = 0;
    for (int i = 0; i < 32; ++i) x |= (a[i] ^ b[i]);
    return x == 0;
}

// ---------------------------- Global secret material (lifetime: Encrypt/Decrypt) ----------------------------

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
    // DEMO: hardcoded key material. Replace with user input if needed.
    const char* demo = "DEMO-PASS-CHANGE-ME-TO-REAL-SECRET";
    g_PassphraseLen = (DWORD)lstrlenA(demo);
    if (g_PassphraseLen > sizeof(g_Passphrase)) g_PassphraseLen = sizeof(g_Passphrase);
    memcpy(g_Passphrase, demo, g_PassphraseLen);
}

// SHA256(pass || salt || purpose) -> 32 bytes
static bool DeriveKeySHA256(HCRYPTPROV hProv, const BYTE* pass, DWORD passLen,
    const BYTE* salt, DWORD saltLen,
    const char* purpose,
    BYTE out32[32])
{
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return false;

    bool ok = false;
    do
    {
        if (passLen && !CryptHashData(hHash, pass, passLen, 0)) break;
        if (saltLen && !CryptHashData(hHash, salt, saltLen, 0)) break;

        const BYTE* purp = (const BYTE*)purpose;
        DWORD purpLen = (DWORD)lstrlenA(purpose);
        if (purpLen && !CryptHashData(hHash, purp, purpLen, 0)) break;

        DWORD cb = 32;
        if (!CryptGetHashParam(hHash, HP_HASHVAL, out32, &cb, 0)) break;
        if (cb != 32) break;

        ok = true;
    } while (0);

    CryptDestroyHash(hHash);
    return ok;
}

static bool ImportAes256Key(HCRYPTPROV hProv, const BYTE key32[32], HCRYPTKEY& outKey)
{
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

    return CryptImportKey(hProv, (const BYTE*)&blob, sizeof(blob), 0, 0, &outKey) != FALSE;
}

static bool ImportHmacSha256Key(HCRYPTPROV hProv, const BYTE key32[32], HCRYPTKEY& outKey)
{
    // For CALG_HMAC we need a key handle (any algorithm), we use a plaintext key blob.
    struct HMACKEYBLOB
    {
        BLOBHEADER hdr;
        DWORD dwKeySize;
        BYTE  key[32];
    } blob{};

    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_RC2; // Any symmetric alg is acceptable as "carrier" for HMAC key in CryptoAPI
    blob.dwKeySize = 32;
    memcpy(blob.key, key32, 32);

    return CryptImportKey(hProv, (const BYTE*)&blob, sizeof(blob), 0, CRYPT_IPSEC_HMAC_KEY, &outKey) != FALSE;
}

static bool CreateHmacSha256(HCRYPTPROV hProv, const BYTE macKey32[32], HCRYPTHASH& outHash, HCRYPTKEY& outKeyCarrier)
{
    outHash = 0;
    outKeyCarrier = 0;

    if (!ImportHmacSha256Key(hProv, macKey32, outKeyCarrier))
        return false;

    if (!CryptCreateHash(hProv, CALG_HMAC, outKeyCarrier, 0, &outHash))
    {
        CryptDestroyKey(outKeyCarrier);
        outKeyCarrier = 0;
        return false;
    }

    HMAC_INFO info{};
    info.HashAlgid = CALG_SHA_256;

    if (!CryptSetHashParam(outHash, HP_HMAC_INFO, (BYTE*)&info, 0))
    {
        CryptDestroyHash(outHash);
        CryptDestroyKey(outKeyCarrier);
        outHash = 0;
        outKeyCarrier = 0;
        return false;
    }

    return true;
}

// ---------------------------- File format ----------------------------

// Header (written at start, included into HMAC):
// [4]  Magic = "FCRY"
// [4]  Version = 1
// [4]  SaltLen (16)
// [16] Salt
// [4]  IvLen (16)
// [16] IV
// [8]  OriginalFileSize (u64)
// ... ciphertext ...
// [32] HMAC-SHA256(header + ciphertext)

#pragma pack(push, 1)
struct FCRY_HEADER_FIXED
{
    BYTE  Magic[4];
    DWORD Version;
    DWORD SaltLen;
    DWORD IvLen;
    ULONGLONG OriginalSize;
};
#pragma pack(pop)

static const BYTE kMagic[4] = { 'F','C','R','Y' };
static const DWORD kVersion = 1;
static const DWORD kSaltLen = 16;
static const DWORD kIvLen = 16;
static const DWORD kTagLen = 32;

// ---------------------------- Encrypt/Decrypt ----------------------------

static bool EncryptFile(const std::wstring& inPath)
{
    ClearSecrets();
    InitPassphraseDemo();

    bool ok = false;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hAesKey = 0;
    HCRYPTKEY hMacCarrier = 0;
    HCRYPTHASH hMac = 0;

    HANDLE hIn = INVALID_HANDLE_VALUE;
    HANDLE hOut = INVALID_HANDLE_VALUE;

    BYTE iv[16];
    SecureZeroMemory(iv, sizeof(iv));

    do
    {
        // Acquire crypto context
        if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            wprintf(L"[!] CryptAcquireContextW failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        // Open input
        hIn = CreateFileW(inPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hIn == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[!] Open input failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        ULONGLONG inSize = 0;
        if (!GetFileSizeU64(hIn, inSize))
        {
            wprintf(L"[!] GetFileSizeEx failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }
        if (inSize < 1ull || inSize > 50ull * 1024ull * 1024ull)
        {
            wprintf(L"[!] File size must be 1..50 MB (got %llu bytes)\n", inSize);
            break;
        }

        // Generate salt & IV
        g_SaltLen = kSaltLen;
        if (!CryptGenRandom(hProv, kSaltLen, g_Salt))
        {
            wprintf(L"[!] CryptGenRandom(salt) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }
        if (!CryptGenRandom(hProv, kIvLen, iv))
        {
            wprintf(L"[!] CryptGenRandom(iv) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        // Derive keys
        if (!DeriveKeySHA256(hProv, g_Passphrase, g_PassphraseLen, g_Salt, g_SaltLen, "ENC", g_EncKeyRaw))
        {
            wprintf(L"[!] DeriveKeySHA256(ENC) failed\n");
            break;
        }
        if (!DeriveKeySHA256(hProv, g_Passphrase, g_PassphraseLen, g_Salt, g_SaltLen, "MAC", g_MacKeyRaw))
        {
            wprintf(L"[!] DeriveKeySHA256(MAC) failed\n");
            break;
        }

        // Import AES key
        if (!ImportAes256Key(hProv, g_EncKeyRaw, hAesKey))
        {
            wprintf(L"[!] CryptImportKey(AES) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        // Set CBC mode
        DWORD mode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hAesKey, KP_MODE, (BYTE*)&mode, 0))
        {
            wprintf(L"[!] CryptSetKeyParam(KP_MODE) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }
        // Set IV
        if (!CryptSetKeyParam(hAesKey, KP_IV, iv, 0))
        {
            wprintf(L"[!] CryptSetKeyParam(KP_IV) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        // Create HMAC
        if (!CreateHmacSha256(hProv, g_MacKeyRaw, hMac, hMacCarrier))
        {
            wprintf(L"[!] CreateHmacSha256 failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        // Output path
        std::wstring outPath = MakeOutPathCrypted(inPath);
        hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hOut == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[!] Create output failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        // Build header
        FCRY_HEADER_FIXED hdr{};
        memcpy(hdr.Magic, kMagic, 4);
        hdr.Version = kVersion;
        hdr.SaltLen = kSaltLen;
        hdr.IvLen = kIvLen;
        hdr.OriginalSize = inSize;

        // Write header: fixed + salt + iv
        if (!WriteExact(hOut, &hdr, sizeof(hdr))) { wprintf(L"[!] Write header failed\n"); break; }
        if (!WriteExact(hOut, g_Salt, kSaltLen)) { wprintf(L"[!] Write salt failed\n"); break; }
        if (!WriteExact(hOut, iv, kIvLen)) { wprintf(L"[!] Write iv failed\n"); break; }

        // HMAC over header bytes too
        if (!CryptHashData(hMac, (BYTE*)&hdr, (DWORD)sizeof(hdr), 0)) { wprintf(L"[!] HMAC hash hdr failed\n"); break; }
        if (!CryptHashData(hMac, g_Salt, kSaltLen, 0)) { wprintf(L"[!] HMAC hash salt failed\n"); break; }
        if (!CryptHashData(hMac, iv, kIvLen, 0)) { wprintf(L"[!] HMAC hash iv failed\n"); break; }

        // Determine block length for buffer sizing
        DWORD blockBits = 0, cb = sizeof(blockBits);
        if (!CryptGetKeyParam(hAesKey, KP_BLOCKLEN, (BYTE*)&blockBits, &cb, 0))
        {
            wprintf(L"[!] CryptGetKeyParam(KP_BLOCKLEN) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }
        DWORD blockBytes = blockBits / 8;
        if (blockBytes == 0 || blockBytes > 32) { wprintf(L"[!] Unexpected block size\n"); break; }

        const DWORD CHUNK = 1u * 1024u * 1024u; // 1MB
        std::vector<BYTE> buf;
        buf.resize(CHUNK + blockBytes); // allow padding

        ULONGLONG processed = 0;
        while (processed < inSize)
        {
            DWORD toRead = (DWORD)((inSize - processed) > CHUNK ? CHUNK : (inSize - processed));
            DWORD got = 0;
            if (!ReadFile(hIn, buf.data(), toRead, &got, nullptr))
            {
                wprintf(L"[!] ReadFile failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
                break;
            }
            if (got == 0) { wprintf(L"[!] Unexpected EOF\n"); break; }

            processed += got;
            BOOL finalBlock = (processed == inSize) ? TRUE : FALSE;

            DWORD dataLen = got;
            DWORD bufLen = (DWORD)buf.size();

            if (!CryptEncrypt(hAesKey, 0, finalBlock, 0, buf.data(), &dataLen, bufLen))
            {
                wprintf(L"[!] CryptEncrypt failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
                break;
            }

            // Write ciphertext
            if (!WriteExact(hOut, buf.data(), dataLen))
            {
                wprintf(L"[!] Write ciphertext failed\n");
                break;
            }

            // HMAC over ciphertext
            if (!CryptHashData(hMac, buf.data(), dataLen, 0))
            {
                wprintf(L"[!] HMAC hash ciphertext failed\n");
                break;
            }

            if (finalBlock)
            {
                ok = true;
                break;
            }
        }

        if (!ok) break;

        // Finalize HMAC tag
        BYTE tag[32];
        DWORD tagLen = sizeof(tag);
        SecureZeroMemory(tag, sizeof(tag));

        if (!CryptGetHashParam(hMac, HP_HASHVAL, tag, &tagLen, 0) || tagLen != 32)
        {
            wprintf(L"[!] CryptGetHashParam(HP_HASHVAL) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        if (!WriteExact(hOut, tag, 32))
        {
            wprintf(L"[!] Write tag failed\n");
            break;
        }

        wprintf(L"[+] Encrypted: %s\n", outPath.c_str());
        ok = true;

    } while (0);

    if (hMac) CryptDestroyHash(hMac);
    if (hMacCarrier) CryptDestroyKey(hMacCarrier);
    if (hAesKey) CryptDestroyKey(hAesKey);
    if (hProv) CryptReleaseContext(hProv, 0);

    if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);

    // Destroy secrets at end
    ClearSecrets();
    return ok;
}

static bool DecryptFile(const std::wstring& inPath)
{
    ClearSecrets();
    InitPassphraseDemo();

    bool ok = false;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hAesKey = 0;
    HCRYPTKEY hMacCarrier = 0;
    HCRYPTHASH hMac = 0;

    HANDLE hIn = INVALID_HANDLE_VALUE;
    HANDLE hTmp = INVALID_HANDLE_VALUE;

    BYTE iv[16];
    SecureZeroMemory(iv, sizeof(iv));

    std::wstring outPath;
    std::wstring tmpPath;

    do
    {
        if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            wprintf(L"[!] CryptAcquireContextW failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        hIn = CreateFileW(inPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hIn == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[!] Open input failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        ULONGLONG inSize = 0;
        if (!GetFileSizeU64(hIn, inSize))
        {
            wprintf(L"[!] GetFileSizeEx failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }
        if (inSize < (sizeof(FCRY_HEADER_FIXED) + kSaltLen + kIvLen + kTagLen))
        {
            wprintf(L"[!] File too small / not valid\n");
            break;
        }

        // Read header fixed
        FCRY_HEADER_FIXED hdr{};
        if (!ReadExact(hIn, &hdr, sizeof(hdr)))
        {
            wprintf(L"[!] Read header failed\n");
            break;
        }

        if (memcmp(hdr.Magic, kMagic, 4) != 0 || hdr.Version != kVersion || hdr.SaltLen != kSaltLen || hdr.IvLen != kIvLen)
        {
            wprintf(L"[!] Invalid header\n");
            break;
        }

        g_SaltLen = kSaltLen;
        if (!ReadExact(hIn, g_Salt, kSaltLen)) { wprintf(L"[!] Read salt failed\n"); break; }
        if (!ReadExact(hIn, iv, kIvLen)) { wprintf(L"[!] Read iv failed\n"); break; }

        // Derive keys
        if (!DeriveKeySHA256(hProv, g_Passphrase, g_PassphraseLen, g_Salt, g_SaltLen, "ENC", g_EncKeyRaw))
        {
            wprintf(L"[!] DeriveKeySHA256(ENC) failed\n");
            break;
        }
        if (!DeriveKeySHA256(hProv, g_Passphrase, g_PassphraseLen, g_Salt, g_SaltLen, "MAC", g_MacKeyRaw))
        {
            wprintf(L"[!] DeriveKeySHA256(MAC) failed\n");
            break;
        }

        if (!ImportAes256Key(hProv, g_EncKeyRaw, hAesKey))
        {
            wprintf(L"[!] CryptImportKey(AES) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        DWORD mode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hAesKey, KP_MODE, (BYTE*)&mode, 0))
        {
            wprintf(L"[!] CryptSetKeyParam(KP_MODE) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }
        if (!CryptSetKeyParam(hAesKey, KP_IV, iv, 0))
        {
            wprintf(L"[!] CryptSetKeyParam(KP_IV) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        if (!CreateHmacSha256(hProv, g_MacKeyRaw, hMac, hMacCarrier))
        {
            wprintf(L"[!] CreateHmacSha256 failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        // HMAC starts with header too
        if (!CryptHashData(hMac, (BYTE*)&hdr, (DWORD)sizeof(hdr), 0)) { wprintf(L"[!] HMAC hash hdr failed\n"); break; }
        if (!CryptHashData(hMac, g_Salt, kSaltLen, 0)) { wprintf(L"[!] HMAC hash salt failed\n"); break; }
        if (!CryptHashData(hMac, iv, kIvLen, 0)) { wprintf(L"[!] HMAC hash iv failed\n"); break; }

        // Determine ciphertext length (excluding tag at end)
        ULONGLONG headerLen = sizeof(FCRY_HEADER_FIXED) + kSaltLen + kIvLen;
        ULONGLONG cipherLen = inSize - headerLen - kTagLen;

        // Create temp file in same directory
        outPath = MakeOutPathDecrypted(inPath);
        tmpPath = outPath + L".tmp";

        hTmp = CreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hTmp == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[!] Create temp output failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }

        // Buffer sizing
        DWORD blockBits = 0, cb = sizeof(blockBits);
        if (!CryptGetKeyParam(hAesKey, KP_BLOCKLEN, (BYTE*)&blockBits, &cb, 0))
        {
            wprintf(L"[!] CryptGetKeyParam(KP_BLOCKLEN) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            break;
        }
        DWORD blockBytes = blockBits / 8;
        if (blockBytes == 0 || blockBytes > 32) { wprintf(L"[!] Unexpected block size\n"); break; }

        const DWORD CHUNK = 1u * 1024u * 1024u; // 1MB
        std::vector<BYTE> buf;
        buf.resize(CHUNK + blockBytes);

        ULONGLONG remaining = cipherLen;
        while (remaining)
        {
            DWORD toRead = (DWORD)(remaining > CHUNK ? CHUNK : remaining);
            DWORD got = 0;
            if (!ReadFile(hIn, buf.data(), toRead, &got, nullptr))
            {
                wprintf(L"[!] ReadFile failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
                break;
            }
            if (got == 0) { wprintf(L"[!] Unexpected EOF\n"); break; }

            remaining -= got;

            // HMAC over ciphertext bytes
            if (!CryptHashData(hMac, buf.data(), got, 0))
            {
                wprintf(L"[!] HMAC hash ciphertext failed\n");
                break;
            }

            BOOL finalBlock = (remaining == 0) ? TRUE : FALSE;

            DWORD dataLen = got;
            if (!CryptDecrypt(hAesKey, 0, finalBlock, 0, buf.data(), &dataLen))
            {
                wprintf(L"[!] CryptDecrypt failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
                break;
            }

            if (!WriteExact(hTmp, buf.data(), dataLen))
            {
                wprintf(L"[!] Write plaintext failed\n");
                break;
            }

            if (finalBlock)
            {
                ok = true;
                break;
            }
        }

        if (!ok) break;

        // Read stored tag (last 32 bytes)
        BYTE storedTag[32];
        SecureZeroMemory(storedTag, sizeof(storedTag));
        if (!ReadExact(hIn, storedTag, 32))
        {
            wprintf(L"[!] Read stored tag failed\n");
            ok = false;
            break;
        }

        // Compute tag
        BYTE calcTag[32];
        DWORD tagLen = 32;
        SecureZeroMemory(calcTag, sizeof(calcTag));

        if (!CryptGetHashParam(hMac, HP_HASHVAL, calcTag, &tagLen, 0) || tagLen != 32)
        {
            wprintf(L"[!] CryptGetHashParam(HP_HASHVAL) failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            ok = false;
            break;
        }

        if (!ConstantTimeEq32(calcTag, storedTag))
        {
            wprintf(L"[!] HMAC mismatch (wrong key or file corrupted). Output will be discarded.\n");
            ok = false;
            break;
        }

        // Close temp handle before rename
        CloseHandle(hTmp);
        hTmp = INVALID_HANDLE_VALUE;

        // Replace existing output if any
        DeleteFileW(outPath.c_str());
        if (!MoveFileExW(tmpPath.c_str(), outPath.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            wprintf(L"[!] MoveFileExW failed: %s\n", Win32ErrorToStringW(GetLastError()).c_str());
            ok = false;
            break;
        }

        // Optional: validate size equals OriginalSize
        // (Not mandatory; CBC padding can make decrypted size exactly original if keys match)
        wprintf(L"[+] Decrypted: %s\n", outPath.c_str());
        ok = true;

    } while (0);

    if (!ok)
    {
        if (hTmp != INVALID_HANDLE_VALUE) CloseHandle(hTmp);
        if (!tmpPath.empty()) DeleteFileW(tmpPath.c_str());
    }

    if (hMac) CryptDestroyHash(hMac);
    if (hMacCarrier) CryptDestroyKey(hMacCarrier);
    if (hAesKey) CryptDestroyKey(hAesKey);
    if (hProv) CryptReleaseContext(hProv, 0);

    if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);

    ClearSecrets();
    return ok;
}

// ---------------------------- CLI ----------------------------

static void PrintUsage()
{
    wprintf(L"FileCrypt (WinAPI CryptoAPI) AES-256-CBC + HMAC-SHA256\n");
    wprintf(L"Usage:\n");
    wprintf(L"  bcrypt.exe --enc <path>\n");
    wprintf(L"  bcrypt.exe --dec <path>\n");
    wprintf(L"Notes:\n");
    wprintf(L"  --enc: creates <name>_crypted<ext> next to input.\n");
    wprintf(L"  --dec: if input has _crypted, removes it; else creates <name>_decrypted<ext>.\n");
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3)
    {
        PrintUsage();
        return 1;
    }

    std::wstring mode = argv[1];
    std::wstring path = argv[2];

    if (mode == L"--enc")
    {
        return EncryptFile(path) ? 0 : 2;
    }
    else if (mode == L"--dec")
    {
        return DecryptFile(path) ? 0 : 3;
    }
    else
    {
        PrintUsage();
        return 4;
    }
}
