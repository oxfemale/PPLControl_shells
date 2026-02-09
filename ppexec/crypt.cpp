#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <stdint.h>
#include <algorithm>
#include "crypt.h"
#include <winternl.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")




static bool NtOk(NTSTATUS s) { return s >= 0; }

// ======= RAII wrappers =======
struct BcryptAlg {
    BCRYPT_ALG_HANDLE h{};
    ~BcryptAlg() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
struct BcryptKey {
    BCRYPT_KEY_HANDLE h{};
    ~BcryptKey() { if (h) BCryptDestroyKey(h); }
};
struct BcryptHash {
    BCRYPT_HASH_HANDLE h{};
    ~BcryptHash() { if (h) BCryptDestroyHash(h); }
};

static bool BCryptRandomBytes(void* p, size_t cb)
{
    return NtOk(BCryptGenRandom(nullptr, (PUCHAR)p, (ULONG)cb, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// ======= Params =======
static const size_t   kSaltLen = 16;
static const size_t   kIvLen = 16;
static const size_t   kAesKeyLen = 32; // AES-256
static const size_t   kHmacKeyLen = 32; // HMAC key
static const size_t   kTagLen = 32; // SHA-256
static const uint32_t kVersion = 1;
static const uint32_t kPBKDF2Iters = 200000;

static const uint8_t kMagic[8] = { 'E','N','C','v','1',0,0,0 };

#pragma pack(push, 1)
struct ENC_HDR
{
    uint8_t  magic[8];       // ENCv1
    uint32_t version;        // 1
    uint32_t iterations;     // PBKDF2 iters
    uint64_t plainCb;        // размер plaintext (в байтах)
    uint8_t  salt[kSaltLen]; // PBKDF2 salt
    uint8_t  iv[kIvLen];     // AES-CBC IV
};
#pragma pack(pop)

// ======= PBKDF2(HMAC-SHA256) => AES key + HMAC key =======

static bool DeriveKeysPBKDF2_SHA256(
    const std::wstring& password,
    const uint8_t salt[kSaltLen],
    uint32_t iterations,
    uint8_t outAesKey[kAesKeyLen],
    uint8_t outHmacKey[kHmacKeyLen]
)
{
    BcryptAlg sha{};
    NTSTATUS st = BCryptOpenAlgorithmProvider(
        &sha.h,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    if (!NtOk(st)) {
        DWORD win32 = RtlNtStatusToDosError(st);
        (void)win32;
        return false;
    }

    const uint8_t* pwdBytes = (const uint8_t*)password.data(); // UTF-16LE
    ULONG pwdCb = (ULONG)(password.size() * sizeof(wchar_t));

    uint8_t dk[kAesKeyLen + kHmacKeyLen]{};

    st = BCryptDeriveKeyPBKDF2(
        sha.h,
        (PUCHAR)pwdBytes, pwdCb,
        (PUCHAR)salt, (ULONG)kSaltLen,
        (ULONGLONG)iterations,
        dk, (ULONG)sizeof(dk),
        0
    );

    if (!NtOk(st)) {
        DWORD win32 = RtlNtStatusToDosError(st);
        (void)win32;
        SecureZeroMemory(dk, sizeof(dk));
        return false;
    }

    memcpy(outAesKey, dk, kAesKeyLen);
    memcpy(outHmacKey, dk + kAesKeyLen, kHmacKeyLen);
    SecureZeroMemory(dk, sizeof(dk));
    return true;
}

// ======= HMAC-SHA256(header + data) =======
static bool HmacSha256_2part(
    const uint8_t* key, size_t keyLen,
    const uint8_t* data1, size_t data1Len,
    const uint8_t* data2, size_t data2Len,
    uint8_t outTag[kTagLen]
)
{
    BcryptAlg alg{};
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NtOk(st)) return false;

    DWORD objLen = 0, cbRes = 0;
    st = BCryptGetProperty(alg.h, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbRes, 0);
    if (!NtOk(st) || objLen == 0) return false;

    std::vector<uint8_t> obj(objLen);

    BcryptHash hh{};
    st = BCryptCreateHash(alg.h, &hh.h, obj.data(), (ULONG)obj.size(), (PUCHAR)key, (ULONG)keyLen, 0);
    if (!NtOk(st)) return false;

    if (data1Len) {
        st = BCryptHashData(hh.h, (PUCHAR)data1, (ULONG)data1Len, 0);
        if (!NtOk(st)) return false;
    }
    if (data2Len) {
        st = BCryptHashData(hh.h, (PUCHAR)data2, (ULONG)data2Len, 0);
        if (!NtOk(st)) return false;
    }

    st = BCryptFinishHash(hh.h, outTag, (ULONG)kTagLen, 0);
    return NtOk(st);
}

// ======= AES-256-CBC encrypt/decrypt =======
static bool Aes256CbcEncrypt(
    const uint8_t key[kAesKeyLen],
    const uint8_t iv[kIvLen],
    const uint8_t* plain, size_t plainLen,
    std::vector<uint8_t>& outCipher
)
{
    outCipher.clear();

    BcryptAlg aes{};
    NTSTATUS st = BCryptOpenAlgorithmProvider(&aes.h, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NtOk(st)) return false;

    st = BCryptSetProperty(aes.h, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NtOk(st)) return false;

    DWORD objLen = 0, cbRes = 0;
    st = BCryptGetProperty(aes.h, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbRes, 0);
    if (!NtOk(st) || objLen == 0) return false;

    std::vector<uint8_t> keyObj(objLen);
    BcryptKey k{};
    st = BCryptGenerateSymmetricKey(aes.h, &k.h, keyObj.data(), (ULONG)keyObj.size(),
        (PUCHAR)key, (ULONG)kAesKeyLen, 0);
    if (!NtOk(st)) return false;

    ULONG cbOut = 0;
    std::vector<uint8_t> ivCopy(iv, iv + kIvLen); // BCryptEncrypt mutates IV buffer

    st = BCryptEncrypt(k.h,
        (PUCHAR)plain, (ULONG)plainLen,
        nullptr,
        ivCopy.data(), (ULONG)ivCopy.size(),
        nullptr, 0,
        &cbOut,
        BCRYPT_BLOCK_PADDING);
    if (!NtOk(st) || cbOut == 0) return false;

    outCipher.resize(cbOut);
    ivCopy.assign(iv, iv + kIvLen);

    st = BCryptEncrypt(k.h,
        (PUCHAR)plain, (ULONG)plainLen,
        nullptr,
        ivCopy.data(), (ULONG)ivCopy.size(),
        outCipher.data(), (ULONG)outCipher.size(),
        &cbOut,
        BCRYPT_BLOCK_PADDING);
    if (!NtOk(st)) return false;

    outCipher.resize(cbOut);
    return true;
}

static bool Aes256CbcDecrypt(
    const uint8_t key[kAesKeyLen],
    const uint8_t iv[kIvLen],
    const uint8_t* cipher, size_t cipherLen,
    std::vector<uint8_t>& outPlain
)
{
    outPlain.clear();

    BcryptAlg aes{};
    NTSTATUS st = BCryptOpenAlgorithmProvider(&aes.h, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NtOk(st)) return false;

    st = BCryptSetProperty(aes.h, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NtOk(st)) return false;

    DWORD objLen = 0, cbRes = 0;
    st = BCryptGetProperty(aes.h, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbRes, 0);
    if (!NtOk(st) || objLen == 0) return false;

    std::vector<uint8_t> keyObj(objLen);
    BcryptKey k{};
    st = BCryptGenerateSymmetricKey(aes.h, &k.h, keyObj.data(), (ULONG)keyObj.size(),
        (PUCHAR)key, (ULONG)kAesKeyLen, 0);
    if (!NtOk(st)) return false;

    ULONG cbOut = 0;
    std::vector<uint8_t> ivCopy(iv, iv + kIvLen);

    st = BCryptDecrypt(k.h,
        (PUCHAR)cipher, (ULONG)cipherLen,
        nullptr,
        ivCopy.data(), (ULONG)ivCopy.size(),
        nullptr, 0,
        &cbOut,
        BCRYPT_BLOCK_PADDING);
    if (!NtOk(st)) return false;

    outPlain.resize(cbOut);
    ivCopy.assign(iv, iv + kIvLen);

    st = BCryptDecrypt(k.h,
        (PUCHAR)cipher, (ULONG)cipherLen,
        nullptr,
        ivCopy.data(), (ULONG)ivCopy.size(),
        outPlain.data(), (ULONG)outPlain.size(),
        &cbOut,
        BCRYPT_BLOCK_PADDING);
    if (!NtOk(st)) return false;

    outPlain.resize(cbOut);
    return true;
}

// ======= API #1: Encrypt plaintext UTF-16 string => encrypted bytes =======
std::vector<BYTE> EncryptStringToBytes_CNG(
    const std::wstring& password,
    const std::wstring& plainTextW
)
{
    std::vector<BYTE> out;

    // plaintext bytes = UTF-16LE (как лежит wstring)
    const uint8_t* plain = (const uint8_t*)plainTextW.data();
    const size_t plainLen = plainTextW.size() * sizeof(wchar_t);

    ENC_HDR hdr{};
    memcpy(hdr.magic, kMagic, sizeof(kMagic));
    hdr.version = kVersion;
    hdr.iterations = kPBKDF2Iters;
    hdr.plainCb = (uint64_t)plainLen;

    if (!BCryptRandomBytes(hdr.salt, kSaltLen)) return {};
    if (!BCryptRandomBytes(hdr.iv, kIvLen)) return {};

    uint8_t aesKey[kAesKeyLen]{};
    uint8_t hmacKey[kHmacKeyLen]{};
    if (!DeriveKeysPBKDF2_SHA256(password, hdr.salt, hdr.iterations, aesKey, hmacKey))
        return {};

    std::vector<uint8_t> cipher;
    if (!Aes256CbcEncrypt(aesKey, hdr.iv, plain, plainLen, cipher)) {
        SecureZeroMemory(aesKey, sizeof(aesKey));
        SecureZeroMemory(hmacKey, sizeof(hmacKey));
        return {};
    }

    uint8_t tag[kTagLen]{};
    if (!HmacSha256_2part(hmacKey, kHmacKeyLen,
        (const uint8_t*)&hdr, sizeof(hdr),
        cipher.data(), cipher.size(),
        tag))
    {
        SecureZeroMemory(aesKey, sizeof(aesKey));
        SecureZeroMemory(hmacKey, sizeof(hmacKey));
        return {};
    }

    SecureZeroMemory(aesKey, sizeof(aesKey));
    SecureZeroMemory(hmacKey, sizeof(hmacKey));

    out.resize(sizeof(hdr) + cipher.size() + kTagLen);
    memcpy(out.data(), &hdr, sizeof(hdr));
    memcpy(out.data() + sizeof(hdr), cipher.data(), cipher.size());
    memcpy(out.data() + sizeof(hdr) + cipher.size(), tag, kTagLen);
    return out;
}

// ======= API #2: Decrypt encrypted bytes => plaintext bytes (vector<BYTE>) =======
// Возвращает {} при ошибке.
std::vector<BYTE> DecryptBytesToBytes_CNG(
    const std::wstring& password,
    const std::vector<BYTE>& encBytes
)
{
    if (encBytes.size() < sizeof(ENC_HDR) + kTagLen) return {};

    ENC_HDR hdr{};
    memcpy(&hdr, encBytes.data(), sizeof(hdr));

    if (memcmp(hdr.magic, kMagic, sizeof(kMagic)) != 0) return {};
    if (hdr.version != kVersion) return {};
    if (hdr.iterations < 10000 || hdr.iterations > 5000000) return {};

    const size_t cipherOff = sizeof(hdr);
    const size_t tagOff = encBytes.size() - kTagLen;
    if (tagOff < cipherOff) return {};

    const uint8_t* cipher = encBytes.data() + cipherOff;
    const size_t cipherLen = tagOff - cipherOff;
    const uint8_t* tagIn = encBytes.data() + tagOff;

    uint8_t aesKey[kAesKeyLen]{};
    uint8_t hmacKey[kHmacKeyLen]{};
    if (!DeriveKeysPBKDF2_SHA256(password, hdr.salt, hdr.iterations, aesKey, hmacKey))
        return {};

    // Verify HMAC first
    uint8_t tagCalc[kTagLen]{};
    bool okTag = HmacSha256_2part(hmacKey, kHmacKeyLen,
        (const uint8_t*)&hdr, sizeof(hdr),
        cipher, cipherLen,
        tagCalc);

    uint8_t diff = 0;
    for (size_t i = 0; i < kTagLen; ++i) diff |= (tagCalc[i] ^ tagIn[i]);

    if (!okTag || diff != 0) {
        SecureZeroMemory(aesKey, sizeof(aesKey));
        SecureZeroMemory(hmacKey, sizeof(hmacKey));
        return {};
    }

    std::vector<uint8_t> plain;
    bool okDec = Aes256CbcDecrypt(aesKey, hdr.iv, cipher, cipherLen, plain);

    SecureZeroMemory(aesKey, sizeof(aesKey));
    SecureZeroMemory(hmacKey, sizeof(hmacKey));

    if (!okDec) return {};
    if (hdr.plainCb != (uint64_t)plain.size()) return {};

    return std::vector<BYTE>(plain.begin(), plain.end());
}
