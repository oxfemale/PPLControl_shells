#pragma once
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <winsvc.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#define SECURITY_WIN32
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <cwchar>
#include <cstdio>
#include <cstdarg>
#include <bcrypt.h>
#include <stdint.h>


extern DWORD glob_debug_out;

std::vector<BYTE> EncryptStringToBytes_CNG( const std::wstring& password, const std::wstring& plainTextW );

std::vector<BYTE> DecryptBytesToBytes_CNG( const std::wstring& password, const std::vector<BYTE>& encBytes );

namespace skc
{
    template<class _Ty>
    using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

    template <int _size, typename T, T _key1, T _key2>
    class skCrypter
    {
    public:
        __forceinline constexpr skCrypter(T* data)
        {
            crypt(data);
        }

        __forceinline T* get()
        {
            return _storage;
        }

        __forceinline int size() // (w)char count
        {
            return _size;
        }

        __forceinline  T key()
        {
            return _key1;
        }

        __forceinline  T* encrypt()
        {
            if (!isEncrypted())
                crypt(_storage);
            return _storage;
        }

        __forceinline  T* decrypt()
        {
            if (isEncrypted())
                crypt(_storage);
            return _storage;
        }

        __forceinline bool isEncrypted()
        {
            return _storage[_size - 1] != 0;
        }

        __forceinline void clear() // set full storage to 0
        {
            for (int i = 0; i < _size; i++)
                _storage[i] = 0;
        }

        __forceinline operator T* ()
        {
            decrypt();
            return _storage;
        }

    private:
        __forceinline constexpr void crypt(T* data)
        {
            for (int i = 0; i < _size; i++)
                _storage[i] = data[i] ^ (_key1 + i % (1 + _key2));
        }

        T _storage[_size]{};
    };
}

//       char,   wchar_t
#define skCrypt(str) skCrypt_key(str, static_cast<decltype(str[0])>(__TIME__[4]), static_cast<decltype(str[0])>(__TIME__[7]))
#define skCrypt_key(str, key1, key2) []() { \
    constexpr static auto crypted = skc::skCrypter< \
        sizeof(str) / sizeof(str[0]), \
        skc::clean_type<decltype(str[0])>, \
        key1, key2>((skc::clean_type<decltype(str[0])>*)str); \
    return crypted; }()

// ------------------------------
// skCrypt helpers for wide/narrow literals
// Usage: MessageBoxW(nullptr, SKW(L"Text"), SKW(L"Title"), MB_OK);
// Thread-safe per-thread buffer (thread_local). Copies decrypted text then re-encrypts.
// ------------------------------
template <typename Crypter>
static const wchar_t* SkWc(Crypter c)
{
    static thread_local std::wstring tmp;
    const wchar_t* p = c.decrypt();
    tmp.assign(p ? p : L"");
    c.encrypt();
    return tmp.c_str();
}

template <typename Crypter>
static const char* SkAc(Crypter c)
{
    static thread_local std::string tmp;
    const char* p = c.decrypt();
    tmp.assign(p ? p : "");
    c.encrypt();
    return tmp.c_str();
}

#define SKW(lit) SkWc(skCrypt(lit))
#define SKA(lit) SkAc(skCrypt(lit))



