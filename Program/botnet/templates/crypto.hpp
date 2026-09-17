// language: C++, file: crypto.hpp, target: Red Sky beacon — AES-GCM + hex + base64
// Uses BCrypt for AES-256-GCM, matching the Python cryptography library.

#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cstdint>

#pragma comment(lib, "bcrypt.lib")

namespace rs { namespace crypto {

inline std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = val(hex[i]), lo = val(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return out;
}

inline std::string hex_encode(const uint8_t* data, size_t len) {
    static const char* tbl = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(tbl[data[i] >> 4]);
        out.push_back(tbl[data[i] & 0xF]);
    }
    return out;
}

inline std::string hex_encode(const std::vector<uint8_t>& v) {
    return hex_encode(v.data(), v.size());
}

inline std::string base64_encode(const std::vector<uint8_t>& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(tbl[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(tbl[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// ── AES-256-GCM encrypt ──
inline bool aes_gcm_encrypt(const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& nonce,
                            const std::vector<uint8_t>& plaintext,
                            const std::vector<uint8_t>& aad,
                            std::vector<uint8_t>& out_cipher,
                            std::vector<uint8_t>& out_tag) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return false;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCRYPT_KEY_HANDLE keyh = nullptr;
    if (BCryptGenerateSymmetricKey(alg, &keyh, nullptr, 0,
                                   (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    out_tag.resize(16);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce.data();
    info.cbNonce = (ULONG)nonce.size();
    info.pbTag   = out_tag.data();
    info.cbTag   = 16;
    info.pbAuthData = aad.empty() ? nullptr : (PUCHAR)aad.data();
    info.cbAuthData = (ULONG)aad.size();

    out_cipher.resize(plaintext.size());
    ULONG outlen = 0;
    NTSTATUS st = BCryptEncrypt(keyh, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
                                &info, nullptr, 0,
                                out_cipher.data(), (ULONG)out_cipher.size(),
                                &outlen, 0);
    BCryptDestroyKey(keyh);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) return false;
    out_cipher.resize(outlen);
    return true;
}

// ── AES-256-GCM decrypt ──
inline bool aes_gcm_decrypt(const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& nonce,
                            const std::vector<uint8_t>& cipher,
                            const std::vector<uint8_t>& tag,
                            const std::vector<uint8_t>& aad,
                            std::vector<uint8_t>& out_plain) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return false;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    BCRYPT_KEY_HANDLE keyh = nullptr;
    if (BCryptGenerateSymmetricKey(alg, &keyh, nullptr, 0,
                                   (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce.data();
    info.cbNonce = (ULONG)nonce.size();
    info.pbTag   = (PUCHAR)tag.data();
    info.cbTag   = (ULONG)tag.size();
    info.pbAuthData = aad.empty() ? nullptr : (PUCHAR)aad.data();
    info.cbAuthData = (ULONG)aad.size();

    out_plain.resize(cipher.size());
    ULONG outlen = 0;
    NTSTATUS st = BCryptDecrypt(keyh, (PUCHAR)cipher.data(), (ULONG)cipher.size(),
                                &info, nullptr, 0,
                                out_plain.data(), (ULONG)out_plain.size(),
                                &outlen, 0);
    BCryptDestroyKey(keyh);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) return false;
    out_plain.resize(outlen);
    return true;
}

}} // namespace rs::crypto
