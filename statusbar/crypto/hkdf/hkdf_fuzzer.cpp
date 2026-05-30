// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for HKDF extract, expand, and one-shot
#include "statusbar/crypto/hkdf/hkdf.hpp"

#include <cstddef>
#include <cstdint>
#include <print>
#include <vector>

using namespace statusbar::crypto;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    // Split fuzz input into salt, IKM, and info using first two bytes as split ratios.
    // No minimum size: HKDF is specified to handle empty salt and IKM (RFC 5869).
    std::span<uint8_t const> salt;
    std::span<uint8_t const> ikm;
    std::span<uint8_t const> info;

    if (size >= 2) {
        size_t payload = size - 2;
        size_t salt_len = payload > 0 ? (data[0] % (payload + 1)) : 0;
        size_t rest = payload - salt_len;
        size_t ikm_len = rest > 0 ? (data[1] % (rest + 1)) : 0;
        size_t info_len = rest - ikm_len;

        salt = std::span<uint8_t const>(data + 2, salt_len);
        ikm = std::span<uint8_t const>(data + 2 + salt_len, ikm_len);
        info_len = info_len > 256 ? 256 : info_len;  // HKDF expand limits info to 256 bytes
        info = std::span<uint8_t const>(data + 2 + salt_len + ikm_len, info_len);
    } else if (size == 1) {
        // Single byte: use as salt, empty IKM and info
        salt = std::span<uint8_t const>(data, 1);
    }
    // size == 0: all empty, still valid

    // Test hkdf_sha256_extract
    auto prk = hkdf_sha256_extract(salt, ikm);

    // Test hkdf_sha256_expand with extracted PRK at various output sizes
    for (size_t okm_size : {16u, 32u, 64u, 256u, 1024u, 8160u}) {
        std::vector<uint8_t> okm(okm_size);
        auto res = hkdf_sha256_expand(prk, info, std::span<uint8_t>(okm.data(), okm.size()));
        if (!res && okm_size <= 8160) {
            __builtin_trap();
        }
    }

    // Test one-shot hkdf_sha256 and verify consistency with extract-then-expand
    std::vector<uint8_t> okm_oneshot(32);
    auto res_oneshot = hkdf_sha256(salt, ikm, info, std::span<uint8_t>(okm_oneshot.data(), okm_oneshot.size()));
    if (!res_oneshot) {
        __builtin_trap();
    }
    std::vector<uint8_t> okm_twostep(32);
    auto res_twostep = hkdf_sha256_expand(prk, info, std::span<uint8_t>(okm_twostep.data(), okm_twostep.size()));
    if (!res_twostep) {
        __builtin_trap();
    }
    if (okm_oneshot != okm_twostep) {
        __builtin_trap();
    }
    return 0;
}
