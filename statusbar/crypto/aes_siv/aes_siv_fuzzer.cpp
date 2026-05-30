// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for AES-256-SIV encrypt/decrypt round-trip (RFC 5297)
#include "statusbar/crypto/aes_siv/aes256_siv.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/crypto/util/test.hpp"

#include <cstddef>
#include <cstdint>
#include <print>
#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_copy;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < 64) {
        return 0;  // 64-byte SIV key (K1 || K2)
    }
    Aes256SivKey key{};
    span_copy(key.data, std::span<uint8_t const>(data, 64));

    // Split remaining bytes: first byte determines AAD/plaintext split
    size_t remaining = size - 64;
    size_t aad_len = 0;
    size_t pt_offset = 64;
    if (remaining > 0) {
        aad_len = data[64] % (remaining);
        pt_offset = 65;
        remaining -= 1;
    }
    if (aad_len > remaining) {
        aad_len = remaining;
    }
    std::span<uint8_t const> aad(data + pt_offset, aad_len);
    std::span<uint8_t const> plaintext(data + pt_offset + aad_len, remaining - aad_len);

    // Round-trip encrypt/decrypt
    std::vector<uint8_t> buffer(plaintext.begin(), plaintext.end());
    auto siv = aes256_siv_encrypt(key, buffer, aad);
    bool ok = aes256_siv_decrypt(key, buffer, std::span<uint8_t const, 16>(siv), aad);
    if (!ok || buffer != std::vector<uint8_t>(plaintext.begin(), plaintext.end())) {
        __builtin_trap();
    }

    // Verify wrong AAD causes auth failure
    if (!aad.empty()) {
        std::vector<uint8_t> buffer2(plaintext.begin(), plaintext.end());
        auto siv2 = aes256_siv_encrypt(key, buffer2, aad);
        bool ok2 = aes256_siv_decrypt(key, buffer2, std::span<uint8_t const, 16>(siv2), std::span<uint8_t const>{});
        if (ok2) {
            __builtin_trap();
        }
    }

    // Verify corrupted SIV tag causes auth failure
    if (!plaintext.empty()) {
        std::vector<uint8_t> buffer3(plaintext.begin(), plaintext.end());
        auto siv3 = aes256_siv_encrypt(key, buffer3, aad);
        siv3[0] ^= 0x01;
        bool ok3 = aes256_siv_decrypt(key, buffer3, std::span<uint8_t const, 16>(siv3), aad);
        if (ok3) {
            __builtin_trap();
        }
    }

    // Feed raw fuzz data to decrypt to exercise SIV verification (must not crash)
    if (size >= 80) {
        std::array<uint8_t, 16> fuzz_siv{};
        span_copy(fuzz_siv, std::span<uint8_t const>(data + 64, 16));
        std::vector<uint8_t> fuzz_ct(data + 80, data + size);
        bool fuzz_ok = aes256_siv_decrypt(
            key, std::span<uint8_t>(fuzz_ct), std::span<uint8_t const, 16>(fuzz_siv), std::span<uint8_t const>{});
        test::do_not_optimize(fuzz_ok);
    }

    return 0;
}
