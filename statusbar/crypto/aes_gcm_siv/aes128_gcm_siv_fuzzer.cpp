// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for AES-128-GCM-SIV encrypt/decrypt with AAD (RFC 8452)
#include "statusbar/crypto/aes_gcm_siv/aes128_gcm_siv.hpp"
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
    if (size < 28) {
        return 0;  // 16 key + 12 nonce
    }
    Aes128Key key{};
    span_copy(key.data, std::span<uint8_t const>(data, 16));
    std::array<uint8_t, aes_gcm_siv_nonce_size> nonce_arr{};
    span_copy(nonce_arr, std::span<uint8_t const>(data + 16, aes_gcm_siv_nonce_size));
    std::span<uint8_t const, aes_gcm_siv_nonce_size> nonce(nonce_arr);

    // Split remaining bytes: first byte determines AAD/plaintext split point
    size_t remaining = size - 28;
    size_t aad_len = 0;
    size_t pt_offset = 28;
    if (remaining > 0) {
        aad_len = data[28] % (remaining);
        pt_offset = 29;
        remaining -= 1;
    }
    if (aad_len > remaining) {
        aad_len = remaining;
    }
    std::span<uint8_t const> aad(data + pt_offset, aad_len);
    std::span<uint8_t const> plaintext(data + pt_offset + aad_len, remaining - aad_len);

    // Round-trip with AAD
    std::vector<uint8_t> buffer(plaintext.begin(), plaintext.end());
    auto tag = aes128_gcm_siv_encrypt(key, nonce, buffer, aad);
    bool ok = aes128_gcm_siv_decrypt(key, nonce, buffer, tag, aad);
    if (!ok || buffer != std::vector<uint8_t>(plaintext.begin(), plaintext.end())) {
        __builtin_trap();
    }

    // Verify wrong AAD causes auth failure
    if (!aad.empty()) {
        std::vector<uint8_t> buffer2(plaintext.begin(), plaintext.end());
        auto tag2 = aes128_gcm_siv_encrypt(key, nonce, buffer2, aad);
        bool ok2 = aes128_gcm_siv_decrypt(key, nonce, buffer2, tag2, std::span<uint8_t const>{});
        if (ok2) {
            __builtin_trap();
        }
    }

    // Verify corrupted tag causes auth failure
    if (!plaintext.empty()) {
        std::vector<uint8_t> buffer3(plaintext.begin(), plaintext.end());
        auto tag3 = aes128_gcm_siv_encrypt(key, nonce, buffer3, aad);
        std::array<uint8_t, 16> bad_tag{};
        span_copy(bad_tag, std::span<uint8_t const, 16>(tag3));
        bad_tag[0] ^= 0x01;
        bool ok3 = aes128_gcm_siv_decrypt(key, nonce, buffer3, std::span<uint8_t const, 16>(bad_tag), aad);
        if (ok3) {
            __builtin_trap();
        }
    }

    // Feed raw fuzz data to decrypt (must not crash)
    if (size >= 44) {
        std::array<uint8_t, 16> fuzz_tag{};
        span_copy(fuzz_tag, std::span<uint8_t const>(data + 28, 16));
        std::vector<uint8_t> fuzz_ct(data + 44, data + size);
        auto fuzz_ok = aes128_gcm_siv_decrypt(key, nonce, std::span<uint8_t>(fuzz_ct), std::span<uint8_t const, 16>(fuzz_tag), aad);
        test::do_not_optimize(fuzz_ok);
    }

    return 0;
}
