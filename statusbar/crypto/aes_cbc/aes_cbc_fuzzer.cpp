// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for AES-256-CBC-IV0 encrypt/decrypt and padding validation
#include "statusbar/crypto/aes_cbc/aes_cbc.hpp"
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
    if (size < 32) {
        return 0;  // 32-byte key minimum
    }
    Aes256Key key{};
    span_copy(key.data, std::span<uint8_t const>(data, 32));
    std::span<uint8_t const> plaintext(data + 32, size - 32);

    // Round-trip encrypt/decrypt
    size_t ct_size = aes_cbc_iv0_ciphertext_size(plaintext.size());
    std::vector<uint8_t> ciphertext(ct_size);
    auto enc_result = aes256_cbc_iv0_encrypt(key, plaintext, std::span<uint8_t>(ciphertext.data(), ciphertext.size()));
    if (enc_result.size() != ct_size) {
        __builtin_trap();
    }

    std::vector<uint8_t> recovered(ct_size);
    auto dec_result = aes256_cbc_iv0_decrypt(key, enc_result, std::span<uint8_t>(recovered.data(), recovered.size()));
    if (dec_result.size() != plaintext.size()) {
        __builtin_trap();
    }
    for (size_t i = 0; i < dec_result.size(); ++i) {
        if (dec_result[i] != plaintext[i]) {
            __builtin_trap();
        }
    }

    // Feed malformed ciphertext to exercise padding validation (must not crash)
    if (size >= 48) {
        // Use fuzz data directly as ciphertext (aligned to 16 bytes)
        size_t fake_ct_len = ((size - 32) / 16) * 16;
        if (fake_ct_len > 0) {
            std::vector<uint8_t> fake_pt(fake_ct_len);
            auto result = aes256_cbc_iv0_decrypt(
                key, std::span<uint8_t const>(data + 32, fake_ct_len), std::span<uint8_t>(fake_pt.data(), fake_pt.size()));
            test::do_not_optimize(result);
        }
    }
    return 0;
}
