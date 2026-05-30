// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Simple libFuzzer harness for AES-128 and AES-256 block round-trip
#include "statusbar/crypto/aes/aes128.hpp"
#include "statusbar/crypto/aes/aes256.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <cstddef>
#include <cstdint>
#include <print>
#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_copy;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    // AES-128 block round-trip (16-byte key + 16-byte plaintext)
    if (size >= 16) {
        Aes128Key key128{};
        span_copy(key128.data, std::span<uint8_t const>(data, 16));

        std::array<uint8_t, 16> pt128{};
        if (size >= 32) {
            span_copy(pt128, std::span<uint8_t const>(data + 16, 16));
        }

        auto rk128 = aes128_expand_key_sw(key128);
        auto ct128 = pt128;
        aes128_encrypt_block_sw(rk128, ct128);
        aes128_decrypt_block_sw(rk128, ct128);
        if (ct128 != pt128) {
            __builtin_trap();
        }
    }

    // AES-256 block round-trip (32-byte key + 16-byte plaintext)
    if (size >= 32) {
        Aes256Key key256{};
        span_copy(key256.data, std::span<uint8_t const>(data, 32));

        std::array<uint8_t, 16> pt256{};
        if (size >= 48) {
            span_copy(pt256, std::span<uint8_t const>(data + 32, 16));
        }

        auto rk256 = aes256_expand_key_sw(key256);
        auto ct256 = pt256;
        aes256_encrypt_block_sw(rk256, ct256);
        aes256_decrypt_block_sw(rk256, ct256);
        if (ct256 != pt256) {
            __builtin_trap();
        }
    }

    return 0;
}
