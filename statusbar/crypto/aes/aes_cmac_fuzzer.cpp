// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for AES-256 CMAC and AES-128 CMAC
#include "statusbar/crypto/aes/aes128.hpp"
#include "statusbar/crypto/aes/aes256.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/crypto/util/test.hpp"

#include <cstddef>
#include <cstdint>
#include <print>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_copy;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < 32) {
        return 0;  // 32-byte key minimum (for AES-256)
    }

    // AES-256 CMAC
    Aes256Key key256{};
    span_copy(key256.data, std::span<uint8_t const>(data, 32));
    auto rk256 = aes256_expand_key_sw(key256);
    std::span<uint8_t const> message(data + 32, size - 32);

    auto tag256 = aes256_cmac_sw(rk256, message);

    // Verify must pass with correct tag
    if (!aes256_cmac_verify_sw(rk256, message, std::span<uint8_t const, 16>(tag256))) {
        __builtin_trap();
    }

    // Corrupted tag must fail
    auto bad_tag256 = tag256;
    bad_tag256[0] ^= 0x01;
    if (aes256_cmac_verify_sw(rk256, message, std::span<uint8_t const, 16>(bad_tag256))) {
        __builtin_trap();
    }

    // AES-256 CMAC xorend (requires message >= 16 bytes)
    if (message.size() >= 16) {
        std::array<uint8_t, 16> xor_end{};
        // Use last 16 bytes of key as xor_end for variety
        span_copy(xor_end, std::span<uint8_t const>(data + 16, 16));
        auto tag_xorend = aes256_cmac_xorend_sw(rk256, message, std::span<uint8_t const, 16>(xor_end));
        test::do_not_optimize(tag_xorend);
    }

    // AES-128 CMAC (use first 16 bytes as key)
    Aes128Key key128{};
    span_copy(key128.data, std::span<uint8_t const>(data, 16));
    auto rk128 = aes128_expand_key_sw(key128);

    auto tag128 = aes128_cmac_sw(rk128, message);

    // Verify must pass with correct tag
    if (!aes128_cmac_verify_sw(rk128, message, std::span<uint8_t const, 16>(tag128))) {
        __builtin_trap();
    }

    // Corrupted tag must fail
    auto bad_tag128 = tag128;
    bad_tag128[0] ^= 0x01;
    if (aes128_cmac_verify_sw(rk128, message, std::span<uint8_t const, 16>(bad_tag128))) {
        __builtin_trap();
    }

    // AES-128 CMAC xorend
    if (message.size() >= 16) {
        std::array<uint8_t, 16> xor_end{};
        span_copy(xor_end, std::span<uint8_t const>(data + 16, 16));
        auto tag_xorend128 = aes128_cmac_xorend_sw(rk128, message, std::span<uint8_t const, 16>(xor_end));
        test::do_not_optimize(tag_xorend128);
    }

    return 0;
}
