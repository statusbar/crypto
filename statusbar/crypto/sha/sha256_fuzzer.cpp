// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for SHA-256, SHA-512, and HMAC-SHA-256
#include "statusbar/crypto/sha/sha256.hpp"
#include "statusbar/crypto/sha/sha512.hpp"

#include <cstddef>
#include <cstdint>
#include <print>
#include <span>

using namespace statusbar::crypto;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    std::span<uint8_t const> input(data, size);

    // SHA-256 one-shot
    auto digest256 = sha256_sw(input);

    // SHA-256 secure variant must produce same result
    auto digest256_secure = sha256_secure_sw(input);
    for (size_t i = 0; i < sha256_digest_size; ++i) {
        if (digest256[i] != digest256_secure.data()[i]) {
            __builtin_trap();
        }
    }

    // SHA-512 one-shot
    auto digest512 = sha512_sw(input);

    // SHA-512 secure variant must produce same result
    auto digest512_secure = sha512_secure_sw(input);
    for (size_t i = 0; i < sha512_digest_size; ++i) {
        if (digest512[i] != digest512_secure.data()[i]) {
            __builtin_trap();
        }
    }

    // SHA-512 incremental must match one-shot
    {
        Sha512Context ctx;
        sha512_init_sw(ctx);
        sha512_update_sw(ctx, input);
        auto digest512_inc = sha512_final_sw(ctx);
        if (digest512 != digest512_inc) {
            __builtin_trap();
        }
    }

    // HMAC-SHA-256 with varying key sizes
    if (size >= 1) {
        // Split: first byte = key length ratio
        size_t key_len = data[0] % size;
        std::span<uint8_t const> key(data, key_len);
        std::span<uint8_t const> message(data + key_len, size - key_len);

        auto tag = sha256_hmac_sw(key, message);

        // Two-span HMAC must match single-span when second span is empty
        auto tag_two = sha256_hmac_sw(key, message, std::span<uint8_t const>{});
        if (tag != tag_two) {
            __builtin_trap();
        }

        // Two-span HMAC with split message must match single-span
        if (message.size() >= 2) {
            size_t split = message.size() / 2;
            auto tag_split = sha256_hmac_sw(key, message.subspan(0, split), message.subspan(split));
            if (tag != tag_split) {
                __builtin_trap();
            }
        }
    }
    return 0;
}
