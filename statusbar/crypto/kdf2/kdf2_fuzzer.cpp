// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// libFuzzer harness for KDF2-SHA-256 (IEEE 1363a-2004 Section 13.2)
#include "statusbar/crypto/kdf2/kdf2.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace statusbar::crypto;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    // Need at least 1 byte for split ratio
    if (size < 1) {
        return 0;
    }

    // Split fuzz input into shared_secret and params using first byte as ratio
    size_t const payload = size - 1;
    size_t const secret_len = payload > 0 ? (data[0] % (payload + 1)) : 0;
    size_t const params_len = payload - secret_len;

    std::span<uint8_t const> shared_secret(data + 1, secret_len);
    std::span<uint8_t const> params(data + 1 + secret_len, params_len);

    // Test various output sizes
    for (size_t out_size : {16u, 32u, 48u, 64u, 128u}) {
        std::vector<uint8_t> output(out_size);
        auto ok = kdf2_sha256(shared_secret, params, output);

        // If input fits in the 256-byte buffer, derivation must succeed
        if (shared_secret.size() + 4 + params.size() <= 256) {
            if (!ok) {
                __builtin_trap();
            }
        }
    }

    // Consistency: deriving twice with same inputs must produce identical output
    {
        std::vector<uint8_t> out1(32);
        std::vector<uint8_t> out2(32);
        auto ok1 = kdf2_sha256(shared_secret, params, out1);
        auto ok2 = kdf2_sha256(shared_secret, params, out2);
        if (ok1 != ok2) {
            __builtin_trap();
        }
        if (ok1 && out1 != out2) {
            __builtin_trap();
        }
    }

    // Prefix consistency: first N bytes of a longer derivation must match
    // a shorter derivation of N bytes
    {
        std::vector<uint8_t> short_out(32);
        std::vector<uint8_t> long_out(64);
        auto ok_short = kdf2_sha256(shared_secret, params, short_out);
        auto ok_long = kdf2_sha256(shared_secret, params, long_out);
        if (ok_short && ok_long) {
            for (size_t i = 0; i < 32; ++i) {
                if (short_out[i] != long_out[i]) {
                    __builtin_trap();
                }
            }
        }
    }

    // Test with empty params
    {
        std::vector<uint8_t> output(32);
        kdf2_sha256(shared_secret, {}, output);
    }

    return 0;
}
