// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// KDF2 Key Derivation Function implementation (IEEE 1363a-2004 Section 13.2)

#include "statusbar/crypto/kdf2/kdf2.hpp"

#include "statusbar/crypto/sha/sha256_hw.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <cstring>

namespace statusbar::crypto {

using internal::span_copy;
using std::span;

auto kdf2_sha256(span<uint8_t const> shared_secret, span<uint8_t const> params, span<uint8_t> output) -> bool
{
    // KDF2: For counter = 1, 2, ..., ceil(outLen/hashLen):
    //   Hash_i = SHA-256(Z || I2OSP(counter, 4) || P)
    //   Output = Hash_1 || Hash_2 || ... (truncated to outLen)

    size_t remaining = output.size();
    size_t offset = 0;
    uint32_t counter = 1;

    // Build the input buffer: Z || counter(4) || P
    // Use SecureWorkArray to securely zero the shared secret on destruction.
    size_t const buf_size = shared_secret.size() + 4 + params.size();
    SecureWorkArray<uint8_t, 256> buf;  // max reasonable KDF input
    if (buf_size > 256) {
        return false;  // input too large
    }

    span_copy(span<uint8_t>(buf.data, shared_secret.size()), shared_secret);
    size_t const counter_offset = shared_secret.size();
    buf.data[counter_offset] = 0;
    buf.data[counter_offset + 1] = 0;
    buf.data[counter_offset + 2] = 0;
    buf.data[counter_offset + 3] = 0;
    if (!params.empty()) {
        span_copy(span<uint8_t>(buf.data + counter_offset + 4, params.size()), params);
    }

    while (remaining > 0) {
        // Update counter (big-endian 32-bit)
        buf.data[counter_offset] = static_cast<uint8_t>(counter >> 24);
        buf.data[counter_offset + 1] = static_cast<uint8_t>(counter >> 16);
        buf.data[counter_offset + 2] = static_cast<uint8_t>(counter >> 8);
        buf.data[counter_offset + 3] = static_cast<uint8_t>(counter);

        // SecureArray so the derived digest block is wiped each iteration —
        // on the final iteration only `to_copy` bytes are emitted but the
        // whole 32-byte block is key material.
        SecureArray<32> const hash = sha256_hw(span<uint8_t const>(buf.data, buf_size));

        size_t const to_copy = std::min(remaining, size_t{32});
        span_copy(output.subspan(offset, to_copy), span<uint8_t const>(hash).first(to_copy));
        offset += to_copy;
        remaining -= to_copy;
        ++counter;
    }
    return true;
}

}  // namespace statusbar::crypto
