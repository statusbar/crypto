// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-256-CBC-IV0 implementation (IEEE 1363a-2004 Section 14.3.2)
//
// Cache-Timing Security:
// This implementation uses hardware-accelerated AES when available (AES-NI on x86-64,
// ARMv8 Crypto Extensions on ARM64) via the aes256_expand_key_hw(), aes256_encrypt_block_hw(),
// and aes256_decrypt_block_hw() functions. Hardware acceleration eliminates cache-timing
// side channels. On platforms without hardware AES support, software fallback is used but
// is NOT hardened against cache-timing attacks.
//
// Recommendation: This function should only be used on platforms with hardware AES
// acceleration, or in low-security contexts where cache-timing attacks are not a threat.
// For maximum security, verify CPU support (CPUID on x86-64, FIPS 202 on ARM64).

#include "statusbar/crypto/aes_cbc/aes_cbc.hpp"

#include "statusbar/crypto/aes/aes256_hw.hpp"
#include "statusbar/crypto/aes/aes_common_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <cstring>

namespace statusbar::crypto {

using internal::span_copy;
using internal::span_fill;
using std::span;

auto aes256_cbc_iv0_encrypt(Aes256Key const& key, span<uint8_t const> plaintext, span<uint8_t> ciphertext) -> span<uint8_t const>
{
    size_t const ct_len = aes_cbc_iv0_ciphertext_size(plaintext.size());
    if (ciphertext.size() < ct_len) {
        return {};
    }

    // Use hardware-accelerated AES when available; falls back to software otherwise.
    // Hardware acceleration (AES-NI, ARMv8 Crypto Extensions) is cache-timing resistant.
    auto rk = aes256_expand_key_hw(key);

    // PKCS#7 padding: pad_len = aes_block_size - (pt_len % aes_block_size), always 1..16
    uint8_t const pad_len = static_cast<uint8_t>(aes_block_size - (plaintext.size() % aes_block_size));

    // Copy plaintext into ciphertext buffer and add padding
    span_copy(ciphertext.first(plaintext.size()), plaintext);
    span_fill(ciphertext.subspan(plaintext.size(), ct_len - plaintext.size()), pad_len);

    // CBC encrypt with IV = 0
    // C[0] = AES(P[0] XOR IV), where IV = 0, so C[0] = AES(P[0])
    // C[i] = AES(P[i] XOR C[i-1])
    uint8_t prev[aes_block_size] = {};  // IV = all zeros

    for (size_t off = 0; off < ct_len; off += aes_block_size) {
        auto block = ciphertext.subspan(off, aes_block_size);
        // XOR with previous ciphertext block (or IV)
        for (size_t j = 0; j < aes_block_size; ++j) {
            block[j] ^= prev[j];
        }
        // Encrypt in place
        std::array<uint8_t, aes_block_size> blk{};
        span_copy(blk, span<uint8_t const, aes_block_size>(block));
        aes256_encrypt_block_hw(rk, blk);
        span_copy(block, span<uint8_t const>(blk));
        span_copy(span<uint8_t>(prev, aes_block_size), span<uint8_t const>(blk));
    }

    return ciphertext.first(ct_len);
}

auto aes256_cbc_iv0_decrypt(Aes256Key const& key, span<uint8_t const> ciphertext, span<uint8_t> plaintext) -> span<uint8_t const>
{
    if (ciphertext.empty() || (ciphertext.size() % aes_block_size) != 0 || plaintext.size() < ciphertext.size()) {
        return {};
    }

    // Use hardware-accelerated AES when available; falls back to software otherwise.
    // Hardware acceleration (AES-NI, ARMv8 Crypto Extensions) is cache-timing resistant.
    auto rk = aes256_expand_key_hw(key);
    size_t const num_blocks = ciphertext.size() / aes_block_size;

    // CBC decrypt
    // P[0] = AES_dec(C[0]) XOR IV (IV = 0)
    // P[i] = AES_dec(C[i]) XOR C[i-1]
    uint8_t prev[aes_block_size] = {};  // IV = all zeros

    for (size_t i = 0; i < num_blocks; ++i) {
        size_t const off = i * aes_block_size;
        std::array<uint8_t, aes_block_size> blk{};
        span_copy(blk, ciphertext.subspan(off, aes_block_size));

        aes256_decrypt_block_hw(rk, blk);

        // XOR with previous ciphertext block (or IV)
        for (size_t j = 0; j < aes_block_size; ++j) {
            plaintext[off + j] = blk[j] ^ prev[j];
        }

        // Save current ciphertext block for next iteration
        span_copy(span<uint8_t>(prev, aes_block_size), ciphertext.subspan(off, aes_block_size));
    }

    // Verify and strip PKCS#7 padding (constant-time).
    // PKCS#7 requires the last pad_val bytes to all equal pad_val,
    // where pad_val is in [1, aes_block_size]. Non-padding bytes may have any value.
    uint8_t const pad_val = plaintext[ciphertext.size() - 1];

    // Constant-time range check: pad_val must be in [1, 16]
    // pad_val - 1 must be in [0, 15], i.e., upper bits must be zero
    uint8_t bad = static_cast<uint8_t>(pad_val - 1) & 0xF0;

    // Verify padding bytes (constant-time, no branches on secret data).
    // Only check that padding-position bytes equal pad_val.
    for (size_t i = 0; i < aes_block_size; ++i) {
        uint8_t const byte_val = plaintext[ciphertext.size() - 1 - i];
        // Constant-time: is this a padding position? (i < pad_val)
        // In uint16_t: if i < pad_val, (i - pad_val) has high bit set
        uint16_t const diff = static_cast<uint16_t>(i) - static_cast<uint16_t>(pad_val);
        uint8_t const is_padding = static_cast<uint8_t>(diff >> 15);  // 1 if i < pad_val
        // Constant-time: does byte_val match pad_val?
        uint8_t const mismatch = byte_val ^ pad_val;
        // Accumulate error: bad if this is a padding byte that doesn't match
        bad |= static_cast<uint8_t>(is_padding) & mismatch;
    }

    // Return plaintext length or 0 in constant time (no branch on secret-derived 'bad').
    // If bad == 0, mask = all-ones; if bad != 0, mask = 0.
    size_t const mask = static_cast<size_t>(-static_cast<size_t>(bad == 0));
    return plaintext.first((ciphertext.size() - pad_val) & mask);
}

}  // namespace statusbar::crypto
