// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-256-CBC-IV0 (IEEE 1363a-2004 Section 14.3.2)
//
// AES-256 in CBC mode with a null (all-zero) IV and PKCS#7 padding.
// Padding always adds 1..16 bytes of padding value equal to the pad length.
//
// Cache-Timing Security:
// This implementation uses hardware-accelerated AES (aes256_expand_key_hw,
// aes256_encrypt_block_hw, aes256_decrypt_block_hw) which are cache-timing
// resistant on platforms with AES acceleration:
//   - x86-64: AES-NI (AESENC/AESDEC instructions have constant-time guarantees)
//   - ARM64: ARMv8 Crypto Extensions (AESE/AESD also constant-time)
//
// On platforms WITHOUT hardware AES support, the backup C++ implementations
// use S-box table lookups, which may be vulnerable to cache-timing attacks
// (Prime+Probe, Spectre, etc.) if the attacker can observe cache behavior.
//
// Recommendation: For cryptographic operations on untrusted systems or systems
// with cache-timing threats (shared cloud, untrusted co-tenants, etc.), verify
// that the platform supports hardware AES before using this function, or use
// ECIES only for non-sensitive key wrapping operations.
//
// References:
// - IEEE 1363a-2004 Section 14.3.2
// - IEEE 1722-2016 clause 17.3.1
// - Cache-timing attacks: https://en.wikipedia.org/wiki/Timing_attack

#pragma once

#include "statusbar/crypto/keys.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Compute the ciphertext size for a given plaintext size.
///
/// AES-CBC-IV0 always adds PKCS#7 padding (1..16 bytes).
/// @param plaintext_len Length of the plaintext in bytes.
/// @return Ciphertext size in bytes (always a multiple of 16, at least 16).
constexpr auto aes_cbc_iv0_ciphertext_size(size_t plaintext_len) -> size_t
{
    return ((plaintext_len / 16) + 1) * 16;
}

/// @brief AES-256-CBC-IV0 encrypt with PKCS#7 padding.
/// @param key AES-256 key.
/// @param plaintext Input plaintext.
/// @param ciphertext Output buffer (must be at least aes_cbc_iv0_ciphertext_size(plaintext.size())).
/// @return Const span of written ciphertext, or empty span on failure.
auto aes256_cbc_iv0_encrypt(Aes256Key const& key, std::span<uint8_t const> plaintext, std::span<uint8_t> ciphertext)
    -> std::span<uint8_t const>;

/// @brief AES-256-CBC-IV0 decrypt with PKCS#7 unpadding.
///
/// @warning Padding Oracle Risk: The return value (0 on error vs plaintext length on success)
/// inherently leaks whether padding was valid. This function uses constant-time padding
/// verification and branchless return value computation internally, but callers MUST NOT
/// expose the success/failure distinction to attackers through observable behavior (e.g.,
/// different error messages, timing differences in subsequent operations). For authenticated
/// encryption, prefer AES-SIV or AES-GCM-SIV which provide built-in integrity checking.
///
/// @param key AES-256 key.
/// @param ciphertext Input ciphertext (must be a multiple of 16 bytes).
/// @param plaintext Output buffer (must be at least ciphertext.size()).
/// @return Const span of decrypted plaintext, or empty span on padding error (constant-time computation).
auto aes256_cbc_iv0_decrypt(Aes256Key const& key, std::span<uint8_t const> ciphertext, std::span<uint8_t> plaintext)
    -> std::span<uint8_t const>;

}  // namespace statusbar::crypto
