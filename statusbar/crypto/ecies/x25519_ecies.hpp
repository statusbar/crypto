// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 ECIES encryption/decryption (IEEE 1722-2016 Clause 17, enc=1)
//
// Implements ECIES using X25519 ECDH with HKDF-SHA-256 key derivation:
// - Ephemeral X25519 keypair for each encryption
// - HKDF-SHA-256 with domain-separated info string ("X25519-ECIES" || V)
// - AES-256-CBC-IV0 (AES-CBC with null IV, PKCS#7 padding)
// - HMAC-SHA-256 (MAC)
//
// Wire format: V(32) || C(variable, block-aligned) || T(32)
//   V: 32 bytes (ephemeral X25519 public key, Montgomery u-coordinate, little-endian)
//   C: AES-256-CBC-IV0 ciphertext with PKCS#7 padding
//   T: 32 bytes (HMAC-SHA-256 MAC tag)
//
// Cache-Timing Security:
// Same as P-256 ECIES — uses hardware-accelerated AES when available
// (AES-NI on x86-64, ARMv8 Crypto Extensions on ARM64). On platforms
// WITHOUT hardware AES, the software implementation may be vulnerable
// to cache-timing side channels.

#pragma once

#include "statusbar/crypto/25519/x25519.hpp"
#include "statusbar/crypto/keys.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// Ephemeral key encoding size: native X25519 public key (32 bytes).
inline constexpr size_t x25519_ecies_ephemeral_key_size = 32;

/// MAC tag size: HMAC-SHA-256 output (32 bytes).
inline constexpr size_t x25519_ecies_mac_tag_size = 32;

/// Fixed overhead: V (32 bytes) + T (32 bytes) = 64 bytes.
/// Ciphertext C adds aes_cbc_iv0_ciphertext_size(plaintext_len) bytes.
inline constexpr size_t x25519_ecies_fixed_overhead = x25519_ecies_ephemeral_key_size + x25519_ecies_mac_tag_size;

/// Compute total X25519 ECIES output size for a given plaintext size.
constexpr auto x25519_ecies_output_size(size_t plaintext_len) -> size_t
{
    return x25519_ecies_fixed_overhead + (((plaintext_len / 16) + 1) * 16);
}

/// X25519 ECIES encrypt.
/// @param recipient_pk Recipient's X25519 public key.
/// @param plaintext Input plaintext to encrypt.
/// @param output Output buffer for V || C || T.
/// @param entropy 32 bytes of random entropy for ephemeral key generation.
/// @return Const span of written output (V || C || T), or empty span on failure.
auto x25519_ecies_encrypt(
    X25519PublicKey const& recipient_pk,
    std::span<uint8_t const> plaintext,
    std::span<uint8_t> output,
    std::span<uint8_t const, X25519PrivateKey::LENGTH> entropy) -> std::span<uint8_t const>;

/// X25519 ECIES decrypt.
/// @param sk Recipient's X25519 private key.
/// @param input Input buffer containing V || C || T.
/// @param plaintext Output buffer for decrypted plaintext.
/// @return Const span of decrypted plaintext, or empty span on failure (MAC mismatch or padding error).
auto x25519_ecies_decrypt(X25519PrivateKey const& sk, std::span<uint8_t const> input, std::span<uint8_t> plaintext)
    -> std::span<uint8_t const>;

}  // namespace statusbar::crypto
