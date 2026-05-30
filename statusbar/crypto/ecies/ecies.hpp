// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// DL/ECIES encryption/decryption (IEEE 1363a-2004 Section 11.3)
//
// Implements DL/ECIES with the scheme options from IEEE 1722-2016 clause 17.3.1:
// - ECSVDP-DHC (cofactor DH, h=1 for P-256)
// - KDF2 with SHA-256
// - AES-256-CBC-IV0 (AES-CBC with null IV, PKCS#7 padding)
// - HMAC-SHA-256 (MAC1)
// - DHAES mode (VZ = V || Z for KDF input)
// - EC2OSP-X (x-coordinate-only point encoding, 33 bytes)
//
// Cache-Timing Security:
// The AES-256-CBC-IV0 component uses hardware-accelerated AES when available
// (AES-NI on x86-64, ARMv8 Crypto Extensions on ARM64), which is constant-time
// against cache-timing attacks. On platforms WITHOUT hardware AES, the software
// implementation may be vulnerable to cache-timing side channels (Prime+Probe,
// Spectre, etc.).
//
// Recommendation: Verify your platform supports hardware AES before using ECIES
// for sensitive key material. For IEEE 1722-2016 key distribution, check CPUID
// (x86-64) or ID_AA64ISAR0_EL1 register (ARM64) for crypto capability.
//
// References:
// - IEEE 1363a-2004 Section 11.3
// - IEEE 1722-2016 clause 17
// - Cache-timing attacks: https://en.wikipedia.org/wiki/Timing_attack

#pragma once

#include "statusbar/crypto/keys.hpp"
#include "statusbar/crypto/p256/p256.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// Ephemeral key encoding size: EC2OSP-X = 0x01 || x (33 bytes).
inline constexpr size_t ecies_ephemeral_key_size = 33;

/// MAC tag size: HMAC-SHA-256 output (32 bytes).
inline constexpr size_t ecies_mac_tag_size = 32;

/// Fixed overhead: V (33 bytes) + T (32 bytes) = 65 bytes.
/// Ciphertext C adds aes_cbc_iv0_ciphertext_size(plaintext_len) bytes.
inline constexpr size_t ecies_fixed_overhead = ecies_ephemeral_key_size + ecies_mac_tag_size;

/// Compute total ECIES output size for a given plaintext size.
constexpr auto ecies_output_size(size_t plaintext_len) -> size_t
{
    return ecies_fixed_overhead + (((plaintext_len / 16) + 1) * 16);
}

/// ECIES encrypt.
/// @param recipient_pk Recipient's P-256 public key.
/// @param plaintext Input plaintext to encrypt.
/// @param output Output buffer for V || C || T.
/// @param entropy 32 bytes of random entropy for ephemeral key generation.
/// @return Const span of written output (V || C || T), or empty span on failure.
auto ecies_encrypt(
    P256PublicKey const& recipient_pk,
    std::span<uint8_t const> plaintext,
    std::span<uint8_t> output,
    std::span<uint8_t const, p256_scalar_size> entropy) -> std::span<uint8_t const>;

/// ECIES decrypt.
/// @param sk Recipient's P-256 private key.
/// @param input Input buffer containing V || C || T.
/// @param plaintext Output buffer for decrypted plaintext.
/// @return Const span of decrypted plaintext, or empty span on failure (MAC mismatch or padding error).
auto ecies_decrypt(P256PrivateKey const& sk, std::span<uint8_t const> input, std::span<uint8_t> plaintext)
    -> std::span<uint8_t const>;

}  // namespace statusbar::crypto
