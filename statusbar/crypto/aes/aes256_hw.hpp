// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes256_hw.hpp
/// @brief AES-256 hardware-accelerated block cipher and CMAC.
///
/// Mirrors the software API in aes256.hpp with @c _hw suffix on all function names.
/// Uses hardware acceleration when available, falls back to software otherwise.
///   - ARM64: ARMv8 Crypto Extensions (AESE/AESD/AESMC/AESIMC)
///   - x86-64: AES-NI (AESENC/AESDEC/AESKEYGENASSIST)
///
/// @see aes256.hpp for the software-only implementations.

#pragma once

#include "statusbar/crypto/aes/aes256.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Expand a 256-bit key into 15 round keys (FIPS 197 Section 5.2).
///
/// Uses hardware-accelerated key expansion when available.
/// @param key The 256-bit AES key.
/// @return Expanded round keys for use with encrypt/decrypt operations.
auto aes256_expand_key_hw(Aes256Key const& key) -> Aes256RoundKeys;

/// @brief Encrypt a single 16-byte block in place (FIPS 197 Section 5.1).
///
/// Uses hardware-accelerated AES encryption when available.
/// @param rk Expanded round keys from aes256_expand_key_hw().
/// @param block 16-byte block to encrypt in place.
void aes256_encrypt_block_hw(Aes256RoundKeys const& rk, std::span<uint8_t, aes256_block_size> block);

/// @brief Decrypt a single 16-byte block in place (FIPS 197 Section 5.3).
///
/// Uses hardware-accelerated AES decryption when available.
/// @param rk Expanded round keys from aes256_expand_key_hw().
/// @param block 16-byte block to decrypt in place.
void aes256_decrypt_block_hw(Aes256RoundKeys const& rk, std::span<uint8_t, aes256_block_size> block);

/// @brief Compute AES-256-CMAC authentication tag (NIST SP 800-38B).
///
/// Uses hardware-accelerated AES encryption when available.
/// @param rk Expanded round keys from aes256_expand_key_hw().
/// @param message Input data of arbitrary length.
/// @return 16-byte CMAC authentication tag.
auto aes256_cmac_hw(Aes256RoundKeys const& rk, std::span<uint8_t const> message) -> std::array<uint8_t, aes256_block_size>;

/// @brief Compute AES-256-CMAC with xorend (RFC 5297 Section 2.4 helper).
///
/// Equivalent to AES-256-CMAC over a modified message where the last 16 bytes
/// are XORed with @p xor_end, but avoids copying the message.
/// Uses hardware-accelerated AES encryption when available.
/// @param rk Expanded round keys from aes256_expand_key_hw().
/// @param message Input data (must be >= 16 bytes).
/// @param xor_end 16-byte mask XORed into the last 16 bytes during processing.
/// @return 16-byte CMAC authentication tag.
auto aes256_cmac_xorend_hw(
    Aes256RoundKeys const& rk, std::span<uint8_t const> message, std::span<uint8_t const, aes256_block_size> xor_end)
    -> std::array<uint8_t, aes256_block_size>;

/// @brief Verify an AES-256-CMAC tag using constant-time comparison.
///
/// Uses hardware-accelerated AES encryption when available.
/// @param rk Expanded round keys from aes256_expand_key_hw().
/// @param message Input data that was authenticated.
/// @param expected_tag The 16-byte tag to verify against.
/// @return true if the computed tag matches expected_tag.
auto aes256_cmac_verify_hw(
    Aes256RoundKeys const& rk, std::span<uint8_t const> message, std::span<uint8_t const, aes256_block_size> expected_tag) -> bool;

}  // namespace statusbar::crypto
