// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes128_hw.hpp
/// @brief AES-128 hardware-accelerated block cipher and CMAC.
///
/// Mirrors the software API in aes128.hpp with @c _hw suffix on all function names.
/// Uses hardware acceleration when available, falls back to software otherwise.
///   - ARM64: ARMv8 Crypto Extensions (AESE/AESD/AESMC/AESIMC)
///   - x86-64: AES-NI (AESENC/AESDEC/AESKEYGENASSIST)
///
/// @see aes128.hpp for the software-only implementations.

#pragma once

#include "statusbar/crypto/aes/aes128.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Expand a 128-bit key into 11 round keys (FIPS 197 Section 5.2).
///
/// Uses hardware-accelerated key expansion when available.
/// @param key The 128-bit AES key.
/// @return Expanded round keys for use with encrypt/decrypt operations.
auto aes128_expand_key_hw(Aes128Key const& key) -> Aes128RoundKeys;

/// @brief Encrypt a single 16-byte block in place (FIPS 197 Section 5.1).
///
/// Uses hardware-accelerated AES encryption when available.
/// @param rk Expanded round keys from aes128_expand_key_hw().
/// @param block 16-byte block to encrypt in place.
void aes128_encrypt_block_hw(Aes128RoundKeys const& rk, std::span<uint8_t, aes128_block_size> block);

/// @brief Decrypt a single 16-byte block in place (FIPS 197 Section 5.3).
///
/// Uses hardware-accelerated AES decryption when available.
/// @param rk Expanded round keys from aes128_expand_key_hw().
/// @param block 16-byte block to decrypt in place.
void aes128_decrypt_block_hw(Aes128RoundKeys const& rk, std::span<uint8_t, aes128_block_size> block);

/// @brief Encrypt 4 independent 16-byte blocks in place, pipelined.
///
/// Interleaves the AES rounds across all 4 blocks so the CPU's AES
/// execution units stay full. Throughput is roughly 4× a single-block
/// call on cores with enough AES issue width (most modern Apple Silicon
/// and Intel/AMD AES-NI parts). Useful for CTR, CBC-MAC over long
/// messages, and GCM-style workloads.
///
/// Input is a single contiguous 64-byte span treated as 4 consecutive
/// blocks. All 4 are encrypted with the same expanded key.
///
/// @param rk Expanded round keys from aes128_expand_key_hw().
/// @param blocks 64 bytes (4 × 16) to encrypt in place.
void aes128_encrypt_blocks_x4_hw(Aes128RoundKeys const& rk, std::span<uint8_t, 4 * aes128_block_size> blocks);

/// @brief Compute AES-128-CMAC authentication tag (RFC 4493).
///
/// Uses hardware-accelerated AES encryption when available.
/// @param rk Expanded round keys from aes128_expand_key_hw().
/// @param message Input data of arbitrary length.
/// @return 16-byte CMAC authentication tag.
auto aes128_cmac_hw(Aes128RoundKeys const& rk, std::span<uint8_t const> message) -> std::array<uint8_t, aes128_block_size>;

/// @brief Compute AES-128-CMAC with xorend (RFC 5297 Section 2.4 helper).
///
/// Equivalent to AES-128-CMAC over a modified message where the last 16 bytes
/// are XORed with @p xor_end, but avoids copying the message.
/// Uses hardware-accelerated AES encryption when available.
/// @param rk Expanded round keys from aes128_expand_key_hw().
/// @param message Input data (must be >= 16 bytes).
/// @param xor_end 16-byte mask XORed into the last 16 bytes during processing.
/// @return 16-byte CMAC authentication tag.
auto aes128_cmac_xorend_hw(
    Aes128RoundKeys const& rk, std::span<uint8_t const> message, std::span<uint8_t const, aes128_block_size> xor_end)
    -> std::array<uint8_t, aes128_block_size>;

/// @brief Verify an AES-128-CMAC tag using constant-time comparison.
///
/// Uses hardware-accelerated AES encryption when available.
/// @param rk Expanded round keys from aes128_expand_key_hw().
/// @param message Input data that was authenticated.
/// @param expected_tag The 16-byte tag to verify against.
/// @return true if the computed tag matches expected_tag.
auto aes128_cmac_verify_hw(
    Aes128RoundKeys const& rk, std::span<uint8_t const> message, std::span<uint8_t const, aes128_block_size> expected_tag) -> bool;

}  // namespace statusbar::crypto
