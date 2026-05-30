// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-256 block cipher and CMAC
//
// References:
// - FIPS 197: Advanced Encryption Standard (AES)
//   https://csrc.nist.gov/publications/detail/fips/197/final
// - NIST SP 800-38B: Recommendation for Block Cipher Modes of Operation: The CMAC Mode
//   https://csrc.nist.gov/publications/detail/sp/800-38b/final

#pragma once

#include "statusbar/crypto/keys.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief AES-256 block size in bytes.
inline constexpr size_t aes256_block_size = 16;

/// @brief Number of AES-256 encryption rounds (FIPS 197 Section 5.1).
inline constexpr size_t aes256_num_rounds = 14;

/// @brief Expanded round keys from the AES-256 key schedule (FIPS 197 Section 5.2).
///
/// Contains Nr+1 = 15 round keys, each 16 bytes, derived from the original
/// 256-bit key. Round keys 0-1 are the key itself (8 words = 32 bytes);
/// subsequent keys are computed via RotWord, SubWord, XOR with round constants,
/// and an additional SubWord on word 4 of each 8-word group (AES-256 specific).
struct Aes256RoundKeys
{
    /// 15 round keys (Nr+1), each 16 bytes, stored in round order.
    std::array<std::array<uint8_t, aes256_block_size>, aes256_num_rounds + 1> round_keys{};

    Aes256RoundKeys() = default;

    /// Prevent accidental copying of key material.
    Aes256RoundKeys(Aes256RoundKeys const&) = delete;
    auto operator=(Aes256RoundKeys const&) -> Aes256RoundKeys& = delete;

    /// Move constructor: transfers key material and zeroes the source.
    Aes256RoundKeys(Aes256RoundKeys&& other) noexcept
        : round_keys(other.round_keys)
    {
        internal::secure_zero(other.round_keys);
    }

    /// Move assignment: transfers key material and zeroes the source.
    auto operator=(Aes256RoundKeys&& other) noexcept -> Aes256RoundKeys&
    {
        if (this != &other) {
            internal::secure_zero(round_keys);
            round_keys = other.round_keys;
            internal::secure_zero(other.round_keys);
        }
        return *this;
    }

    /// Securely zero expanded key material on destruction.
    ~Aes256RoundKeys() { internal::secure_zero(round_keys); }
};

/// @brief Expand a 256-bit key into 15 round keys (FIPS 197 Section 5.2).
/// @param key The 256-bit AES key.
/// @return Expanded round keys for use with encrypt/decrypt operations.
auto aes256_expand_key_sw(Aes256Key const& key) -> Aes256RoundKeys;

/// @brief Encrypt a single 16-byte block in place (FIPS 197 Section 5.1).
/// @param rk Expanded round keys from aes256_expand_key().
/// @param block 16-byte block to encrypt in place.
void aes256_encrypt_block_sw(Aes256RoundKeys const& rk, std::span<uint8_t, aes256_block_size> block);

/// @brief Decrypt a single 16-byte block in place (FIPS 197 Section 5.3).
/// @param rk Expanded round keys from aes256_expand_key().
/// @param block 16-byte block to decrypt in place.
void aes256_decrypt_block_sw(Aes256RoundKeys const& rk, std::span<uint8_t, aes256_block_size> block);

/// @brief Compute AES-256-CMAC authentication tag (NIST SP 800-38B).
///
/// Used in IEEE 1722 for key derivation and message authentication.
/// @param rk Expanded round keys from aes256_expand_key().
/// @param message Input data of arbitrary length.
/// @return 16-byte CMAC authentication tag.
auto aes256_cmac_sw(Aes256RoundKeys const& rk, std::span<uint8_t const> message) -> std::array<uint8_t, aes256_block_size>;

/// @brief Compute AES-256-CMAC with xorend (RFC 5297 Section 2.4 helper).
///
/// Equivalent to AES-256-CMAC over a modified message where the last 16 bytes
/// are XORed with @p xor_end, but avoids copying the message.
///
/// @pre message.size() >= 16. Returns an all-zero tag if this precondition is violated.
///
/// @param rk Expanded round keys from aes256_expand_key().
/// @param message Input data (must be >= 16 bytes).
/// @param xor_end 16-byte mask XORed into the last 16 bytes during processing.
/// @return 16-byte CMAC authentication tag, or all-zeros if message < 16 bytes.
auto aes256_cmac_xorend_sw(
    Aes256RoundKeys const& rk, std::span<uint8_t const> message, std::span<uint8_t const, aes256_block_size> xor_end)
    -> std::array<uint8_t, aes256_block_size>;

/// @brief Verify an AES-256-CMAC tag using constant-time comparison.
/// @param rk Expanded round keys from aes256_expand_key().
/// @param message Input data that was authenticated.
/// @param expected_tag The 16-byte tag to verify against.
/// @return true if the computed tag matches expected_tag.
auto aes256_cmac_verify_sw(
    Aes256RoundKeys const& rk, std::span<uint8_t const> message, std::span<uint8_t const, aes256_block_size> expected_tag) -> bool;

}  // namespace statusbar::crypto
