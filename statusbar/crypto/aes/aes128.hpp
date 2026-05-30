// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-128 block cipher and CMAC
//
// References:
// - FIPS 197: Advanced Encryption Standard (AES)
//   https://csrc.nist.gov/publications/detail/fips/197/final
// - NIST SP 800-38B / RFC 4493: AES-CMAC
//   https://www.rfc-editor.org/rfc/rfc4493

#pragma once

#include "statusbar/crypto/keys.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief AES-128 block size in bytes.
inline constexpr size_t aes128_block_size = 16;

/// @brief Number of AES-128 encryption rounds (FIPS 197 Section 5.1).
inline constexpr size_t aes128_num_rounds = 10;

/// @brief Expanded round keys from the AES-128 key schedule (FIPS 197 Section 5.2).
///
/// Contains Nr+1 = 11 round keys, each 16 bytes, derived from the original
/// 128-bit key. Round key 0 is the key itself; subsequent keys are computed
/// via RotWord, SubWord, and XOR with round constants.
struct Aes128RoundKeys
{
    /// 11 round keys (Nr+1), each 16 bytes, stored in round order.
    std::array<std::array<uint8_t, aes128_block_size>, aes128_num_rounds + 1> round_keys{};

    Aes128RoundKeys() = default;

    /// Prevent accidental copying of key material.
    Aes128RoundKeys(Aes128RoundKeys const&) = delete;
    auto operator=(Aes128RoundKeys const&) -> Aes128RoundKeys& = delete;

    /// Move constructor: transfers key material and zeroes the source.
    Aes128RoundKeys(Aes128RoundKeys&& other) noexcept
        : round_keys(other.round_keys)
    {
        internal::secure_zero(other.round_keys);
    }

    /// Move assignment: transfers key material and zeroes the source.
    auto operator=(Aes128RoundKeys&& other) noexcept -> Aes128RoundKeys&
    {
        if (this != &other) {
            internal::secure_zero(round_keys);
            round_keys = other.round_keys;
            internal::secure_zero(other.round_keys);
        }
        return *this;
    }

    /// Securely zero expanded key material on destruction.
    ~Aes128RoundKeys() { internal::secure_zero(round_keys); }
};

/// @brief Expand a 128-bit key into 11 round keys (FIPS 197 Section 5.2).
/// @param key The 128-bit AES key.
/// @return Expanded round keys for use with encrypt/decrypt operations.
auto aes128_expand_key_sw(Aes128Key const& key) -> Aes128RoundKeys;

/// @brief Encrypt a single 16-byte block in place (FIPS 197 Section 5.1).
/// @param rk Expanded round keys from aes128_expand_key().
/// @param block 16-byte block to encrypt in place.
void aes128_encrypt_block_sw(Aes128RoundKeys const& rk, std::span<uint8_t, aes128_block_size> block);

/// @brief Decrypt a single 16-byte block in place (FIPS 197 Section 5.3).
/// @param rk Expanded round keys from aes128_expand_key().
/// @param block 16-byte block to decrypt in place.
void aes128_decrypt_block_sw(Aes128RoundKeys const& rk, std::span<uint8_t, aes128_block_size> block);

/// @brief Compute AES-128-CMAC authentication tag (RFC 4493).
///
/// Used in IEEE 1722 for key derivation and message authentication.
/// @param rk Expanded round keys from aes128_expand_key().
/// @param message Input data of arbitrary length.
/// @return 16-byte CMAC authentication tag.
auto aes128_cmac_sw(Aes128RoundKeys const& rk, std::span<uint8_t const> message) -> std::array<uint8_t, aes128_block_size>;

/// @brief Compute AES-128-CMAC with xorend (RFC 5297 Section 2.4 helper).
///
/// Equivalent to AES-128-CMAC over a modified message where the last 16 bytes
/// are XORed with @p xor_end, but avoids copying the message.
///
/// @pre message.size() >= 16. Returns an all-zero tag if this precondition is violated.
///
/// @param rk Expanded round keys from aes128_expand_key().
/// @param message Input data (must be >= 16 bytes).
/// @param xor_end 16-byte mask XORed into the last 16 bytes during processing.
/// @return 16-byte CMAC authentication tag, or all-zeros if message < 16 bytes.
auto aes128_cmac_xorend_sw(
    Aes128RoundKeys const& rk, std::span<uint8_t const> message, std::span<uint8_t const, aes128_block_size> xor_end)
    -> std::array<uint8_t, aes128_block_size>;

/// @brief Verify an AES-128-CMAC tag using constant-time comparison.
/// @param rk Expanded round keys from aes128_expand_key().
/// @param message Input data that was authenticated.
/// @param expected_tag The 16-byte tag to verify against.
/// @return true if the computed tag matches expected_tag.
auto aes128_cmac_verify_sw(
    Aes128RoundKeys const& rk, std::span<uint8_t const> message, std::span<uint8_t const, aes128_block_size> expected_tag) -> bool;

}  // namespace statusbar::crypto
