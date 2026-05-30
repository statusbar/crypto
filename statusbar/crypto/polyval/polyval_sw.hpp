// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file polyval_sw.hpp
/// @brief POLYVAL universal hash function — types and software implementation (RFC 8452 Section 3).
///
/// Defines the POLYVAL hash primitive specified in RFC 8452 Section 3.
/// POLYVAL is used within AES-GCM-SIV to compute authentication tags over
/// additional authenticated data (AAD) and plaintext.
///
/// @see https://www.rfc-editor.org/rfc/rfc8452

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief POLYVAL block size in bytes (128 bits).
inline constexpr size_t polyval_block_size = 16;

/// @brief Check whether input is valid for polyval_update_sw() / polyval_update_hw().
///
/// Input must be a multiple of polyval_block_size (16 bytes). Callers should
/// invoke this as early as possible, before calling polyval_sw(), polyval_update_sw(),
/// polyval_hw(), or polyval_update_hw().
///
/// @param input The data to validate.
/// @return true if input size is a multiple of polyval_block_size (16 bytes).
inline auto polyval_can_update(std::span<uint8_t const> input) -> bool
{
    return input.size() % polyval_block_size == 0;
}

/// @brief POLYVAL hash key (128-bit), derived per-message during the AES-GCM-SIV key schedule.
///
/// The key is used as the hash multiplier H in the POLYVAL accumulation.
/// A fresh key is derived for each message from the master key and nonce
/// via the AES-GCM-SIV key derivation function (RFC 8452 Section 4).
struct PolyvalKey
{
    /// @brief The 16-byte (128-bit) hash key value, stored in little-endian byte order.
    std::array<uint8_t, polyval_block_size> data{};

    /// Securely zero key material on destruction.
    ~PolyvalKey() { internal::secure_zero(data); }
};

/// @brief Compute the POLYVAL hash over the given input in a single call.
///
/// POLYVAL is a universal hash function defined in RFC 8452 Section 3.
/// It operates over GF(2^128) with the irreducible polynomial
/// x^128 + x^127 + x^126 + x^121 + 1, processing 16-byte blocks.
///
/// @pre polyval_can_update(input) — input size must be a multiple of 16 bytes.
/// @param H     The 128-bit POLYVAL hash key.
/// @param input Data to hash. The caller is responsible for zero-padding partial blocks.
/// @return      The 16-byte POLYVAL hash result.
auto polyval_sw(PolyvalKey const& H, std::span<uint8_t const> input) -> std::array<uint8_t, polyval_block_size>;

/// @brief Incrementally update a POLYVAL accumulator with additional input blocks.
///
/// Processes one or more 16-byte blocks into an existing accumulator,
/// enabling streaming computation of POLYVAL across disjoint data
/// segments (e.g., AAD, plaintext, and length block separately).
///
/// @pre polyval_can_update(input) — input size must be a multiple of 16 bytes.
/// @param H           The 128-bit POLYVAL hash key.
/// @param input       Data to absorb. The caller is responsible for zero-padding partial blocks.
/// @param accumulator The running POLYVAL state, updated in place. Must be
///                    zero-initialized for the first call in a new hash computation.
void polyval_update_sw(PolyvalKey const& H, std::span<uint8_t const> input, std::span<uint8_t, polyval_block_size> accumulator);

}  // namespace statusbar::crypto
