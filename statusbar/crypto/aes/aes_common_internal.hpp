// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes_common_internal.hpp
/// @brief Internal shared CMAC helpers for statusbar_crypto AES.
///
/// CMAC subkey derivation, the templated CMAC cores, and constant-time
/// comparison, shared between the AES-128 and AES-256 implementations.
/// Not part of the public API — used only by aes128.cpp and aes256.cpp.
///
/// The block-cipher round primitives (SubBytes and friends) live in
/// aes_ct_internal.hpp as a constant-time bitsliced core; this module
/// deliberately contains no S-box tables and no secret-indexed lookups.

#pragma once

#include "statusbar/buffer/span_utils.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <utility>

namespace statusbar::crypto {

/// @brief AES block size in bytes (128 bits), shared by AES-128 and AES-256.
inline constexpr size_t aes_block_size = 16;

namespace internal {

/// @brief Left-shift a 16-byte block by 1 bit (big-endian bit order).
///
/// Used in CMAC subkey derivation to compute K1 = L << 1 and K2 = K1 << 1.
/// @param block The 16-byte block to shift in place.
void left_shift_one(std::array<uint8_t, aes_block_size>& block);

/// @brief Constant-time 16-byte comparison for CMAC tag verification.
///
/// Uses fixed-size spans to eliminate the variable-time size check.
/// The comparison accumulates XOR differences so timing is independent of content.
/// @param a First 16-byte value.
/// @param b Second 16-byte value.
/// @return true if a and b are byte-wise identical.
auto constant_time_equal(std::span<uint8_t const, aes_block_size> a, std::span<uint8_t const, aes_block_size> b) -> bool;

/// @brief CMAC subkey pair (K1, K2) derived from the encrypted zero block L.
struct CmacSubkeys
{
    std::array<uint8_t, aes_block_size> K1{};  ///< First subkey.
    std::array<uint8_t, aes_block_size> K2{};  ///< Second subkey.
};

/// @brief CMAC subkey derivation (RFC 4493 / NIST SP 800-38B, constant-time).
///
/// Computes K1 = (L << 1) ^ (msb(L) ? Rb : 0) and K2 = (K1 << 1) ^ (msb(K1) ? Rb : 0),
/// where Rb = 0x87 is the block cipher reduction constant for 128-bit blocks.
/// Uses constant-time masking instead of branching on the MSB to prevent timing leaks.
/// @param L The encrypted zero block E(K, 0^128).
/// @return Subkey pair {K1, K2}.
auto cmac_derive_subkeys(std::array<uint8_t, aes_block_size> const& L) -> CmacSubkeys;

/// @brief Templated CMAC core computation (RFC 4493 / NIST SP 800-38B).
///
/// Computes the 16-byte CMAC tag over an arbitrary-length message using the
/// provided block cipher encryption function.
/// @tparam EncryptFn Callable type with signature void(std::span<uint8_t, aes_block_size>).
/// @param encrypt_block AES block encryption function (encrypts in place).
/// @param message Input data of arbitrary length (including empty).
/// @return 16-byte CMAC authentication tag.
template <typename EncryptFn>
auto cmac_core(EncryptFn encrypt_block, std::span<uint8_t const> message) -> std::array<uint8_t, aes_block_size>
{
    std::array<uint8_t, aes_block_size> L{};
    encrypt_block(std::span<uint8_t, aes_block_size>(L));

    auto [K1, K2] = cmac_derive_subkeys(L);

    size_t const n = message.empty() ? 1 : (message.size() + aes_block_size - 1) / aes_block_size;
    bool const complete = !message.empty() && (message.size() % aes_block_size == 0);

    std::array<uint8_t, aes_block_size> X{};

    for (size_t i = 0; i + 1 < n; ++i) {
        for (size_t j = 0; j < aes_block_size; ++j) {
            X[j] ^= message[(i * aes_block_size) + j];
        }
        encrypt_block(std::span<uint8_t, aes_block_size>(X));
    }

    std::array<uint8_t, aes_block_size> last{};
    size_t const offset = (n - 1) * aes_block_size;
    size_t const remaining = message.size() - offset;

    if (remaining > 0) {
        statusbar::span_copy(std::span<uint8_t>(last).first(remaining), message.subspan(offset, remaining));
    }

    if (complete) {
        for (size_t j = 0; j < aes_block_size; ++j) {
            last[j] ^= K1[j];
        }
    } else {
        last[remaining] = 0x80;
        for (size_t j = 0; j < aes_block_size; ++j) {
            last[j] ^= K2[j];
        }
    }

    for (size_t j = 0; j < aes_block_size; ++j) {
        X[j] ^= last[j];
    }
    encrypt_block(std::span<uint8_t, aes_block_size>(X));

    return X;
}

/// @brief Templated CMAC-xorend computation (RFC 5297 Section 2.4 helper).
///
/// Computes CMAC over a modified message where the last 16 bytes are XORed
/// with @p xor_end during processing, avoiding a copy of the message.
/// Used by AES-SIV's S2V construction.
///
/// @pre message.size() >= 16. Returns a zero tag if this precondition is violated.
///
/// @tparam EncryptFn Callable type with signature void(std::span<uint8_t, aes_block_size>).
/// @param encrypt_block AES block encryption function (encrypts in place).
/// @param message Input data (must be >= 16 bytes).
/// @param xor_end 16-byte mask XORed into the last 16 bytes during processing.
/// @return 16-byte CMAC authentication tag, or all-zeros if message < 16 bytes.
template <typename EncryptFn>
auto cmac_xorend_core(EncryptFn encrypt_block, std::span<uint8_t const> message, std::span<uint8_t const, aes_block_size> xor_end)
    -> std::array<uint8_t, aes_block_size>
{
    if (message.size() < aes_block_size) {
        return {};
    }

    std::array<uint8_t, aes_block_size> L{};
    encrypt_block(std::span<uint8_t, aes_block_size>(L));

    auto [K1, K2] = cmac_derive_subkeys(L);

    size_t const n = (message.size() + aes_block_size - 1) / aes_block_size;
    bool const complete = (message.size() % aes_block_size == 0);
    size_t const xor_off = message.size() - aes_block_size;

    std::array<uint8_t, aes_block_size> X{};

    for (size_t i = 0; i + 1 < n; ++i) {
        for (size_t j = 0; j < aes_block_size; ++j) {
            size_t const pos = (i * aes_block_size) + j;
            uint8_t byte = message[pos];
            if (pos >= xor_off) {
                byte ^= xor_end[pos - xor_off];
            }
            X[j] ^= byte;
        }
        encrypt_block(std::span<uint8_t, aes_block_size>(X));
    }

    std::array<uint8_t, aes_block_size> last{};
    size_t const offset = (n - 1) * aes_block_size;
    size_t const remaining = message.size() - offset;

    for (size_t j = 0; j < remaining; ++j) {
        size_t const pos = offset + j;
        uint8_t byte = message[pos];
        if (pos >= xor_off) {
            byte ^= xor_end[pos - xor_off];
        }
        last[j] = byte;
    }

    if (complete) {
        for (size_t j = 0; j < aes_block_size; ++j) {
            last[j] ^= K1[j];
        }
    } else {
        last[remaining] = 0x80;
        for (size_t j = 0; j < aes_block_size; ++j) {
            last[j] ^= K2[j];
        }
    }

    for (size_t j = 0; j < aes_block_size; ++j) {
        X[j] ^= last[j];
    }
    encrypt_block(std::span<uint8_t, aes_block_size>(X));

    return X;
}

/// @brief Templated CMAC tag verification with constant-time comparison.
/// @tparam EncryptFn Callable type with signature void(std::span<uint8_t, aes_block_size>).
/// @param encrypt_block AES block encryption function (encrypts in place).
/// @param message Input data that was authenticated.
/// @param expected_tag The 16-byte tag to verify against.
/// @return true if the computed CMAC tag matches @p expected_tag.
template <typename EncryptFn>
auto cmac_verify_core(
    EncryptFn encrypt_block, std::span<uint8_t const> message, std::span<uint8_t const, aes_block_size> expected_tag) -> bool
{
    auto computed = cmac_core(encrypt_block, message);
    return constant_time_equal(
        std::span<uint8_t const, aes_block_size>{computed}, std::span<uint8_t const, aes_block_size>{expected_tag});
}

}  // namespace internal
}  // namespace statusbar::crypto
