// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes_common_internal.hpp
/// @brief Internal shared AES primitives for statusbar_crypto.
///
/// Contains S-box tables, GF(2^8) arithmetic, state transformations,
/// and CMAC helper functions shared between AES-128 and AES-256 implementations.
/// Not part of the public API — used only by aes128.cpp and aes256.cpp.
///
/// @warning Cache-Timing: The S-box and inverse S-box are 256-byte lookup tables.
/// Table-based AES is vulnerable to cache-timing side channels (Prime+Probe, Flush+Reload,
/// Spectre) when an attacker can observe cache behavior. This software fallback is used ONLY
/// when hardware AES acceleration (AES-NI on x86-64, ARMv8 Crypto Extensions on ARM64) is
/// unavailable. All public API functions (aes*_hw) prefer hardware acceleration and fall back
/// to these tables only on platforms without hardware support. For security-critical deployments,
/// verify hardware AES is available at runtime.

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

/// @brief FIPS 197 S-box (Section 5.1.1).
///
/// Non-linear substitution table used in SubBytes and key schedule.
// clang-format off
constexpr uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/// @brief FIPS 197 inverse S-box (Section 5.3.2).
///
/// Used in InvSubBytes during decryption.
constexpr uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};
// clang-format on

/// @brief Multiply by x (i.e. by 2) in GF(2^8) with reduction by x^8+x^4+x^3+x+1.
///
/// The conditional XOR with 0x1b reduces if the high bit was set.
/// @param x The field element to multiply by 2.
/// @return x * 2 in GF(2^8).
constexpr auto xtime(uint8_t x) -> uint8_t
{
    return static_cast<uint8_t>((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/// @brief Multiply two elements in GF(2^8) using shift-and-add (peasant multiplication).
///
/// Used by InvMixColumns which needs multiplication by {09}, {0b}, {0d}, {0e}.
/// @param a First operand in GF(2^8).
/// @param b Second operand in GF(2^8).
/// @return a * b in GF(2^8).
constexpr auto gf_mul(uint8_t a, uint8_t b) -> uint8_t
{
    uint8_t result = 0;
    uint8_t temp = a;
    for (int i = 0; i < 8; ++i) {
        if ((b & 1) != 0) {
            result ^= temp;
        }
        temp = xtime(temp);
        b >>= 1;
    }
    return result;
}

/// @brief AES state: 4x4 byte matrix stored column-major [col][row] (FIPS 197 Section 3.4).
///
/// Input/output bytes map to state[col][row] = in[col*4 + row].
using State = std::array<std::array<uint8_t, 4>, 4>;

/// @brief Load 16 input bytes into the AES state matrix (FIPS 197 Section 3.4).
/// @param s Output state matrix to populate.
/// @param in 16-byte input data.
void state_from_bytes(State& s, std::span<uint8_t const, aes_block_size> in);

/// @brief Store the AES state matrix back to 16 output bytes (FIPS 197 Section 3.4).
/// @param s Input state matrix to serialize.
/// @param out 16-byte output buffer.
void state_to_bytes(State const& s, std::span<uint8_t, aes_block_size> out);

/// @brief AddRoundKey (FIPS 197 Section 5.1.4): XOR state with a round key.
/// @param s State matrix to modify in place.
/// @param rk 16-byte round key.
void add_round_key(State& s, std::array<uint8_t, aes_block_size> const& rk);

/// @brief SubBytes (FIPS 197 Section 5.1.1): Apply S-box to every byte in state.
/// @param s State matrix to transform in place.
void sub_bytes(State& s);

/// @brief InvSubBytes (FIPS 197 Section 5.3.2): Apply inverse S-box to every byte.
/// @param s State matrix to transform in place.
void inv_sub_bytes(State& s);

/// @brief ShiftRows (FIPS 197 Section 5.1.2): Cyclically left-shift each row.
///
/// Row 0 unchanged, row 1 by 1, row 2 by 2, row 3 by 3.
/// @param s State matrix to transform in place.
void shift_rows(State& s);

/// @brief InvShiftRows (FIPS 197 Section 5.3.1): Cyclically right-shift each row.
///
/// Inverse of ShiftRows. Row 0 unchanged, row 1 right by 1, row 2 right by 2, row 3 right by 3.
/// @param s State matrix to transform in place.
void inv_shift_rows(State& s);

/// @brief MixColumns (FIPS 197 Section 5.1.3): Multiply each column by the fixed polynomial.
///
/// Polynomial: {03}x^3 + {01}x^2 + {01}x + {02} in GF(2^8).
/// Optimized: uses xtime (multiply-by-2) and XOR instead of full gf_mul.
/// @param s State matrix to transform in place.
void mix_columns(State& s);

/// @brief InvMixColumns (FIPS 197 Section 5.3.3): Multiply each column by the inverse polynomial.
///
/// Polynomial: {0b}x^3 + {0d}x^2 + {09}x + {0e} in GF(2^8).
/// Uses full gf_mul since the inverse coefficients aren't simple powers of x.
/// @param s State matrix to transform in place.
void inv_mix_columns(State& s);

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
