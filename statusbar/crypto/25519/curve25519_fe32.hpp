// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Curve25519 field arithmetic — 32-bit reduced-radix implementation.
//
// This is a portable alternative to the 5x51-bit field arithmetic in
// curve25519.cpp, which relies on a 128-bit integer type (__uint128_t) for
// 64x64->128 products. That type is only available on 64-bit targets; this
// file provides the same GF(2^255-19) field operations using nothing wider
// than uint64_t, so the library can run on a 32-bit ALU.
//
// Both implementations are always compiled. curve25519_fe32_test.cpp
// cross-checks every operation here against the 5x51-bit implementation, so
// this code is continuously validated and cannot bit-rot.
//
// Representation
// --------------
// A field element is 10 limbs (radix 2^25.5 — the ref10 layout): limb i
// holds value limbs[i] * 2^e(i) where
//     e = {0, 26, 51, 77, 102, 128, 153, 179, 204, 230}.
// Even-index limbs carry 26 bits, odd-index limbs carry 25 bits, summing to
// 255. This split is chosen so that a schoolbook product's per-limb column
// sums stay within a uint64_t accumulator without a 128-bit type, and so the
// 2^255 wraparound lands exactly on the limb-10 boundary (2^255 = 19 mod p).
//
// Limbs may be slightly unreduced (a few bits above the nominal width)
// between operations; full reduction to [0, p) happens in fe25519x32_to_bytes.

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Curve25519 field element in GF(2^255-19), 10 limbs of radix 2^25.5.
///
/// The 32-bit-ALU-friendly counterpart of Fe25519. Limbs are zeroed on
/// destruction to keep intermediate values off the stack.
struct Fe25519x32
{
    std::array<uint32_t, 10> limbs{};

    /// constexpr so Fe25519x32 stays a literal type for constexpr constants.
    constexpr ~Fe25519x32()
    {
        if !consteval {
            internal::secure_zero(limbs);
        }
    }
};

//
// Field operations (constant-time). Semantics match the fe25519_* functions
// in curve25519.hpp exactly; only the internal representation differs.
//

/// @brief Return the additive identity (zero).
auto fe25519x32_zero() -> Fe25519x32;

/// @brief Return the multiplicative identity (one).
auto fe25519x32_one() -> Fe25519x32;

/// @brief Add two field elements. Result may be unreduced.
auto fe25519x32_add(Fe25519x32 const& a, Fe25519x32 const& b) -> Fe25519x32;

/// @brief Subtract two field elements (b from a). Result may be unreduced.
auto fe25519x32_sub(Fe25519x32 const& a, Fe25519x32 const& b) -> Fe25519x32;

/// @brief Multiply two field elements mod p. Result partially reduced.
auto fe25519x32_mul(Fe25519x32 const& a, Fe25519x32 const& b) -> Fe25519x32;

/// @brief Square a field element mod p. Result partially reduced.
auto fe25519x32_sq(Fe25519x32 const& a) -> Fe25519x32;

/// @brief Multiply a field element by a small (<= 32-bit) integer mod p.
auto fe25519x32_mul_small(Fe25519x32 const& a, uint32_t b) -> Fe25519x32;

/// @brief Negate a field element: p - a mod p.
auto fe25519x32_neg(Fe25519x32 const& a) -> Fe25519x32;

/// @brief Multiplicative inverse a^(p-2) mod p via addition chain.
auto fe25519x32_invert(Fe25519x32 const& a) -> Fe25519x32;

/// @brief Compute a^((p-5)/8) = a^(2^252 - 3), used in point decompression.
auto fe25519x32_pow22523(Fe25519x32 const& a) -> Fe25519x32;

/// @brief Constant-time conditional move: f = (b != 0) ? g : f. b must be 0 or 1.
void fe25519x32_cmov(Fe25519x32& f, Fe25519x32 const& g, uint32_t b);

/// @brief Deserialize 32 little-endian bytes into a field element (bit 255 masked).
auto fe25519x32_from_bytes(std::span<uint8_t const, 32> s) -> Fe25519x32;

/// @brief Serialize to canonical 32-byte little-endian form (fully reduced).
auto fe25519x32_to_bytes(Fe25519x32 const& h) -> std::array<uint8_t, 32>;

/// @brief Return the low bit of the canonical encoding (the RFC 8032 "sign").
auto fe25519x32_is_negative(Fe25519x32 const& f) -> uint32_t;

/// @brief Return 1 if f == 0 mod p, else 0 (constant-time).
auto fe25519x32_is_zero(Fe25519x32 const& f) -> uint32_t;

}  // namespace statusbar::crypto
