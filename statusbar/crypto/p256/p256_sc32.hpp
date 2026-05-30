// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// NIST P-256 scalar arithmetic (mod n) — 32-bit reduced-radix implementation.
//
// The 32-bit-ALU-friendly counterpart of the p256_sc_* functions in p256.cpp,
// which rely on __uint128_t for 64x64->128 products. This file uses nothing
// wider than uint64_t. It is the scalar-field companion of p256_fe32 (the
// prime-field arithmetic) and is cross-checked against the 4x64-bit
// implementation by p256_sc32_test.cpp.
//
// Representation
// --------------
// A scalar is 8 limbs of radix 2^32 (limbs[0] least significant). The group
// order n has no Solinas structure, so a wide value is reduced mod n by the
// fold  x = x_hi * (2^256 mod n) + x_lo, iterated until the high half clears.

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief NIST P-256 scalar in Z_n, 8 limbs of radix 2^32.
///
/// The 32-bit-ALU-friendly counterpart of P256Scalar. Limbs are zeroed on
/// destruction to protect private key / nonce material.
struct P256Scalar32
{
    std::array<uint32_t, 8> limbs{};

    constexpr ~P256Scalar32()
    {
        if !consteval {
            internal::secure_zero(limbs);
        }
    }
};

//
// Scalar operations (constant-time). Semantics match the p256_sc_* functions
// in p256.hpp exactly; only the internal representation differs.
//

/// @brief Add two scalars mod n.
auto p256_sc32_add(P256Scalar32 const& a, P256Scalar32 const& b) -> P256Scalar32;

/// @brief Subtract b from a mod n.
auto p256_sc32_sub(P256Scalar32 const& a, P256Scalar32 const& b) -> P256Scalar32;

/// @brief Negate a scalar: n - a mod n.
auto p256_sc32_negate(P256Scalar32 const& a) -> P256Scalar32;

/// @brief Multiply two scalars mod n.
auto p256_sc32_mul(P256Scalar32 const& a, P256Scalar32 const& b) -> P256Scalar32;

/// @brief Multiplicative inverse a^(n-2) mod n via square-and-multiply.
auto p256_sc32_inv(P256Scalar32 const& a) -> P256Scalar32;

/// @brief Return true if a == 0 (a must already be reduced mod n).
auto p256_sc32_is_zero(P256Scalar32 const& a) -> bool;

/// @brief Deserialize a 32-byte big-endian encoding (not reduced mod n).
auto p256_sc32_from_bytes(std::span<uint8_t const, 32> bytes) -> P256Scalar32;

/// @brief Serialize to a 32-byte big-endian encoding (not reduced mod n).
auto p256_sc32_to_bytes(P256Scalar32 const& a) -> std::array<uint8_t, 32>;

/// @brief Reduce a 64-byte big-endian (512-bit) value mod n.
auto p256_sc32_reduce_wide(std::span<uint8_t const, 64> wide) -> P256Scalar32;

}  // namespace statusbar::crypto
