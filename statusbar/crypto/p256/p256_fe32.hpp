// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// NIST P-256 field arithmetic — 32-bit reduced-radix implementation.
//
// A portable alternative to the 4x64-bit field arithmetic in p256.cpp, which
// relies on __uint128_t (and __int128_t) for 64x64->128 products and the
// signed Solinas-reduction accumulators. Those types are only available on
// 64-bit targets; this file provides the same GF(p) field operations using
// nothing wider than uint64_t / int64_t, so the field layer runs on a 32-bit
// ALU.
//
// Both implementations are always compiled. p256_fe32_test.cpp cross-checks
// every operation here against the 4x64-bit implementation.
//
// Representation
// --------------
// A field element is 8 limbs of radix 2^32 (limbs[0] least significant) — the
// natural word size for the NIST P-256 Solinas reduction, which is defined in
// terms of 32-bit words. The prime is
//     p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
// A schoolbook 8x8 product is reduced with the NIST formula
//     T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4   (mod p).

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

/// @brief NIST P-256 field element in GF(p), 8 limbs of radix 2^32.
///
/// The 32-bit-ALU-friendly counterpart of P256FieldElement. Limbs are zeroed
/// on destruction to keep intermediate values off the stack.
struct P256FieldElement32
{
    std::array<uint32_t, 8> limbs{};

    constexpr ~P256FieldElement32()
    {
        if !consteval {
            internal::secure_zero(limbs);
        }
    }
};

//
// Field operations (constant-time). Semantics match the p256_fe_* functions
// in p256.hpp exactly; only the internal representation differs.
//

/// @brief Return the multiplicative identity (one).
auto p256_fe32_one() -> P256FieldElement32;

/// @brief Add two field elements mod p.
auto p256_fe32_add(P256FieldElement32 const& a, P256FieldElement32 const& b) -> P256FieldElement32;

/// @brief Subtract b from a mod p.
auto p256_fe32_sub(P256FieldElement32 const& a, P256FieldElement32 const& b) -> P256FieldElement32;

/// @brief Negate a field element: p - a mod p.
auto p256_fe32_neg(P256FieldElement32 const& a) -> P256FieldElement32;

/// @brief Multiply two field elements mod p (schoolbook + Solinas reduction).
auto p256_fe32_mul(P256FieldElement32 const& a, P256FieldElement32 const& b) -> P256FieldElement32;

/// @brief Square a field element mod p.
auto p256_fe32_sqr(P256FieldElement32 const& a) -> P256FieldElement32;

/// @brief Multiplicative inverse a^(p-2) mod p via addition chain.
auto p256_fe32_inv(P256FieldElement32 const& a) -> P256FieldElement32;

/// @brief Square root a^((p+1)/4) mod p, or nullopt if a is not a residue.
auto p256_fe32_sqrt(P256FieldElement32 const& a) -> std::optional<P256FieldElement32>;

/// @brief Return true if a == 0 mod p.
auto p256_fe32_is_zero(P256FieldElement32 const& a) -> bool;

/// @brief Return true if a == b mod p.
auto p256_fe32_equal(P256FieldElement32 const& a, P256FieldElement32 const& b) -> bool;

/// @brief Constant-time conditional move: f = (b != 0) ? g : f. b must be 0 or 1.
void p256_fe32_cmov(P256FieldElement32& f, P256FieldElement32 const& g, uint32_t b);

/// @brief Deserialize a 32-byte big-endian encoding (not reduced mod p).
auto p256_fe32_from_bytes(std::span<uint8_t const, 32> bytes) -> P256FieldElement32;

/// @brief Serialize to a canonical 32-byte big-endian encoding (reduced mod p).
auto p256_fe32_to_bytes(P256FieldElement32 const& a) -> std::array<uint8_t, 32>;

}  // namespace statusbar::crypto
