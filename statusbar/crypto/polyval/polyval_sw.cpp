// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file polyval_sw.cpp
/// @brief POLYVAL universal hash function — software implementation (RFC 8452 Section 3).
///
/// Implements the POLYVAL hash used by AES-GCM-SIV for authentication tag
/// computation. POLYVAL is closely related to GHASH but uses a different
/// field representation that is more efficient on little-endian platforms.
///
/// Key operations:
///  - GF(2^128) multiplication (dot product) with the reduction polynomial
///    x^128 + x^127 + x^126 + x^121 + 1.
///  - Byte reversal convention: POLYVAL uses a reflected (little-endian)
///    bit ordering compared to GHASH's big-endian convention.
///  - Accumulation: S_i = dot(S_{i-1} XOR X_i, H), where H is the hash
///    key and X_i are successive 16-byte input blocks.
///
/// @see https://www.rfc-editor.org/rfc/rfc8452#section-3

#include "statusbar/crypto/polyval/polyval_sw.hpp"

#include "statusbar/crypto/polyval/polyval_constants.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/status/statusbar_assert.hpp"

namespace statusbar::crypto {

using internal::load_le64;
using internal::make_const_span;
using internal::store_le64;
using std::span;

namespace {

constexpr auto POLYVAL_REDUCTION = constants::POLYVAL_REDUCTION;

//
// GF(2^128) arithmetic for POLYVAL
//
// The POLYVAL field uses the irreducible polynomial:
//   p(x) = x^128 + x^127 + x^126 + x^121 + 1
//
// This is the "reflected" version of the GHASH polynomial. Elements are
// stored in little-endian bit order within a 128-bit value split into
// two 64-bit halves (lo = bits 0-63, hi = bits 64-127).
//

// 128-bit value stored as two 64-bit halves in little-endian bit order.
struct U128
{
    uint64_t lo;  // bits 0-63
    uint64_t hi;  // bits 64-127
};

// Load a 128-bit value from memory as two little-endian 64-bit halves.
auto load128(span<uint8_t const, 16> p) -> U128
{
    return {.lo = load_le64(p.first<8>()), .hi = load_le64(p.last<8>())};
}

// Store a 128-bit value to memory as two little-endian 64-bit halves.
void store128(span<uint8_t, 16> p, U128 v)
{
    store_le64(p.first<8>(), v.lo);
    store_le64(p.last<8>(), v.hi);
}

// POLYVAL dot product: dot(a, b) = a * b * x^{-128} mod p(x)
// where p(x) = x^128 + x^127 + x^126 + x^121 + 1
//
// This is the core GF(2^128) multiplication used by POLYVAL. The x^{-128}
// factor distinguishes POLYVAL from GHASH and arises from the reflected
// bit ordering convention.
//
// Algorithm: right-shift (bit-serial) multiplication.
//   - v tracks the running reduction of a: at each step v is right-shifted
//     by one bit, and if the bit shifted out (carry) is 1, the reduction
//     constant is XORed into the high half.
//   - The reduction constant 0xE100000000000000 corresponds to
//     x^{-1} mod p = x^127 + x^126 + x^125 + x^120, which encodes the
//     feedback polynomial for right-shifting in the reflected representation.
//   - z accumulates partial products: when bit j of b is set, the current
//     reduced value v is XORed into z.
//
// The two loops iterate over the 128 bits of b: first the upper 64 bits
// (hi, bits 127-64), then the lower 64 bits (lo, bits 63-0), processing
// from MSB to LSB within each half.
auto polyval_dot(U128 a, U128 b) -> U128
{
    U128 z = {.lo = 0, .hi = 0};  // accumulator for the product
    U128 v = a;                   // running reduced value of a

    // Process b from bit 127 (hi bit 63) down to bit 64 (hi bit 0)
    // Constant-time: use masking instead of branching on secret data.
    for (int i = 63; i >= 0; --i) {
        // Right-shift v by 1 bit with polynomial reduction (constant-time)
        uint64_t const carry_mask = ~(v.lo & 1) + 1;  // 0 if carry==0, ~0 if carry==1
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi = (v.hi >> 1) ^ (POLYVAL_REDUCTION & carry_mask);

        // Accumulate v into z if this bit of b is set (constant-time)
        uint64_t const bit_mask = ~((b.hi >> i) & 1) + 1;  // 0 or ~0
        z.lo ^= v.lo & bit_mask;
        z.hi ^= v.hi & bit_mask;
    }

    // Process b from bit 63 (lo bit 63) down to bit 0 (lo bit 0)
    for (int i = 63; i >= 0; --i) {
        uint64_t const carry_mask = ~(v.lo & 1) + 1;
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi = (v.hi >> 1) ^ (POLYVAL_REDUCTION & carry_mask);

        uint64_t const bit_mask = ~((b.lo >> i) & 1) + 1;
        z.lo ^= v.lo & bit_mask;
        z.hi ^= v.hi & bit_mask;
    }

    return z;
}

}  // anonymous namespace

//
// POLYVAL (RFC 8452 Section 3)
//
// POLYVAL computes a keyed hash over a sequence of 16-byte blocks:
//   S_0 = 0
//   S_i = dot(S_{i-1} XOR X_i, H)   for i = 1, ..., n
//   POLYVAL(H, X_1, ..., X_n) = S_n
//
// polyval_sw() is a convenience wrapper that hashes input from a zero state.
// polyval_update_sw() enables incremental hashing by accepting an existing
// accumulator, allowing AES-GCM-SIV to hash AAD, plaintext, and the
// length block in separate calls.
//

// Single-shot POLYVAL: initializes accumulator to zero and hashes all input.
auto polyval_sw(PolyvalKey const& H, span<uint8_t const> input) -> std::array<uint8_t, polyval_block_size>
{
    std::array<uint8_t, polyval_block_size> result{};
    polyval_update_sw(H, input, result);
    return result;
}

// Incremental POLYVAL: absorbs input blocks into the running accumulator.
//
// Flow:
//   1. Load the hash key H and current accumulator state S from memory.
//   2. For each 16-byte input block X_i:
//      a. XOR X_i into S  (S = S XOR X_i)
//      b. Multiply S by H in GF(2^128)  (S = dot(S, H))
//   3. Store the updated S back to the accumulator.
void polyval_update_sw(PolyvalKey const& H, span<uint8_t const> input, span<uint8_t, polyval_block_size> accumulator)
{
    auto const can_update = polyval_can_update(input);
    STATUSBAR_ASSERT(can_update);
    auto h = load128(make_const_span(H.data));
    auto s = load128(accumulator);

    // Process each 16-byte block: XOR into state, then multiply by H
    size_t const num_blocks = input.size() / polyval_block_size;
    for (size_t i = 0; i < num_blocks; ++i) {
        auto x = load128(input.subspan(i * polyval_block_size).first<polyval_block_size>());
        s.lo ^= x.lo;
        s.hi ^= x.hi;
        s = polyval_dot(s, h);
    }

    store128(accumulator, s);
}

}  // namespace statusbar::crypto
