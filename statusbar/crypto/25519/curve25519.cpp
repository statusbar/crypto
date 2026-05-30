// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Curve25519 field arithmetic and group operations
// References:
// - RFC 7748 (X25519): https://www.rfc-editor.org/rfc/rfc7748
// - RFC 8032 (Ed25519): https://www.rfc-editor.org/rfc/rfc8032
// - Daniel J. Bernstein, "Curve25519: new Diffie-Hellman speed records"
//
// This file implements:
// - GF(2^255-19) field arithmetic using 5 x 51-bit radix-2^51 limbs
// - Extended Edwards curve operations for Ed25519 (a=-1 twisted Edwards)
// - Scalar arithmetic mod L (group order) using 12 x 21-bit signed limbs
// - Montgomery ladder for X25519 key agreement (RFC 7748 Section 5)
//
// Representation:
// - Field elements use 5 limbs of up to 51 bits each, stored in uint64_t.
//   Products use internal::Uint128 (128-bit unsigned) for 64x64->128-bit multiplication.
// - Limbs may be slightly unreduced between operations; full reduction
//   to [0, p) happens only in to_bytes/is_zero/is_negative.

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/25519/curve25519.hpp"
#    include "statusbar/crypto/25519/curve25519_constants.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"

namespace statusbar::crypto {

using std::span;

namespace {

using internal::load_le64;
using internal::store_le64;
using internal::Uint128;

using constants::BASE_POINT_COMPRESSED;
using constants::ED25519_2D;
using constants::ED25519_D;
using constants::FE25519_2P;
using constants::MASK51;
using constants::SQRT_M1;

// Propagate carries through 5-limb field element. After carry propagation,
// each limb is at most 51 bits (except limb 0 which gets the wrapped carry
// from limb 4, multiplied by 19 due to the 2^255 = 19 reduction).
void carry_propagate(uint64_t* h)
{
    uint64_t carry;
    carry = h[0] >> 51;
    h[1] += carry;
    h[0] &= MASK51;
    carry = h[1] >> 51;
    h[2] += carry;
    h[1] &= MASK51;
    carry = h[2] >> 51;
    h[3] += carry;
    h[2] &= MASK51;
    carry = h[3] >> 51;
    h[4] += carry;
    h[3] &= MASK51;
    carry = h[4] >> 51;
    h[0] += carry * 19;
    h[4] &= MASK51;
    carry = h[0] >> 51;
    h[1] += carry;
    h[0] &= MASK51;
}

// Constant-time conditional swap of two field elements.
// mask = -b (all 1s if b=1, all 0s if b=0); XOR-swap under mask.
void fe25519_cswap(Fe25519& f, Fe25519& g, uint64_t b)
{
    uint64_t const mask = -(b & 1);
    for (int i = 0; i < 5; ++i) {
        uint64_t const x = mask & (f.limbs[static_cast<size_t>(i)] ^ g.limbs[static_cast<size_t>(i)]);
        f.limbs[static_cast<size_t>(i)] ^= x;
        g.limbs[static_cast<size_t>(i)] ^= x;
    }
}

}  // anonymous namespace

//
// Field operations
//

auto fe25519_zero() -> Fe25519
{
    return Fe25519{{0, 0, 0, 0, 0}};
}

auto fe25519_one() -> Fe25519
{
    return Fe25519{{1, 0, 0, 0, 0}};
}

// Limb-wise addition. Result may exceed 2^51 per limb; caller reduces via subsequent mul/sq.
auto fe25519_add(Fe25519 const& a, Fe25519 const& b) -> Fe25519
{
    Fe25519 h;
    for (int i = 0; i < 5; ++i) {
        h.limbs[static_cast<size_t>(i)] = a.limbs[static_cast<size_t>(i)] + b.limbs[static_cast<size_t>(i)];
    }
    return h;
}

// Subtraction with bias: add 2*p first to avoid underflow, then subtract.
auto fe25519_sub(Fe25519 const& a, Fe25519 const& b) -> Fe25519
{
    Fe25519 h;
    std::get<0>(h.limbs) = (std::get<0>(a.limbs) + std::get<0>(FE25519_2P.limbs)) - std::get<0>(b.limbs);
    std::get<1>(h.limbs) = (std::get<1>(a.limbs) + std::get<1>(FE25519_2P.limbs)) - std::get<1>(b.limbs);
    std::get<2>(h.limbs) = (std::get<2>(a.limbs) + std::get<2>(FE25519_2P.limbs)) - std::get<2>(b.limbs);
    std::get<3>(h.limbs) = (std::get<3>(a.limbs) + std::get<3>(FE25519_2P.limbs)) - std::get<3>(b.limbs);
    std::get<4>(h.limbs) = (std::get<4>(a.limbs) + std::get<4>(FE25519_2P.limbs)) - std::get<4>(b.limbs);

    carry_propagate(h.limbs.data());
    return h;
}

// Schoolbook multiplication of two 5-limb numbers producing a 10-limb result,
// then reduce mod p using 2^255 = 19. Uses __uint128_t for 64x64->128 products.
// The 19x factor for upper limbs comes from the identity
// h[i+5] * 2^(255 + 51*i) = h[i+5] * 19 * 2^(51*i) (mod p).
auto fe25519_mul(Fe25519 const& a, Fe25519 const& b) -> Fe25519
{
    uint64_t const f0 = std::get<0>(a.limbs);
    uint64_t const f1 = std::get<1>(a.limbs);
    uint64_t const f2 = std::get<2>(a.limbs);
    uint64_t const f3 = std::get<3>(a.limbs);
    uint64_t const f4 = std::get<4>(a.limbs);

    uint64_t const g0 = std::get<0>(b.limbs);
    uint64_t const g1 = std::get<1>(b.limbs);
    uint64_t const g2 = std::get<2>(b.limbs);
    uint64_t const g3 = std::get<3>(b.limbs);
    uint64_t const g4 = std::get<4>(b.limbs);

    Uint128 const h0 = (static_cast<Uint128>(f0) * g0) +
        (19 *
         ((static_cast<Uint128>(f1) * g4) + (static_cast<Uint128>(f2) * g3) + (static_cast<Uint128>(f3) * g2) +
          (static_cast<Uint128>(f4) * g1)));
    Uint128 h1 = (static_cast<Uint128>(f0) * g1) + (static_cast<Uint128>(f1) * g0) +
        (19 * ((static_cast<Uint128>(f2) * g4) + (static_cast<Uint128>(f3) * g3) + (static_cast<Uint128>(f4) * g2)));
    Uint128 h2 = (static_cast<Uint128>(f0) * g2) + (static_cast<Uint128>(f1) * g1) + (static_cast<Uint128>(f2) * g0) +
        (19 * ((static_cast<Uint128>(f3) * g4) + (static_cast<Uint128>(f4) * g3)));
    Uint128 h3 = (static_cast<Uint128>(f0) * g3) + (static_cast<Uint128>(f1) * g2) + (static_cast<Uint128>(f2) * g1) +
        (static_cast<Uint128>(f3) * g0) + (19 * (static_cast<Uint128>(f4) * g4));
    Uint128 h4 = (static_cast<Uint128>(f0) * g4) + (static_cast<Uint128>(f1) * g3) + (static_cast<Uint128>(f2) * g2) +
        (static_cast<Uint128>(f3) * g1) + (static_cast<Uint128>(f4) * g0);

    // Carry propagation from 128-bit accumulators
    uint64_t carry;
    uint64_t r0 = static_cast<uint64_t>(h0) & MASK51;
    carry = static_cast<uint64_t>(h0 >> 51);
    h1 += carry;

    uint64_t r1 = static_cast<uint64_t>(h1) & MASK51;
    carry = static_cast<uint64_t>(h1 >> 51);
    h2 += carry;

    uint64_t const r2 = static_cast<uint64_t>(h2) & MASK51;
    carry = static_cast<uint64_t>(h2 >> 51);
    h3 += carry;

    uint64_t const r3 = static_cast<uint64_t>(h3) & MASK51;
    carry = static_cast<uint64_t>(h3 >> 51);
    h4 += carry;

    uint64_t const r4 = static_cast<uint64_t>(h4) & MASK51;
    carry = static_cast<uint64_t>(h4 >> 51);
    r0 += carry * 19;

    carry = r0 >> 51;
    r1 += carry;
    r0 &= MASK51;

    Fe25519 h_out;
    std::get<0>(h_out.limbs) = r0;
    std::get<1>(h_out.limbs) = r1;
    std::get<2>(h_out.limbs) = r2;
    std::get<3>(h_out.limbs) = r3;
    std::get<4>(h_out.limbs) = r4;
    return h_out;
}

// Squaring: same as mul but with doubled cross-terms for efficiency.
auto fe25519_sq(Fe25519 const& a) -> Fe25519
{
    uint64_t const f0 = std::get<0>(a.limbs);
    uint64_t const f1 = std::get<1>(a.limbs);
    uint64_t const f2 = std::get<2>(a.limbs);
    uint64_t const f3 = std::get<3>(a.limbs);
    uint64_t const f4 = std::get<4>(a.limbs);

    Uint128 const h0 = (static_cast<Uint128>(f0) * f0) +
        (static_cast<Uint128>(2 * 19) * ((static_cast<Uint128>(f1) * f4) + (static_cast<Uint128>(f2) * f3)));
    Uint128 h1 =
        (2 * static_cast<Uint128>(f0) * f1) + (19 * ((2 * static_cast<Uint128>(f2) * f4) + (static_cast<Uint128>(f3) * f3)));
    Uint128 h2 = (2 * static_cast<Uint128>(f0) * f2) + (static_cast<Uint128>(f1) * f1) +
        (static_cast<Uint128>(2 * 19) * static_cast<Uint128>(f3) * f4);
    Uint128 h3 = (2 * static_cast<Uint128>(f0) * f3) + (2 * static_cast<Uint128>(f1) * f2) + (19 * static_cast<Uint128>(f4) * f4);
    Uint128 h4 = (2 * static_cast<Uint128>(f0) * f4) + (2 * static_cast<Uint128>(f1) * f3) + (static_cast<Uint128>(f2) * f2);

    // Carry propagation
    uint64_t carry;
    uint64_t r0 = static_cast<uint64_t>(h0) & MASK51;
    carry = static_cast<uint64_t>(h0 >> 51);
    h1 += carry;

    uint64_t r1 = static_cast<uint64_t>(h1) & MASK51;
    carry = static_cast<uint64_t>(h1 >> 51);
    h2 += carry;

    uint64_t const r2 = static_cast<uint64_t>(h2) & MASK51;
    carry = static_cast<uint64_t>(h2 >> 51);
    h3 += carry;

    uint64_t const r3 = static_cast<uint64_t>(h3) & MASK51;
    carry = static_cast<uint64_t>(h3 >> 51);
    h4 += carry;

    uint64_t const r4 = static_cast<uint64_t>(h4) & MASK51;
    carry = static_cast<uint64_t>(h4 >> 51);
    r0 += carry * 19;

    carry = r0 >> 51;
    r1 += carry;
    r0 &= MASK51;

    Fe25519 h_out;
    std::get<0>(h_out.limbs) = r0;
    std::get<1>(h_out.limbs) = r1;
    std::get<2>(h_out.limbs) = r2;
    std::get<3>(h_out.limbs) = r3;
    std::get<4>(h_out.limbs) = r4;
    return h_out;
}

// Multiply field element by small constant. Used for 2*Z in point
// addition/doubling and 121665 in Montgomery ladder.
auto fe25519_mul_small(Fe25519 const& a, uint64_t b) -> Fe25519
{
    Uint128 const h0 = static_cast<Uint128>(std::get<0>(a.limbs)) * b;
    Uint128 h1 = static_cast<Uint128>(std::get<1>(a.limbs)) * b;
    Uint128 h2 = static_cast<Uint128>(std::get<2>(a.limbs)) * b;
    Uint128 h3 = static_cast<Uint128>(std::get<3>(a.limbs)) * b;
    Uint128 h4 = static_cast<Uint128>(std::get<4>(a.limbs)) * b;

    uint64_t carry;
    uint64_t r0 = static_cast<uint64_t>(h0) & MASK51;
    carry = static_cast<uint64_t>(h0 >> 51);
    h1 += carry;

    uint64_t r1 = static_cast<uint64_t>(h1) & MASK51;
    carry = static_cast<uint64_t>(h1 >> 51);
    h2 += carry;

    uint64_t const r2 = static_cast<uint64_t>(h2) & MASK51;
    carry = static_cast<uint64_t>(h2 >> 51);
    h3 += carry;

    uint64_t const r3 = static_cast<uint64_t>(h3) & MASK51;
    carry = static_cast<uint64_t>(h3 >> 51);
    h4 += carry;

    uint64_t const r4 = static_cast<uint64_t>(h4) & MASK51;
    carry = static_cast<uint64_t>(h4 >> 51);
    r0 += carry * 19;

    carry = r0 >> 51;
    r1 += carry;
    r0 &= MASK51;

    Fe25519 h_out;
    std::get<0>(h_out.limbs) = r0;
    std::get<1>(h_out.limbs) = r1;
    std::get<2>(h_out.limbs) = r2;
    std::get<3>(h_out.limbs) = r3;
    std::get<4>(h_out.limbs) = r4;
    return h_out;
}

// Unpack 32 little-endian bytes into 5x51-bit limbs.
// Bits are distributed: limb[0]=bits 0-50, limb[1]=bits 51-101, etc.
auto fe25519_from_bytes(span<uint8_t const, curve25519_point_size> s) -> Fe25519
{
    uint64_t const t0 = load_le64(s.first<8>());
    uint64_t const t1 = load_le64(s.subspan<8, 8>());
    uint64_t const t2 = load_le64(s.subspan<16, 8>());
    uint64_t const t3 = load_le64(s.subspan<24, 8>());

    Fe25519 h;
    std::get<0>(h.limbs) = t0 & MASK51;
    std::get<1>(h.limbs) = ((t0 >> 51) | (t1 << 13)) & MASK51;
    std::get<2>(h.limbs) = ((t1 >> 38) | (t2 << 26)) & MASK51;
    std::get<3>(h.limbs) = ((t2 >> 25) | (t3 << 39)) & MASK51;
    std::get<4>(h.limbs) = (t3 >> 12) & MASK51;
    return h;
}

// Serialize to canonical form. First fully reduce to [0, p) by:
// (1) carry propagation, (2) conditional subtraction of p.
// Then pack 5x51-bit limbs into 32 bytes.
auto fe25519_to_bytes(Fe25519 const& h) -> std::array<uint8_t, curve25519_point_size>
{
    uint64_t t[5];
    for (int i = 0; i < 5; ++i) {
        t[i] = h.limbs[static_cast<size_t>(i)];
    }

    // First carry propagation
    carry_propagate(t);

    // Full reduction: compute q = floor((h + 19) / 2^255)
    uint64_t q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;

    // Subtract q*p (i.e., add 19*q and propagate carries linearly — no wraparound)
    t[0] += 19 * q;
    uint64_t carry;
    carry = t[0] >> 51;
    t[0] &= MASK51;
    t[1] += carry;
    carry = t[1] >> 51;
    t[1] &= MASK51;
    t[2] += carry;
    carry = t[2] >> 51;
    t[2] &= MASK51;
    t[3] += carry;
    carry = t[3] >> 51;
    t[3] &= MASK51;
    t[4] += carry;
    t[4] &= MASK51;

    // Pack into bytes
    uint64_t const w0 = t[0] | (t[1] << 51);
    uint64_t const w1 = (t[1] >> 13) | (t[2] << 38);
    uint64_t const w2 = (t[2] >> 26) | (t[3] << 25);
    uint64_t const w3 = (t[3] >> 39) | (t[4] << 12);

    std::array<uint8_t, curve25519_point_size> out{};
    auto out_span = span(out);
    store_le64(out_span.first<8>(), w0);
    store_le64(out_span.subspan<8, 8>(), w1);
    store_le64(out_span.subspan<16, 8>(), w2);
    store_le64(out_span.subspan<24, 8>(), w3);
    return out;
}

// Return the low bit of the canonical byte encoding (i.e. the 'sign').
auto fe25519_is_negative(Fe25519 const& f) -> uint64_t
{
    auto bytes = fe25519_to_bytes(f);
    return static_cast<uint64_t>(bytes[0]) & 1;
}

// Canonicalize and check if all bytes are zero.
auto fe25519_is_zero(Fe25519 const& f) -> uint64_t
{
    auto bytes = fe25519_to_bytes(f);
    uint8_t acc = 0;
    for (int i = 0; i < 32; ++i) {
        acc |= bytes[static_cast<size_t>(i)];
    }
    // Return 1 if zero, 0 otherwise (constant-time)
    return static_cast<uint64_t>((static_cast<uint32_t>(acc) - 1) >> 31) & 1;
}

// Negate by computing (0 - a) with bias to avoid underflow.
auto fe25519_neg(Fe25519 const& a) -> Fe25519
{
    return fe25519_sub(fe25519_zero(), a);
}

// Constant-time conditional move using arithmetic masking:
// mask = -b (all 1s if b=1, all 0s if b=0).
void fe25519_cmov(Fe25519& f, Fe25519 const& g, uint64_t b)
{
    uint64_t const mask = -(b & 1);
    for (int i = 0; i < 5; ++i) {
        f.limbs[static_cast<size_t>(i)] ^= mask & (f.limbs[static_cast<size_t>(i)] ^ g.limbs[static_cast<size_t>(i)]);
    }
}

// Compute a^(p-2) mod p via addition chain.
// p-2 = 2^255 - 21, so the chain computes z^(2^k - c) for various k,c
// using repeated squaring and multiplication.
// Total: 11 multiplications + 254 squarings.
auto fe25519_invert(Fe25519 const& z) -> Fe25519
{
    // Compute z^(p-2) = z^(2^255 - 21) using addition chain

    auto z2 = fe25519_sq(z);                        // z^2
    auto z8 = fe25519_sq(fe25519_sq(z2));           // z^8
    auto z9 = fe25519_mul(z, z8);                   // z^9
    auto z11 = fe25519_mul(z2, z9);                 // z^11
    auto z_5_0 = fe25519_mul(z9, fe25519_sq(z11));  // z^(2^5 - 1) = z^31

    // z^(2^10 - 1)
    auto t = fe25519_sq(z_5_0);
    for (int i = 1; i < 5; ++i) {
        t = fe25519_sq(t);
    }
    auto z_10_0 = fe25519_mul(z_5_0, t);

    // z^(2^20 - 1)
    t = fe25519_sq(z_10_0);
    for (int i = 1; i < 10; ++i) {
        t = fe25519_sq(t);
    }
    auto z_20_0 = fe25519_mul(z_10_0, t);

    // z^(2^40 - 1)
    t = fe25519_sq(z_20_0);
    for (int i = 1; i < 20; ++i) {
        t = fe25519_sq(t);
    }
    auto z_40_0 = fe25519_mul(z_20_0, t);

    // z^(2^50 - 1)
    t = fe25519_sq(z_40_0);
    for (int i = 1; i < 10; ++i) {
        t = fe25519_sq(t);
    }
    auto z_50_0 = fe25519_mul(z_10_0, t);

    // z^(2^100 - 1)
    t = fe25519_sq(z_50_0);
    for (int i = 1; i < 50; ++i) {
        t = fe25519_sq(t);
    }
    auto z_100_0 = fe25519_mul(z_50_0, t);

    // z^(2^200 - 1)
    t = fe25519_sq(z_100_0);
    for (int i = 1; i < 100; ++i) {
        t = fe25519_sq(t);
    }
    auto z_200_0 = fe25519_mul(z_100_0, t);

    // z^(2^250 - 1)
    t = fe25519_sq(z_200_0);
    for (int i = 1; i < 50; ++i) {
        t = fe25519_sq(t);
    }
    auto z_250_0 = fe25519_mul(z_50_0, t);

    // z^(2^255 - 21) = z^(p-2)
    t = fe25519_sq(z_250_0);
    for (int i = 1; i < 5; ++i) {
        t = fe25519_sq(t);
    }
    return fe25519_mul(z11, t);
}

// Compute z^(2^252 - 3) = z^((p-5)/8) via addition chain.
// This exponent arises in the Tonelli-Shanks square root:
//   x = (u*v^3) * (u*v^7)^((p-5)/8).
// Chain: z^1 -> z^2 -> z^(2^2-1) -> z^(2^5-1) -> z^(2^10-1) ->
// z^(2^20-1) -> z^(2^40-1) -> z^(2^50-1) -> z^(2^100-1) ->
// z^(2^200-1) -> z^(2^250-1) -> z^(2^252-3).
auto fe25519_pow22523(Fe25519 const& z) -> Fe25519
{
    // Compute z^((p-5)/8) = z^(2^252 - 3)
    // Same addition chain as invert up to z_250_0, then different final step

    auto z2 = fe25519_sq(z);
    auto z8 = fe25519_sq(fe25519_sq(z2));
    auto z9 = fe25519_mul(z, z8);
    auto z11 = fe25519_mul(z2, z9);
    auto z_5_0 = fe25519_mul(z9, fe25519_sq(z11));

    auto t = fe25519_sq(z_5_0);
    for (int i = 1; i < 5; ++i) {
        t = fe25519_sq(t);
    }
    auto z_10_0 = fe25519_mul(z_5_0, t);

    t = fe25519_sq(z_10_0);
    for (int i = 1; i < 10; ++i) {
        t = fe25519_sq(t);
    }
    auto z_20_0 = fe25519_mul(z_10_0, t);

    t = fe25519_sq(z_20_0);
    for (int i = 1; i < 20; ++i) {
        t = fe25519_sq(t);
    }
    auto z_40_0 = fe25519_mul(z_20_0, t);

    t = fe25519_sq(z_40_0);
    for (int i = 1; i < 10; ++i) {
        t = fe25519_sq(t);
    }
    auto z_50_0 = fe25519_mul(z_10_0, t);

    t = fe25519_sq(z_50_0);
    for (int i = 1; i < 50; ++i) {
        t = fe25519_sq(t);
    }
    auto z_100_0 = fe25519_mul(z_50_0, t);

    t = fe25519_sq(z_100_0);
    for (int i = 1; i < 100; ++i) {
        t = fe25519_sq(t);
    }
    auto z_200_0 = fe25519_mul(z_100_0, t);

    t = fe25519_sq(z_200_0);
    for (int i = 1; i < 50; ++i) {
        t = fe25519_sq(t);
    }
    auto z_250_0 = fe25519_mul(z_50_0, t);

    // z^(2^252 - 3) = z^((p-5)/8)
    t = fe25519_sq(z_250_0);
    t = fe25519_sq(t);
    return fe25519_mul(z, t);
}

//
// Edwards group operations
//

// The neutral element: (X=0, Y=1, Z=1, T=0) representing affine (0, 1).
auto ge_p3_identity() -> GeP3
{
    GeP3 p;
    p.X = fe25519_zero();
    p.Y = fe25519_one();
    p.Z = fe25519_one();
    p.T = fe25519_zero();
    return p;
}

// Encode extended point to 32 bytes: compute affine x=X/Z, y=Y/Z,
// encode y as little-endian 32 bytes with sign(x) in the high bit
// of byte 31 (RFC 8032 Section 5.1.2).
auto ge_p3_to_bytes(GeP3 const& p) -> std::array<uint8_t, curve25519_point_size>
{
    auto zinv = fe25519_invert(p.Z);
    auto x = fe25519_mul(p.X, zinv);
    auto y = fe25519_mul(p.Y, zinv);

    auto out = fe25519_to_bytes(y);
    out[31] ^= static_cast<uint8_t>(fe25519_is_negative(x) << 7);
    return out;
}

// Point decompression from 32-byte encoding (RFC 8032 Section 5.1.3).
// The encoding is y || sign(x): the lower 255 bits are the y-coordinate
// and the high bit of byte 31 is the sign of x.
// Recovery of x from y:
//   1. Extract sign bit, load y (clearing sign bit)
//   2. Compute u = y^2 - 1 and v = d*y^2 + 1
//   3. Candidate x = (u*v^3) * (u*v^7)^((p-5)/8)
//   4. Check: if v*x^2 == u, x is correct
//   5. If v*x^2 == -u, multiply x by sqrt(-1)
//   6. If neither, the point is not on the curve -> return false
//   7. Adjust sign of x to match the encoded sign bit
auto ge_from_bytes(span<uint8_t const, curve25519_point_size> s) -> std::optional<GeP3>
{
    // Extract sign bit
    uint64_t const sign = s[31] >> 7;

    // Load y, clearing the sign bit
    std::array<uint8_t, curve25519_point_size> temp{};
    for (int i = 0; i < 32; ++i) {
        temp[static_cast<size_t>(i)] = s[static_cast<size_t>(i)];
    }
    temp[31] &= 0x7F;

    auto y = fe25519_from_bytes(temp);

    // Compute u = y^2 - 1
    auto y2 = fe25519_sq(y);
    auto u = fe25519_sub(y2, fe25519_one());

    // Compute v = d*y^2 + 1
    auto v = fe25519_add(fe25519_mul(ED25519_D, y2), fe25519_one());

    // Compute x = u * v^3 * (u * v^7)^((p-5)/8)
    auto v2 = fe25519_sq(v);
    auto v3 = fe25519_mul(v, v2);
    auto uv3 = fe25519_mul(u, v3);
    auto v7 = fe25519_mul(fe25519_sq(v3), v);  // v^6 * v = v^7
    auto uv7 = fe25519_mul(u, v7);
    auto x = fe25519_mul(uv3, fe25519_pow22523(uv7));

    // Check: v * x^2 should equal u or -u
    auto vx2 = fe25519_mul(v, fe25519_sq(x));
    auto check = fe25519_sub(vx2, u);

    if (fe25519_is_zero(check) == 0) {
        // Try v*x^2 == -u
        auto neg_check = fe25519_add(vx2, u);
        if (fe25519_is_zero(neg_check) == 0) {
            // Not on curve
            return std::nullopt;
        }
        x = fe25519_mul(x, SQRT_M1);
    }

    // Adjust sign
    if (fe25519_is_negative(x) != sign) {
        x = fe25519_neg(x);
    }

    auto t = fe25519_mul(x, y);

    GeP3 point;
    point.X = x;
    point.Y = y;
    point.Z = fe25519_one();
    point.T = t;
    return point;
}

// Unified addition for extended coordinates (add-2008-hwcd-3, a=-1).
// Formula: A=(Y1-X1)(Y2-X2), B=(Y1+X1)(Y2+X2), C=T1*2d*T2,
// D=2*Z1*Z2, E=B-A, F=D-C, G=D+C, H=B+A,
// X3=E*F, Y3=G*H, T3=E*H, Z3=F*G.
// Cost: 8M + 1D (where D = multiply by 2d).
auto ge_p3_add(GeP3 const& P, GeP3 const& Q) -> GeP3
{
    // Unified addition formula for extended coordinates
    auto A = fe25519_mul(fe25519_sub(P.Y, P.X), fe25519_sub(Q.Y, Q.X));
    auto B = fe25519_mul(fe25519_add(P.Y, P.X), fe25519_add(Q.Y, Q.X));
    auto C = fe25519_mul(P.T, fe25519_mul(ED25519_2D, Q.T));
    auto D = fe25519_mul(P.Z, fe25519_mul_small(Q.Z, 2));
    auto E = fe25519_sub(B, A);
    auto F = fe25519_sub(D, C);
    auto G = fe25519_add(D, C);
    auto H = fe25519_add(B, A);

    GeP3 R;
    R.X = fe25519_mul(E, F);
    R.Y = fe25519_mul(G, H);
    R.T = fe25519_mul(E, H);
    R.Z = fe25519_mul(F, G);
    return R;
}

// Dedicated doubling for a=-1 twisted Edwards (dbl-2008-hwcd).
// A=X1^2, B=Y1^2, C=2*Z1^2, D=-A (since a=-1),
// E=(X1+Y1)^2-A-B, G=D+B, F=G-C, H=D-B.
// Cost: 4S + 4M.
auto ge_p3_dbl(GeP3 const& P) -> GeP3
{
    // Dedicated doubling formula for twisted Edwards (a = -1)
    auto A = fe25519_sq(P.X);
    auto B = fe25519_sq(P.Y);
    auto C = fe25519_mul_small(fe25519_sq(P.Z), 2);
    auto D = fe25519_neg(A);  // D = -A (since a = -1)
    auto E = fe25519_sub(fe25519_sq(fe25519_add(P.X, P.Y)), fe25519_add(A, B));
    auto G = fe25519_add(D, B);
    auto F = fe25519_sub(G, C);
    auto H = fe25519_sub(D, B);

    GeP3 R;
    R.X = fe25519_mul(E, F);
    R.Y = fe25519_mul(G, H);
    R.T = fe25519_mul(E, H);
    R.Z = fe25519_mul(F, G);
    return R;
}

// Negate: (-X, Y, Z, -T). The negation of (x,y) on the curve is (-x,y).
auto ge_p3_neg(GeP3 const& P) -> GeP3
{
    GeP3 R;
    R.X = fe25519_neg(P.X);
    R.Y = P.Y;
    R.Z = P.Z;
    R.T = fe25519_neg(P.T);
    return R;
}

// Constant-time scalar multiplication [scalar]B using 4-bit fixed window.
//
// Precomputes a 16-entry lookup table: table[i] = i*G for i = 0..15.
// Processes the 256-bit scalar in 64 four-bit nibbles from MSB to LSB.
// For each nibble: 4 doublings, then constant-time table lookup via cmov.
//
// Cost: 252 doublings + 63 additions + 64 constant-time lookups (15 cmovs each).
// This is ~40% faster than the naive bit-at-a-time approach (255 doublings +
// 255 conditional additions).
auto ge_scalar_mult_base(span<uint8_t const, curve25519_scalar_size> scalar) -> GeP3
{
    // Precompute table of multiples of the base point (computed once).
    // Thread-safe initialization guaranteed by C++11 [stmt.dcl]/4 ("magic statics").
    static auto const table = [] {
        auto base = *ge_from_bytes(BASE_POINT_COMPRESSED);
        std::array<GeP3, 16> t;
        t[0] = ge_p3_identity();
        t[1] = base;
        for (int i = 2; i < 16; ++i) {
            t[static_cast<size_t>(i)] = ge_p3_add(t[static_cast<size_t>(i - 1)], base);
        }
        return t;
    }();

    // Extract 4-bit nibble from scalar (little-endian byte order).
    // nibble i = bits [4i+3 .. 4i] of the scalar.
    auto get_nibble = [&](int i) -> uint8_t {
        int const byte_idx = i / 2;
        if (i % 2 == 0) {
            return scalar[static_cast<size_t>(byte_idx)] & 0x0F;
        }
        return (scalar[static_cast<size_t>(byte_idx)] >> 4) & 0x0F;
    };

    // Constant-time table lookup: scan all 16 entries, selecting the matching one.
    auto ct_lookup = [&](uint8_t index) -> GeP3 {
        GeP3 result = table[0];
        for (int i = 1; i < 16; ++i) {
            // ct_eq: 1 if i == index, 0 otherwise (constant-time for values < 2^31)
            uint64_t const eq = 1 & ((static_cast<uint32_t>(i ^ index) - 1) >> 31);
            fe25519_cmov(result.X, table[static_cast<size_t>(i)].X, eq);
            fe25519_cmov(result.Y, table[static_cast<size_t>(i)].Y, eq);
            fe25519_cmov(result.Z, table[static_cast<size_t>(i)].Z, eq);
            fe25519_cmov(result.T, table[static_cast<size_t>(i)].T, eq);
        }
        return result;
    };

    // Process from most significant nibble (63) down to least significant (0).
    // First nibble: just lookup (no doubling needed).
    auto result = ct_lookup(get_nibble(63));

    // Remaining 63 nibbles: 4 doublings + lookup + addition.
    for (int i = 62; i >= 0; --i) {
        result = ge_p3_dbl(result);
        result = ge_p3_dbl(result);
        result = ge_p3_dbl(result);
        result = ge_p3_dbl(result);

        auto selected = ct_lookup(get_nibble(i));
        result = ge_p3_add(result, selected);
    }

    return result;
}

// Compute [a]A + [b]B using Straus's trick (simultaneous double-and-add).
// Precompute table[0]=identity, table[1]=B, table[2]=A, table[3]=A+B.
// For each bit position (MSB to LSB): double the accumulator, then add
// table[(a_bit<<1)|b_bit].
// Variable-time: branch on scalar bits is acceptable because scalars a,b
// are public during Ed25519 verification.
auto ge_double_scalar_mult_vartime(
    span<uint8_t const, curve25519_scalar_size> a, GeP3 const& A, span<uint8_t const, curve25519_scalar_size> b) -> GeP3
{
    // Decompress base point
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) — BASE_POINT_COMPRESSED is a known-valid constant
    static auto const B = *ge_from_bytes(BASE_POINT_COMPRESSED);

    // Precompute: table[0] = identity, table[1] = B, table[2] = A, table[3] = A+B
    GeP3 table[4];
    table[0] = ge_p3_identity();
    table[1] = B;
    table[2] = A;
    table[3] = ge_p3_add(A, B);

    auto result = ge_p3_identity();

    for (int bit = 254; bit >= 0; --bit) {
        result = ge_p3_dbl(result);

        uint64_t const a_bit = (static_cast<uint64_t>(a[static_cast<size_t>(bit / 8)]) >> (bit % 8)) & 1;
        uint64_t const b_bit = (static_cast<uint64_t>(b[static_cast<size_t>(bit / 8)]) >> (bit % 8)) & 1;
        auto index = (a_bit << 1) | b_bit;

        if (index != 0) {
            result = ge_p3_add(result, table[index]);
        }
    }

    return result;
}

//
// Montgomery ladder (X25519)
//

// X25519 scalar multiplication using the Montgomery ladder (RFC 7748 Section 5).
// Given a scalar and u-coordinate point on the Montgomery curve
// y^2 = x^3 + 486662*x^2 + x:
//   1. Clamp scalar: clear bits 0-2, set bit 254, clear bit 255
//   2. Initialize: (x_2, z_2) = (1, 0), (x_3, z_3) = (u, 1)
//   3. For each bit from 254 down to 0: conditional swap based on scalar
//      bit, then differential addition step
//   4. Final conditional swap, compute result = x_2 * z_2^(-1)
// The constant 121665 = (486662 - 2) / 4 appears in the differential
// addition formula.
auto curve25519_scalar_mult(span<uint8_t const, curve25519_scalar_size> scalar, span<uint8_t const, curve25519_point_size> point_u)
    -> std::array<uint8_t, curve25519_point_size>
{
    // Copy and clamp scalar per RFC 7748.
    // SecureArray zeroes the clamped scalar on scope exit.
    SecureArray<curve25519_scalar_size> s{};
    for (int i = 0; i < 32; ++i) {
        s[static_cast<size_t>(i)] = scalar[static_cast<size_t>(i)];
    }
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    auto u = fe25519_from_bytes(point_u);

    auto x_2 = fe25519_one();
    auto z_2 = fe25519_zero();
    auto x_3 = u;
    auto z_3 = fe25519_one();

    uint64_t swap = 0;

    for (int bit = 254; bit >= 0; --bit) {
        uint64_t const b = (static_cast<uint64_t>(s[static_cast<size_t>(bit / 8)]) >> (bit % 8)) & 1;
        swap ^= b;
        fe25519_cswap(x_2, x_3, swap);
        fe25519_cswap(z_2, z_3, swap);
        swap = b;

        auto A = fe25519_add(x_2, z_2);
        auto AA = fe25519_sq(A);
        auto B = fe25519_sub(x_2, z_2);
        auto BB = fe25519_sq(B);
        auto E = fe25519_sub(AA, BB);
        auto C = fe25519_add(x_3, z_3);
        auto D = fe25519_sub(x_3, z_3);
        auto DA = fe25519_mul(D, A);
        auto CB = fe25519_mul(C, B);
        x_3 = fe25519_sq(fe25519_add(DA, CB));
        z_3 = fe25519_mul(u, fe25519_sq(fe25519_sub(DA, CB)));
        x_2 = fe25519_mul(AA, BB);
        z_2 = fe25519_mul(E, fe25519_add(AA, fe25519_mul_small(E, 121665)));
    }

    fe25519_cswap(x_2, x_3, swap);
    fe25519_cswap(z_2, z_3, swap);

    auto result = fe25519_mul(x_2, fe25519_invert(z_2));

    // s is SecureArray — zeroed by RAII.
    return fe25519_to_bytes(result);
}

}  // namespace statusbar::crypto

#endif  // STATUSBAR_CRYPTO_HAS_INT128
