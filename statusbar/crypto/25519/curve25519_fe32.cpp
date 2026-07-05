// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Curve25519 field arithmetic — 32-bit reduced-radix implementation.
// See curve25519_fe32.hpp for the representation rationale.
//
// This file uses nothing wider than uint64_t (for 32x32->64 products and
// carry accumulation); it never uses __uint128_t, so it builds and runs on a
// 32-bit ALU. It is always compiled and is cross-checked against the 5x51-bit
// implementation by curve25519_fe32_test.cpp.

#include "statusbar/crypto/25519/curve25519_fe32.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

using std::span;

namespace {

using internal::load_le64;
using internal::store_le64;

// Limb bit-width masks: even-index limbs are 26 bits, odd-index 25 bits.
constexpr uint64_t M26 = 0x3FFFFFF;  // 2^26 - 1
constexpr uint64_t M25 = 0x1FFFFFF;  // 2^25 - 1

// 4*p in 10-limb radix-2^25.5 form (4p = 2^257 - 76, congruent to 0 mod p).
// Added as a per-limb bias in subtraction so the difference never underflows.
// The subtrahend may be an unreduced add() result — e.g. add(X^2, Y^2) in
// point doubling — whose limbs reach ~2x the canonical width (even limb up to
// 2^27-2, odd up to 2^26-2). 2p was 36 short in limb 0 (its value there is
// only 2^27-38 because the "-38" of 2p = 2^256-38 lands in limb 0), so a small
// minuend limb 0 minus a large subtrahend limb 0 underflowed the uint64 and
// corrupted the result by 2^64 mod p. 4p clears every limb with margin.
constexpr std::array<uint64_t, 10> FE_4P = {
    (1ULL << 28) - 76,
    (1ULL << 27) - 4,
    (1ULL << 28) - 4,
    (1ULL << 27) - 4,
    (1ULL << 28) - 4,
    (1ULL << 27) - 4,
    (1ULL << 28) - 4,
    (1ULL << 27) - 4,
    (1ULL << 28) - 4,
    (1ULL << 27) - 4,
};

// Propagate carries through 10 limbs. The carry out of limb 9 wraps into
// limb 0 multiplied by 19, since 2^255 = 19 (mod p). After this each limb is
// at its nominal width (limb 0 and 1 may carry a few extra bits).
void carry_propagate(uint64_t* h)
{
    uint64_t c;
    c = h[0] >> 26;
    h[1] += c;
    h[0] &= M26;
    c = h[1] >> 25;
    h[2] += c;
    h[1] &= M25;
    c = h[2] >> 26;
    h[3] += c;
    h[2] &= M26;
    c = h[3] >> 25;
    h[4] += c;
    h[3] &= M25;
    c = h[4] >> 26;
    h[5] += c;
    h[4] &= M26;
    c = h[5] >> 25;
    h[6] += c;
    h[5] &= M25;
    c = h[6] >> 26;
    h[7] += c;
    h[6] &= M26;
    c = h[7] >> 25;
    h[8] += c;
    h[7] &= M25;
    c = h[8] >> 26;
    h[9] += c;
    h[8] &= M26;
    c = h[9] >> 25;
    h[0] += c * 19;
    h[9] &= M25;
    c = h[0] >> 26;
    h[1] += c;
    h[0] &= M26;
}

// Store a carry-propagated 10-limb accumulator into a field element.
auto pack(uint64_t const* h) -> Fe25519x32
{
    Fe25519x32 r;
    for (int i = 0; i < 10; ++i) {
        r.limbs[static_cast<size_t>(i)] = static_cast<uint32_t>(h[static_cast<size_t>(i)]);
    }
    return r;
}

}  // namespace

auto fe25519x32_zero() -> Fe25519x32
{
    return Fe25519x32{};
}

auto fe25519x32_one() -> Fe25519x32
{
    Fe25519x32 r;
    r.limbs[0] = 1;
    return r;
}

// Limb-wise addition. Result may exceed the nominal limb width; the caller
// reduces it via a subsequent mul/sq/sub.
auto fe25519x32_add(Fe25519x32 const& a, Fe25519x32 const& b) -> Fe25519x32
{
    Fe25519x32 r;
    for (int i = 0; i < 10; ++i) {
        r.limbs[static_cast<size_t>(i)] = a.limbs[static_cast<size_t>(i)] + b.limbs[static_cast<size_t>(i)];
    }
    return r;
}

// Subtraction with a 4*p bias to avoid underflow, then carry propagation.
auto fe25519x32_sub(Fe25519x32 const& a, Fe25519x32 const& b) -> Fe25519x32
{
    uint64_t h[10];
    for (int i = 0; i < 10; ++i) {
        h[i] = (static_cast<uint64_t>(a.limbs[static_cast<size_t>(i)]) + FE_4P[static_cast<size_t>(i)]) -
            static_cast<uint64_t>(b.limbs[static_cast<size_t>(i)]);
    }
    carry_propagate(h);
    return pack(h);
}

// Schoolbook product of two 10-limb numbers, reduced mod p.
//
// Output limb h_k collects every partial product a_i*b_j with i+j == k, plus
// 19 times every product with i+j == k+10 (the 2^255 = 19 wraparound). A
// product of two odd-index limbs carries an extra factor of 2 because the
// radix-2^25.5 exponents satisfy e_i + e_j = e_{i+j} + 1 in that case; this
// is folded into the doubled odd a-limbs (aN_2) and the 19x b-limbs (bN_19).
auto fe25519x32_mul(Fe25519x32 const& a, Fe25519x32 const& b) -> Fe25519x32
{
    uint64_t const a0 = a.limbs[0], a1 = a.limbs[1], a2 = a.limbs[2], a3 = a.limbs[3], a4 = a.limbs[4];
    uint64_t const a5 = a.limbs[5], a6 = a.limbs[6], a7 = a.limbs[7], a8 = a.limbs[8], a9 = a.limbs[9];
    uint64_t const b0 = b.limbs[0], b1 = b.limbs[1], b2 = b.limbs[2], b3 = b.limbs[3], b4 = b.limbs[4];
    uint64_t const b5 = b.limbs[5], b6 = b.limbs[6], b7 = b.limbs[7], b8 = b.limbs[8], b9 = b.limbs[9];

    uint64_t const a1_2 = 2 * a1, a3_2 = 2 * a3, a5_2 = 2 * a5, a7_2 = 2 * a7, a9_2 = 2 * a9;
    uint64_t const b1_19 = 19 * b1, b2_19 = 19 * b2, b3_19 = 19 * b3, b4_19 = 19 * b4, b5_19 = 19 * b5;
    uint64_t const b6_19 = 19 * b6, b7_19 = 19 * b7, b8_19 = 19 * b8, b9_19 = 19 * b9;

    uint64_t h[10];
    h[0] = a0 * b0 + a1_2 * b9_19 + a2 * b8_19 + a3_2 * b7_19 + a4 * b6_19 + a5_2 * b5_19 + a6 * b4_19 + a7_2 * b3_19 + a8 * b2_19 +
        a9_2 * b1_19;
    h[1] =
        a0 * b1 + a1 * b0 + a2 * b9_19 + a3 * b8_19 + a4 * b7_19 + a5 * b6_19 + a6 * b5_19 + a7 * b4_19 + a8 * b3_19 + a9 * b2_19;
    h[2] = a0 * b2 + a1_2 * b1 + a2 * b0 + a3_2 * b9_19 + a4 * b8_19 + a5_2 * b7_19 + a6 * b6_19 + a7_2 * b5_19 + a8 * b4_19 +
        a9_2 * b3_19;
    h[3] = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b9_19 + a5 * b8_19 + a6 * b7_19 + a7 * b6_19 + a8 * b5_19 + a9 * b4_19;
    h[4] =
        a0 * b4 + a1_2 * b3 + a2 * b2 + a3_2 * b1 + a4 * b0 + a5_2 * b9_19 + a6 * b8_19 + a7_2 * b7_19 + a8 * b6_19 + a9_2 * b5_19;
    h[5] = a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0 + a6 * b9_19 + a7 * b8_19 + a8 * b7_19 + a9 * b6_19;
    h[6] = a0 * b6 + a1_2 * b5 + a2 * b4 + a3_2 * b3 + a4 * b2 + a5_2 * b1 + a6 * b0 + a7_2 * b9_19 + a8 * b8_19 + a9_2 * b7_19;
    h[7] = a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0 + a8 * b9_19 + a9 * b8_19;
    h[8] = a0 * b8 + a1_2 * b7 + a2 * b6 + a3_2 * b5 + a4 * b4 + a5_2 * b3 + a6 * b2 + a7_2 * b1 + a8 * b0 + a9_2 * b9_19;
    h[9] = a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;

    carry_propagate(h);
    return pack(h);
}

// Squaring is implemented as mul(a, a). The 5x51-bit code has a dedicated
// squaring path for speed; correctness-first here, an optimized variant can
// be added later (the cross-check test would validate it).
auto fe25519x32_sq(Fe25519x32 const& a) -> Fe25519x32
{
    return fe25519x32_mul(a, a);
}

// Multiply every limb by a single small (<= 32-bit) value, then reduce.
auto fe25519x32_mul_small(Fe25519x32 const& a, uint32_t b) -> Fe25519x32
{
    uint64_t const bb = b;
    uint64_t h[10];
    for (int i = 0; i < 10; ++i) {
        h[i] = static_cast<uint64_t>(a.limbs[static_cast<size_t>(i)]) * bb;
    }
    carry_propagate(h);
    return pack(h);
}

auto fe25519x32_neg(Fe25519x32 const& a) -> Fe25519x32
{
    return fe25519x32_sub(fe25519x32_zero(), a);
}

void fe25519x32_cmov(Fe25519x32& f, Fe25519x32 const& g, uint32_t b)
{
    uint32_t const mask = static_cast<uint32_t>(0) - (b & 1U);
    for (int i = 0; i < 10; ++i) {
        f.limbs[static_cast<size_t>(i)] ^= mask & (f.limbs[static_cast<size_t>(i)] ^ g.limbs[static_cast<size_t>(i)]);
    }
}

// Unpack 32 little-endian bytes into 10 limbs (bit 255 discarded).
auto fe25519x32_from_bytes(span<uint8_t const, 32> s) -> Fe25519x32
{
    uint64_t const t0 = load_le64(s.first<8>());
    uint64_t const t1 = load_le64(s.subspan<8, 8>());
    uint64_t const t2 = load_le64(s.subspan<16, 8>());
    uint64_t const t3 = load_le64(s.subspan<24, 8>());

    Fe25519x32 h;
    h.limbs[0] = static_cast<uint32_t>(t0 & M26);
    h.limbs[1] = static_cast<uint32_t>((t0 >> 26) & M25);
    h.limbs[2] = static_cast<uint32_t>(((t0 >> 51) | (t1 << 13)) & M26);
    h.limbs[3] = static_cast<uint32_t>((t1 >> 13) & M25);
    h.limbs[4] = static_cast<uint32_t>((t1 >> 38) & M26);
    h.limbs[5] = static_cast<uint32_t>(t2 & M25);
    h.limbs[6] = static_cast<uint32_t>((t2 >> 25) & M26);
    h.limbs[7] = static_cast<uint32_t>(((t2 >> 51) | (t3 << 13)) & M25);
    h.limbs[8] = static_cast<uint32_t>((t3 >> 12) & M26);
    h.limbs[9] = static_cast<uint32_t>((t3 >> 38) & M25);
    return h;
}

// Serialize to canonical 32-byte little-endian form: carry-propagate, then a
// conditional subtraction of p, then pack the 10 limbs into 4 64-bit words.
auto fe25519x32_to_bytes(Fe25519x32 const& h) -> std::array<uint8_t, 32>
{
    uint64_t t[10];
    for (int i = 0; i < 10; ++i) {
        t[i] = h.limbs[static_cast<size_t>(i)];
    }
    carry_propagate(t);

    // q = floor((value + 19) / 2^255), which is 1 iff value >= p.
    uint64_t q = (t[0] + 19) >> 26;
    q = (t[1] + q) >> 25;
    q = (t[2] + q) >> 26;
    q = (t[3] + q) >> 25;
    q = (t[4] + q) >> 26;
    q = (t[5] + q) >> 25;
    q = (t[6] + q) >> 26;
    q = (t[7] + q) >> 25;
    q = (t[8] + q) >> 26;
    q = (t[9] + q) >> 25;

    // Subtract q*p by adding 19*q and propagating linearly (the carry out of
    // limb 9 is the borrow of bit 255 and is discarded).
    t[0] += 19 * q;
    uint64_t c;
    c = t[0] >> 26;
    t[0] &= M26;
    t[1] += c;
    c = t[1] >> 25;
    t[1] &= M25;
    t[2] += c;
    c = t[2] >> 26;
    t[2] &= M26;
    t[3] += c;
    c = t[3] >> 25;
    t[3] &= M25;
    t[4] += c;
    c = t[4] >> 26;
    t[4] &= M26;
    t[5] += c;
    c = t[5] >> 25;
    t[5] &= M25;
    t[6] += c;
    c = t[6] >> 26;
    t[6] &= M26;
    t[7] += c;
    c = t[7] >> 25;
    t[7] &= M25;
    t[8] += c;
    c = t[8] >> 26;
    t[8] &= M26;
    t[9] += c;
    t[9] &= M25;

    uint64_t const w0 = t[0] | (t[1] << 26) | (t[2] << 51);
    uint64_t const w1 = (t[2] >> 13) | (t[3] << 13) | (t[4] << 38);
    uint64_t const w2 = t[5] | (t[6] << 25) | (t[7] << 51);
    uint64_t const w3 = (t[7] >> 13) | (t[8] << 12) | (t[9] << 38);

    std::array<uint8_t, 32> out{};
    auto os = span(out);
    store_le64(os.first<8>(), w0);
    store_le64(os.subspan<8, 8>(), w1);
    store_le64(os.subspan<16, 8>(), w2);
    store_le64(os.subspan<24, 8>(), w3);
    return out;
}

auto fe25519x32_is_negative(Fe25519x32 const& f) -> uint32_t
{
    auto bytes = fe25519x32_to_bytes(f);
    return static_cast<uint32_t>(bytes[0]) & 1U;
}

auto fe25519x32_is_zero(Fe25519x32 const& f) -> uint32_t
{
    auto bytes = fe25519x32_to_bytes(f);
    uint8_t acc = 0;
    for (int i = 0; i < 32; ++i) {
        acc |= bytes[static_cast<size_t>(i)];
    }
    return ((static_cast<uint32_t>(acc) - 1) >> 31) & 1U;
}

// a^(p-2) mod p — same addition chain as fe25519_invert.
auto fe25519x32_invert(Fe25519x32 const& z) -> Fe25519x32
{
    auto z2 = fe25519x32_sq(z);
    auto z8 = fe25519x32_sq(fe25519x32_sq(z2));
    auto z9 = fe25519x32_mul(z, z8);
    auto z11 = fe25519x32_mul(z2, z9);
    auto z_5_0 = fe25519x32_mul(z9, fe25519x32_sq(z11));

    auto t = fe25519x32_sq(z_5_0);
    for (int i = 1; i < 5; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_10_0 = fe25519x32_mul(z_5_0, t);

    t = fe25519x32_sq(z_10_0);
    for (int i = 1; i < 10; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_20_0 = fe25519x32_mul(z_10_0, t);

    t = fe25519x32_sq(z_20_0);
    for (int i = 1; i < 20; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_40_0 = fe25519x32_mul(z_20_0, t);

    t = fe25519x32_sq(z_40_0);
    for (int i = 1; i < 10; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_50_0 = fe25519x32_mul(z_10_0, t);

    t = fe25519x32_sq(z_50_0);
    for (int i = 1; i < 50; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_100_0 = fe25519x32_mul(z_50_0, t);

    t = fe25519x32_sq(z_100_0);
    for (int i = 1; i < 100; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_200_0 = fe25519x32_mul(z_100_0, t);

    t = fe25519x32_sq(z_200_0);
    for (int i = 1; i < 50; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_250_0 = fe25519x32_mul(z_50_0, t);

    t = fe25519x32_sq(z_250_0);
    for (int i = 1; i < 5; ++i) {
        t = fe25519x32_sq(t);
    }
    return fe25519x32_mul(z11, t);
}

// a^((p-5)/8) = a^(2^252 - 3) — same addition chain as fe25519_pow22523.
auto fe25519x32_pow22523(Fe25519x32 const& z) -> Fe25519x32
{
    auto z2 = fe25519x32_sq(z);
    auto z8 = fe25519x32_sq(fe25519x32_sq(z2));
    auto z9 = fe25519x32_mul(z, z8);
    auto z11 = fe25519x32_mul(z2, z9);
    auto z_5_0 = fe25519x32_mul(z9, fe25519x32_sq(z11));

    auto t = fe25519x32_sq(z_5_0);
    for (int i = 1; i < 5; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_10_0 = fe25519x32_mul(z_5_0, t);

    t = fe25519x32_sq(z_10_0);
    for (int i = 1; i < 10; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_20_0 = fe25519x32_mul(z_10_0, t);

    t = fe25519x32_sq(z_20_0);
    for (int i = 1; i < 20; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_40_0 = fe25519x32_mul(z_20_0, t);

    t = fe25519x32_sq(z_40_0);
    for (int i = 1; i < 10; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_50_0 = fe25519x32_mul(z_10_0, t);

    t = fe25519x32_sq(z_50_0);
    for (int i = 1; i < 50; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_100_0 = fe25519x32_mul(z_50_0, t);

    t = fe25519x32_sq(z_100_0);
    for (int i = 1; i < 100; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_200_0 = fe25519x32_mul(z_100_0, t);

    t = fe25519x32_sq(z_200_0);
    for (int i = 1; i < 50; ++i) {
        t = fe25519x32_sq(t);
    }
    auto z_250_0 = fe25519x32_mul(z_50_0, t);

    t = fe25519x32_sq(z_250_0);
    t = fe25519x32_sq(t);
    return fe25519x32_mul(z, t);
}

}  // namespace statusbar::crypto
