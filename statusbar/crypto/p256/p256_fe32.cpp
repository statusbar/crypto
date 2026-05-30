// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// NIST P-256 field arithmetic — 32-bit reduced-radix implementation.
// See p256_fe32.hpp for the representation rationale.
//
// This file uses nothing wider than uint64_t / int64_t (for 32x32->64
// products and signed reduction accumulators); it never uses __uint128_t, so
// it builds and runs on a 32-bit ALU. It is always compiled and is
// cross-checked against the 4x64-bit implementation by p256_fe32_test.cpp.

#include "statusbar/crypto/p256/p256_fe32.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

namespace {

// p = 2^256 - 2^224 + 2^192 + 2^96 - 1, as 8 little-endian 32-bit words.
constexpr std::array<uint32_t, 8> P256_P32 = {
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000001,
    0xFFFFFFFF,
};

// 2^256 mod p = 2^224 - 2^192 - 2^96 + 1, as 8 little-endian 32-bit words.
// Used to fold the carry out of the Solinas reduction back into the limbs.
constexpr std::array<uint32_t, 8> FOLD = {
    0x00000001,
    0x00000000,
    0x00000000,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFE,
    0x00000000,
};

// Constant-time conditional subtraction of p: r -= p if r >= p.
void csub_p(uint32_t* r)
{
    int64_t borrow = 0;
    uint32_t t[8];
    for (int i = 0; i < 8; ++i) {
        int64_t const d = static_cast<int64_t>(r[i]) - static_cast<int64_t>(P256_P32[static_cast<size_t>(i)]) - borrow;
        t[i] = static_cast<uint32_t>(d);
        borrow = (d >> 63) & 1;  // 1 if d < 0
    }
    // borrow == 0 means r >= p: select the subtracted value t.
    uint32_t const mask = static_cast<uint32_t>(borrow) - 1;  // ~0 if r >= p, else 0
    for (int i = 0; i < 8; ++i) {
        r[i] = (r[i] & ~mask) | (t[i] & mask);
    }
}

}  // namespace

auto p256_fe32_one() -> P256FieldElement32
{
    P256FieldElement32 r;
    r.limbs[0] = 1;
    return r;
}

// Big-endian 32-byte decode (does not reduce mod p), matching p256_fe_from_bytes.
auto p256_fe32_from_bytes(std::span<uint8_t const, 32> bytes) -> P256FieldElement32
{
    P256FieldElement32 r{};
    for (int i = 0; i < 8; ++i) {
        size_t const o = static_cast<size_t>(7 - i) * 4;
        r.limbs[static_cast<size_t>(i)] = (static_cast<uint32_t>(bytes[o]) << 24) | (static_cast<uint32_t>(bytes[o + 1]) << 16) |
            (static_cast<uint32_t>(bytes[o + 2]) << 8) | static_cast<uint32_t>(bytes[o + 3]);
    }
    return r;
}

// Canonical big-endian 32-byte encoding: reduce once mod p, then pack.
auto p256_fe32_to_bytes(P256FieldElement32 const& a) -> std::array<uint8_t, 32>
{
    uint32_t r[8];
    for (int i = 0; i < 8; ++i) {
        r[i] = a.limbs[static_cast<size_t>(i)];
    }
    csub_p(r);

    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        size_t const o = static_cast<size_t>(7 - i) * 4;
        uint32_t const v = r[i];
        out[o] = static_cast<uint8_t>(v >> 24);
        out[o + 1] = static_cast<uint8_t>(v >> 16);
        out[o + 2] = static_cast<uint8_t>(v >> 8);
        out[o + 3] = static_cast<uint8_t>(v);
    }
    return out;
}

auto p256_fe32_add(P256FieldElement32 const& a, P256FieldElement32 const& b) -> P256FieldElement32
{
    uint32_t r[8];
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t const s = static_cast<uint64_t>(a.limbs[static_cast<size_t>(i)]) + b.limbs[static_cast<size_t>(i)] + carry;
        r[i] = static_cast<uint32_t>(s);
        carry = s >> 32;
    }
    // r - p, tracking the borrow.
    uint64_t borrow = 0;
    uint32_t t[8];
    for (int i = 0; i < 8; ++i) {
        int64_t const d =
            static_cast<int64_t>(r[i]) - static_cast<int64_t>(P256_P32[static_cast<size_t>(i)]) - static_cast<int64_t>(borrow);
        t[i] = static_cast<uint32_t>(d);
        borrow = static_cast<uint64_t>(d >> 63) & 1;
    }
    // (carry:r) >= p  iff  carry == 1, or (carry == 0 and no borrow).
    uint64_t const use_reduced = 1 - (borrow & (1 - carry));
    uint32_t const mask = static_cast<uint32_t>(0) - static_cast<uint32_t>(use_reduced);
    P256FieldElement32 out;
    for (int i = 0; i < 8; ++i) {
        out.limbs[static_cast<size_t>(i)] = (r[i] & ~mask) | (t[i] & mask);
    }
    return out;
}

auto p256_fe32_sub(P256FieldElement32 const& a, P256FieldElement32 const& b) -> P256FieldElement32
{
    uint32_t r[8];
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        int64_t const d = static_cast<int64_t>(a.limbs[static_cast<size_t>(i)]) -
            static_cast<int64_t>(b.limbs[static_cast<size_t>(i)]) - static_cast<int64_t>(borrow);
        r[i] = static_cast<uint32_t>(d);
        borrow = static_cast<uint64_t>(d >> 63) & 1;
    }
    // If a < b, add p back.
    uint32_t t[8];
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t const s = static_cast<uint64_t>(r[i]) + P256_P32[static_cast<size_t>(i)] + carry;
        t[i] = static_cast<uint32_t>(s);
        carry = s >> 32;
    }
    uint32_t const mask = static_cast<uint32_t>(0) - static_cast<uint32_t>(borrow);
    P256FieldElement32 out;
    for (int i = 0; i < 8; ++i) {
        out.limbs[static_cast<size_t>(i)] = (r[i] & ~mask) | (t[i] & mask);
    }
    return out;
}

auto p256_fe32_neg(P256FieldElement32 const& a) -> P256FieldElement32
{
    return p256_fe32_sub(P256FieldElement32{}, a);
}

// a * b mod p: schoolbook 8x8 product, then the NIST P-256 Solinas reduction
//   T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4   (mod p)
// expressed per output word over the 16-word product c[0..15].
auto p256_fe32_mul(P256FieldElement32 const& a, P256FieldElement32 const& b) -> P256FieldElement32
{
    uint32_t c[16] = {};
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t const prod = static_cast<uint64_t>(c[i + j]) +
                static_cast<uint64_t>(a.limbs[static_cast<size_t>(i)]) * b.limbs[static_cast<size_t>(j)] + carry;
            c[i + j] = static_cast<uint32_t>(prod);
            carry = prod >> 32;
        }
        c[i + 8] = static_cast<uint32_t>(carry);
    }

    // Per-word Solinas accumulators (signed: the D-terms are subtracted).
    int64_t w[8];
    w[0] = static_cast<int64_t>(c[0]) + c[8] + c[9] - c[11] - c[12] - c[13] - c[14];
    w[1] = static_cast<int64_t>(c[1]) + c[9] + c[10] - c[12] - c[13] - c[14] - c[15];
    w[2] = static_cast<int64_t>(c[2]) + c[10] + c[11] - c[13] - c[14] - c[15];
    w[3] = static_cast<int64_t>(c[3]) + 2 * static_cast<int64_t>(c[11]) + 2 * static_cast<int64_t>(c[12]) + c[13] - c[8] - c[9] -
        c[15];
    w[4] = static_cast<int64_t>(c[4]) + 2 * static_cast<int64_t>(c[12]) + 2 * static_cast<int64_t>(c[13]) + c[14] - c[9] - c[10];
    w[5] = static_cast<int64_t>(c[5]) + 2 * static_cast<int64_t>(c[13]) + 2 * static_cast<int64_t>(c[14]) + c[15] - c[10] - c[11];
    w[6] = static_cast<int64_t>(c[6]) + 3 * static_cast<int64_t>(c[14]) + 2 * static_cast<int64_t>(c[15]) + c[13] - c[8] - c[9];
    w[7] = static_cast<int64_t>(c[7]) + 3 * static_cast<int64_t>(c[15]) + c[8] - c[10] - c[11] - c[12] - c[13];

    // Carry-propagate the signed accumulators into 8 words plus a carry.
    int64_t carry = 0;
    uint32_t rl[8];
    for (int i = 0; i < 8; ++i) {
        int64_t const v = w[i] + carry;
        rl[i] = static_cast<uint32_t>(v);
        carry = v >> 32;  // arithmetic shift — signed carry
    }

    // Fold carry * (2^256 mod p) back in; the carry is small, two passes clear it.
    for (int fold = 0; fold < 2 && carry != 0; ++fold) {
        int64_t const cw = carry;
        int64_t acc = 0;
        for (int i = 0; i < 8; ++i) {
            acc += static_cast<int64_t>(rl[i]) + cw * static_cast<int64_t>(FOLD[static_cast<size_t>(i)]);
            rl[i] = static_cast<uint32_t>(acc);
            acc >>= 32;
        }
        carry = acc;
    }

    // Bring into [0, p): the reduced value is below 3p.
    csub_p(rl);
    csub_p(rl);

    P256FieldElement32 r;
    for (int i = 0; i < 8; ++i) {
        r.limbs[static_cast<size_t>(i)] = rl[i];
    }
    return r;
}

auto p256_fe32_sqr(P256FieldElement32 const& a) -> P256FieldElement32
{
    return p256_fe32_mul(a, a);
}

namespace {

// Square `x` n times.
auto sqr_n(P256FieldElement32 const& x, int n) -> P256FieldElement32
{
    P256FieldElement32 r = x;
    for (int i = 0; i < n; ++i) {
        r = p256_fe32_sqr(r);
    }
    return r;
}

}  // namespace

// a^(p-2) mod p — the same addition chain as p256_fe_inv.
auto p256_fe32_inv(P256FieldElement32 const& a) -> P256FieldElement32
{
    P256FieldElement32 const x2 = p256_fe32_mul(p256_fe32_sqr(a), a);
    P256FieldElement32 const x3 = p256_fe32_mul(p256_fe32_sqr(x2), a);
    P256FieldElement32 const x6 = p256_fe32_mul(sqr_n(x3, 3), x3);
    P256FieldElement32 const x12 = p256_fe32_mul(sqr_n(x6, 6), x6);
    P256FieldElement32 const x15 = p256_fe32_mul(sqr_n(x12, 3), x3);
    P256FieldElement32 const x30 = p256_fe32_mul(sqr_n(x15, 15), x15);
    P256FieldElement32 const x32 = p256_fe32_mul(sqr_n(x30, 2), x2);

    P256FieldElement32 r = sqr_n(x32, 32);
    r = p256_fe32_mul(r, a);
    r = sqr_n(r, 128);
    r = p256_fe32_mul(r, x32);
    r = sqr_n(r, 32);
    r = p256_fe32_mul(r, x32);
    r = sqr_n(r, 30);
    r = p256_fe32_mul(r, x30);
    r = p256_fe32_sqr(r);
    r = p256_fe32_sqr(r);
    r = p256_fe32_mul(r, a);
    return r;
}

// a^((p+1)/4) mod p via square-and-multiply, or nullopt if a is not a residue.
auto p256_fe32_sqrt(P256FieldElement32 const& a) -> std::optional<P256FieldElement32>
{
    // (p+1)/4, as 8 little-endian 32-bit words.
    constexpr std::array<uint32_t, 8> exp = {
        0x00000000,
        0x00000000,
        0x40000000,
        0x00000000,
        0x00000000,
        0x40000000,
        0xC0000000,
        0x3FFFFFFF,
    };

    P256FieldElement32 r = p256_fe32_one();
    P256FieldElement32 base = a;
    for (int word = 0; word < 8; ++word) {
        for (int bit = 0; bit < 32; ++bit) {
            if (((exp[static_cast<size_t>(word)] >> bit) & 1U) != 0) {
                r = p256_fe32_mul(r, base);
            }
            base = p256_fe32_sqr(base);
        }
    }

    if (!p256_fe32_equal(p256_fe32_sqr(r), a)) {
        return std::nullopt;
    }
    return r;
}

auto p256_fe32_is_zero(P256FieldElement32 const& a) -> bool
{
    auto bytes = p256_fe32_to_bytes(a);
    uint8_t acc = 0;
    for (auto byte : bytes) {
        acc |= byte;
    }
    return acc == 0;
}

auto p256_fe32_equal(P256FieldElement32 const& a, P256FieldElement32 const& b) -> bool
{
    return p256_fe32_is_zero(p256_fe32_sub(a, b));
}

void p256_fe32_cmov(P256FieldElement32& f, P256FieldElement32 const& g, uint32_t b)
{
    uint32_t const mask = ~b + 1;  // 0 if b == 0, ~0 if b == 1
    for (int i = 0; i < 8; ++i) {
        f.limbs[static_cast<size_t>(i)] ^= mask & (f.limbs[static_cast<size_t>(i)] ^ g.limbs[static_cast<size_t>(i)]);
    }
}

}  // namespace statusbar::crypto
