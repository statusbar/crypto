// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// NIST P-256 scalar arithmetic (mod n) — 32-bit reduced-radix implementation.
// See p256_sc32.hpp for the representation rationale.
//
// Uses nothing wider than uint64_t / int64_t, so it builds and runs on a
// 32-bit ALU. Always compiled; cross-checked against the 4x64-bit
// implementation by p256_sc32_test.cpp.

#include "statusbar/crypto/p256/p256_sc32.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

namespace {

// n = group order, as 8 little-endian 32-bit words.
constexpr std::array<uint32_t, 8> N32 = {
    0xFC632551,
    0xF3B9CAC2,
    0xA7179E84,
    0xBCE6FAAD,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0x00000000,
    0xFFFFFFFF,
};

// n - 2 (the Fermat inversion exponent), as 8 little-endian 32-bit words.
constexpr std::array<uint32_t, 8> N_MINUS_2 = {
    0xFC63254F,
    0xF3B9CAC2,
    0xA7179E84,
    0xBCE6FAAD,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0x00000000,
    0xFFFFFFFF,
};

// 2^256 mod n, as 8 little-endian 32-bit words. Folds a wide value's high
// half down into the low 256 bits during reduction (it is below 2^224).
constexpr std::array<uint32_t, 8> R256 = {
    0x039CDAAF,
    0x0C46353D,
    0x58E8617B,
    0x43190552,
    0x00000000,
    0x00000000,
    0xFFFFFFFF,
    0x00000000,
};

// Constant-time conditional subtraction of n: r -= n if r >= n.
void csub_n(uint32_t* r)
{
    int64_t borrow = 0;
    uint32_t t[8];
    for (int i = 0; i < 8; ++i) {
        int64_t const d = static_cast<int64_t>(r[i]) - static_cast<int64_t>(N32[static_cast<size_t>(i)]) - borrow;
        t[i] = static_cast<uint32_t>(d);
        borrow = (d >> 63) & 1;
    }
    uint32_t const mask = static_cast<uint32_t>(borrow) - 1;  // ~0 if r >= n
    for (int i = 0; i < 8; ++i) {
        r[i] = (r[i] & ~mask) | (t[i] & mask);
    }
}

// Schoolbook product of two 8-word values into a 16-word result.
void mul_8x8(uint32_t const* a, uint32_t const* b, uint32_t* out)
{
    for (int k = 0; k < 16; ++k) {
        out[k] = 0;
    }
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t const t = static_cast<uint64_t>(out[i + j]) + static_cast<uint64_t>(a[i]) * b[j] + carry;
            out[i + j] = static_cast<uint32_t>(t);
            carry = t >> 32;
        }
        out[i + 8] = static_cast<uint32_t>(carry);
    }
}

// Add an 8-word value into the low half of a 16-word accumulator, carrying
// into the high half.
void add_lo(uint32_t* acc, uint32_t const* addend)
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t const s = static_cast<uint64_t>(acc[i]) + addend[i] + carry;
        acc[i] = static_cast<uint32_t>(s);
        carry = s >> 32;
    }
    for (int i = 8; i < 16; ++i) {
        uint64_t const s = static_cast<uint64_t>(acc[i]) + carry;
        acc[i] = static_cast<uint32_t>(s);
        carry = s >> 32;
    }
}

// Reduce a 16-word (512-bit) value mod n, given the words little-endian.
auto reduce_wide_words(uint32_t const* w) -> P256Scalar32
{
    // prod = x_hi * (2^256 mod n) + x_lo.
    uint32_t prod[16];
    mul_8x8(w + 8, R256.data(), prod);
    add_lo(prod, w);

    // Iterate the same fold; R256 < 2^224, so the high half shrinks by ~32
    // bits each pass. Ten passes is a constant, side-channel-safe bound.
    for (int iter = 0; iter < 10; ++iter) {
        uint32_t next[16];
        mul_8x8(prod + 8, R256.data(), next);
        add_lo(next, prod);
        for (int k = 0; k < 16; ++k) {
            prod[k] = next[k];
        }
    }

    uint32_t r[8];
    for (int i = 0; i < 8; ++i) {
        r[i] = prod[i];
    }
    csub_n(r);
    csub_n(r);
    csub_n(r);

    P256Scalar32 out;
    for (int i = 0; i < 8; ++i) {
        out.limbs[static_cast<size_t>(i)] = r[i];
    }
    return out;
}

}  // namespace

auto p256_sc32_add(P256Scalar32 const& a, P256Scalar32 const& b) -> P256Scalar32
{
    uint32_t r[8];
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t const s = static_cast<uint64_t>(a.limbs[static_cast<size_t>(i)]) + b.limbs[static_cast<size_t>(i)] + carry;
        r[i] = static_cast<uint32_t>(s);
        carry = s >> 32;
    }
    uint64_t borrow = 0;
    uint32_t t[8];
    for (int i = 0; i < 8; ++i) {
        int64_t const d =
            static_cast<int64_t>(r[i]) - static_cast<int64_t>(N32[static_cast<size_t>(i)]) - static_cast<int64_t>(borrow);
        t[i] = static_cast<uint32_t>(d);
        borrow = static_cast<uint64_t>(d >> 63) & 1;
    }
    uint64_t const use_reduced = 1 - (borrow & (1 - carry));
    uint32_t const mask = static_cast<uint32_t>(0) - static_cast<uint32_t>(use_reduced);
    P256Scalar32 out;
    for (int i = 0; i < 8; ++i) {
        out.limbs[static_cast<size_t>(i)] = (r[i] & ~mask) | (t[i] & mask);
    }
    return out;
}

auto p256_sc32_sub(P256Scalar32 const& a, P256Scalar32 const& b) -> P256Scalar32
{
    uint32_t r[8];
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        int64_t const d = static_cast<int64_t>(a.limbs[static_cast<size_t>(i)]) -
            static_cast<int64_t>(b.limbs[static_cast<size_t>(i)]) - static_cast<int64_t>(borrow);
        r[i] = static_cast<uint32_t>(d);
        borrow = static_cast<uint64_t>(d >> 63) & 1;
    }
    uint32_t t[8];
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t const s = static_cast<uint64_t>(r[i]) + N32[static_cast<size_t>(i)] + carry;
        t[i] = static_cast<uint32_t>(s);
        carry = s >> 32;
    }
    uint32_t const mask = static_cast<uint32_t>(0) - static_cast<uint32_t>(borrow);
    P256Scalar32 out;
    for (int i = 0; i < 8; ++i) {
        out.limbs[static_cast<size_t>(i)] = (r[i] & ~mask) | (t[i] & mask);
    }
    return out;
}

auto p256_sc32_negate(P256Scalar32 const& a) -> P256Scalar32
{
    return p256_sc32_sub(P256Scalar32{}, a);
}

auto p256_sc32_mul(P256Scalar32 const& a, P256Scalar32 const& b) -> P256Scalar32
{
    uint32_t wide[16];
    mul_8x8(a.limbs.data(), b.limbs.data(), wide);
    return reduce_wide_words(wide);
}

auto p256_sc32_inv(P256Scalar32 const& a) -> P256Scalar32
{
    // a^(n-2) mod n via left-to-right square-and-multiply.
    P256Scalar32 r;
    r.limbs[0] = 1;
    for (int word = 7; word >= 0; --word) {
        for (int bit = 31; bit >= 0; --bit) {
            r = p256_sc32_mul(r, r);
            if (((N_MINUS_2[static_cast<size_t>(word)] >> bit) & 1U) != 0) {
                r = p256_sc32_mul(r, a);
            }
        }
    }
    return r;
}

auto p256_sc32_is_zero(P256Scalar32 const& a) -> bool
{
    uint32_t acc = 0;
    for (int i = 0; i < 8; ++i) {
        acc |= a.limbs[static_cast<size_t>(i)];
    }
    return acc == 0;
}

auto p256_sc32_from_bytes(std::span<uint8_t const, 32> bytes) -> P256Scalar32
{
    P256Scalar32 r{};
    for (int i = 0; i < 8; ++i) {
        size_t const o = static_cast<size_t>(7 - i) * 4;
        r.limbs[static_cast<size_t>(i)] = (static_cast<uint32_t>(bytes[o]) << 24) | (static_cast<uint32_t>(bytes[o + 1]) << 16) |
            (static_cast<uint32_t>(bytes[o + 2]) << 8) | static_cast<uint32_t>(bytes[o + 3]);
    }
    return r;
}

auto p256_sc32_to_bytes(P256Scalar32 const& a) -> std::array<uint8_t, 32>
{
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        size_t const o = static_cast<size_t>(7 - i) * 4;
        uint32_t const v = a.limbs[static_cast<size_t>(i)];
        out[o] = static_cast<uint8_t>(v >> 24);
        out[o + 1] = static_cast<uint8_t>(v >> 16);
        out[o + 2] = static_cast<uint8_t>(v >> 8);
        out[o + 3] = static_cast<uint8_t>(v);
    }
    return out;
}

auto p256_sc32_reduce_wide(std::span<uint8_t const, 64> wide) -> P256Scalar32
{
    uint32_t w[16];
    for (int i = 0; i < 16; ++i) {
        size_t const o = static_cast<size_t>(15 - i) * 4;
        w[i] = (static_cast<uint32_t>(wide[o]) << 24) | (static_cast<uint32_t>(wide[o + 1]) << 16) |
            (static_cast<uint32_t>(wide[o + 2]) << 8) | static_cast<uint32_t>(wide[o + 3]);
    }
    return reduce_wide_words(w);
}

}  // namespace statusbar::crypto
