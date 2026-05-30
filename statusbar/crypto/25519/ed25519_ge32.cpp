// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Ed25519 Edwards-group operations — 32-bit reduced-radix implementation.
// See ed25519_ge32.hpp. This mirrors the GeP3 / ge_* layer in curve25519.cpp,
// with every field operation routed through curve25519_fe32 (no __uint128_t).

#include "statusbar/crypto/25519/ed25519_ge32.hpp"

#include "statusbar/crypto/25519/curve25519_fe32.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

namespace {

// Ed25519 base point B, compressed (RFC 8032). y = 4/5, sign bit clear.
constexpr std::array<uint8_t, 32> kBaseCompressed = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

// The field element equal to a small integer.
auto fe_small(uint32_t k) -> Fe25519x32
{
    std::array<uint8_t, 32> b{};
    b[0] = static_cast<uint8_t>(k);
    b[1] = static_cast<uint8_t>(k >> 8);
    b[2] = static_cast<uint8_t>(k >> 16);
    b[3] = static_cast<uint8_t>(k >> 24);
    return fe25519x32_from_bytes(std::span<uint8_t const, 32>(b));
}

// Curve constants, derived once from first principles using only 32-bit field
// operations — no hardcoded limb values.

// d = -121665/121666 mod p.
auto ed_d() -> Fe25519x32 const&
{
    static Fe25519x32 const d = fe25519x32_neg(fe25519x32_mul(fe_small(121665), fe25519x32_invert(fe_small(121666))));
    return d;
}

// 2*d, used by the addition formula.
auto ed_2d() -> Fe25519x32 const&
{
    static Fe25519x32 const d2 = fe25519x32_add(ed_d(), ed_d());
    return d2;
}

// sqrt(-1) = 2^((p-1)/4) mod p. Since (p-1)/4 = 2*(2^252-3) + 1, this is
// pow22523(2)^2 * 2; 2 is a quadratic non-residue mod p, so the result
// squares to -1.
auto ed_sqrt_m1() -> Fe25519x32 const&
{
    static Fe25519x32 const r = fe25519x32_mul(fe25519x32_sq(fe25519x32_pow22523(fe_small(2))), fe_small(2));
    return r;
}

}  // namespace

auto ge32_p3_identity() -> GeP3x32
{
    GeP3x32 p;
    p.X = fe25519x32_zero();
    p.Y = fe25519x32_one();
    p.Z = fe25519x32_one();
    p.T = fe25519x32_zero();
    return p;
}

// Encode: affine x = X/Z, y = Y/Z; emit y little-endian with sign(x) in the
// top bit of byte 31.
auto ge32_p3_to_bytes(GeP3x32 const& p) -> std::array<uint8_t, 32>
{
    auto const zinv = fe25519x32_invert(p.Z);
    auto const x = fe25519x32_mul(p.X, zinv);
    auto const y = fe25519x32_mul(p.Y, zinv);

    auto out = fe25519x32_to_bytes(y);
    out[31] ^= static_cast<uint8_t>(fe25519x32_is_negative(x) << 7);
    return out;
}

// Decode (RFC 8032 Section 5.1.3): recover x from y and the sign bit.
auto ge32_from_bytes(std::span<uint8_t const, 32> s) -> std::optional<GeP3x32>
{
    uint32_t const sign = static_cast<uint32_t>(s[31]) >> 7;

    std::array<uint8_t, 32> temp{};
    for (int i = 0; i < 32; ++i) {
        temp[static_cast<size_t>(i)] = s[static_cast<size_t>(i)];
    }
    temp[31] &= 0x7F;

    auto const y = fe25519x32_from_bytes(std::span<uint8_t const, 32>(temp));
    auto const y2 = fe25519x32_sq(y);
    auto const u = fe25519x32_sub(y2, fe25519x32_one());
    auto const v = fe25519x32_add(fe25519x32_mul(ed_d(), y2), fe25519x32_one());

    // x = u * v^3 * (u * v^7)^((p-5)/8)
    auto const v2 = fe25519x32_sq(v);
    auto const v3 = fe25519x32_mul(v, v2);
    auto const uv3 = fe25519x32_mul(u, v3);
    auto const v7 = fe25519x32_mul(fe25519x32_sq(v3), v);
    auto const uv7 = fe25519x32_mul(u, v7);
    auto x = fe25519x32_mul(uv3, fe25519x32_pow22523(uv7));

    // Check v*x^2 == u, or == -u (then multiply x by sqrt(-1)).
    auto const vx2 = fe25519x32_mul(v, fe25519x32_sq(x));
    if (fe25519x32_is_zero(fe25519x32_sub(vx2, u)) == 0) {
        if (fe25519x32_is_zero(fe25519x32_add(vx2, u)) == 0) {
            return std::nullopt;
        }
        x = fe25519x32_mul(x, ed_sqrt_m1());
    }

    if (fe25519x32_is_negative(x) != sign) {
        x = fe25519x32_neg(x);
    }

    GeP3x32 point;
    point.X = x;
    point.Y = y;
    point.Z = fe25519x32_one();
    point.T = fe25519x32_mul(x, y);
    return point;
}

// Unified addition for extended coordinates (add-2008-hwcd-3, a = -1).
auto ge32_p3_add(GeP3x32 const& P, GeP3x32 const& Q) -> GeP3x32
{
    auto const A = fe25519x32_mul(fe25519x32_sub(P.Y, P.X), fe25519x32_sub(Q.Y, Q.X));
    auto const B = fe25519x32_mul(fe25519x32_add(P.Y, P.X), fe25519x32_add(Q.Y, Q.X));
    auto const C = fe25519x32_mul(P.T, fe25519x32_mul(ed_2d(), Q.T));
    auto const D = fe25519x32_mul(P.Z, fe25519x32_mul_small(Q.Z, 2));
    auto const E = fe25519x32_sub(B, A);
    auto const F = fe25519x32_sub(D, C);
    auto const G = fe25519x32_add(D, C);
    auto const H = fe25519x32_add(B, A);

    GeP3x32 R;
    R.X = fe25519x32_mul(E, F);
    R.Y = fe25519x32_mul(G, H);
    R.T = fe25519x32_mul(E, H);
    R.Z = fe25519x32_mul(F, G);
    return R;
}

// Dedicated doubling for a = -1 twisted Edwards (dbl-2008-hwcd).
auto ge32_p3_dbl(GeP3x32 const& P) -> GeP3x32
{
    auto const A = fe25519x32_sq(P.X);
    auto const B = fe25519x32_sq(P.Y);
    auto const C = fe25519x32_mul_small(fe25519x32_sq(P.Z), 2);
    auto const D = fe25519x32_neg(A);
    auto const E = fe25519x32_sub(fe25519x32_sq(fe25519x32_add(P.X, P.Y)), fe25519x32_add(A, B));
    auto const G = fe25519x32_add(D, B);
    auto const F = fe25519x32_sub(G, C);
    auto const H = fe25519x32_sub(D, B);

    GeP3x32 R;
    R.X = fe25519x32_mul(E, F);
    R.Y = fe25519x32_mul(G, H);
    R.T = fe25519x32_mul(E, H);
    R.Z = fe25519x32_mul(F, G);
    return R;
}

auto ge32_p3_neg(GeP3x32 const& P) -> GeP3x32
{
    GeP3x32 R;
    R.X = fe25519x32_neg(P.X);
    R.Y = P.Y;
    R.Z = P.Z;
    R.T = fe25519x32_neg(P.T);
    return R;
}

// Constant-time fixed-base scalar multiplication via a 4-bit fixed window.
auto ge32_scalar_mult_base(std::span<uint8_t const, 32> scalar) -> GeP3x32
{
    // 16-entry table table[i] = i*B, built once.
    static auto const table = [] {
        auto const base = *ge32_from_bytes(std::span<uint8_t const, 32>(kBaseCompressed));
        std::array<GeP3x32, 16> t;
        t[0] = ge32_p3_identity();
        t[1] = base;
        for (int i = 2; i < 16; ++i) {
            t[static_cast<size_t>(i)] = ge32_p3_add(t[static_cast<size_t>(i - 1)], base);
        }
        return t;
    }();

    auto get_nibble = [&](int i) -> uint8_t {
        int const byte_idx = i / 2;
        if (i % 2 == 0) {
            return scalar[static_cast<size_t>(byte_idx)] & 0x0F;
        }
        return (scalar[static_cast<size_t>(byte_idx)] >> 4) & 0x0F;
    };

    auto ct_lookup = [&](uint8_t index) -> GeP3x32 {
        GeP3x32 result = table[0];
        for (int i = 1; i < 16; ++i) {
            uint32_t const eq = 1U & ((static_cast<uint32_t>(i ^ index) - 1) >> 31);
            fe25519x32_cmov(result.X, table[static_cast<size_t>(i)].X, eq);
            fe25519x32_cmov(result.Y, table[static_cast<size_t>(i)].Y, eq);
            fe25519x32_cmov(result.Z, table[static_cast<size_t>(i)].Z, eq);
            fe25519x32_cmov(result.T, table[static_cast<size_t>(i)].T, eq);
        }
        return result;
    };

    auto result = ct_lookup(get_nibble(63));
    for (int i = 62; i >= 0; --i) {
        result = ge32_p3_dbl(result);
        result = ge32_p3_dbl(result);
        result = ge32_p3_dbl(result);
        result = ge32_p3_dbl(result);
        result = ge32_p3_add(result, ct_lookup(get_nibble(i)));
    }
    return result;
}

// [a]A + [b]B via Straus's trick. Variable-time: a, b are public in verify.
auto ge32_double_scalar_mult_vartime(std::span<uint8_t const, 32> a, GeP3x32 const& A, std::span<uint8_t const, 32> b) -> GeP3x32
{
    static auto const B = *ge32_from_bytes(std::span<uint8_t const, 32>(kBaseCompressed));

    GeP3x32 table[4];
    table[0] = ge32_p3_identity();
    table[1] = B;
    table[2] = A;
    table[3] = ge32_p3_add(A, B);

    auto result = ge32_p3_identity();
    for (int bit = 254; bit >= 0; --bit) {
        result = ge32_p3_dbl(result);

        uint32_t const a_bit = (static_cast<uint32_t>(a[static_cast<size_t>(bit / 8)]) >> (bit % 8)) & 1U;
        uint32_t const b_bit = (static_cast<uint32_t>(b[static_cast<size_t>(bit / 8)]) >> (bit % 8)) & 1U;
        auto const index = (a_bit << 1) | b_bit;
        if (index != 0) {
            result = ge32_p3_add(result, table[index]);
        }
    }
    return result;
}

}  // namespace statusbar::crypto
