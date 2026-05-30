// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// NIST P-256 Jacobian-group operations — 32-bit reduced-radix implementation.
// See p256_jac32.hpp. This mirrors the P256JacobianPoint / p256_point_* layer
// in p256.cpp, with every field / scalar operation routed through p256_fe32 /
// p256_sc32 (no __uint128_t).

#include "statusbar/crypto/p256/p256_jac32.hpp"

#include "statusbar/crypto/p256/p256_fe32.hpp"
#include "statusbar/crypto/p256/p256_sc32.hpp"
#include "statusbar/crypto/sha/sha256_hw.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace statusbar::crypto {

namespace {

// Parse a 64-character hex string into 32 big-endian bytes.
auto from_hex32(char const* h) -> std::array<uint8_t, 32>
{
    auto nyb = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') {
            return static_cast<uint8_t>(c - '0');
        }
        return static_cast<uint8_t>((c | 0x20) - 'a' + 10);
    };
    std::array<uint8_t, 32> b{};
    for (int i = 0; i < 32; ++i) {
        b[static_cast<size_t>(i)] = static_cast<uint8_t>((nyb(h[2 * i]) << 4) | nyb(h[(2 * i) + 1]));
    }
    return b;
}

auto fe_const(char const* hex) -> P256FieldElement32
{
    auto const b = from_hex32(hex);
    return p256_fe32_from_bytes(std::span<uint8_t const, 32>(b));
}

// Curve constants (FIPS 186-4 / SEC 2 secp256r1), decoded once.
auto curve_gx() -> P256FieldElement32 const&
{
    static P256FieldElement32 const v = fe_const("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    return v;
}

auto curve_gy() -> P256FieldElement32 const&
{
    static P256FieldElement32 const v = fe_const("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    return v;
}

auto curve_b() -> P256FieldElement32 const&
{
    static P256FieldElement32 const v = fe_const("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    return v;
}

// 1 if the field element has any nonzero limb, else 0 (raw limb test —
// identity points carry an all-zero Z).
auto limbs_nonzero(P256FieldElement32 const& f) -> uint32_t
{
    uint32_t acc = 0;
    for (int i = 0; i < 8; ++i) {
        acc |= f.limbs[static_cast<size_t>(i)];
    }
    return (acc | (static_cast<uint32_t>(0) - acc)) >> 31;
}

// Constant-time mixed addition for scalar multiplication: no branches, the
// P == identity case is fixed up with cmov.
auto ct_add_affine(P256JacobianPoint32 const& P, P256AffinePoint32 const& Q) -> P256JacobianPoint32
{
    uint32_t const p_is_id = 1U - limbs_nonzero(P.Z);

    auto const z1z1 = p256_fe32_sqr(P.Z);
    auto const z1z1z1 = p256_fe32_mul(z1z1, P.Z);
    auto const u2 = p256_fe32_mul(Q.x, z1z1);
    auto const s2 = p256_fe32_mul(Q.y, z1z1z1);
    auto const h = p256_fe32_sub(u2, P.X);
    auto const r = p256_fe32_sub(s2, P.Y);
    auto const hh = p256_fe32_sqr(h);
    auto const hhh = p256_fe32_mul(h, hh);
    auto const v = p256_fe32_mul(P.X, hh);
    auto x3 = p256_fe32_sub(p256_fe32_sqr(r), hhh);
    x3 = p256_fe32_sub(x3, p256_fe32_add(v, v));
    auto y3 = p256_fe32_mul(r, p256_fe32_sub(v, x3));
    y3 = p256_fe32_sub(y3, p256_fe32_mul(P.Y, hhh));
    auto z3 = p256_fe32_mul(P.Z, h);

    // If P was the identity, the formula is wrong; select Q (as Jacobian Z=1).
    p256_fe32_cmov(x3, Q.x, p_is_id);
    p256_fe32_cmov(y3, Q.y, p_is_id);
    p256_fe32_cmov(z3, p256_fe32_one(), p_is_id);
    return P256JacobianPoint32{.X = x3, .Y = y3, .Z = z3};
}

}  // namespace

auto p256x32_generator() -> P256AffinePoint32
{
    return P256AffinePoint32{.x = curve_gx(), .y = curve_gy()};
}

auto p256x32_point_identity() -> P256JacobianPoint32
{
    P256JacobianPoint32 id{};
    id.Y.limbs[0] = 1;  // (0 : 1 : 0)
    return id;
}

auto p256x32_point_is_identity(P256JacobianPoint32 const& P) -> bool
{
    return p256_fe32_is_zero(P.Z);
}

auto p256x32_affine_to_jacobian(P256AffinePoint32 const& P) -> P256JacobianPoint32
{
    return P256JacobianPoint32{.X = P.x, .Y = P.y, .Z = p256_fe32_one()};
}

// Jacobian doubling (a = -3 optimization, Algorithm 3.21 from "Guide to ECC").
auto p256x32_point_double(P256JacobianPoint32 const& P) -> P256JacobianPoint32
{
    auto const delta = p256_fe32_sqr(P.Z);
    auto const gamma = p256_fe32_sqr(P.Y);
    auto const beta = p256_fe32_mul(P.X, gamma);

    auto const alpha = p256_fe32_mul(p256_fe32_sub(P.X, delta), p256_fe32_add(P.X, delta));
    auto alpha3 = p256_fe32_add(alpha, alpha);
    alpha3 = p256_fe32_add(alpha3, alpha);

    auto beta4 = p256_fe32_add(beta, beta);
    beta4 = p256_fe32_add(beta4, beta4);
    auto const beta8 = p256_fe32_add(beta4, beta4);

    auto x3 = p256_fe32_sub(p256_fe32_sqr(alpha3), beta8);

    auto z3 = p256_fe32_sqr(p256_fe32_add(P.Y, P.Z));
    z3 = p256_fe32_sub(z3, gamma);
    z3 = p256_fe32_sub(z3, delta);

    auto y3 = p256_fe32_mul(alpha3, p256_fe32_sub(beta4, x3));
    auto const gamma2 = p256_fe32_sqr(gamma);
    auto gamma8 = p256_fe32_add(gamma2, gamma2);
    gamma8 = p256_fe32_add(gamma8, gamma8);
    gamma8 = p256_fe32_add(gamma8, gamma8);
    y3 = p256_fe32_sub(y3, gamma8);

    return P256JacobianPoint32{.X = x3, .Y = y3, .Z = z3};
}

// Jacobian + affine mixed addition (branches on the identity / doubling edge
// cases; used outside the constant-time scalar-mult inner loop).
auto p256x32_point_add_affine(P256JacobianPoint32 const& P, P256AffinePoint32 const& Q) -> P256JacobianPoint32
{
    if (p256_fe32_is_zero(P.Z)) {
        return p256x32_affine_to_jacobian(Q);
    }

    auto const z1z1 = p256_fe32_sqr(P.Z);
    auto const z1z1z1 = p256_fe32_mul(z1z1, P.Z);
    auto const u2 = p256_fe32_mul(Q.x, z1z1);
    auto const s2 = p256_fe32_mul(Q.y, z1z1z1);
    auto const h = p256_fe32_sub(u2, P.X);
    auto const r = p256_fe32_sub(s2, P.Y);

    if (p256_fe32_is_zero(h)) {
        if (p256_fe32_is_zero(r)) {
            return p256x32_point_double(P);
        }
        return p256x32_point_identity();
    }

    auto const hh = p256_fe32_sqr(h);
    auto const hhh = p256_fe32_mul(h, hh);
    auto const v = p256_fe32_mul(P.X, hh);
    auto x3 = p256_fe32_sub(p256_fe32_sqr(r), hhh);
    x3 = p256_fe32_sub(x3, p256_fe32_add(v, v));
    auto y3 = p256_fe32_mul(r, p256_fe32_sub(v, x3));
    y3 = p256_fe32_sub(y3, p256_fe32_mul(P.Y, hhh));
    auto const z3 = p256_fe32_mul(P.Z, h);

    return P256JacobianPoint32{.X = x3, .Y = y3, .Z = z3};
}

// Full Jacobian addition.
auto p256x32_point_add(P256JacobianPoint32 const& P, P256JacobianPoint32 const& Q) -> P256JacobianPoint32
{
    if (p256_fe32_is_zero(P.Z)) {
        return Q;
    }
    if (p256_fe32_is_zero(Q.Z)) {
        return P;
    }

    auto const z1z1 = p256_fe32_sqr(P.Z);
    auto const z2z2 = p256_fe32_sqr(Q.Z);
    auto const u1 = p256_fe32_mul(P.X, z2z2);
    auto const u2 = p256_fe32_mul(Q.X, z1z1);
    auto const s1 = p256_fe32_mul(P.Y, p256_fe32_mul(Q.Z, z2z2));
    auto const s2 = p256_fe32_mul(Q.Y, p256_fe32_mul(P.Z, z1z1));
    auto const h = p256_fe32_sub(u2, u1);
    auto const r = p256_fe32_sub(s2, s1);

    if (p256_fe32_is_zero(h)) {
        if (p256_fe32_is_zero(r)) {
            return p256x32_point_double(P);
        }
        return p256x32_point_identity();
    }

    auto const hh = p256_fe32_sqr(h);
    auto const hhh = p256_fe32_mul(h, hh);
    auto const v = p256_fe32_mul(u1, hh);
    auto x3 = p256_fe32_sub(p256_fe32_sqr(r), hhh);
    x3 = p256_fe32_sub(x3, p256_fe32_add(v, v));
    auto y3 = p256_fe32_mul(r, p256_fe32_sub(v, x3));
    y3 = p256_fe32_sub(y3, p256_fe32_mul(s1, hhh));
    auto z3 = p256_fe32_mul(p256_fe32_mul(P.Z, Q.Z), h);

    return P256JacobianPoint32{.X = x3, .Y = y3, .Z = z3};
}

auto p256x32_point_neg(P256JacobianPoint32 const& P) -> P256JacobianPoint32
{
    return P256JacobianPoint32{.X = P.X, .Y = p256_fe32_neg(P.Y), .Z = P.Z};
}

auto p256x32_point_to_affine(P256JacobianPoint32 const& P) -> P256AffinePoint32
{
    if (p256_fe32_is_zero(P.Z)) {
        return P256AffinePoint32{};
    }
    auto const z_inv = p256_fe32_inv(P.Z);
    auto const z_inv2 = p256_fe32_sqr(z_inv);
    auto const z_inv3 = p256_fe32_mul(z_inv2, z_inv);
    return P256AffinePoint32{.x = p256_fe32_mul(P.X, z_inv2), .y = p256_fe32_mul(P.Y, z_inv3)};
}

auto p256x32_point_on_curve(P256AffinePoint32 const& P) -> bool
{
    // y^2 == x^3 - 3x + b
    auto const y2 = p256_fe32_sqr(P.y);
    auto const x3 = p256_fe32_mul(p256_fe32_sqr(P.x), P.x);
    auto three_x = p256_fe32_add(P.x, P.x);
    three_x = p256_fe32_add(three_x, P.x);
    auto rhs = p256_fe32_sub(x3, three_x);
    rhs = p256_fe32_add(rhs, curve_b());
    return p256_fe32_equal(y2, rhs);
}

// Variable-base scalar multiplication, constant-time double-and-always-add.
auto p256x32_scalar_mult(P256Scalar32 const& scalar, P256AffinePoint32 const& P) -> P256JacobianPoint32
{
    auto const sc = p256_sc32_to_bytes(scalar);
    auto r = p256x32_point_identity();
    for (int i = 0; i < 256; ++i) {
        r = p256x32_point_double(r);
        int const byte_idx = i / 8;
        int const bit_idx = 7 - (i % 8);
        uint32_t const bit = (sc[static_cast<size_t>(byte_idx)] >> bit_idx) & 1U;

        auto const r_add = ct_add_affine(r, P);
        p256_fe32_cmov(r.X, r_add.X, bit);
        p256_fe32_cmov(r.Y, r_add.Y, bit);
        p256_fe32_cmov(r.Z, r_add.Z, bit);
    }
    return r;
}

auto p256x32_scalar_mult_base(P256Scalar32 const& scalar) -> P256JacobianPoint32
{
    return p256x32_scalar_mult(scalar, p256x32_generator());
}

// [a]G + [b]Q via Shamir's trick, constant-time table selection.
auto p256x32_double_scalar_mult(P256Scalar32 const& a, P256Scalar32 const& b, P256AffinePoint32 const& Q) -> P256JacobianPoint32
{
    auto const a_bytes = p256_sc32_to_bytes(a);
    auto const b_bytes = p256_sc32_to_bytes(b);

    auto const g = p256x32_generator();
    auto const gpq = p256x32_point_to_affine(p256x32_point_add(p256x32_affine_to_jacobian(g), p256x32_affine_to_jacobian(Q)));

    P256AffinePoint32 table[4];
    table[0] = P256AffinePoint32{};
    table[1] = g;
    table[2] = Q;
    table[3] = gpq;

    auto r = p256x32_point_identity();
    for (int i = 0; i < 256; ++i) {
        r = p256x32_point_double(r);
        int const byte_idx = i / 8;
        int const bit_idx = 7 - (i % 8);
        uint32_t const a_bit = (a_bytes[static_cast<size_t>(byte_idx)] >> bit_idx) & 1U;
        uint32_t const b_bit = (b_bytes[static_cast<size_t>(byte_idx)] >> bit_idx) & 1U;
        uint32_t const idx = a_bit | (b_bit << 1);

        P256AffinePoint32 selected = table[0];
        for (uint32_t k = 1; k < 4; ++k) {
            uint32_t const eq = static_cast<uint32_t>(idx == k);
            p256_fe32_cmov(selected.x, table[k].x, eq);
            p256_fe32_cmov(selected.y, table[k].y, eq);
        }

        auto const r_add = p256x32_point_add_affine(r, selected);
        uint32_t const do_add = static_cast<uint32_t>(idx != 0);
        p256_fe32_cmov(r.X, r_add.X, do_add);
        p256_fe32_cmov(r.Y, r_add.Y, do_add);
        p256_fe32_cmov(r.Z, r_add.Z, do_add);
    }
    return r;
}

auto p256x32_keypair_from_seed(std::span<uint8_t const, 32> seed) -> std::pair<P256Scalar32, P256AffinePoint32>
{
    auto hash = sha256_hw(seed);
    P256Scalar32 d{};

    // Reduce the hash mod n; retry once on the (astronomically unlikely) zero.
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::array<uint8_t, 64> wide{};
        for (size_t i = 0; i < 32; ++i) {
            wide[32 + i] = hash[i];
        }
        d = p256_sc32_reduce_wide(std::span<uint8_t const, 64>(wide));
        if (!p256_sc32_is_zero(d)) {
            break;
        }
        hash = sha256_hw(hash);
    }

    auto const q = p256x32_point_to_affine(p256x32_scalar_mult_base(d));
    return {d, q};
}

auto p256x32_encode_point_x(P256AffinePoint32 const& P) -> std::array<uint8_t, 33>
{
    std::array<uint8_t, 33> out{};
    out[0] = 0x01;
    auto const xb = p256_fe32_to_bytes(P.x);
    for (size_t i = 0; i < 32; ++i) {
        out[1 + i] = xb[i];
    }
    return out;
}

auto p256x32_decode_point_x(std::span<uint8_t const, 33> encoded) -> std::optional<P256AffinePoint32>
{
    if (encoded[0] != 0x01) {
        return std::nullopt;
    }
    auto const x = p256_fe32_from_bytes(encoded.subspan<1, 32>());

    // y^2 = x^3 - 3x + b
    auto const x3 = p256_fe32_mul(p256_fe32_sqr(x), x);
    auto three_x = p256_fe32_add(x, x);
    three_x = p256_fe32_add(three_x, x);
    auto y2 = p256_fe32_sub(x3, three_x);
    y2 = p256_fe32_add(y2, curve_b());

    auto y = p256_fe32_sqrt(y2);
    if (!y.has_value()) {
        return std::nullopt;
    }
    auto const y_bytes = p256_fe32_to_bytes(*y);
    if ((y_bytes[31] & 1) != 0) {
        *y = p256_fe32_neg(*y);
    }
    return P256AffinePoint32{.x = x, .y = *y};
}

auto p256x32_encode_point_uncompressed(P256AffinePoint32 const& P) -> std::array<uint8_t, 64>
{
    std::array<uint8_t, 64> out{};
    auto const xb = p256_fe32_to_bytes(P.x);
    auto const yb = p256_fe32_to_bytes(P.y);
    for (size_t i = 0; i < 32; ++i) {
        out[i] = xb[i];
        out[32 + i] = yb[i];
    }
    return out;
}

auto p256x32_decode_point_uncompressed(std::span<uint8_t const, 64> encoded) -> std::optional<P256AffinePoint32>
{
    P256AffinePoint32 const p{
        .x = p256_fe32_from_bytes(encoded.subspan<0, 32>()), .y = p256_fe32_from_bytes(encoded.subspan<32, 32>())};
    if (!p256x32_point_on_curve(p)) {
        return std::nullopt;
    }
    return p;
}

}  // namespace statusbar::crypto
