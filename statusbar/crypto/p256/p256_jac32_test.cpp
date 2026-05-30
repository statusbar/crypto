// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the 32-bit P-256 Jacobian-group operations (p256_jac32).
//
// The standalone section validates the group layer through group-law
// identities and known-answer checks (generator on the curve, small fixed
// multiples, encode/decode round trips, keypair consistency). It needs no
// 128-bit integer type, so it compiles and runs on a 32-bit ALU.
//
// The cross-check section compares against the 4x64-bit group layer and is
// guarded by STATUSBAR_CRYPTO_HAS_INT128.

#include "statusbar/crypto/p256/p256_jac32.hpp"

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128
#    include "statusbar/crypto/p256/p256.hpp"
#endif

#include "statusbar/test/test.hpp"

#include <array>
#include <cstdint>
#include <span>

using namespace statusbar::crypto;

namespace {

// splitmix64 — deterministic generator of test inputs.
class Rng
{
    uint64_t s_;

  public:
    explicit Rng(uint64_t seed)
        : s_(seed)
    {}

    auto next() -> uint64_t
    {
        s_ += 0x9E3779B97F4A7C15ULL;
        uint64_t z = s_;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    auto bytes32() -> std::array<uint8_t, 32>
    {
        std::array<uint8_t, 32> out{};
        for (auto& x : out) {
            x = static_cast<uint8_t>(next());
        }
        return out;
    }
};

template <size_t N>
auto same(std::array<uint8_t, N> const& a, std::array<uint8_t, N> const& b) -> bool
{
    for (size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

// A 32-byte scalar holding a small integer (big-endian).
auto sc_small(uint8_t k) -> P256Scalar32
{
    std::array<uint8_t, 32> b{};
    b[31] = k;
    return p256_sc32_from_bytes(std::span<uint8_t const, 32>(b));
}

auto sc_of(Rng& rng) -> P256Scalar32
{
    auto b = rng.bytes32();
    return p256_sc32_from_bytes(std::span<uint8_t const, 32>(b));
}

// Canonical encoding of a Jacobian point (uncompressed affine, 64 bytes).
auto enc(P256JacobianPoint32 const& P) -> std::array<uint8_t, 64>
{
    return p256x32_encode_point_uncompressed(p256x32_point_to_affine(P));
}

auto jeq(P256JacobianPoint32 const& P, P256JacobianPoint32 const& Q) -> bool
{
    return same(enc(P), enc(Q));
}

auto point_of(Rng& rng) -> P256JacobianPoint32
{
    return p256x32_scalar_mult_base(sc_of(rng));
}

}  // namespace

// ─────────────── standalone tests (no 128-bit dependency) ───────────────

TEST(p256_jac32, kat_generator_on_curve)
{
    EXPECT_TRUE(p256x32_point_on_curve(p256x32_generator()));
    EXPECT_TRUE(p256x32_point_is_identity(p256x32_point_identity()));
}

TEST(p256_jac32, id_double_is_add)
{
    Rng rng(1);
    for (int i = 0; i < 48; ++i) {
        auto const p = point_of(rng);
        EXPECT_TRUE(jeq(p256x32_point_double(p), p256x32_point_add(p, p)));
    }
}

TEST(p256_jac32, id_add_commutes)
{
    Rng rng(2);
    for (int i = 0; i < 48; ++i) {
        auto const p = point_of(rng);
        auto const q = point_of(rng);
        EXPECT_TRUE(jeq(p256x32_point_add(p, q), p256x32_point_add(q, p)));
    }
}

TEST(p256_jac32, id_add_identity_and_neg)
{
    Rng rng(3);
    auto const id = p256x32_point_identity();
    for (int i = 0; i < 48; ++i) {
        auto const p = point_of(rng);
        EXPECT_TRUE(jeq(p256x32_point_add(p, id), p));
        EXPECT_TRUE(p256x32_point_is_identity(p256x32_point_add(p, p256x32_point_neg(p))));
    }
}

TEST(p256_jac32, kat_scalar_mult_small)
{
    auto const g = p256x32_generator();
    auto const gj = p256x32_affine_to_jacobian(g);
    EXPECT_TRUE(p256x32_point_is_identity(p256x32_scalar_mult(sc_small(0), g)));
    EXPECT_TRUE(jeq(p256x32_scalar_mult(sc_small(1), g), gj));
    EXPECT_TRUE(jeq(p256x32_scalar_mult(sc_small(2), g), p256x32_point_double(gj)));
    EXPECT_TRUE(jeq(p256x32_scalar_mult(sc_small(8), g), p256x32_point_double(p256x32_point_double(p256x32_point_double(gj)))));
}

TEST(p256_jac32, id_affine_roundtrip)
{
    Rng rng(4);
    for (int i = 0; i < 48; ++i) {
        auto const a = p256x32_point_to_affine(point_of(rng));
        auto const a2 = p256x32_point_to_affine(p256x32_affine_to_jacobian(a));
        EXPECT_TRUE(p256_fe32_equal(a.x, a2.x));
        EXPECT_TRUE(p256_fe32_equal(a.y, a2.y));
        EXPECT_TRUE(p256x32_point_on_curve(a));
    }
}

TEST(p256_jac32, id_encode_decode)
{
    Rng rng(5);
    for (int i = 0; i < 48; ++i) {
        auto const a = p256x32_point_to_affine(point_of(rng));

        auto const u = p256x32_decode_point_uncompressed(std::span<uint8_t const, 64>(p256x32_encode_point_uncompressed(a)));
        EXPECT_TRUE(u.has_value());
        if (u.has_value()) {
            EXPECT_TRUE(p256_fe32_equal(u->x, a.x));
            EXPECT_TRUE(p256_fe32_equal(u->y, a.y));
        }

        auto const c = p256x32_decode_point_x(std::span<uint8_t const, 33>(p256x32_encode_point_x(a)));
        EXPECT_TRUE(c.has_value());
        if (c.has_value()) {
            EXPECT_TRUE(p256_fe32_equal(c->x, a.x));  // x recovered; y sign is free
        }
    }
}

TEST(p256_jac32, id_double_scalar_mult)
{
    Rng rng(6);
    auto const zero = sc_small(0);
    for (int i = 0; i < 24; ++i) {
        auto const q = p256x32_point_to_affine(point_of(rng));
        auto const s = sc_of(rng);
        // [s]G + [0]Q == [s]G
        EXPECT_TRUE(jeq(p256x32_double_scalar_mult(s, zero, q), p256x32_scalar_mult_base(s)));
        // [0]G + [s]Q == [s]Q
        EXPECT_TRUE(jeq(p256x32_double_scalar_mult(zero, s, q), p256x32_scalar_mult(s, q)));
    }
}

TEST(p256_jac32, kat_keypair)
{
    Rng rng(7);
    for (int i = 0; i < 16; ++i) {
        auto const seed = rng.bytes32();
        auto const kp = p256x32_keypair_from_seed(std::span<uint8_t const, 32>(seed));
        EXPECT_TRUE(p256x32_point_on_curve(kp.second));
        // Public point must equal [d]G.
        auto const q = p256x32_point_to_affine(p256x32_scalar_mult_base(kp.first));
        EXPECT_TRUE(p256_fe32_equal(q.x, kp.second.x));
        EXPECT_TRUE(p256_fe32_equal(q.y, kp.second.y));
    }
}

// ───────── cross-check vs the 4x64-bit group layer (64-bit hosts) ────────

#if STATUSBAR_CRYPTO_HAS_INT128

namespace {

auto enc64(P256JacobianPoint const& P) -> std::array<uint8_t, 64>
{
    return p256_encode_point_uncompressed(p256_point_to_affine(P));
}

}  // namespace

TEST(p256_jac32, xc_scalar_mult_base)
{
    Rng rng(101);
    for (int i = 0; i < 64; ++i) {
        auto s = rng.bytes32();
        auto const r64 = p256_scalar_mult_base(p256_sc_from_bytes(std::span<uint8_t const, 32>(s)));
        auto const r32 = p256x32_scalar_mult_base(p256_sc32_from_bytes(std::span<uint8_t const, 32>(s)));
        EXPECT_TRUE(same(enc64(r64), enc(r32)));
    }
}

TEST(p256_jac32, xc_point_add_and_double)
{
    Rng rng(102);
    for (int i = 0; i < 64; ++i) {
        auto s1 = rng.bytes32();
        auto s2 = rng.bytes32();
        auto const p64 = p256_scalar_mult_base(p256_sc_from_bytes(std::span<uint8_t const, 32>(s1)));
        auto const q64 = p256_scalar_mult_base(p256_sc_from_bytes(std::span<uint8_t const, 32>(s2)));
        auto const p32 = p256x32_scalar_mult_base(p256_sc32_from_bytes(std::span<uint8_t const, 32>(s1)));
        auto const q32 = p256x32_scalar_mult_base(p256_sc32_from_bytes(std::span<uint8_t const, 32>(s2)));
        EXPECT_TRUE(same(enc64(p256_point_add(p64, q64)), enc(p256x32_point_add(p32, q32))));
        EXPECT_TRUE(same(enc64(p256_point_double(p64)), enc(p256x32_point_double(p32))));
    }
}

TEST(p256_jac32, xc_double_scalar_mult)
{
    Rng rng(103);
    for (int i = 0; i < 48; ++i) {
        auto sq = rng.bytes32();
        auto a = rng.bytes32();
        auto b = rng.bytes32();
        auto const q64 = p256_point_to_affine(p256_scalar_mult_base(p256_sc_from_bytes(std::span<uint8_t const, 32>(sq))));
        auto const q32 = p256x32_point_to_affine(p256x32_scalar_mult_base(p256_sc32_from_bytes(std::span<uint8_t const, 32>(sq))));
        auto const r64 = p256_double_scalar_mult(
            p256_sc_from_bytes(std::span<uint8_t const, 32>(a)), p256_sc_from_bytes(std::span<uint8_t const, 32>(b)), q64);
        auto const r32 = p256x32_double_scalar_mult(
            p256_sc32_from_bytes(std::span<uint8_t const, 32>(a)), p256_sc32_from_bytes(std::span<uint8_t const, 32>(b)), q32);
        EXPECT_TRUE(same(enc64(r64), enc(r32)));
    }
}

TEST(p256_jac32, xc_keypair)
{
    Rng rng(104);
    for (int i = 0; i < 32; ++i) {
        auto seed = rng.bytes32();
        auto const kp64 = p256_keypair_from_seed(std::span<uint8_t const, 32>(seed));
        auto const kp32 = p256x32_keypair_from_seed(std::span<uint8_t const, 32>(seed));
        EXPECT_TRUE(same(p256_sc_to_bytes(kp64.first), p256_sc32_to_bytes(kp32.first)));
        EXPECT_TRUE(same(p256_encode_point_uncompressed(kp64.second), p256x32_encode_point_uncompressed(kp32.second)));
    }
}

#endif  // STATUSBAR_CRYPTO_HAS_INT128

TEST_MAIN(statusbar_crypto_p256, p256_jac32_test)
