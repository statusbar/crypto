// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the 32-bit Ed25519 Edwards-group operations (ed25519_ge32).
//
// The standalone section validates the group layer through group-law
// identities (commutativity, the neutral element, doubling, negation) and
// known-answer vectors (the base point, small fixed-base multiples). It needs
// no 128-bit integer type, so it compiles and runs on a 32-bit ALU.
//
// The cross-check section compares against the 5x51-bit group layer and is
// guarded by STATUSBAR_CRYPTO_HAS_INT128.

#include "statusbar/crypto/25519/ed25519_ge32.hpp"

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128
#    include "statusbar/crypto/25519/curve25519.hpp"
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

// Ed25519 base point B, compressed.
constexpr std::array<uint8_t, 32> kBase = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

auto same(std::array<uint8_t, 32> const& a, std::array<uint8_t, 32> const& b) -> bool
{
    for (size_t i = 0; i < 32; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

// Point equality, via the canonical compressed encoding.
auto peq(GeP3x32 const& p, GeP3x32 const& q) -> bool
{
    return same(ge32_p3_to_bytes(p), ge32_p3_to_bytes(q));
}

// A valid random point: [random scalar] B.
auto point_of(Rng& rng) -> GeP3x32
{
    auto s = rng.bytes32();
    return ge32_scalar_mult_base(std::span<uint8_t const, 32>(s));
}

// A 32-byte scalar holding a small integer.
auto scalar_small(uint8_t k) -> std::array<uint8_t, 32>
{
    std::array<uint8_t, 32> s{};
    s[0] = k;
    return s;
}

}  // namespace

// ─────────────── standalone tests (no 128-bit dependency) ───────────────

TEST(ed25519_ge32, kat_identity_encoding)
{
    // The identity (0, 1) encodes as y = 1, sign 0.
    std::array<uint8_t, 32> expected{};
    expected[0] = 1;
    EXPECT_TRUE(same(ge32_p3_to_bytes(ge32_p3_identity()), expected));
}

TEST(ed25519_ge32, kat_base_point_roundtrip)
{
    auto const b = ge32_from_bytes(std::span<uint8_t const, 32>(kBase));
    EXPECT_TRUE(b.has_value());
    if (b.has_value()) {
        EXPECT_TRUE(same(ge32_p3_to_bytes(*b), kBase));
    }
}

TEST(ed25519_ge32, id_add_identity)
{
    Rng rng(1);
    auto const id = ge32_p3_identity();
    for (int i = 0; i < 64; ++i) {
        auto const p = point_of(rng);
        EXPECT_TRUE(peq(ge32_p3_add(p, id), p));
    }
}

TEST(ed25519_ge32, id_add_commutes)
{
    Rng rng(2);
    for (int i = 0; i < 64; ++i) {
        auto const p = point_of(rng);
        auto const q = point_of(rng);
        EXPECT_TRUE(peq(ge32_p3_add(p, q), ge32_p3_add(q, p)));
    }
}

TEST(ed25519_ge32, id_dbl_is_add)
{
    Rng rng(3);
    for (int i = 0; i < 64; ++i) {
        auto const p = point_of(rng);
        EXPECT_TRUE(peq(ge32_p3_dbl(p), ge32_p3_add(p, p)));
    }
}

TEST(ed25519_ge32, id_neg)
{
    Rng rng(4);
    auto const id = ge32_p3_identity();
    for (int i = 0; i < 64; ++i) {
        auto const p = point_of(rng);
        EXPECT_TRUE(peq(ge32_p3_add(p, ge32_p3_neg(p)), id));
    }
}

TEST(ed25519_ge32, kat_scalar_mult_base_small)
{
    auto const b = *ge32_from_bytes(std::span<uint8_t const, 32>(kBase));
    auto const zero = scalar_small(0);
    auto const one = scalar_small(1);
    auto const two = scalar_small(2);
    auto const eight = scalar_small(8);

    EXPECT_TRUE(peq(ge32_scalar_mult_base(std::span<uint8_t const, 32>(zero)), ge32_p3_identity()));
    EXPECT_TRUE(peq(ge32_scalar_mult_base(std::span<uint8_t const, 32>(one)), b));
    EXPECT_TRUE(peq(ge32_scalar_mult_base(std::span<uint8_t const, 32>(two)), ge32_p3_add(b, b)));
    EXPECT_TRUE(peq(ge32_scalar_mult_base(std::span<uint8_t const, 32>(eight)), ge32_p3_dbl(ge32_p3_dbl(ge32_p3_dbl(b)))));
}

TEST(ed25519_ge32, id_double_scalar_mult)
{
    // [0]A + [b]B must equal [b]B = scalar_mult_base(b). double_scalar_mult
    // processes bits 254..0 (it expects scalars reduced mod L), so bit 255 of
    // b is cleared to match scalar_mult_base, which uses the full 256 bits.
    Rng rng(5);
    auto const a = point_of(rng);
    auto const zero = scalar_small(0);
    for (int i = 0; i < 32; ++i) {
        auto b = rng.bytes32();
        b[31] &= 0x7F;
        auto const lhs = ge32_double_scalar_mult_vartime(std::span<uint8_t const, 32>(zero), a, std::span<uint8_t const, 32>(b));
        auto const rhs = ge32_scalar_mult_base(std::span<uint8_t const, 32>(b));
        EXPECT_TRUE(peq(lhs, rhs));
    }
}

// ───────── cross-check vs the 5x51-bit group layer (64-bit hosts) ────────

#if STATUSBAR_CRYPTO_HAS_INT128

TEST(ed25519_ge32, xc_decode)
{
    Rng rng(101);
    for (int i = 0; i < 256; ++i) {
        auto s = rng.bytes32();
        auto const r64 = ge_from_bytes(std::span<uint8_t const, 32>(s));
        auto const r32 = ge32_from_bytes(std::span<uint8_t const, 32>(s));
        EXPECT_EQ(r64.has_value(), r32.has_value());
        if (r64.has_value() && r32.has_value()) {
            EXPECT_TRUE(same(ge_p3_to_bytes(*r64), ge32_p3_to_bytes(*r32)));
        }
    }
}

TEST(ed25519_ge32, xc_scalar_mult_base)
{
    Rng rng(102);
    for (int i = 0; i < 128; ++i) {
        auto s = rng.bytes32();
        EXPECT_TRUE(same(
            ge_p3_to_bytes(ge_scalar_mult_base(std::span<uint8_t const, 32>(s))),
            ge32_p3_to_bytes(ge32_scalar_mult_base(std::span<uint8_t const, 32>(s)))));
    }
}

TEST(ed25519_ge32, xc_add_and_dbl)
{
    Rng rng(103);
    for (int i = 0; i < 128; ++i) {
        auto s1 = rng.bytes32();
        auto s2 = rng.bytes32();
        auto const p64 = ge_scalar_mult_base(std::span<uint8_t const, 32>(s1));
        auto const q64 = ge_scalar_mult_base(std::span<uint8_t const, 32>(s2));
        auto const p32 = ge32_scalar_mult_base(std::span<uint8_t const, 32>(s1));
        auto const q32 = ge32_scalar_mult_base(std::span<uint8_t const, 32>(s2));
        EXPECT_TRUE(same(ge_p3_to_bytes(ge_p3_add(p64, q64)), ge32_p3_to_bytes(ge32_p3_add(p32, q32))));
        EXPECT_TRUE(same(ge_p3_to_bytes(ge_p3_dbl(p64)), ge32_p3_to_bytes(ge32_p3_dbl(p32))));
    }
}

TEST(ed25519_ge32, xc_double_scalar_mult)
{
    Rng rng(104);
    for (int i = 0; i < 128; ++i) {
        auto sa = rng.bytes32();
        auto a = rng.bytes32();
        auto b = rng.bytes32();
        auto const aff64 = ge_scalar_mult_base(std::span<uint8_t const, 32>(sa));
        auto const aff32 = ge32_scalar_mult_base(std::span<uint8_t const, 32>(sa));
        auto const r64 = ge_double_scalar_mult_vartime(std::span<uint8_t const, 32>(a), aff64, std::span<uint8_t const, 32>(b));
        auto const r32 = ge32_double_scalar_mult_vartime(std::span<uint8_t const, 32>(a), aff32, std::span<uint8_t const, 32>(b));
        EXPECT_TRUE(same(ge_p3_to_bytes(r64), ge32_p3_to_bytes(r32)));
    }
}

#endif  // STATUSBAR_CRYPTO_HAS_INT128

TEST_MAIN(statusbar_crypto_25519, ed25519_ge32_test)
