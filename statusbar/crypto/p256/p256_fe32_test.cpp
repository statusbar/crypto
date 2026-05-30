// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the 32-bit reduced-radix P-256 field arithmetic (p256_fe32).
//
// The standalone section validates the implementation through algebraic
// identities that need no external oracle and no 128-bit integer type, so it
// compiles and runs on a 32-bit ALU. The cross-check section additionally
// compares against the 4x64-bit / 128-bit implementation and is guarded by
// STATUSBAR_CRYPTO_HAS_INT128.

#include "statusbar/crypto/p256/p256_fe32.hpp"

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
        for (int i = 0; i < 4; ++i) {
            uint64_t const v = next();
            for (int j = 0; j < 8; ++j) {
                out[static_cast<size_t>(i * 8 + j)] = static_cast<uint8_t>(v >> (8 * j));
            }
        }
        return out;
    }
};

constexpr int num_rounds = 256;

auto same(std::array<uint8_t, 32> const& a, std::array<uint8_t, 32> const& b) -> bool
{
    for (size_t i = 0; i < 32; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

// A random field element, reduced into [0, p).
auto fe_of(Rng& rng) -> P256FieldElement32
{
    auto raw = rng.bytes32();
    auto const a = p256_fe32_from_bytes(std::span<uint8_t const, 32>(raw));
    auto const enc = p256_fe32_to_bytes(a);  // canonicalizes
    return p256_fe32_from_bytes(std::span<uint8_t const, 32>(enc));
}

}  // namespace

// ─────────────── standalone tests (no 128-bit dependency) ───────────────

TEST(p256_fe32, id_from_to_roundtrip)
{
    Rng rng(1);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const enc = p256_fe32_to_bytes(a);
        auto const a2 = p256_fe32_from_bytes(std::span<uint8_t const, 32>(enc));
        EXPECT_TRUE(same(enc, p256_fe32_to_bytes(a2)));
    }
}

TEST(p256_fe32, id_add_commutes)
{
    Rng rng(2);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const b = fe_of(rng);
        EXPECT_TRUE(p256_fe32_equal(p256_fe32_add(a, b), p256_fe32_add(b, a)));
    }
}

TEST(p256_fe32, id_mul_commutes)
{
    Rng rng(3);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const b = fe_of(rng);
        EXPECT_TRUE(p256_fe32_equal(p256_fe32_mul(a, b), p256_fe32_mul(b, a)));
    }
}

TEST(p256_fe32, id_mul_one)
{
    Rng rng(4);
    auto const one = p256_fe32_one();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(p256_fe32_equal(p256_fe32_mul(a, one), a));
    }
}

TEST(p256_fe32, id_mul_zero)
{
    Rng rng(5);
    P256FieldElement32 const zero{};
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(p256_fe32_equal(p256_fe32_mul(a, zero), zero));
    }
}

TEST(p256_fe32, id_distributive)
{
    Rng rng(6);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const b = fe_of(rng);
        auto const c = fe_of(rng);
        auto const lhs = p256_fe32_mul(a, p256_fe32_add(b, c));
        auto const rhs = p256_fe32_add(p256_fe32_mul(a, b), p256_fe32_mul(a, c));
        EXPECT_TRUE(p256_fe32_equal(lhs, rhs));
    }
}

TEST(p256_fe32, id_sq_is_mul)
{
    Rng rng(7);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(p256_fe32_equal(p256_fe32_sqr(a), p256_fe32_mul(a, a)));
    }
}

TEST(p256_fe32, id_sub_and_neg)
{
    Rng rng(8);
    P256FieldElement32 const zero{};
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(p256_fe32_equal(p256_fe32_sub(a, a), zero));
        EXPECT_TRUE(p256_fe32_equal(p256_fe32_add(a, p256_fe32_neg(a)), zero));
    }
}

TEST(p256_fe32, id_inverse)
{
    Rng rng(9);
    auto const one = p256_fe32_one();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);  // nonzero with overwhelming probability
        EXPECT_TRUE(p256_fe32_equal(p256_fe32_mul(a, p256_fe32_inv(a)), one));
    }
}

TEST(p256_fe32, id_sqrt)
{
    // a^2 is always a quadratic residue; its square root must exist and
    // square back to a^2.
    Rng rng(10);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const q = p256_fe32_sqr(a);
        auto const r = p256_fe32_sqrt(q);
        EXPECT_TRUE(r.has_value());
        if (r.has_value()) {
            EXPECT_TRUE(p256_fe32_equal(p256_fe32_sqr(*r), q));
        }
    }
}

TEST(p256_fe32, id_predicates)
{
    EXPECT_TRUE(p256_fe32_is_zero(P256FieldElement32{}));
    EXPECT_FALSE(p256_fe32_is_zero(p256_fe32_one()));
    Rng rng(11);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(p256_fe32_is_zero(p256_fe32_sub(a, a)));
        EXPECT_TRUE(p256_fe32_equal(a, a));
    }
}

TEST(p256_fe32, id_cmov)
{
    Rng rng(12);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const b = fe_of(rng);
        P256FieldElement32 r0 = a;
        p256_fe32_cmov(r0, b, 0);
        EXPECT_TRUE(p256_fe32_equal(r0, a));
        P256FieldElement32 r1 = a;
        p256_fe32_cmov(r1, b, 1);
        EXPECT_TRUE(p256_fe32_equal(r1, b));
    }
}

// ───────── cross-check vs the 4x64-bit reference (64-bit hosts) ──────────

#if STATUSBAR_CRYPTO_HAS_INT128

namespace {

auto canon(std::array<uint8_t, 32> const& raw) -> std::array<uint8_t, 32>
{
    return p256_fe_to_bytes(p256_fe_from_bytes(std::span<uint8_t const, 32>(raw)));
}

auto ref64(std::array<uint8_t, 32> const& b) -> P256FieldElement
{
    return p256_fe_from_bytes(std::span<uint8_t const, 32>(b));
}

auto v32(std::array<uint8_t, 32> const& b) -> P256FieldElement32
{
    return p256_fe32_from_bytes(std::span<uint8_t const, 32>(b));
}

}  // namespace

TEST(p256_fe32, xc_roundtrip)
{
    Rng rng(101);
    for (int i = 0; i < num_rounds; ++i) {
        auto b = canon(rng.bytes32());
        EXPECT_TRUE(same(p256_fe_to_bytes(ref64(b)), p256_fe32_to_bytes(v32(b))));
    }
}

TEST(p256_fe32, xc_add)
{
    Rng rng(102);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng.bytes32());
        auto b = canon(rng.bytes32());
        EXPECT_TRUE(same(p256_fe_to_bytes(p256_fe_add(ref64(a), ref64(b))), p256_fe32_to_bytes(p256_fe32_add(v32(a), v32(b)))));
    }
}

TEST(p256_fe32, xc_sub)
{
    Rng rng(103);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng.bytes32());
        auto b = canon(rng.bytes32());
        EXPECT_TRUE(same(p256_fe_to_bytes(p256_fe_sub(ref64(a), ref64(b))), p256_fe32_to_bytes(p256_fe32_sub(v32(a), v32(b)))));
    }
}

TEST(p256_fe32, xc_mul)
{
    Rng rng(104);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng.bytes32());
        auto b = canon(rng.bytes32());
        EXPECT_TRUE(same(p256_fe_to_bytes(p256_fe_mul(ref64(a), ref64(b))), p256_fe32_to_bytes(p256_fe32_mul(v32(a), v32(b)))));
    }
}

TEST(p256_fe32, xc_sqr)
{
    Rng rng(105);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng.bytes32());
        EXPECT_TRUE(same(p256_fe_to_bytes(p256_fe_sqr(ref64(a))), p256_fe32_to_bytes(p256_fe32_sqr(v32(a)))));
    }
}

TEST(p256_fe32, xc_inv)
{
    Rng rng(106);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng.bytes32());
        EXPECT_TRUE(same(p256_fe_to_bytes(p256_fe_inv(ref64(a))), p256_fe32_to_bytes(p256_fe32_inv(v32(a)))));
    }
}

TEST(p256_fe32, xc_sqrt)
{
    Rng rng(107);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng.bytes32());
        auto s64 = p256_fe_sqrt(ref64(a));
        auto s32 = p256_fe32_sqrt(v32(a));
        EXPECT_EQ(s64.has_value(), s32.has_value());
        if (s64.has_value() && s32.has_value()) {
            EXPECT_TRUE(same(p256_fe_to_bytes(*s64), p256_fe32_to_bytes(*s32)));
        }
    }
}

#endif  // STATUSBAR_CRYPTO_HAS_INT128

TEST_MAIN(statusbar_crypto_p256, p256_fe32_test)
