// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the 32-bit reduced-radix Curve25519 field arithmetic
// (curve25519_fe32).
//
// The standalone section validates the implementation through algebraic
// identities — commutativity, distributivity, inverses, Fermat relations —
// which require no external oracle and, crucially, no 128-bit integer type.
// It therefore compiles and runs on a 32-bit ALU.
//
// The cross-check section additionally compares every operation against the
// 5x51-bit / 128-bit implementation. It is guarded by STATUSBAR_CRYPTO_HAS_INT128 so it
// is built only on targets that actually have the 128-bit reference.

#include "statusbar/crypto/25519/curve25519_fe32.hpp"

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

// Field-element equality, via the canonical byte encoding.
auto feq(Fe25519x32 const& a, Fe25519x32 const& b) -> bool
{
    return same(fe25519x32_to_bytes(a), fe25519x32_to_bytes(b));
}

// A random field element.
auto fe_of(Rng& rng) -> Fe25519x32
{
    auto b = rng.bytes32();
    return fe25519x32_from_bytes(std::span<uint8_t const, 32>(b));
}

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

}  // namespace

// ─────────────── standalone tests (no 128-bit dependency) ───────────────

TEST(curve25519_fe32, id_from_to_roundtrip)
{
    Rng rng(1);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const enc = fe25519x32_to_bytes(a);
        auto const a2 = fe25519x32_from_bytes(std::span<uint8_t const, 32>(enc));
        EXPECT_TRUE(same(enc, fe25519x32_to_bytes(a2)));
    }
}

TEST(curve25519_fe32, id_add_commutes)
{
    Rng rng(2);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const b = fe_of(rng);
        EXPECT_TRUE(feq(fe25519x32_add(a, b), fe25519x32_add(b, a)));
    }
}

TEST(curve25519_fe32, id_mul_commutes)
{
    Rng rng(3);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const b = fe_of(rng);
        EXPECT_TRUE(feq(fe25519x32_mul(a, b), fe25519x32_mul(b, a)));
    }
}

TEST(curve25519_fe32, id_mul_one)
{
    Rng rng(4);
    auto const one = fe25519x32_one();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(feq(fe25519x32_mul(a, one), a));
    }
}

TEST(curve25519_fe32, id_mul_zero)
{
    Rng rng(5);
    auto const zero = fe25519x32_zero();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(feq(fe25519x32_mul(a, zero), zero));
    }
}

TEST(curve25519_fe32, id_distributive)
{
    Rng rng(6);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const b = fe_of(rng);
        auto const c = fe_of(rng);
        auto const lhs = fe25519x32_mul(a, fe25519x32_add(b, c));
        auto const rhs = fe25519x32_add(fe25519x32_mul(a, b), fe25519x32_mul(a, c));
        EXPECT_TRUE(feq(lhs, rhs));
    }
}

TEST(curve25519_fe32, id_sq_is_mul)
{
    Rng rng(7);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(feq(fe25519x32_sq(a), fe25519x32_mul(a, a)));
    }
}

TEST(curve25519_fe32, id_sub_and_neg)
{
    Rng rng(8);
    auto const zero = fe25519x32_zero();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        EXPECT_TRUE(feq(fe25519x32_sub(a, a), zero));
        EXPECT_TRUE(feq(fe25519x32_add(a, fe25519x32_neg(a)), zero));
    }
}

TEST(curve25519_fe32, id_inverse)
{
    Rng rng(9);
    auto const one = fe25519x32_one();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);  // nonzero with overwhelming probability
        EXPECT_TRUE(feq(fe25519x32_mul(a, fe25519x32_invert(a)), one));
    }
}

TEST(curve25519_fe32, id_mul_small)
{
    Rng rng(10);
    for (uint32_t k : {1U, 2U, 19U, 121665U, 0x00FFFFFFU}) {
        auto const kf = fe_small(k);
        for (int i = 0; i < 64; ++i) {
            auto const a = fe_of(rng);
            EXPECT_TRUE(feq(fe25519x32_mul_small(a, k), fe25519x32_mul(a, kf)));
        }
    }
}

TEST(curve25519_fe32, id_pow22523)
{
    // pow22523(a) = a^((p-5)/8); raising it to the 8th and multiplying by a^4
    // gives a^(p-1) = 1.
    Rng rng(11);
    auto const one = fe25519x32_one();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const r = fe25519x32_pow22523(a);
        auto const r8 = fe25519x32_sq(fe25519x32_sq(fe25519x32_sq(r)));
        auto const a4 = fe25519x32_sq(fe25519x32_sq(a));
        EXPECT_TRUE(feq(fe25519x32_mul(r8, a4), one));
    }
}

TEST(curve25519_fe32, id_predicates)
{
    EXPECT_EQ(fe25519x32_is_zero(fe25519x32_zero()), 1U);
    EXPECT_EQ(fe25519x32_is_zero(fe25519x32_one()), 0U);
    Rng rng(12);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        // is_zero(a - a) holds for every a.
        EXPECT_EQ(fe25519x32_is_zero(fe25519x32_sub(a, a)), 1U);
    }
}

TEST(curve25519_fe32, id_cmov)
{
    Rng rng(13);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = fe_of(rng);
        auto const b = fe_of(rng);
        Fe25519x32 r0 = a;
        fe25519x32_cmov(r0, b, 0);
        EXPECT_TRUE(feq(r0, a));
        Fe25519x32 r1 = a;
        fe25519x32_cmov(r1, b, 1);
        EXPECT_TRUE(feq(r1, b));
    }
}

// ───────── cross-check vs the 5x51-bit reference (64-bit hosts) ──────────

#if STATUSBAR_CRYPTO_HAS_INT128

namespace {

auto ref64(std::array<uint8_t, 32> const& bytes) -> Fe25519
{
    return fe25519_from_bytes(std::span<uint8_t const, 32>(bytes));
}

auto v32(std::array<uint8_t, 32> const& bytes) -> Fe25519x32
{
    return fe25519x32_from_bytes(std::span<uint8_t const, 32>(bytes));
}

}  // namespace

TEST(curve25519_fe32, xc_roundtrip)
{
    Rng rng(101);
    for (int i = 0; i < num_rounds; ++i) {
        auto b = rng.bytes32();
        EXPECT_TRUE(same(fe25519_to_bytes(ref64(b)), fe25519x32_to_bytes(v32(b))));
    }
}

TEST(curve25519_fe32, xc_add)
{
    Rng rng(102);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        auto b = rng.bytes32();
        EXPECT_TRUE(same(fe25519_to_bytes(fe25519_add(ref64(a), ref64(b))), fe25519x32_to_bytes(fe25519x32_add(v32(a), v32(b)))));
    }
}

TEST(curve25519_fe32, xc_sub)
{
    Rng rng(103);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        auto b = rng.bytes32();
        EXPECT_TRUE(same(fe25519_to_bytes(fe25519_sub(ref64(a), ref64(b))), fe25519x32_to_bytes(fe25519x32_sub(v32(a), v32(b)))));
    }
}

TEST(curve25519_fe32, xc_mul)
{
    Rng rng(104);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        auto b = rng.bytes32();
        EXPECT_TRUE(same(fe25519_to_bytes(fe25519_mul(ref64(a), ref64(b))), fe25519x32_to_bytes(fe25519x32_mul(v32(a), v32(b)))));
    }
}

TEST(curve25519_fe32, xc_sq)
{
    Rng rng(105);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        EXPECT_TRUE(same(fe25519_to_bytes(fe25519_sq(ref64(a))), fe25519x32_to_bytes(fe25519x32_sq(v32(a)))));
    }
}

TEST(curve25519_fe32, xc_mul_small)
{
    Rng rng(106);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        auto b = static_cast<uint32_t>(rng.next() & 0xFFFFFFU);
        EXPECT_TRUE(same(fe25519_to_bytes(fe25519_mul_small(ref64(a), b)), fe25519x32_to_bytes(fe25519x32_mul_small(v32(a), b))));
    }
}

TEST(curve25519_fe32, xc_neg)
{
    Rng rng(107);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        EXPECT_TRUE(same(fe25519_to_bytes(fe25519_neg(ref64(a))), fe25519x32_to_bytes(fe25519x32_neg(v32(a)))));
    }
}

TEST(curve25519_fe32, xc_invert)
{
    Rng rng(108);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        EXPECT_TRUE(same(fe25519_to_bytes(fe25519_invert(ref64(a))), fe25519x32_to_bytes(fe25519x32_invert(v32(a)))));
    }
}

TEST(curve25519_fe32, xc_pow22523)
{
    Rng rng(109);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        EXPECT_TRUE(same(fe25519_to_bytes(fe25519_pow22523(ref64(a))), fe25519x32_to_bytes(fe25519x32_pow22523(v32(a)))));
    }
}

TEST(curve25519_fe32, xc_predicates)
{
    Rng rng(110);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = rng.bytes32();
        EXPECT_EQ(static_cast<uint32_t>(fe25519_is_negative(ref64(a))), fe25519x32_is_negative(v32(a)));
        EXPECT_EQ(static_cast<uint32_t>(fe25519_is_zero(ref64(a))), fe25519x32_is_zero(v32(a)));
    }
}

#endif  // STATUSBAR_CRYPTO_HAS_INT128

TEST_MAIN(statusbar_crypto_25519, curve25519_fe32_test)
