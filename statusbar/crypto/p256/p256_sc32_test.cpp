// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the 32-bit reduced-radix P-256 scalar arithmetic (p256_sc32).
//
// The standalone section validates the implementation through ring identities
// mod n that need no external oracle and no 128-bit integer type, so it
// compiles and runs on a 32-bit ALU. The cross-check section additionally
// compares against the 4x64-bit / 128-bit implementation and is guarded by
// STATUSBAR_CRYPTO_HAS_INT128.

#include "statusbar/crypto/p256/p256_sc32.hpp"

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

    auto bytes64() -> std::array<uint8_t, 64>
    {
        std::array<uint8_t, 64> out{};
        for (auto& x : out) {
            x = static_cast<uint8_t>(next());
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

// Scalar equality, via the byte encoding (both operands must be reduced).
auto sceq(P256Scalar32 const& a, P256Scalar32 const& b) -> bool
{
    return same(p256_sc32_to_bytes(a), p256_sc32_to_bytes(b));
}

// The scalar equal to 1.
auto sc_one() -> P256Scalar32
{
    P256Scalar32 r{};
    r.limbs[0] = 1;
    return r;
}

// A random scalar reduced into [0, n).
auto sc_of(Rng& rng) -> P256Scalar32
{
    auto w = rng.bytes64();
    return p256_sc32_reduce_wide(std::span<uint8_t const, 64>(w));
}

}  // namespace

// ─────────────── standalone tests (no 128-bit dependency) ───────────────

TEST(p256_sc32, id_from_to_roundtrip)
{
    // from_bytes / to_bytes are both plain (non-reducing) codecs.
    Rng rng(1);
    for (int i = 0; i < num_rounds; ++i) {
        auto const raw = rng.bytes32();
        auto const s = p256_sc32_from_bytes(std::span<uint8_t const, 32>(raw));
        EXPECT_TRUE(same(raw, p256_sc32_to_bytes(s)));
    }
}

TEST(p256_sc32, id_add_commutes)
{
    Rng rng(2);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);
        auto const b = sc_of(rng);
        EXPECT_TRUE(sceq(p256_sc32_add(a, b), p256_sc32_add(b, a)));
    }
}

TEST(p256_sc32, id_mul_commutes)
{
    Rng rng(3);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);
        auto const b = sc_of(rng);
        EXPECT_TRUE(sceq(p256_sc32_mul(a, b), p256_sc32_mul(b, a)));
    }
}

TEST(p256_sc32, id_mul_one)
{
    Rng rng(4);
    auto const one = sc_one();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);
        EXPECT_TRUE(sceq(p256_sc32_mul(a, one), a));
    }
}

TEST(p256_sc32, id_mul_zero)
{
    Rng rng(5);
    P256Scalar32 const zero{};
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);
        EXPECT_TRUE(sceq(p256_sc32_mul(a, zero), zero));
    }
}

TEST(p256_sc32, id_distributive)
{
    Rng rng(6);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);
        auto const b = sc_of(rng);
        auto const c = sc_of(rng);
        auto const lhs = p256_sc32_mul(a, p256_sc32_add(b, c));
        auto const rhs = p256_sc32_add(p256_sc32_mul(a, b), p256_sc32_mul(a, c));
        EXPECT_TRUE(sceq(lhs, rhs));
    }
}

TEST(p256_sc32, id_sub_and_negate)
{
    Rng rng(7);
    P256Scalar32 const zero{};
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);
        EXPECT_TRUE(sceq(p256_sc32_sub(a, a), zero));
        EXPECT_TRUE(sceq(p256_sc32_add(a, p256_sc32_negate(a)), zero));
    }
}

TEST(p256_sc32, id_inverse)
{
    Rng rng(8);
    auto const one = sc_one();
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);  // nonzero with overwhelming probability
        EXPECT_TRUE(sceq(p256_sc32_mul(a, p256_sc32_inv(a)), one));
    }
}

TEST(p256_sc32, id_reduce_wide_idempotent)
{
    // Reducing an already-reduced value (placed in the low 256 bits, high
    // half zero) must return that value unchanged.
    Rng rng(9);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);
        auto const enc = p256_sc32_to_bytes(a);
        std::array<uint8_t, 64> w{};
        for (size_t j = 0; j < 32; ++j) {
            w[32 + j] = enc[j];
        }
        EXPECT_TRUE(sceq(p256_sc32_reduce_wide(std::span<uint8_t const, 64>(w)), a));
    }
}

TEST(p256_sc32, id_reduce_wide_small)
{
    // A small value below n reduces to itself.
    std::array<uint8_t, 64> w{};
    w[63] = 7;
    P256Scalar32 expected{};
    expected.limbs[0] = 7;
    EXPECT_TRUE(sceq(p256_sc32_reduce_wide(std::span<uint8_t const, 64>(w)), expected));

    std::array<uint8_t, 64> z{};
    EXPECT_TRUE(p256_sc32_is_zero(p256_sc32_reduce_wide(std::span<uint8_t const, 64>(z))));
}

TEST(p256_sc32, id_is_zero)
{
    EXPECT_TRUE(p256_sc32_is_zero(P256Scalar32{}));
    EXPECT_FALSE(p256_sc32_is_zero(sc_one()));
    Rng rng(10);
    for (int i = 0; i < num_rounds; ++i) {
        auto const a = sc_of(rng);
        EXPECT_TRUE(p256_sc32_is_zero(p256_sc32_sub(a, a)));
    }
}

// ───────── cross-check vs the 4x64-bit reference (64-bit hosts) ──────────

#if STATUSBAR_CRYPTO_HAS_INT128

namespace {

auto canon(Rng& rng) -> std::array<uint8_t, 32>
{
    std::array<uint8_t, 64> w{};
    auto r = rng.bytes32();
    for (size_t i = 0; i < 32; ++i) {
        w[32 + i] = r[i];
    }
    return p256_sc_to_bytes(p256_sc_reduce_wide(std::span<uint8_t const, 64>(w)));
}

auto ref64(std::array<uint8_t, 32> const& b) -> P256Scalar
{
    return p256_sc_from_bytes(std::span<uint8_t const, 32>(b));
}

auto v32(std::array<uint8_t, 32> const& b) -> P256Scalar32
{
    return p256_sc32_from_bytes(std::span<uint8_t const, 32>(b));
}

}  // namespace

TEST(p256_sc32, xc_reduce_wide)
{
    Rng rng(101);
    for (int i = 0; i < num_rounds; ++i) {
        auto w = rng.bytes64();
        EXPECT_TRUE(same(
            p256_sc_to_bytes(p256_sc_reduce_wide(std::span<uint8_t const, 64>(w))),
            p256_sc32_to_bytes(p256_sc32_reduce_wide(std::span<uint8_t const, 64>(w)))));
    }
}

TEST(p256_sc32, xc_add)
{
    Rng rng(102);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng);
        auto b = canon(rng);
        EXPECT_TRUE(same(p256_sc_to_bytes(p256_sc_add(ref64(a), ref64(b))), p256_sc32_to_bytes(p256_sc32_add(v32(a), v32(b)))));
    }
}

TEST(p256_sc32, xc_sub)
{
    Rng rng(103);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng);
        auto b = canon(rng);
        EXPECT_TRUE(same(p256_sc_to_bytes(p256_sc_sub(ref64(a), ref64(b))), p256_sc32_to_bytes(p256_sc32_sub(v32(a), v32(b)))));
    }
}

TEST(p256_sc32, xc_negate)
{
    Rng rng(104);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng);
        EXPECT_TRUE(same(p256_sc_to_bytes(p256_sc_negate(ref64(a))), p256_sc32_to_bytes(p256_sc32_negate(v32(a)))));
    }
}

TEST(p256_sc32, xc_mul)
{
    Rng rng(105);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng);
        auto b = canon(rng);
        EXPECT_TRUE(same(p256_sc_to_bytes(p256_sc_mul(ref64(a), ref64(b))), p256_sc32_to_bytes(p256_sc32_mul(v32(a), v32(b)))));
    }
}

TEST(p256_sc32, xc_inv)
{
    Rng rng(106);
    for (int i = 0; i < num_rounds; ++i) {
        auto a = canon(rng);
        EXPECT_TRUE(same(p256_sc_to_bytes(p256_sc_inv(ref64(a))), p256_sc32_to_bytes(p256_sc32_inv(v32(a)))));
    }
}

#endif  // STATUSBAR_CRYPTO_HAS_INT128

TEST_MAIN(statusbar_crypto_p256, p256_sc32_test)
