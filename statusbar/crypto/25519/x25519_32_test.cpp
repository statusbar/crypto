// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Tests for the 32-bit X25519 Montgomery ladder (x25519_32).
//
// The standalone section runs the RFC 7748 Section 5.2 known-answer vectors,
// which need no 128-bit integer type and therefore compile and run on a
// 32-bit ALU. The cross-check section additionally compares against the
// 5x51-bit implementation and is guarded by STATUSBAR_CRYPTO_HAS_INT128.

#include "statusbar/crypto/25519/x25519_32.hpp"

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128
#    include "statusbar/crypto/25519/curve25519.hpp"
#endif

#include "statusbar/test/test.hpp"
#include "statusbar/test/test_util.hpp"

#include <array>
#include <cstdint>
#include <span>

using namespace statusbar::crypto;

namespace {

auto same(std::array<uint8_t, 32> const& a, std::array<uint8_t, 32> const& b) -> bool
{
    for (size_t i = 0; i < 32; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

// Run X25519 on the 32-bit field.
auto x25519(std::array<uint8_t, 32> const& scalar, std::array<uint8_t, 32> const& point) -> std::array<uint8_t, 32>
{
    return curve25519x32_scalar_mult(std::span<uint8_t const, 32>(scalar), std::span<uint8_t const, 32>(point));
}

}  // namespace

// ─────────────── standalone tests (no 128-bit dependency) ───────────────

TEST(x25519_32, rfc7748_vector_1)
{
    // RFC 7748 Section 5.2, first X25519 test vector.
    auto const scalar = hex_to_bytes<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto const point = hex_to_bytes<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    auto const expected = hex_to_bytes<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    EXPECT_TRUE(same(x25519(scalar, point), expected));
}

TEST(x25519_32, rfc7748_vector_2)
{
    // RFC 7748 Section 5.2, second X25519 test vector.
    auto const scalar = hex_to_bytes<32>("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    auto const point = hex_to_bytes<32>("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    auto const expected = hex_to_bytes<32>("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    EXPECT_TRUE(same(x25519(scalar, point), expected));
}

TEST(x25519_32, rfc7748_base_point)
{
    // The RFC 7748 Section 5.2 iterated test, first step: applying the scalar
    // 0x09..(=base) to the u-coordinate 9 gives the documented k_1.
    std::array<uint8_t, 32> base{};
    base[0] = 9;
    auto const out = x25519(base, base);
    auto const expected = hex_to_bytes<32>("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    EXPECT_TRUE(same(out, expected));
}

// ───────── cross-check vs the 5x51-bit reference (64-bit hosts) ──────────

#if STATUSBAR_CRYPTO_HAS_INT128

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

}  // namespace

TEST(x25519_32, xc_cross_check)
{
    Rng rng(1);
    for (int i = 0; i < 256; ++i) {
        auto scalar = rng.bytes32();
        auto point = rng.bytes32();
        std::span<uint8_t const, 32> const ss(scalar);
        std::span<uint8_t const, 32> const sp(point);
        EXPECT_TRUE(same(curve25519_scalar_mult(ss, sp), curve25519x32_scalar_mult(ss, sp)));
    }
}

#endif  // STATUSBAR_CRYPTO_HAS_INT128

TEST_MAIN(statusbar_crypto_25519, x25519_32_test)
