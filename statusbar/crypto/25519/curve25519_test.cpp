// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - RFC 7748 (X25519): https://www.rfc-editor.org/rfc/rfc7748#section-5.2
// - RFC 7748 (X25519 basepoint): https://www.rfc-editor.org/rfc/rfc7748#section-6.1
// - RFC 8032 (Ed25519): https://www.rfc-editor.org/rfc/rfc8032#section-5.1

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/buffer/span_utils.hpp"
#    include "statusbar/crypto/25519/curve25519.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"
#    include "statusbar/test/test.hpp"
#    include "statusbar/test/test_util.hpp"

#    include <array>
#    include <cstdint>
#    include <cstring>

using namespace statusbar::crypto;
using statusbar::make_const_span;
using statusbar::make_span;
using statusbar::span_copy;
using statusbar::crypto::internal::span_compare;

//
// Fe25519 from_bytes -> to_bytes roundtrip
//

TEST(curve25519, fe25519_roundtrip)
{
    // All zeros
    {
        auto bytes = std::array<uint8_t, 32>{};
        auto fe = fe25519_from_bytes(bytes);
        auto result = fe25519_to_bytes(fe);
        EXPECT_TRUE(span_compare(result, bytes));
    }

    // {1, 0, 0, ..., 0} — the encoding of the integer 1
    {
        auto bytes = std::array<uint8_t, 32>{};
        bytes[0] = 1;
        auto fe = fe25519_from_bytes(bytes);
        auto result = fe25519_to_bytes(fe);
        EXPECT_TRUE(span_compare(result, bytes));
    }

    // All 0xFF bytes — from_bytes clears bit 255, so effective input is
    // 0x7FFFFFFF...FF = 2^255 - 1.  Reduced mod p = 2^255 - 19 this is 18.
    {
        std::array<uint8_t, 32> bytes;
        bytes.fill(0xff);
        auto fe = fe25519_from_bytes(bytes);
        auto result = fe25519_to_bytes(fe);

        std::array<uint8_t, 32> expected{};
        expected[0] = 18;
        EXPECT_TRUE(span_compare(result, expected));
    }
}

//
// Fe25519 multiply by one: a * 1 = a
//

TEST(curve25519, fe25519_mul_one)
{
    // Encode the integer 42
    std::array<uint8_t, 32> bytes{};
    bytes[0] = 42;
    auto a = fe25519_from_bytes(bytes);
    auto one = fe25519_one();

    auto product = fe25519_mul(a, one);
    auto result = fe25519_to_bytes(product);
    EXPECT_TRUE(span_compare(result, bytes));
}

//
// Fe25519 invert: a * a^(-1) = 1
//

TEST(curve25519, fe25519_invert)
{
    // Use a = 42
    std::array<uint8_t, 32> bytes{};
    bytes[0] = 42;
    auto a = fe25519_from_bytes(bytes);

    auto a_inv = fe25519_invert(a);
    auto product = fe25519_mul(a, a_inv);
    auto result = fe25519_to_bytes(product);

    std::array<uint8_t, 32> expected_one{};
    expected_one[0] = 1;
    EXPECT_TRUE(span_compare(result, expected_one));
}

//
// RFC 7748 Section 5.2 — X25519 test vector 1
//

TEST(curve25519, x25519_rfc7748_vector1)
{
    auto scalar = hex_to_bytes<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto u_coord = hex_to_bytes<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    auto expected = hex_to_bytes<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    auto result = curve25519_scalar_mult(scalar, u_coord);
    EXPECT_TRUE(span_compare(result, expected));
}

//
// RFC 7748 Section 5.2 — X25519 test vector 2
//

TEST(curve25519, x25519_rfc7748_vector2)
{
    auto scalar = hex_to_bytes<32>("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    auto u_coord = hex_to_bytes<32>("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    auto expected = hex_to_bytes<32>("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    auto result = curve25519_scalar_mult(scalar, u_coord);
    EXPECT_TRUE(span_compare(result, expected));
}

//
// RFC 7748 Section 6.1 — X25519 basepoint iteration (1 iteration)
// Scalar = 9, basepoint u = 9
// After 1 iteration: 422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
//

TEST(curve25519, x25519_basepoint)
{
    std::array<uint8_t, 32> scalar{};
    scalar[0] = 9;

    std::array<uint8_t, 32> u{};
    u[0] = 9;

    auto expected = hex_to_bytes<32>("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

    auto result = curve25519_scalar_mult(scalar, u);
    EXPECT_TRUE(span_compare(result, expected));
}

//
// Ed25519 base point: decompress -> recompress roundtrip
// The Ed25519 base point encoding (RFC 8032 Section 5.1):
// y = 4/5 mod p, x is the positive root
// Standard encoding: 5866666666...66 (little-endian y with x sign in top bit)
//

TEST(curve25519, ge_from_bytes_to_bytes_roundtrip)
{
    auto basepoint = hex_to_bytes<32>("5866666666666666666666666666666666666666666666666666666666666666");

    auto point = ge_from_bytes(basepoint);
    EXPECT_TRUE(point.has_value());

    auto result = ge_p3_to_bytes(*point);
    EXPECT_TRUE(span_compare(result, basepoint));
}

//
// ge_scalar_mult_base with scalar = 1: [1]B should equal the base point
//

TEST(curve25519, ge_scalar_mult_base_identity)
{
    // Scalar = 1 in little-endian
    std::array<uint8_t, 32> scalar{};
    scalar[0] = 1;

    auto result_point = ge_scalar_mult_base(scalar);
    auto result_bytes = ge_p3_to_bytes(result_point);

    // The Ed25519 base point encoding
    auto basepoint = hex_to_bytes<32>("5866666666666666666666666666666666666666666666666666666666666666");

    EXPECT_TRUE(span_compare(result_bytes, basepoint));
}

//
// sc_reduce of 64 zero bytes should return 32 zero bytes
//

TEST(curve25519, sc_reduce_zero)
{
    std::array<uint8_t, 64> input{};
    auto result = sc_reduce(input);

    std::array<uint8_t, 32> expected{};
    EXPECT_TRUE(span_compare(result, expected));
}

//
// ge_p3_add: B + B = [2]B (adding base point to itself equals doubling)
// Also verify ge_p3_dbl(B) = [2]B
//

TEST(curve25519, ge_p3_add_double)
{
    // Get the base point via [1]B
    std::array<uint8_t, 32> scalar_one{};
    scalar_one[0] = 1;
    auto B = ge_scalar_mult_base(scalar_one);

    // Compute B + B via addition
    auto sum = ge_p3_add(B, B);
    auto sum_bytes = ge_p3_to_bytes(sum);

    // Compute [2]B via scalar multiplication
    std::array<uint8_t, 32> scalar_two{};
    scalar_two[0] = 2;
    auto doubled = ge_scalar_mult_base(scalar_two);
    auto doubled_bytes = ge_p3_to_bytes(doubled);

    EXPECT_TRUE(span_compare(sum_bytes, doubled_bytes));

    // Also verify via ge_p3_dbl
    auto dbl_result = ge_p3_dbl(B);
    auto dbl_bytes = ge_p3_to_bytes(dbl_result);
    EXPECT_TRUE(span_compare(dbl_bytes, doubled_bytes));
}

//
// sc_reduce non-trivial: L mod L = 0, 2*L mod L = 0, (L+1) mod L = 1
//
// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
// L in little-endian bytes:
//   ed d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14
//   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
//

TEST(curve25519, sc_reduce_nontrivial)
{
    // Ed25519 group order L in little-endian (32 bytes)
    auto const L = hex_to_bytes<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

    // L mod L should be 0
    {
        std::array<uint8_t, 64> input{};
        span_copy(make_span(input).first(32), make_const_span(L));

        auto result = sc_reduce(input);

        std::array<uint8_t, 32> expected{};
        EXPECT_TRUE(span_compare(result, expected));
    }

    // 2*L mod L should be 0
    {
        std::array<uint8_t, 64> input{};
        // Compute 2*L in little-endian by doubling each byte with carry
        uint16_t carry = 0;
        for (size_t i = 0; i < 32; ++i) {
            uint16_t sum = static_cast<uint16_t>(L[i]) * 2 + carry;
            input[i] = static_cast<uint8_t>(sum & 0xff);
            carry = sum >> 8;
        }
        input[32] = static_cast<uint8_t>(carry);
        // Remaining bytes are already zero from value-initialization

        auto result = sc_reduce(input);

        std::array<uint8_t, 32> expected{};
        EXPECT_TRUE(span_compare(result, expected));
    }

    // (L + 1) mod L should be 1
    {
        std::array<uint8_t, 64> input{};
        // L + 1 in little-endian: first byte changes from 0xed to 0xee, rest same
        span_copy(make_span(input).first(32), make_const_span(L));
        input[0] = 0xee;

        auto result = sc_reduce(input);

        std::array<uint8_t, 32> expected{};
        expected[0] = 1;
        EXPECT_TRUE(span_compare(result, expected));
    }
}

//
// ge_from_bytes rejects invalid (off-curve) point encodings
//

TEST(curve25519, ge_from_bytes_invalid_point)
{
    // y = 1 (the identity point encoding) — x^2 = 0, so x = 0, this IS valid
    {
        std::array<uint8_t, 32> one{};
        one[0] = 1;
        auto pt = ge_from_bytes(one);
        EXPECT_TRUE(pt.has_value());
    }

    // y = 2: x^2 = (4-1)/(4d+1) — not a quadratic residue mod p
    {
        std::array<uint8_t, 32> two{};
        two[0] = 2;
        auto pt = ge_from_bytes(two);
        EXPECT_TRUE(!pt.has_value());
    }

    // Arbitrary bytes unlikely to be on the curve
    {
        auto bad = hex_to_bytes<32>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        auto pt = ge_from_bytes(bad);
        EXPECT_TRUE(!pt.has_value());
    }

    // y = p (all 0xff with top bit cleared = 2^255-1 = p+18) reduces to 18 mod p
    // Test that the function handles near-p values
    {
        std::array<uint8_t, 32> near_p{};
        near_p.fill(0xff);
        near_p[31] = 0x7f;  // clear top bit (sign bit)
        auto pt = ge_from_bytes(near_p);
        // This may or may not be on the curve; the important thing is it doesn't crash
        do_not_optimize(pt);
    }
}

//
// RFC 7748 Section 6.1 — X25519 iterated test (1000 iterations)
// Start with k = u = {9, 0, 0, ..., 0} (32 bytes, little-endian encoding of 9)
// For 1000 iterations: k_new = X25519(k, u), u = k, k = k_new
// After 1000 iterations:
//   k = 684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51
//

TEST(curve25519, x25519_1000_iterations)
{
    std::array<uint8_t, 32> k{};
    k[0] = 9;

    std::array<uint8_t, 32> u{};
    u[0] = 9;

    for (int i = 0; i < 1000; ++i) {
        auto k_new = curve25519_scalar_mult(k, u);
        u = k;
        k = k_new;
    }

    auto expected = hex_to_bytes<32>("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    EXPECT_TRUE(span_compare(k, expected));
}

TEST_MAIN(statusbar_crypto_25519, curve25519_test)

#else  // !STATUSBAR_CRYPTO_HAS_INT128
#    include "statusbar/test/test.hpp"
TEST_MAIN(statusbar_crypto_25519, curve25519_test)
#endif  // STATUSBAR_CRYPTO_HAS_INT128
