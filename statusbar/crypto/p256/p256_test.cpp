// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// P-256 field arithmetic, scalar field, and group operation tests

#include "statusbar/crypto/util/crypto_has_int128.hpp"

#if STATUSBAR_CRYPTO_HAS_INT128

#    include "statusbar/crypto/p256/p256.hpp"
#    include "statusbar/crypto/util/crypto_util_internal.hpp"
#    include "statusbar/test/test.hpp"

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;

//
// Field arithmetic tests
//

TEST(p256, field_one)
{
    auto one = p256_fe_one();
    EXPECT_TRUE(!p256_fe_is_zero(one));

    P256FieldElement zero{};
    EXPECT_TRUE(p256_fe_is_zero(zero));
}

TEST(p256, field_add_sub)
{
    // a + b - b == a
    uint8_t a_bytes[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                           0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t b_bytes[32] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                           0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00};

    auto a = p256_fe_from_bytes(a_bytes);
    auto b = p256_fe_from_bytes(b_bytes);

    auto sum = p256_fe_add(a, b);
    auto diff = p256_fe_sub(sum, b);
    EXPECT_TRUE(p256_fe_equal(diff, a));

    auto diff2 = p256_fe_sub(a, b);
    auto sum2 = p256_fe_add(diff2, b);
    EXPECT_TRUE(p256_fe_equal(sum2, a));
}

TEST(p256, field_mul_identity)
{
    uint8_t a_bytes[32] = {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    auto a = p256_fe_from_bytes(a_bytes);
    auto one = p256_fe_one();

    auto prod = p256_fe_mul(a, one);
    EXPECT_TRUE(p256_fe_equal(prod, a));

    P256FieldElement zero{};
    auto prod2 = p256_fe_mul(a, zero);
    EXPECT_TRUE(p256_fe_is_zero(prod2));
}

TEST(p256, field_sqr)
{
    uint8_t a_bytes[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    auto a = p256_fe_from_bytes(a_bytes);

    auto sqr = p256_fe_sqr(a);
    auto mul = p256_fe_mul(a, a);
    EXPECT_TRUE(p256_fe_equal(sqr, mul));
}

TEST(p256, field_inv)
{
    uint8_t a_bytes[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    auto a = p256_fe_from_bytes(a_bytes);

    auto inv = p256_fe_inv(a);
    auto prod = p256_fe_mul(a, inv);
    auto one = p256_fe_one();
    EXPECT_TRUE(p256_fe_equal(prod, one));
}

TEST(p256, field_roundtrip)
{
    // Test bytes -> field element -> bytes roundtrip
    uint8_t bytes[32] = {0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
    auto fe = p256_fe_from_bytes(bytes);
    auto out = p256_fe_to_bytes(fe);
    EXPECT_TRUE(span_compare(bytes, out));
}

//
// Scalar field tests
//

TEST(p256, scalar_add_sub)
{
    uint8_t a_bytes[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42};
    uint8_t b_bytes[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17};
    auto a = p256_sc_from_bytes(a_bytes);
    auto b = p256_sc_from_bytes(b_bytes);

    auto sum = p256_sc_add(a, b);
    auto diff = p256_sc_sub(sum, b);
    auto diff_bytes = p256_sc_to_bytes(diff);
    EXPECT_TRUE(span_compare(a_bytes, diff_bytes));
}

TEST(p256, scalar_mul_inv)
{
    uint8_t a_bytes[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    auto a = p256_sc_from_bytes(a_bytes);

    auto inv = p256_sc_inv(a);
    auto prod = p256_sc_mul(a, inv);
    auto prod_bytes = p256_sc_to_bytes(prod);

    // Should be 1
    uint8_t one_bytes[32] = {};
    one_bytes[31] = 0x01;
    EXPECT_TRUE(span_compare(prod_bytes, one_bytes));
}

//
// Scalar negation
//

TEST(p256, scalar_negate)
{
    uint8_t a_bytes[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42};
    auto a = p256_sc_from_bytes(a_bytes);

    auto neg_a = p256_sc_negate(a);

    // a + (-a) == 0
    auto sum = p256_sc_add(a, neg_a);
    EXPECT_TRUE(p256_sc_is_zero(sum));

    // -(-a) == a
    auto neg_neg_a = p256_sc_negate(neg_a);
    auto neg_neg_bytes = p256_sc_to_bytes(neg_neg_a);
    EXPECT_TRUE(span_compare(a_bytes, neg_neg_bytes));
}

TEST(p256, scalar_negate_zero)
{
    P256Scalar zero{};
    auto neg_zero = p256_sc_negate(zero);
    EXPECT_TRUE(p256_sc_is_zero(neg_zero));
}

//
// Group operation tests
//

TEST(p256, generator_on_curve)
{
    auto G = p256_generator();
    EXPECT_TRUE(p256_point_on_curve(G));
}

TEST(p256, double_equals_add)
{
    auto G = p256_generator();
    auto G_jac = p256_affine_to_jacobian(G);

    auto G2_dbl = p256_point_double(G_jac);
    auto G2_add = p256_point_add(G_jac, G_jac);

    auto G2_dbl_aff = p256_point_to_affine(G2_dbl);
    auto G2_add_aff = p256_point_to_affine(G2_add);

    EXPECT_TRUE(p256_fe_equal(G2_dbl_aff.x, G2_add_aff.x));
    EXPECT_TRUE(p256_fe_equal(G2_dbl_aff.y, G2_add_aff.y));
    EXPECT_TRUE(p256_point_on_curve(G2_dbl_aff));
}

TEST(p256, known_2g)
{
    // 2*G for P-256 (from SEC 2):
    // x = 7CF27B188D034F7E8A52380304B51AC3C90E15DA0E046D2C93B8F8C5EF7B11F0
    // y = 89C14BCA33CB8FF63C9FC5E9D7FE77FFB4A51F01D4D1F67D0DEFD0F0CA06CF26 (not standard, will verify via on-curve)

    auto G = p256_generator();
    P256Scalar two{};
    two.limbs[0] = 2;
    auto G2_jac = p256_scalar_mult_base(two);
    auto G2 = p256_point_to_affine(G2_jac);

    EXPECT_TRUE(p256_point_on_curve(G2));

    // Known x-coordinate of 2G (computed from P-256 doubling formula)
    uint8_t expected_x[32] = {0x7C, 0xF2, 0x7B, 0x18, 0x8D, 0x03, 0x4F, 0x7E, 0x8A, 0x52, 0x38, 0x03, 0x04, 0xB5, 0x1A, 0xC3,
                              0xC0, 0x89, 0x69, 0xE2, 0x77, 0xF2, 0x1B, 0x35, 0xA6, 0x0B, 0x48, 0xFC, 0x47, 0x66, 0x99, 0x78};

    auto x_bytes = p256_fe_to_bytes(G2.x);
    EXPECT_TRUE(span_compare(x_bytes, expected_x));
}

TEST(p256, scalar_mult_identity)
{
    // n * G = identity
    // n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    uint8_t n_bytes[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
    auto n = p256_sc_from_bytes(n_bytes);

    auto nG = p256_scalar_mult_base(n);
    EXPECT_TRUE(p256_point_is_identity(nG));
}

TEST(p256, point_encoding_uncompressed)
{
    auto G = p256_generator();
    auto encoded = p256_encode_point_uncompressed(G);
    auto decoded = p256_decode_point_uncompressed(encoded);

    EXPECT_TRUE(decoded.has_value());
    EXPECT_TRUE(p256_fe_equal(G.x, decoded->x));
    EXPECT_TRUE(p256_fe_equal(G.y, decoded->y));
}

TEST(p256, point_encoding_x)
{
    auto G = p256_generator();
    auto encoded = p256_encode_point_x(G);
    auto decoded = p256_decode_point_x(encoded);

    EXPECT_TRUE(decoded.has_value());
    EXPECT_TRUE(p256_fe_equal(G.x, decoded->x));
    EXPECT_TRUE(p256_point_on_curve(*decoded));
}

TEST(p256, point_neg)
{
    auto G = p256_generator();
    auto G_jac = p256_affine_to_jacobian(G);

    auto neg_G = p256_point_neg(G_jac);

    // G + (-G) = identity
    auto sum = p256_point_add(G_jac, neg_G);
    EXPECT_TRUE(p256_point_is_identity(sum));

    // -(-G) should have same affine coordinates as G
    auto neg_neg_G = p256_point_neg(neg_G);
    auto result = p256_point_to_affine(neg_neg_G);
    EXPECT_TRUE(p256_fe_equal(G.x, result.x));
    EXPECT_TRUE(p256_fe_equal(G.y, result.y));
}

TEST(p256, keygen)
{
    uint8_t seed[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    auto [d, Q] = p256_keypair_from_seed(seed);

    EXPECT_TRUE(!p256_sc_is_zero(d));
    EXPECT_TRUE(p256_point_on_curve(Q));

    // Verify Q = d * G
    auto Q2_jac = p256_scalar_mult_base(d);
    auto Q2 = p256_point_to_affine(Q2_jac);
    EXPECT_TRUE(p256_fe_equal(Q.x, Q2.x));
    EXPECT_TRUE(p256_fe_equal(Q.y, Q2.y));
}

//
// Main
//

TEST_MAIN(statusbar_crypto_p256, p256_test)

#else  // !STATUSBAR_CRYPTO_HAS_INT128
#    include "statusbar/test/test.hpp"
TEST_MAIN(statusbar_crypto_p256, p256_test)
#endif  // STATUSBAR_CRYPTO_HAS_INT128
