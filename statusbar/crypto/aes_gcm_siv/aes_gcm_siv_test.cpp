// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - RFC 8452 (AES-GCM-SIV): https://www.rfc-editor.org/rfc/rfc8452

#include "statusbar/crypto/aes_gcm_siv/aes_gcm_siv.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

using namespace statusbar::crypto;
using statusbar::crypto::internal::make_const_span;
using statusbar::crypto::internal::span_compare;
using statusbar::crypto::internal::span_copy;
using std::span;

//
// RFC 8452 Appendix A — POLYVAL test vector
//

TEST(aes_gcm_siv, polyval_rfc_appendix_a)
{
    // H = 25629347589242761d31f826ba4b757b
    // X1 = 4f4f95668c83dfb6401762bb2d01a262
    // X2 = d1a24ddd2721d006bbe45f20d3c9f362
    // POLYVAL(H, X1, X2) = f7a3b47b846119fae5b7866cf5e5b77e

    PolyvalKey H;
    uint8_t h_bytes[] = {0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b};
    span_copy(H.data, make_const_span(h_bytes));

    uint8_t input[32] = {
        0x4f, 0x4f, 0x95, 0x66, 0x8c, 0x83, 0xdf, 0xb6, 0x40, 0x17, 0x62, 0xbb, 0x2d, 0x01, 0xa2, 0x62,
        0xd1, 0xa2, 0x4d, 0xdd, 0x27, 0x21, 0xd0, 0x06, 0xbb, 0xe4, 0x5f, 0x20, 0xd3, 0xc9, 0xf3, 0x62,
    };

    uint8_t expected[] = {0xf7, 0xa3, 0xb4, 0x7b, 0x84, 0x61, 0x19, 0xfa, 0xe5, 0xb7, 0x86, 0x6c, 0xf5, 0xe5, 0xb7, 0x7e};

    auto result = polyval_sw(H, span<uint8_t const>(input, 32));
    EXPECT_TRUE(span_compare(result, expected));
}

//
// RFC 8452 dot product test vector
// dot(a, b) = a * b * x^{-128} mod p
//

TEST(aes_gcm_siv, polyval_dot_product)
{
    // a = 66e94bd4ef8a2c3b884cfa59ca342b2e
    // b = ff000000000000000000000000000000
    // dot(a, b) = ebe563401e7e91ea3ad6426b8140c394

    PolyvalKey H;
    uint8_t h_bytes[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    span_copy(H.data, make_const_span(h_bytes));

    uint8_t input[16] = {
        0x66,
        0xe9,
        0x4b,
        0xd4,
        0xef,
        0x8a,
        0x2c,
        0x3b,
        0x88,
        0x4c,
        0xfa,
        0x59,
        0xca,
        0x34,
        0x2b,
        0x2e,
    };

    // polyval_sw(H, X) = dot(0 ^ X, H) = dot(X, H)
    uint8_t expected[] = {0xeb, 0xe5, 0x63, 0x40, 0x1e, 0x7e, 0x91, 0xea, 0x3a, 0xd6, 0x42, 0x6b, 0x81, 0x40, 0xc3, 0x94};

    auto result = polyval_sw(H, span<uint8_t const>(input, 16));
    EXPECT_TRUE(span_compare(result, expected));
}

//
// POLYVAL of empty input
//

TEST(aes_gcm_siv, polyval_empty)
{
    PolyvalKey H;
    uint8_t h_bytes[] = {0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b};
    span_copy(H.data, make_const_span(h_bytes));

    auto result = polyval_sw(H, {});

    uint8_t zero[16] = {};
    EXPECT_TRUE(span_compare(result, zero));
}

//
// POLYVAL incremental update
//

TEST(aes_gcm_siv, polyval_update_incremental)
{
    // Verify that polyval_update called block-by-block matches polyval on all blocks
    PolyvalKey H;
    uint8_t h_bytes[] = {0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b};
    span_copy(H.data, make_const_span(h_bytes));

    uint8_t x1[16] = {
        0x4f,
        0x4f,
        0x95,
        0x66,
        0x8c,
        0x83,
        0xdf,
        0xb6,
        0x40,
        0x17,
        0x62,
        0xbb,
        0x2d,
        0x01,
        0xa2,
        0x62,
    };
    uint8_t x2[16] = {
        0xd1,
        0xa2,
        0x4d,
        0xdd,
        0x27,
        0x21,
        0xd0,
        0x06,
        0xbb,
        0xe4,
        0x5f,
        0x20,
        0xd3,
        0xc9,
        0xf3,
        0x62,
    };

    uint8_t expected[] = {0xf7, 0xa3, 0xb4, 0x7b, 0x84, 0x61, 0x19, 0xfa, 0xe5, 0xb7, 0x86, 0x6c, 0xf5, 0xe5, 0xb7, 0x7e};

    std::array<uint8_t, 16> accum{};
    polyval_update_sw(H, span<uint8_t const>(x1, 16), accum);
    polyval_update_sw(H, span<uint8_t const>(x2, 16), accum);

    EXPECT_TRUE(span_compare(accum, expected));
}

//
// POLYVAL of a single zero block
//

TEST(aes_gcm_siv, polyval_zero_block)
{
    PolyvalKey H;
    uint8_t h_bytes[] = {0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b};
    span_copy(H.data, make_const_span(h_bytes));

    uint8_t zero_block[16] = {};
    auto result = polyval_sw(H, span<uint8_t const>(zero_block, 16));

    // dot(0, H) = 0
    uint8_t zero[16] = {};
    EXPECT_TRUE(span_compare(result, zero));
}

//
// POLYVAL intermediate value from AES-128-GCM-SIV (RFC 8452 C.1 test 2)
//

TEST(aes_gcm_siv, polyval_aes128_intermediate)
{
    // auth_key = d9b360279694941ac5dbc6987ada7377
    // Input: padded 8B plaintext (01 00...00) || length block (00...00 40 00...00)
    // Expected: eb93b7740962c5e49d2a90a7dc5cec74
    PolyvalKey H;
    uint8_t ak[] = {0xd9, 0xb3, 0x60, 0x27, 0x96, 0x94, 0x94, 0x1a, 0xc5, 0xdb, 0xc6, 0x98, 0x7a, 0xda, 0x73, 0x77};
    span_copy(H.data, make_const_span(ak));

    uint8_t pv_input[32] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t expected[] = {0xeb, 0x93, 0xb7, 0x74, 0x09, 0x62, 0xc5, 0xe4, 0x9d, 0x2a, 0x90, 0xa7, 0xdc, 0x5c, 0xec, 0x74};

    auto result = polyval_sw(H, span<uint8_t const>(pv_input, 32));
    EXPECT_TRUE(span_compare(result, expected));
}

//

TEST_MAIN(statusbar_crypto_aes_gcm_siv, aes_gcm_siv_test)
