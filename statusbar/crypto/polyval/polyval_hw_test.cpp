// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// POLYVAL hardware-accelerated tests
// Runs the same RFC 8452 test vectors through the _hw functions
// and cross-validates against the software implementation.

#include "statusbar/crypto/polyval/polyval_hw.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::make_const_span;
using statusbar::crypto::internal::span_compare;
using statusbar::crypto::internal::span_copy;
using std::span;

//
// RFC 8452 Appendix A — POLYVAL test vector via _hw
//

TEST(polyval_hw, polyval_rfc_appendix_a_hw)
{
    PolyvalKey H;
    uint8_t h_bytes[] = {0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b};
    span_copy(H.data, make_const_span(h_bytes));

    uint8_t input[32] = {
        0x4f, 0x4f, 0x95, 0x66, 0x8c, 0x83, 0xdf, 0xb6, 0x40, 0x17, 0x62, 0xbb, 0x2d, 0x01, 0xa2, 0x62,
        0xd1, 0xa2, 0x4d, 0xdd, 0x27, 0x21, 0xd0, 0x06, 0xbb, 0xe4, 0x5f, 0x20, 0xd3, 0xc9, 0xf3, 0x62,
    };

    uint8_t expected[] = {0xf7, 0xa3, 0xb4, 0x7b, 0x84, 0x61, 0x19, 0xfa, 0xe5, 0xb7, 0x86, 0x6c, 0xf5, 0xe5, 0xb7, 0x7e};

    auto result = polyval_hw(H, span<uint8_t const>(input, 32));
    EXPECT_TRUE(span_compare(result, expected));
}

//
// RFC 8452 dot product test vector via _hw
//

TEST(polyval_hw, polyval_dot_product_hw)
{
    PolyvalKey H;
    uint8_t h_bytes[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    span_copy(H.data, make_const_span(h_bytes));

    uint8_t input[16] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};

    uint8_t expected[] = {0xeb, 0xe5, 0x63, 0x40, 0x1e, 0x7e, 0x91, 0xea, 0x3a, 0xd6, 0x42, 0x6b, 0x81, 0x40, 0xc3, 0x94};

    auto result = polyval_hw(H, span<uint8_t const>(input, 16));
    EXPECT_TRUE(span_compare(result, expected));
}

//
// POLYVAL empty input via _hw
//

TEST(polyval_hw, polyval_empty_hw)
{
    PolyvalKey H;
    uint8_t h_bytes[] = {0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b};
    span_copy(H.data, make_const_span(h_bytes));

    auto result = polyval_hw(H, {});

    uint8_t zero[16] = {};
    EXPECT_TRUE(span_compare(result, zero));
}

//
// POLYVAL incremental update via _hw
//

TEST(polyval_hw, polyval_update_incremental_hw)
{
    PolyvalKey H;
    uint8_t h_bytes[] = {0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b};
    span_copy(H.data, make_const_span(h_bytes));

    uint8_t x1[16] = {0x4f, 0x4f, 0x95, 0x66, 0x8c, 0x83, 0xdf, 0xb6, 0x40, 0x17, 0x62, 0xbb, 0x2d, 0x01, 0xa2, 0x62};
    uint8_t x2[16] = {0xd1, 0xa2, 0x4d, 0xdd, 0x27, 0x21, 0xd0, 0x06, 0xbb, 0xe4, 0x5f, 0x20, 0xd3, 0xc9, 0xf3, 0x62};

    uint8_t expected[] = {0xf7, 0xa3, 0xb4, 0x7b, 0x84, 0x61, 0x19, 0xfa, 0xe5, 0xb7, 0x86, 0x6c, 0xf5, 0xe5, 0xb7, 0x7e};

    std::array<uint8_t, 16> accum{};
    polyval_update_hw(H, span<uint8_t const>(x1, 16), accum);
    polyval_update_hw(H, span<uint8_t const>(x2, 16), accum);

    EXPECT_TRUE(span_compare(accum, expected));
}

//
// POLYVAL intermediate from AES-128-GCM-SIV via _hw
//

TEST(polyval_hw, polyval_aes128_intermediate_hw)
{
    PolyvalKey H;
    uint8_t ak[] = {0xd9, 0xb3, 0x60, 0x27, 0x96, 0x94, 0x94, 0x1a, 0xc5, 0xdb, 0xc6, 0x98, 0x7a, 0xda, 0x73, 0x77};
    span_copy(H.data, make_const_span(ak));

    uint8_t pv_input[32] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t expected[] = {0xeb, 0x93, 0xb7, 0x74, 0x09, 0x62, 0xc5, 0xe4, 0x9d, 0x2a, 0x90, 0xa7, 0xdc, 0x5c, 0xec, 0x74};

    auto result = polyval_hw(H, span<uint8_t const>(pv_input, 32));
    EXPECT_TRUE(span_compare(result, expected));
}

//
// Cross-validate: _hw results must match software
//

TEST(polyval_hw, cross_validate)
{
    // Test with various keys and input lengths
    for (uint8_t key_byte : {0x00, 0x01, 0x42, 0xab, 0xff}) {
        PolyvalKey H;
        for (size_t i = 0; i < 16; ++i) {
            H.data[i] = static_cast<uint8_t>(key_byte + i * 17);
        }

        for (size_t num_blocks : {1, 2, 3, 4, 8, 16}) {
            std::vector<uint8_t> input(num_blocks * 16);
            for (size_t i = 0; i < input.size(); ++i) {
                input[i] = static_cast<uint8_t>(i * 31 + key_byte);
            }

            auto sw = polyval_sw(H, input);
            auto hw = polyval_hw(H, input);
            EXPECT_TRUE(sw == hw);

            // Also cross-validate incremental
            std::array<uint8_t, 16> accum_sw{};
            std::array<uint8_t, 16> accum_hw{};
            for (size_t b = 0; b < num_blocks; ++b) {
                auto block = span<uint8_t const>(input.data() + b * 16, 16);
                polyval_update_sw(H, block, accum_sw);
                polyval_update_hw(H, block, accum_hw);
            }
            EXPECT_TRUE(accum_sw == accum_hw);
        }
    }
}

//

TEST_MAIN(statusbar_crypto_polyval, polyval_hw_test)
