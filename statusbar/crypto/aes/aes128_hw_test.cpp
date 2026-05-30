// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-128 hardware-accelerated tests
// Runs the same FIPS 197 / RFC 4493 test vectors through the _hw functions
// and cross-validates against the software implementation.

#include "statusbar/crypto/aes/aes128_hw.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <cstring>
#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;

// FIPS 197 Appendix B test key
static auto fips_key() -> Aes128Key
{
    return {{{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}}};
}

//
// FIPS 197 Appendix B — encrypt / decrypt via _hw
//

TEST(aes128_hw, encrypt_fips197_hw)
{
    auto rk = aes128_expand_key_hw(fips_key());

    std::array<uint8_t, 16> block = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    std::array<uint8_t, 16> expected = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};

    aes128_encrypt_block_hw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

TEST(aes128_hw, decrypt_fips197_hw)
{
    auto rk = aes128_expand_key_hw(fips_key());

    std::array<uint8_t, 16> block = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
    std::array<uint8_t, 16> expected = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    aes128_decrypt_block_hw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

TEST(aes128_hw, roundtrip_hw)
{
    auto rk = aes128_expand_key_hw(fips_key());

    std::array<uint8_t, 16> original = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    auto block = original;

    aes128_encrypt_block_hw(rk, block);
    EXPECT_TRUE(!span_compare(block, original));
    aes128_decrypt_block_hw(rk, block);
    EXPECT_TRUE(span_compare(block, original));
}

//
// NIST SP 800-38A ECB — encrypt / decrypt via _hw
//

TEST(aes128_hw, encrypt_nist_ecb_hw)
{
    auto rk = aes128_expand_key_hw(fips_key());

    std::array<uint8_t, 16> block = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    std::array<uint8_t, 16> expected = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};

    aes128_encrypt_block_hw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

//
// RFC 4493 — CMAC via _hw
//

TEST(aes128_hw, cmac_empty_hw)
{
    auto rk = aes128_expand_key_hw(fips_key());
    std::array<uint8_t, 16> expected = {
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
    auto tag = aes128_cmac_hw(rk, {});
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes128_hw, cmac_16bytes_hw)
{
    auto rk = aes128_expand_key_hw(fips_key());
    std::array<uint8_t, 16> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    std::array<uint8_t, 16> expected = {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
    auto tag = aes128_cmac_hw(rk, message);
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes128_hw, cmac_64bytes_hw)
{
    auto rk = aes128_expand_key_hw(fips_key());
    std::array<uint8_t, 64> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    std::array<uint8_t, 16> expected = {
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};
    auto tag = aes128_cmac_hw(rk, message);
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes128_hw, cmac_verify_hw)
{
    auto rk = aes128_expand_key_hw(fips_key());
    std::array<uint8_t, 16> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    std::array<uint8_t, 16> valid_tag = {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
    std::array<uint8_t, 16> bad_tag = {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x00};

    EXPECT_TRUE(aes128_cmac_verify_hw(rk, message, valid_tag));
    EXPECT_TRUE(!aes128_cmac_verify_hw(rk, message, bad_tag));
}

//
// CMAC-xorend via _hw
//

TEST(aes128_hw, cmac_xorend_zero_hw)
{
    // cmac_xorend(rk, msg, zero) == cmac(rk, msg) since XOR with zero is identity
    auto rk = aes128_expand_key_hw(fips_key());

    std::array<uint8_t, 40> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    };
    std::array<uint8_t, 16> zero_xor{};

    auto tag_cmac = aes128_cmac_hw(rk, message);
    auto tag_xorend = aes128_cmac_xorend_hw(rk, message, zero_xor);
    EXPECT_TRUE(span_compare(tag_cmac, tag_xorend));
}

TEST(aes128_hw, cmac_xorend_cross_validate)
{
    // cmac_xorend _hw must match _sw
    Aes128Key key = {{{0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98}}};
    auto rk_sw = aes128_expand_key_sw(key);
    auto rk_hw = aes128_expand_key_hw(key);

    std::array<uint8_t, 16> xor_end = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    for (size_t len : {0, 1, 15, 16, 17, 31, 32, 48, 64, 100}) {
        std::vector<uint8_t> msg(len);
        for (size_t i = 0; i < len; ++i) {
            msg[i] = static_cast<uint8_t>(i * 37 + 13);
        }
        auto tag_sw = aes128_cmac_xorend_sw(rk_sw, msg, xor_end);
        auto tag_hw = aes128_cmac_xorend_hw(rk_hw, msg, xor_end);
        EXPECT_TRUE(span_compare(tag_sw, tag_hw));
    }
}

//
// Cross-validate: _hw results must match software for random-ish data
//

TEST(aes128_hw, cross_validate)
{
    Aes128Key key = {{{0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98}}};

    auto rk_sw = aes128_expand_key_sw(key);
    auto rk_hw = aes128_expand_key_hw(key);

    // Key expansion should match
    for (size_t i = 0; i <= aes128_num_rounds; ++i) {
        EXPECT_TRUE(span_compare(rk_sw.round_keys[i], rk_hw.round_keys[i]));
    }

    // Encrypt should match
    std::array<uint8_t, 16> block_sw = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    auto block_hw = block_sw;

    aes128_encrypt_block_sw(rk_sw, block_sw);
    aes128_encrypt_block_hw(rk_hw, block_hw);
    EXPECT_TRUE(span_compare(block_sw, block_hw));

    // Decrypt should match
    aes128_decrypt_block_sw(rk_sw, block_sw);
    aes128_decrypt_block_hw(rk_hw, block_hw);
    EXPECT_TRUE(span_compare(block_sw, block_hw));

    // CMAC should match on various lengths
    for (size_t len : {0, 1, 15, 16, 17, 31, 32, 48, 64, 100}) {
        std::vector<uint8_t> msg(len);
        for (size_t i = 0; i < len; ++i) {
            msg[i] = static_cast<uint8_t>(i * 37 + 13);
        }
        auto tag_sw = aes128_cmac_sw(rk_sw, msg);
        auto tag_hw = aes128_cmac_hw(rk_hw, msg);
        EXPECT_TRUE(span_compare(tag_sw, tag_hw));
    }
}

//

TEST(aes128_hw, encrypt_blocks_x4_matches_serial)
{
    auto const rk = aes128_expand_key_hw(fips_key());

    std::array<uint8_t, 4UL * 16UL> blocks_x4{};
    std::array<uint8_t, 4UL * 16UL> blocks_serial{};
    for (size_t i = 0; i < blocks_x4.size(); ++i) {
        blocks_x4[i] = static_cast<uint8_t>((i * 31UL) + 7UL);
        blocks_serial[i] = blocks_x4[i];
    }

    aes128_encrypt_blocks_x4_hw(rk, std::span<uint8_t, 4UL * 16UL>{blocks_x4});
    for (size_t i = 0; i < 4; ++i) {
        aes128_encrypt_block_hw(rk, std::span<uint8_t, 16>{blocks_serial.data() + (i * 16UL), 16});
    }

    EXPECT_TRUE(span_compare(blocks_x4, blocks_serial));
}

TEST_MAIN(statusbar_crypto_aes, aes128_hw_test)
