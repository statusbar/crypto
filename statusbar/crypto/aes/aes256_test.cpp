// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - FIPS 197: https://csrc.nist.gov/publications/detail/fips/197/final
// - NIST SP 800-38A: https://csrc.nist.gov/publications/detail/sp/800-38a/final
// - NIST SP 800-38B: https://csrc.nist.gov/publications/detail/sp/800-38b/final

#include "statusbar/crypto/aes/aes256.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <cstring>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;

// FIPS 197 Appendix C.3 test key (256-bit)
static auto fips_key() -> Aes256Key
{
    return {{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}}};
}

// NIST SP 800-38A / 800-38B test key (256-bit)
static auto nist_key() -> Aes256Key
{
    return {{{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
              0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}}};
}

//
// FIPS 197 Appendix C.3 — AES-256 encrypt / decrypt
//

TEST(aes256, encrypt_fips197)
{
    auto rk = aes256_expand_key_sw(fips_key());

    std::array<uint8_t, 16> block = {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
    };
    std::array<uint8_t, 16> expected = {
        0x8e,
        0xa2,
        0xb7,
        0xca,
        0x51,
        0x67,
        0x45,
        0xbf,
        0xea,
        0xfc,
        0x49,
        0x90,
        0x4b,
        0x49,
        0x60,
        0x89,
    };

    aes256_encrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

TEST(aes256, decrypt_fips197)
{
    auto rk = aes256_expand_key_sw(fips_key());

    std::array<uint8_t, 16> block = {
        0x8e,
        0xa2,
        0xb7,
        0xca,
        0x51,
        0x67,
        0x45,
        0xbf,
        0xea,
        0xfc,
        0x49,
        0x90,
        0x4b,
        0x49,
        0x60,
        0x89,
    };
    std::array<uint8_t, 16> expected = {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
    };

    aes256_decrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

TEST(aes256, encrypt_decrypt_roundtrip)
{
    auto rk = aes256_expand_key_sw(fips_key());

    std::array<uint8_t, 16> original = {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
    };
    auto block = original;

    aes256_encrypt_block_sw(rk, block);
    EXPECT_TRUE(!span_compare(block, original));

    aes256_decrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, original));
}

//
// NIST SP 800-38A F.1.5 / F.1.6 — ECB-AES256 encrypt / decrypt
//

TEST(aes256, encrypt_nist_ecb)
{
    // NIST SP 800-38A F.1.5 ECB-AES256.Encrypt, Block 1
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 16> block = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a,
    };
    std::array<uint8_t, 16> expected = {
        0xf3,
        0xee,
        0xd1,
        0xbd,
        0xb5,
        0xd2,
        0xa0,
        0x3c,
        0x06,
        0x4b,
        0x5a,
        0x7e,
        0x3d,
        0xb1,
        0x81,
        0xf8,
    };

    aes256_encrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

TEST(aes256, decrypt_nist_ecb)
{
    // NIST SP 800-38A F.1.6 ECB-AES256.Decrypt, Block 1
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 16> block = {
        0xf3,
        0xee,
        0xd1,
        0xbd,
        0xb5,
        0xd2,
        0xa0,
        0x3c,
        0x06,
        0x4b,
        0x5a,
        0x7e,
        0x3d,
        0xb1,
        0x81,
        0xf8,
    };
    std::array<uint8_t, 16> expected = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a,
    };

    aes256_decrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

//
// NIST SP 800-38B — AES-256-CMAC test vectors
//

TEST(aes256, cmac_empty)
{
    // NIST SP 800-38B D.2 Example 1: AES-256-CMAC, len = 0
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 16> expected = {
        0x02,
        0x89,
        0x62,
        0xf6,
        0x1b,
        0x7b,
        0xf8,
        0x9e,
        0xfc,
        0x6b,
        0x55,
        0x1f,
        0x46,
        0x67,
        0xd9,
        0x83,
    };

    auto tag = aes256_cmac_sw(rk, {});
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes256, cmac_16bytes)
{
    // NIST SP 800-38B D.2 Example 2: AES-256-CMAC, len = 16
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 16> message = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a,
    };
    std::array<uint8_t, 16> expected = {
        0x28,
        0xa7,
        0x02,
        0x3f,
        0x45,
        0x2e,
        0x8f,
        0x82,
        0xbd,
        0x4b,
        0xf2,
        0x8d,
        0x8c,
        0x37,
        0xc3,
        0x5c,
    };

    auto tag = aes256_cmac_sw(rk, message);
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes256, cmac_40bytes)
{
    // NIST SP 800-38B D.2 Example 3: AES-256-CMAC, len = 40
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 40> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    };
    std::array<uint8_t, 16> expected = {
        0xaa,
        0xf3,
        0xd8,
        0xf1,
        0xde,
        0x56,
        0x40,
        0xc2,
        0x32,
        0xf5,
        0xb1,
        0x69,
        0xb9,
        0xc9,
        0x11,
        0xe6,
    };

    auto tag = aes256_cmac_sw(rk, message);
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes256, cmac_64bytes)
{
    // NIST SP 800-38B D.2 Example 4: AES-256-CMAC, len = 64
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 64> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    std::array<uint8_t, 16> expected = {
        0xe1,
        0x99,
        0x21,
        0x90,
        0x54,
        0x9f,
        0x6e,
        0xd5,
        0x69,
        0x6a,
        0x2c,
        0x05,
        0x6c,
        0x31,
        0x54,
        0x10,
    };

    auto tag = aes256_cmac_sw(rk, message);
    EXPECT_TRUE(span_compare(tag, expected));
}

//
// CMAC verify
//

TEST(aes256, cmac_verify_valid)
{
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 16> message = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a,
    };
    std::array<uint8_t, 16> valid_tag = {
        0x28,
        0xa7,
        0x02,
        0x3f,
        0x45,
        0x2e,
        0x8f,
        0x82,
        0xbd,
        0x4b,
        0xf2,
        0x8d,
        0x8c,
        0x37,
        0xc3,
        0x5c,
    };

    EXPECT_TRUE(aes256_cmac_verify_sw(rk, message, valid_tag));
}

TEST(aes256, cmac_verify_invalid)
{
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 16> message = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a,
    };
    std::array<uint8_t, 16> bad_tag = {
        0x28,
        0xa7,
        0x02,
        0x3f,
        0x45,
        0x2e,
        0x8f,
        0x82,
        0xbd,
        0x4b,
        0xf2,
        0x8d,
        0x8c,
        0x37,
        0xc3,
        0x00,  // last byte wrong
    };

    EXPECT_TRUE(!aes256_cmac_verify_sw(rk, message, bad_tag));
}

TEST(aes256, cmac_verify_empty)
{
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 16> valid_tag = {
        0x02,
        0x89,
        0x62,
        0xf6,
        0x1b,
        0x7b,
        0xf8,
        0x9e,
        0xfc,
        0x6b,
        0x55,
        0x1f,
        0x46,
        0x67,
        0xd9,
        0x83,
    };

    EXPECT_TRUE(aes256_cmac_verify_sw(rk, {}, valid_tag));
}

//
// CMAC-xorend (RFC 5297 Section 2.4 helper)
//

TEST(aes256, cmac_xorend_zero)
{
    // cmac_xorend(rk, msg, zero) == cmac(rk, msg) since XOR with zero is identity
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 40> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    };
    std::array<uint8_t, 16> zero_xor{};

    auto tag_cmac = aes256_cmac_sw(rk, message);
    auto tag_xorend = aes256_cmac_xorend_sw(rk, message, zero_xor);
    EXPECT_TRUE(span_compare(tag_cmac, tag_xorend));
}

TEST(aes256, cmac_xorend_nonzero)
{
    // cmac_xorend with nonzero xor_end should differ from plain cmac
    auto rk = aes256_expand_key_sw(nist_key());

    std::array<uint8_t, 16> message = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a,
    };
    std::array<uint8_t, 16> xor_end = {
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    };

    auto tag_cmac = aes256_cmac_sw(rk, message);
    auto tag_xorend = aes256_cmac_xorend_sw(rk, message, xor_end);
    EXPECT_TRUE(!span_compare(tag_cmac, tag_xorend));
}

TEST(aes256, cmac_xorend_empty)
{
    // cmac_xorend with empty message
    auto rk = aes256_expand_key_sw(nist_key());
    std::array<uint8_t, 16> xor_end = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    auto tag = aes256_cmac_xorend_sw(rk, {}, xor_end);
    // Just verify it doesn't crash and produces 16 bytes
    EXPECT_TRUE(tag.size() == 16);
}

//
// Key expansion sanity — FIPS 197 Appendix A.3
//

TEST(aes256, key_expansion)
{
    auto rk = aes256_expand_key_sw(fips_key());

    // Round key 0 should be the first 16 bytes of the original key
    std::array<uint8_t, 16> rk0_expected = {
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    };
    EXPECT_TRUE(span_compare(rk.round_keys[0], rk0_expected));

    // Round key 1 should be the second 16 bytes of the original key
    std::array<uint8_t, 16> rk1_expected = {
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1a,
        0x1b,
        0x1c,
        0x1d,
        0x1e,
        0x1f,
    };
    EXPECT_TRUE(span_compare(rk.round_keys[1], rk1_expected));

    // Round key 14 (last) from FIPS 197 Appendix A.3: w[56..59]
    std::array<uint8_t, 16> rk14_expected = {
        0x24,
        0xfc,
        0x79,
        0xcc,
        0xbf,
        0x09,
        0x79,
        0xe9,
        0x37,
        0x1a,
        0xc2,
        0x3c,
        0x6d,
        0x68,
        0xde,
        0x36,
    };
    EXPECT_TRUE(span_compare(rk.round_keys[14], rk14_expected));
}

//

TEST_MAIN(statusbar_crypto_aes, aes256_test)
