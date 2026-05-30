// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - FIPS 197: https://csrc.nist.gov/publications/detail/fips/197/final
// - NIST SP 800-38A: https://csrc.nist.gov/publications/detail/sp/800-38a/final
// - RFC 4493 (AES-CMAC): https://www.rfc-editor.org/rfc/rfc4493

#include "statusbar/crypto/aes/aes128.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <cstring>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;

// FIPS 197 Appendix B test key
static auto fips_key() -> Aes128Key
{
    return {{{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}}};
}

//
// FIPS 197 Appendix B — encrypt / decrypt
//

TEST(aes128, encrypt_fips197)
{
    auto rk = aes128_expand_key_sw(fips_key());

    std::array<uint8_t, 16> block = {
        0x32,
        0x43,
        0xf6,
        0xa8,
        0x88,
        0x5a,
        0x30,
        0x8d,
        0x31,
        0x31,
        0x98,
        0xa2,
        0xe0,
        0x37,
        0x07,
        0x34,
    };
    std::array<uint8_t, 16> expected = {
        0x39,
        0x25,
        0x84,
        0x1d,
        0x02,
        0xdc,
        0x09,
        0xfb,
        0xdc,
        0x11,
        0x85,
        0x97,
        0x19,
        0x6a,
        0x0b,
        0x32,
    };

    aes128_encrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

TEST(aes128, decrypt_fips197)
{
    auto rk = aes128_expand_key_sw(fips_key());

    std::array<uint8_t, 16> block = {
        0x39,
        0x25,
        0x84,
        0x1d,
        0x02,
        0xdc,
        0x09,
        0xfb,
        0xdc,
        0x11,
        0x85,
        0x97,
        0x19,
        0x6a,
        0x0b,
        0x32,
    };
    std::array<uint8_t, 16> expected = {
        0x32,
        0x43,
        0xf6,
        0xa8,
        0x88,
        0x5a,
        0x30,
        0x8d,
        0x31,
        0x31,
        0x98,
        0xa2,
        0xe0,
        0x37,
        0x07,
        0x34,
    };

    aes128_decrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

TEST(aes128, encrypt_decrypt_roundtrip)
{
    auto rk = aes128_expand_key_sw(fips_key());

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

    aes128_encrypt_block_sw(rk, block);
    EXPECT_TRUE(!span_compare(block, original));

    aes128_decrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, original));
}

//
// NIST SP 800-38A F.1.1 / F.1.2 — ECB encrypt / decrypt
//

TEST(aes128, encrypt_nist_ecb)
{
    // NIST SP 800-38A F.1.1 ECB-AES128.Encrypt, Block 1
    auto rk = aes128_expand_key_sw(fips_key());

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
        0x3a,
        0xd7,
        0x7b,
        0xb4,
        0x0d,
        0x7a,
        0x36,
        0x60,
        0xa8,
        0x9e,
        0xca,
        0xf3,
        0x24,
        0x66,
        0xef,
        0x97,
    };

    aes128_encrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

TEST(aes128, decrypt_nist_ecb)
{
    // NIST SP 800-38A F.1.2 ECB-AES128.Decrypt, Block 1
    auto rk = aes128_expand_key_sw(fips_key());

    std::array<uint8_t, 16> block = {
        0x3a,
        0xd7,
        0x7b,
        0xb4,
        0x0d,
        0x7a,
        0x36,
        0x60,
        0xa8,
        0x9e,
        0xca,
        0xf3,
        0x24,
        0x66,
        0xef,
        0x97,
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

    aes128_decrypt_block_sw(rk, block);
    EXPECT_TRUE(span_compare(block, expected));
}

//
// RFC 4493 — AES-CMAC test vectors
//

TEST(aes128, cmac_empty)
{
    // RFC 4493 Example 1: len = 0
    auto rk = aes128_expand_key_sw(fips_key());

    std::array<uint8_t, 16> expected = {
        0xbb,
        0x1d,
        0x69,
        0x29,
        0xe9,
        0x59,
        0x37,
        0x28,
        0x7f,
        0xa3,
        0x7d,
        0x12,
        0x9b,
        0x75,
        0x67,
        0x46,
    };

    auto tag = aes128_cmac_sw(rk, {});
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes128, cmac_16bytes)
{
    // RFC 4493 Example 2: len = 16 (exactly one block)
    auto rk = aes128_expand_key_sw(fips_key());

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
        0x07,
        0x0a,
        0x16,
        0xb4,
        0x6b,
        0x4d,
        0x41,
        0x44,
        0xf7,
        0x9b,
        0xdd,
        0x9d,
        0xd0,
        0x4a,
        0x28,
        0x7c,
    };

    auto tag = aes128_cmac_sw(rk, message);
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes128, cmac_40bytes)
{
    // RFC 4493 Example 3: len = 40 (incomplete last block)
    auto rk = aes128_expand_key_sw(fips_key());

    std::array<uint8_t, 40> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    };
    std::array<uint8_t, 16> expected = {
        0xdf,
        0xa6,
        0x67,
        0x47,
        0xde,
        0x9a,
        0xe6,
        0x30,
        0x30,
        0xca,
        0x32,
        0x61,
        0x14,
        0x97,
        0xc8,
        0x27,
    };

    auto tag = aes128_cmac_sw(rk, message);
    EXPECT_TRUE(span_compare(tag, expected));
}

TEST(aes128, cmac_64bytes)
{
    // RFC 4493 Example 4: len = 64 (exactly four blocks)
    auto rk = aes128_expand_key_sw(fips_key());

    std::array<uint8_t, 64> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    std::array<uint8_t, 16> expected = {
        0x51,
        0xf0,
        0xbe,
        0xbf,
        0x7e,
        0x3b,
        0x9d,
        0x92,
        0xfc,
        0x49,
        0x74,
        0x17,
        0x79,
        0x36,
        0x3c,
        0xfe,
    };

    auto tag = aes128_cmac_sw(rk, message);
    EXPECT_TRUE(span_compare(tag, expected));
}

//
// CMAC verify
//

TEST(aes128, cmac_verify_valid)
{
    auto rk = aes128_expand_key_sw(fips_key());

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
        0x07,
        0x0a,
        0x16,
        0xb4,
        0x6b,
        0x4d,
        0x41,
        0x44,
        0xf7,
        0x9b,
        0xdd,
        0x9d,
        0xd0,
        0x4a,
        0x28,
        0x7c,
    };

    EXPECT_TRUE(aes128_cmac_verify_sw(rk, message, valid_tag));
}

TEST(aes128, cmac_verify_invalid)
{
    auto rk = aes128_expand_key_sw(fips_key());

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
        0x07,
        0x0a,
        0x16,
        0xb4,
        0x6b,
        0x4d,
        0x41,
        0x44,
        0xf7,
        0x9b,
        0xdd,
        0x9d,
        0xd0,
        0x4a,
        0x28,
        0x00,  // last byte wrong
    };

    EXPECT_TRUE(!aes128_cmac_verify_sw(rk, message, bad_tag));
}

TEST(aes128, cmac_verify_empty)
{
    auto rk = aes128_expand_key_sw(fips_key());

    std::array<uint8_t, 16> valid_tag = {
        0xbb,
        0x1d,
        0x69,
        0x29,
        0xe9,
        0x59,
        0x37,
        0x28,
        0x7f,
        0xa3,
        0x7d,
        0x12,
        0x9b,
        0x75,
        0x67,
        0x46,
    };

    EXPECT_TRUE(aes128_cmac_verify_sw(rk, {}, valid_tag));
}

//
// CMAC-xorend (RFC 5297 Section 2.4 helper)
//

TEST(aes128, cmac_xorend_zero)
{
    // cmac_xorend(rk, msg, zero) == cmac(rk, msg) since XOR with zero is identity
    auto rk = aes128_expand_key_sw(fips_key());

    std::array<uint8_t, 40> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    };
    std::array<uint8_t, 16> zero_xor{};

    auto tag_cmac = aes128_cmac_sw(rk, message);
    auto tag_xorend = aes128_cmac_xorend_sw(rk, message, zero_xor);
    EXPECT_TRUE(span_compare(tag_cmac, tag_xorend));
}

TEST(aes128, cmac_xorend_nonzero)
{
    // cmac_xorend with nonzero xor_end should differ from plain cmac
    auto rk = aes128_expand_key_sw(fips_key());

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

    auto tag_cmac = aes128_cmac_sw(rk, message);
    auto tag_xorend = aes128_cmac_xorend_sw(rk, message, xor_end);
    EXPECT_TRUE(!span_compare(tag_cmac, tag_xorend));
}

TEST(aes128, cmac_xorend_empty)
{
    // cmac_xorend with empty message
    auto rk = aes128_expand_key_sw(fips_key());
    std::array<uint8_t, 16> xor_end = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    auto tag = aes128_cmac_xorend_sw(rk, {}, xor_end);
    // Just verify it doesn't crash and produces 16 bytes
    EXPECT_TRUE(tag.size() == 16);
}

//
// Key expansion sanity
//

TEST(aes128, key_expansion)
{
    // Verify first and last round keys match FIPS 197 Appendix A.1
    auto rk = aes128_expand_key_sw(fips_key());

    // Round key 0 should be the original key
    std::array<uint8_t, 16> rk0_expected = {
        0x2b,
        0x7e,
        0x15,
        0x16,
        0x28,
        0xae,
        0xd2,
        0xa6,
        0xab,
        0xf7,
        0x15,
        0x88,
        0x09,
        0xcf,
        0x4f,
        0x3c,
    };
    EXPECT_TRUE(span_compare(rk.round_keys[0], rk0_expected));

    // Round key 10 (last) from FIPS 197 Appendix A.1
    std::array<uint8_t, 16> rk10_expected = {
        0xd0,
        0x14,
        0xf9,
        0xa8,
        0xc9,
        0xee,
        0x25,
        0x89,
        0xe1,
        0x3f,
        0x0c,
        0xc8,
        0xb6,
        0x63,
        0x0c,
        0xa6,
    };
    EXPECT_TRUE(span_compare(rk.round_keys[10], rk10_expected));
}

//

TEST_MAIN(statusbar_crypto_aes, aes128_test)
