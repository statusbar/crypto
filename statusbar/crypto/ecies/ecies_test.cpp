// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// DL/ECIES encrypt/decrypt tests

#include "statusbar/crypto/ecies/ecies.hpp"

#include "statusbar/crypto/p256/p256_ecdsa.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstring>
#include <string_view>
#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

TEST(ecies, roundtrip)
{
    // Generate recipient keypair
    uint8_t seed[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t plaintext[] = "Hello, DL/ECIES!";
    size_t pt_len = sizeof(plaintext) - 1;

    // Ephemeral key entropy
    uint8_t entropy[32] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

    size_t out_len = ecies_output_size(pt_len);
    std::vector<uint8_t> ciphertext(out_len);
    std::vector<uint8_t> decrypted(pt_len + 16);  // Extra room for padding

    auto enc_result = ecies_encrypt(sk.public_key, {plaintext, pt_len}, ciphertext, entropy);
    EXPECT_TRUE(!enc_result.empty());
    EXPECT_TRUE(enc_result.size() == out_len);

    auto dec_result = ecies_decrypt(sk, enc_result, decrypted);
    EXPECT_TRUE(dec_result.size() == pt_len);
    EXPECT_TRUE(span_compare(dec_result, span<uint8_t const>(plaintext, pt_len)));
}

TEST(ecies, tamper_v)
{
    uint8_t seed[32] = {0xAA};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t plaintext[] = "test";
    uint8_t entropy[32] = {0xBB};

    size_t out_len = ecies_output_size(4);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    ecies_encrypt(sk.public_key, {plaintext, 4}, ct, entropy);

    // Tamper with V (ephemeral key)
    ct[1] ^= 0x01;
    auto dec_result = ecies_decrypt(sk, ct, pt);
    EXPECT_TRUE(dec_result.empty());
}

TEST(ecies, tamper_c)
{
    uint8_t seed[32] = {0xCC};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t plaintext[] = "test data";
    uint8_t entropy[32] = {0xDD};

    size_t out_len = ecies_output_size(9);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    ecies_encrypt(sk.public_key, {plaintext, 9}, ct, entropy);

    // Tamper with C (ciphertext body)
    ct[ecies_ephemeral_key_size] ^= 0x01;
    auto dec_result = ecies_decrypt(sk, ct, pt);
    EXPECT_TRUE(dec_result.empty());
}

TEST(ecies, tamper_t)
{
    uint8_t seed[32] = {0xEE};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t plaintext[] = "test";
    uint8_t entropy[32] = {0xFF};

    size_t out_len = ecies_output_size(4);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    ecies_encrypt(sk.public_key, {plaintext, 4}, ct, entropy);

    // Tamper with T (MAC tag, last 32 bytes)
    ct[out_len - 1] ^= 0x01;
    auto dec_result = ecies_decrypt(sk, ct, pt);
    EXPECT_TRUE(dec_result.empty());
}

TEST(ecies, wrong_key)
{
    uint8_t seed1[32] = {0x01};
    uint8_t seed2[32] = {0x02};
    auto sk1 = p256_ecdsa_keypair_from_seed(seed1);
    auto sk2 = p256_ecdsa_keypair_from_seed(seed2);

    uint8_t plaintext[] = "secret";
    uint8_t entropy[32] = {0x42};

    size_t out_len = ecies_output_size(6);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    ecies_encrypt(sk1.public_key, {plaintext, 6}, ct, entropy);

    // Try decrypting with wrong key
    auto dec_result = ecies_decrypt(sk2, ct, pt);
    EXPECT_TRUE(dec_result.empty());
}

TEST(ecies, encrypt_output_too_small)
{
    uint8_t seed[32] = {0x01};
    auto sk = p256_ecdsa_keypair_from_seed(seed);
    uint8_t plaintext[] = "test";
    uint8_t entropy[32] = {0x42};

    // Output buffer is 1 byte too small
    size_t needed = ecies_output_size(4);
    std::vector<uint8_t> output(needed - 1);
    auto result = ecies_encrypt(sk.public_key, {plaintext, 4}, output, entropy);
    EXPECT_TRUE(result.empty());
}

TEST(ecies, decrypt_input_too_short)
{
    uint8_t seed[32] = {0x01};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    // Input shorter than minimum (V=33 + C=16 + T=32 = 81)
    std::vector<uint8_t> short_input(80, 0);
    std::vector<uint8_t> pt(16);
    auto result = ecies_decrypt(sk, short_input, pt);
    EXPECT_TRUE(result.empty());
}

TEST(ecies, decrypt_wrong_v_marker)
{
    uint8_t seed[32] = {0x01};
    auto sk = p256_ecdsa_keypair_from_seed(seed);
    uint8_t plaintext[] = "test";
    uint8_t entropy[32] = {0x42};

    size_t out_len = ecies_output_size(4);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    ecies_encrypt(sk.public_key, {plaintext, 4}, ct, entropy);

    // Corrupt V marker byte (should be 0x01)
    ct[0] = 0x04;
    auto result = ecies_decrypt(sk, ct, pt);
    EXPECT_TRUE(result.empty());
}

TEST(ecies, decrypt_unaligned_ciphertext)
{
    uint8_t seed[32] = {0x01};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    // c_len = 82 - 65 = 17, not a multiple of 16
    std::vector<uint8_t> input(82, 0);
    input[0] = 0x01;  // valid V marker so we get past that check
    std::vector<uint8_t> pt(32);
    auto result = ecies_decrypt(sk, input, pt);
    EXPECT_TRUE(result.empty());
}

//
// Known-answer tests
//
// Vectors generated by an independent Python reference (IEEE 1363a-2004 11.3.2 with the IEEE 1722 ECC1 options:
// P-256 ECSVDP-DHC, KDF2-SHA-256, AES-256-CBC-IV0, HMAC-SHA-256, DHAES mode, EC2OSP-X, P1 = P2 = empty)
// built on the `cryptography` package, not on this library. They pin the
// K1 || K2 key order (IEEE 1363a-2004 11.3.2 step 10a: K1 = leftmost bits is
// the cipher key, K2 = the rest is the MAC key) and the full V || C || T layout.
//

namespace {

constexpr std::array<uint8_t, 32> kat_seed{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                                           0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                           0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
constexpr std::array<uint8_t, 32> kat_entropy{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03,
                                              0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                                              0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

// "Hello, DL/ECIES!" (16 bytes -> two AES blocks after PKCS#7)
constexpr std::array<uint8_t, 97> kat_hello{
    0x01, 0xC2, 0x3F, 0x7A, 0x6A, 0x51, 0xAA, 0x50, 0xAE, 0xCD, 0x3A, 0xAA, 0xC1, 0xC6, 0x59, 0x33, 0xCF, 0xAA, 0x92, 0x56,
    0xEA, 0xFD, 0x36, 0x3C, 0xA2, 0xD3, 0x45, 0xF9, 0xE5, 0x3D, 0x95, 0xA5, 0x9A, 0x29, 0x21, 0xCB, 0x33, 0x6C, 0xC0, 0x99,
    0x52, 0x82, 0x0B, 0x97, 0xFD, 0xCA, 0x2A, 0xC7, 0xC6, 0xBA, 0x74, 0x25, 0xAF, 0x01, 0x1E, 0x3D, 0xC5, 0xA2, 0x67, 0xE5,
    0xD2, 0x68, 0x6E, 0x9A, 0x13, 0xA0, 0x44, 0x7C, 0xD5, 0x6E, 0xDB, 0x42, 0xA5, 0xCE, 0xC0, 0x4C, 0xA4, 0xD4, 0x50, 0x6E,
    0xE7, 0xC1, 0xA2, 0x8F, 0x62, 0x07, 0x7C, 0x3C, 0xA9, 0x56, 0xE3, 0x5F, 0xC8, 0x94, 0xBA, 0x21, 0x87,
};

// "test data" (9 bytes -> one AES block)
constexpr std::array<uint8_t, 81> kat_short{
    0x01, 0xC2, 0x3F, 0x7A, 0x6A, 0x51, 0xAA, 0x50, 0xAE, 0xCD, 0x3A, 0xAA, 0xC1, 0xC6, 0x59, 0x33, 0xCF, 0xAA, 0x92, 0x56, 0xEA,
    0xFD, 0x36, 0x3C, 0xA2, 0xD3, 0x45, 0xF9, 0xE5, 0x3D, 0x95, 0xA5, 0x9A, 0xE5, 0x76, 0x04, 0xC8, 0xB3, 0x85, 0xD2, 0x69, 0x16,
    0x48, 0x3F, 0xB9, 0x94, 0xBF, 0x70, 0xCB, 0x93, 0xB4, 0x14, 0x2A, 0x38, 0x9C, 0x19, 0xEF, 0x21, 0x3A, 0x41, 0x5F, 0xF6, 0x81,
    0xFA, 0x68, 0x27, 0x79, 0x59, 0xEE, 0x07, 0x71, 0xFD, 0xA0, 0xAF, 0xA2, 0x85, 0x46, 0x7A, 0x9D, 0x25, 0x32,
};

template <size_t N>
void check_known_answer(std::string_view plaintext, std::array<uint8_t, N> const& expected)
{
    auto const sk = p256_ecdsa_keypair_from_seed(kat_seed);
    auto const pt = span<uint8_t const>(reinterpret_cast<uint8_t const*>(plaintext.data()), plaintext.size());
    std::array<uint8_t, N> ct{};
    EXPECT_TRUE(span_compare(ecies_encrypt(sk.public_key, pt, ct, kat_entropy), span<uint8_t const>(expected)));
    std::array<uint8_t, N> recovered{};
    EXPECT_TRUE(span_compare(ecies_decrypt(sk, expected, recovered), pt));
}

}  // namespace

TEST(ecies, known_answer_two_blocks)
{
    check_known_answer("Hello, DL/ECIES!", kat_hello);
}

TEST(ecies, known_answer_one_block)
{
    check_known_answer("test data", kat_short);
}

TEST_MAIN(statusbar_crypto_ecies, ecies_test)
