// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// DL/ECIES encrypt/decrypt tests

#include "statusbar/crypto/ecies/ecies.hpp"

#include "statusbar/crypto/p256/p256_ecdsa.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <cstring>
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

TEST_MAIN(statusbar_crypto_ecies, ecies_test)
