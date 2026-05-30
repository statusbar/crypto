// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 ECIES encrypt/decrypt tests

#include "statusbar/crypto/ecies/x25519_ecies.hpp"

#include "statusbar/crypto/25519/x25519.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <cstring>
#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

TEST(x25519_ecies, roundtrip)
{
    // Generate recipient keypair
    uint8_t seed[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    auto sk = x25519_keypair_from_seed(seed);

    uint8_t plaintext[] = "Hello, X25519 ECIES!";
    size_t pt_len = sizeof(plaintext) - 1;

    // Ephemeral key entropy
    uint8_t entropy[32] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

    size_t out_len = x25519_ecies_output_size(pt_len);
    std::vector<uint8_t> ciphertext(out_len);
    std::vector<uint8_t> decrypted(pt_len + 16);  // Extra room for padding

    auto enc_result = x25519_ecies_encrypt(sk.public_key, {plaintext, pt_len}, ciphertext, entropy);
    EXPECT_TRUE(!enc_result.empty());
    EXPECT_TRUE(enc_result.size() == out_len);

    auto dec_result = x25519_ecies_decrypt(sk, enc_result, decrypted);
    EXPECT_TRUE(dec_result.size() == pt_len);
    EXPECT_TRUE(span_compare(dec_result, span<uint8_t const>(plaintext, pt_len)));
}

TEST(x25519_ecies, tamper_v)
{
    uint8_t seed[32] = {0xAA};
    auto sk = x25519_keypair_from_seed(seed);

    uint8_t plaintext[] = "test";
    uint8_t entropy[32] = {0xBB};

    size_t out_len = x25519_ecies_output_size(4);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    x25519_ecies_encrypt(sk.public_key, {plaintext, 4}, ct, entropy);

    // Tamper with V (ephemeral key)
    ct[1] ^= 0x01;
    auto dec_result = x25519_ecies_decrypt(sk, ct, pt);
    EXPECT_TRUE(dec_result.empty());
}

TEST(x25519_ecies, tamper_c)
{
    uint8_t seed[32] = {0xCC};
    auto sk = x25519_keypair_from_seed(seed);

    uint8_t plaintext[] = "test data";
    uint8_t entropy[32] = {0xDD};

    size_t out_len = x25519_ecies_output_size(9);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    x25519_ecies_encrypt(sk.public_key, {plaintext, 9}, ct, entropy);

    // Tamper with C (ciphertext body)
    ct[x25519_ecies_ephemeral_key_size] ^= 0x01;
    auto dec_result = x25519_ecies_decrypt(sk, ct, pt);
    EXPECT_TRUE(dec_result.empty());
}

TEST(x25519_ecies, tamper_t)
{
    uint8_t seed[32] = {0xEE};
    auto sk = x25519_keypair_from_seed(seed);

    uint8_t plaintext[] = "test";
    uint8_t entropy[32] = {0xFF};

    size_t out_len = x25519_ecies_output_size(4);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    x25519_ecies_encrypt(sk.public_key, {plaintext, 4}, ct, entropy);

    // Tamper with T (MAC tag, last 32 bytes)
    ct[out_len - 1] ^= 0x01;
    auto dec_result = x25519_ecies_decrypt(sk, ct, pt);
    EXPECT_TRUE(dec_result.empty());
}

TEST(x25519_ecies, wrong_key)
{
    uint8_t seed1[32] = {0x10, 0x01};
    uint8_t seed2[32] = {0x20, 0x02};
    auto sk1 = x25519_keypair_from_seed(seed1);
    auto sk2 = x25519_keypair_from_seed(seed2);

    uint8_t plaintext[] = "secret";
    uint8_t entropy[32] = {0x42};

    size_t out_len = x25519_ecies_output_size(6);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    x25519_ecies_encrypt(sk1.public_key, {plaintext, 6}, ct, entropy);

    // Try decrypting with wrong key
    auto dec_result = x25519_ecies_decrypt(sk2, ct, pt);
    EXPECT_TRUE(dec_result.empty());
}

TEST(x25519_ecies, encrypt_output_too_small)
{
    uint8_t seed[32] = {0x01};
    auto sk = x25519_keypair_from_seed(seed);
    uint8_t plaintext[] = "test";
    uint8_t entropy[32] = {0x42};

    // Output buffer is 1 byte too small
    size_t needed = x25519_ecies_output_size(4);
    std::vector<uint8_t> output(needed - 1);
    auto result = x25519_ecies_encrypt(sk.public_key, {plaintext, 4}, output, entropy);
    EXPECT_TRUE(result.empty());
}

TEST(x25519_ecies, decrypt_input_too_short)
{
    uint8_t seed[32] = {0x01};
    auto sk = x25519_keypair_from_seed(seed);

    // Input shorter than minimum (V=32 + C=16 + T=32 = 80)
    std::vector<uint8_t> short_input(79, 0);
    std::vector<uint8_t> pt(16);
    auto result = x25519_ecies_decrypt(sk, short_input, pt);
    EXPECT_TRUE(result.empty());
}

TEST(x25519_ecies, decrypt_unaligned_ciphertext)
{
    uint8_t seed[32] = {0x01};
    auto sk = x25519_keypair_from_seed(seed);

    // c_len = 81 - 64 = 17, not a multiple of 16
    std::vector<uint8_t> input(81, 0);
    std::vector<uint8_t> pt(32);
    auto result = x25519_ecies_decrypt(sk, input, pt);
    EXPECT_TRUE(result.empty());
}

TEST(x25519_ecies, empty_plaintext)
{
    uint8_t seed[32] = {0x55};
    auto sk = x25519_keypair_from_seed(seed);
    uint8_t entropy[32] = {0x66};

    // Empty plaintext: output = V(32) + C(16, one padding block) + T(32) = 80
    size_t out_len = x25519_ecies_output_size(0);
    EXPECT_TRUE(out_len == 80);

    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> pt(16);

    auto enc_result = x25519_ecies_encrypt(sk.public_key, {}, ct, entropy);
    EXPECT_TRUE(!enc_result.empty());
    EXPECT_TRUE(enc_result.size() == 80);

    auto dec_result = x25519_ecies_decrypt(sk, enc_result, pt);
    EXPECT_TRUE(dec_result.size() == 0);
}

TEST(x25519_ecies, large_plaintext)
{
    uint8_t seed[32] = {0x77};
    auto sk = x25519_keypair_from_seed(seed);
    uint8_t entropy[32] = {0x88};

    // 256-byte plaintext
    std::vector<uint8_t> plaintext(256);
    for (size_t i = 0; i < 256; ++i) {
        plaintext[i] = static_cast<uint8_t>(i);
    }

    size_t out_len = x25519_ecies_output_size(256);
    std::vector<uint8_t> ct(out_len);
    std::vector<uint8_t> dec(256 + 16);

    auto enc_result = x25519_ecies_encrypt(sk.public_key, plaintext, ct, entropy);
    EXPECT_TRUE(!enc_result.empty());

    auto dec_result = x25519_ecies_decrypt(sk, enc_result, dec);
    EXPECT_TRUE(dec_result.size() == 256);
    EXPECT_TRUE(span_compare(dec_result, span<uint8_t const>(plaintext)));
}

TEST(x25519_ecies, output_size_helper)
{
    // 0-byte plaintext: 64 + 16 (one padding block) = 80
    EXPECT_TRUE(x25519_ecies_output_size(0) == 80);
    // 1-byte plaintext: 64 + 16 = 80
    EXPECT_TRUE(x25519_ecies_output_size(1) == 80);
    // 15-byte plaintext: 64 + 16 = 80
    EXPECT_TRUE(x25519_ecies_output_size(15) == 80);
    // 16-byte plaintext: 64 + 32 = 96 (plaintext fills one block, padding adds another)
    EXPECT_TRUE(x25519_ecies_output_size(16) == 96);
    // 17-byte plaintext: 64 + 32 = 96
    EXPECT_TRUE(x25519_ecies_output_size(17) == 96);
    // 256-byte plaintext: 64 + 272 = 336
    EXPECT_TRUE(x25519_ecies_output_size(256) == 336);
}

TEST_MAIN(statusbar_crypto_ecies, x25519_ecies_test)
