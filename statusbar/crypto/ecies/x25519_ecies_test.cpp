// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 ECIES encrypt/decrypt tests

#include "statusbar/crypto/ecies/x25519_ecies.hpp"

#include "statusbar/crypto/25519/x25519.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstring>
#include <string_view>
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

//
// Known-answer tests
//
// Vectors generated by an independent Python reference (X25519, HKDF-SHA-256 with info "X25519-ECIES" || V,
// AES-256-CBC-IV0, HMAC-SHA-256 over C || I2OSP(0, 8))
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
constexpr std::array<uint8_t, 96> kat_hello{
    0x11, 0x13, 0xF6, 0x37, 0x6E, 0x2A, 0xE2, 0x21, 0x35, 0xBB, 0x91, 0xA6, 0x34, 0xC2, 0xEE, 0x6C, 0xE2, 0xA5, 0x45, 0x76,
    0x6C, 0xBA, 0x69, 0xE2, 0x56, 0x42, 0x02, 0x27, 0x52, 0x78, 0x22, 0x67, 0x03, 0x2F, 0xD2, 0x46, 0x9A, 0xB2, 0xB8, 0x9C,
    0x47, 0x6F, 0x15, 0xE9, 0x3B, 0x3E, 0xEE, 0x7B, 0xB3, 0xAE, 0x8E, 0x62, 0x3C, 0x9D, 0x1C, 0x32, 0x0A, 0x36, 0x92, 0x28,
    0xA2, 0x56, 0x6A, 0x76, 0x5B, 0x55, 0xA5, 0x8E, 0x71, 0xC2, 0x47, 0xF1, 0x0E, 0x8C, 0xCC, 0x31, 0x58, 0x0E, 0xBC, 0x26,
    0xE2, 0x22, 0x36, 0xB2, 0xAC, 0xE9, 0x94, 0x9E, 0x83, 0x0C, 0xA9, 0x6A, 0xC7, 0xBB, 0xEB, 0xFE,
};

// "test data" (9 bytes -> one AES block)
constexpr std::array<uint8_t, 80> kat_short{
    0x11, 0x13, 0xF6, 0x37, 0x6E, 0x2A, 0xE2, 0x21, 0x35, 0xBB, 0x91, 0xA6, 0x34, 0xC2, 0xEE, 0x6C, 0xE2, 0xA5, 0x45, 0x76,
    0x6C, 0xBA, 0x69, 0xE2, 0x56, 0x42, 0x02, 0x27, 0x52, 0x78, 0x22, 0x67, 0x73, 0x7D, 0x06, 0x63, 0x08, 0x21, 0x0D, 0xBC,
    0x97, 0x51, 0xB4, 0x9B, 0x7D, 0x34, 0x1C, 0xFB, 0x01, 0xBC, 0xE7, 0xA5, 0xEB, 0xA0, 0x6C, 0x48, 0x8B, 0x40, 0xC9, 0x58,
    0xEF, 0xD7, 0x41, 0xFB, 0xED, 0xB3, 0x0E, 0x82, 0xBB, 0x93, 0x7C, 0x17, 0xA9, 0x5D, 0x96, 0x0E, 0x72, 0xE0, 0x50, 0x5A,
};

template <size_t N>
void check_known_answer(std::string_view plaintext, std::array<uint8_t, N> const& expected)
{
    auto const sk = x25519_keypair_from_seed(kat_seed);
    auto const pt = span<uint8_t const>(reinterpret_cast<uint8_t const*>(plaintext.data()), plaintext.size());
    std::array<uint8_t, N> ct{};
    EXPECT_TRUE(span_compare(x25519_ecies_encrypt(sk.public_key, pt, ct, kat_entropy), span<uint8_t const>(expected)));
    std::array<uint8_t, N> recovered{};
    EXPECT_TRUE(span_compare(x25519_ecies_decrypt(sk, expected, recovered), pt));
}

}  // namespace

TEST(x25519_ecies, known_answer_two_blocks)
{
    check_known_answer("Hello, DL/ECIES!", kat_hello);
}

TEST(x25519_ecies, known_answer_one_block)
{
    check_known_answer("test data", kat_short);
}

TEST_MAIN(statusbar_crypto_ecies, x25519_ecies_test)
