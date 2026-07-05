// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-256-CBC-IV0 tests

#include "statusbar/crypto/aes_cbc/aes_cbc.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <cstring>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

TEST(aes_cbc, roundtrip)
{
    Aes256Key key{};
    for (int i = 0; i < 32; ++i) {
        key.data[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    }

    uint8_t plaintext[] = "Hello, AES-CBC-IV0!";
    size_t pt_len = sizeof(plaintext) - 1;

    size_t ct_len = aes_cbc_iv0_ciphertext_size(pt_len);
    std::array<uint8_t, 64> ciphertext{};
    std::array<uint8_t, 64> decrypted{};

    auto enc_result = aes256_cbc_iv0_encrypt(key, {plaintext, pt_len}, ciphertext);
    EXPECT_TRUE(enc_result.size() == ct_len);
    EXPECT_TRUE(enc_result.size() == 32);

    auto dec_result = aes256_cbc_iv0_decrypt(key, enc_result, decrypted);
    EXPECT_TRUE(dec_result.size() == pt_len);
    EXPECT_TRUE(span_compare(dec_result, span<uint8_t const>(plaintext, pt_len)));
}

TEST(aes_cbc, block_aligned)
{
    Aes256Key key{};
    for (int i = 0; i < 32; ++i) {
        key.data[static_cast<size_t>(i)] = static_cast<uint8_t>(0xAA);
    }

    // 16 bytes = exactly one block, should add a full padding block
    uint8_t plaintext[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    size_t ct_len = aes_cbc_iv0_ciphertext_size(16);
    EXPECT_TRUE(ct_len == 32);

    std::array<uint8_t, 32> ciphertext{};
    std::array<uint8_t, 32> decrypted{};

    aes256_cbc_iv0_encrypt(key, plaintext, ciphertext);
    auto dec_result = aes256_cbc_iv0_decrypt(key, ciphertext, decrypted);

    EXPECT_TRUE(dec_result.size() == 16);
    EXPECT_TRUE(span_compare(dec_result, span<uint8_t const>(plaintext, 16)));
}

TEST(aes_cbc, single_byte)
{
    Aes256Key key{};
    key.data[0] = 0x42;

    uint8_t plaintext[] = {0xFF};
    size_t ct_len = aes_cbc_iv0_ciphertext_size(1);
    EXPECT_TRUE(ct_len == 16);

    std::array<uint8_t, 16> ciphertext{};
    std::array<uint8_t, 16> decrypted{};

    aes256_cbc_iv0_encrypt(key, plaintext, ciphertext);
    auto dec_result = aes256_cbc_iv0_decrypt(key, ciphertext, decrypted);

    EXPECT_TRUE(dec_result.size() == 1);
    EXPECT_TRUE(dec_result[0] == 0xFF);
}

TEST(aes_cbc, wrong_key)
{
    Aes256Key key1{};
    Aes256Key key2{};
    key1.data[0] = 0x01;
    key2.data[0] = 0x02;

    uint8_t plaintext[] = "secret data";

    std::array<uint8_t, 32> ciphertext{};
    std::array<uint8_t, 32> decrypted{};

    aes256_cbc_iv0_encrypt(key1, {plaintext, 11}, ciphertext);
    auto dec_result = aes256_cbc_iv0_decrypt(key2, {ciphertext.data(), 16}, decrypted);

    // Wrong key should produce invalid padding -> return empty span
    EXPECT_TRUE(
        dec_result.empty() ||
        !span_compare(dec_result.first(std::min(dec_result.size(), size_t(11))), span<uint8_t const>(plaintext, 11)));
}

TEST(aes_cbc, invalid_ciphertext)
{
    Aes256Key key{};
    key.data[0] = 0x42;

    // Invalid: not a multiple of 16
    std::array<uint8_t, 17> bad_ct{};
    std::array<uint8_t, 32> decrypted{};

    auto dec_result = aes256_cbc_iv0_decrypt(key, bad_ct, decrypted);
    EXPECT_TRUE(dec_result.empty());

    // Invalid: empty
    auto dec_result2 = aes256_cbc_iv0_decrypt(key, {}, decrypted);
    EXPECT_TRUE(dec_result2.empty());
}

// Regression: padding verification must reject a padding byte that differs
// from pad_val in a HIGH bit, not only in bit 0. A one-block plaintext pads to
// a full 0x10 block; flipping bit 4 of ciphertext block 0 flips bit 4 of the
// decrypted block-1 padding byte at the same offset (CBC malleability),
// turning a 0x10 padding byte into 0x00 while leaving pad_val (the last byte)
// intact. The old bit-0-only mask accepted this; correct verification rejects.
TEST(aes_cbc, rejects_high_bit_corrupted_padding)
{
    Aes256Key key{};
    for (int i = 0; i < 32; ++i) {
        key.data[static_cast<size_t>(i)] = static_cast<uint8_t>(i * 3 + 1);
    }

    std::array<uint8_t, 16> plaintext{};
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(0xA0 + i);
    }

    std::array<uint8_t, 32> ciphertext{};  // 16 data + 16 pad(0x10) block
    std::array<uint8_t, 32> decrypted{};
    aes256_cbc_iv0_encrypt(key, plaintext, ciphertext);

    // Sanity: unmodified ciphertext round-trips.
    auto ok = aes256_cbc_iv0_decrypt(key, ciphertext, decrypted);
    EXPECT_TRUE(ok.size() == 16);

    // Flip bit 4 of ciphertext[5] (block 0) -> flips bit 4 of padding byte 5
    // of the decrypted block-1 padding (0x10 -> 0x00). Last byte (pad_val)
    // untouched, so the [1,16] range check still passes; only the per-byte
    // content check can catch it.
    ciphertext[5] ^= 0x10;
    auto bad = aes256_cbc_iv0_decrypt(key, ciphertext, decrypted);
    EXPECT_TRUE(bad.empty());
}

TEST(aes_cbc, encrypt_buffer_validation)
{
    Aes256Key key{};
    for (int i = 0; i < 32; ++i) {
        key.data[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    }

    // 19 bytes of plaintext requires 32 bytes of ciphertext (with PKCS#7 padding)
    uint8_t plaintext[] = "Hello, AES-CBC-IV0!";
    size_t pt_len = sizeof(plaintext) - 1;  // 19 bytes
    size_t required_ct_len = aes_cbc_iv0_ciphertext_size(pt_len);
    EXPECT_TRUE(required_ct_len == 32);

    // Too-small buffer: only 16 bytes, but 32 needed
    std::array<uint8_t, 16> small_buf{};
    auto enc_result = aes256_cbc_iv0_encrypt(key, {plaintext, pt_len}, small_buf);
    EXPECT_TRUE(enc_result.empty());

    // Exactly-right-sized buffer: 32 bytes
    std::array<uint8_t, 32> exact_buf{};
    auto enc_result2 = aes256_cbc_iv0_encrypt(key, {plaintext, pt_len}, exact_buf);
    EXPECT_TRUE(enc_result2.size() == 32);

    // Verify roundtrip with exact buffer
    std::array<uint8_t, 32> decrypted{};
    auto dec_result = aes256_cbc_iv0_decrypt(key, enc_result2, decrypted);
    EXPECT_TRUE(dec_result.size() == pt_len);
    EXPECT_TRUE(span_compare(dec_result, span<uint8_t const>(plaintext, pt_len)));
}

TEST(aes_cbc, empty_plaintext)
{
    Aes256Key key{};
    for (int i = 0; i < 32; ++i) {
        key.data[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    }

    // 0-byte plaintext should produce exactly 16 bytes (one PKCS#7 padding block of 0x10)
    size_t ct_len = aes_cbc_iv0_ciphertext_size(0);
    EXPECT_TRUE(ct_len == 16);

    std::array<uint8_t, 16> ciphertext{};
    auto enc_result = aes256_cbc_iv0_encrypt(key, {}, ciphertext);
    EXPECT_TRUE(enc_result.size() == 16);

    // Decrypting those 16 bytes should produce 0 bytes
    std::array<uint8_t, 16> decrypted{};
    auto dec_result = aes256_cbc_iv0_decrypt(key, enc_result, decrypted);
    EXPECT_TRUE(dec_result.empty());
}

TEST(aes_cbc, known_answer)
{
    // NIST-style known-answer test: AES-256-CBC-IV0
    // Key = all zeros (32 bytes of 0x00)
    // Plaintext = all zeros (16 bytes of 0x00)
    // Since IV=0, the first block is AES-256-ECB(0x00...00) with key=0x00...00
    // Known AES-256 ECB answer for zero key, zero plaintext:
    //   dc95c078a2408989ad48a21492842087
    Aes256Key key{};  // all zeros

    std::array<uint8_t, 16> plaintext{};  // all zeros, 16 bytes

    // With PKCS#7, 16 bytes of plaintext produces 32 bytes of ciphertext
    // (a full padding block of 0x10 is added)
    size_t ct_len = aes_cbc_iv0_ciphertext_size(16);
    EXPECT_TRUE(ct_len == 32);

    std::array<uint8_t, 32> ciphertext{};
    auto enc_result = aes256_cbc_iv0_encrypt(key, plaintext, ciphertext);
    EXPECT_TRUE(enc_result.size() == 32);

    // First 16 bytes of ciphertext should be AES-256(zero_block, zero_key)
    // = dc95c078a2408989ad48a21492842087
    uint8_t const expected_block0[] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87};
    EXPECT_TRUE(span_compare(enc_result.first(16), span<uint8_t const>(expected_block0, 16)));

    // Ciphertext must differ from plaintext (basic sanity)
    EXPECT_TRUE(!span_compare(enc_result.first(16), span<uint8_t const>(plaintext)));

    // Decrypt and verify roundtrip
    std::array<uint8_t, 32> decrypted{};
    auto dec_result = aes256_cbc_iv0_decrypt(key, enc_result, decrypted);
    EXPECT_TRUE(dec_result.size() == 16);
    EXPECT_TRUE(span_compare(dec_result, span<uint8_t const>(plaintext)));
}

TEST_MAIN(statusbar_crypto_aes_cbc, aes_cbc_test)
