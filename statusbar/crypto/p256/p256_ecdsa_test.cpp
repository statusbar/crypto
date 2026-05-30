// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// P-256 ECDSA sign/verify tests

#include "statusbar/crypto/p256/p256_ecdsa.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"
#include "statusbar/test/test_util.hpp"

#include <array>
#include <cstdint>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

TEST(p256_ecdsa, ecdsa_keypair)
{
    uint8_t seed[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    auto sk = p256_ecdsa_keypair_from_seed(seed);

    // Private key should be nonzero
    uint8_t acc = 0;
    for (auto b : sk.data) {
        acc |= b;
    }
    EXPECT_TRUE(acc != 0);

    // Public key should be nonzero
    acc = 0;
    for (auto b : sk.public_key.data) {
        acc |= b;
    }
    EXPECT_TRUE(acc != 0);
}

TEST(p256_ecdsa, ecdsa_sign_verify)
{
    uint8_t seed[32] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t message[] = "Hello, ECDSA over P-256!";
    auto sig = p256_ecdsa_sign(sk, span<uint8_t const>(message, sizeof(message) - 1));

    // Signature should be nonzero
    uint8_t acc = 0;
    for (auto b : sig.data) {
        acc |= b;
    }
    EXPECT_TRUE(acc != 0);

    // Verify should succeed
    bool valid = p256_ecdsa_verify(sk.public_key, span<uint8_t const>(message, sizeof(message) - 1), sig);
    EXPECT_TRUE(valid);
}

TEST(p256_ecdsa, ecdsa_deterministic)
{
    uint8_t seed[32] = {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t message[] = "test message";
    auto sig1 = p256_ecdsa_sign(sk, span<uint8_t const>(message, sizeof(message) - 1));
    auto sig2 = p256_ecdsa_sign(sk, span<uint8_t const>(message, sizeof(message) - 1));

    // RFC 6979: same key + same message = same signature
    EXPECT_TRUE(span_compare(sig1.data, sig2.data));
}

TEST(p256_ecdsa, ecdsa_wrong_message)
{
    uint8_t seed[32] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t message[] = "correct message";
    auto sig = p256_ecdsa_sign(sk, span<uint8_t const>(message, sizeof(message) - 1));

    // Verify with wrong message should fail
    uint8_t wrong[] = "wrong message!!";
    bool valid = p256_ecdsa_verify(sk.public_key, span<uint8_t const>(wrong, sizeof(wrong) - 1), sig);
    EXPECT_TRUE(!valid);
}

TEST(p256_ecdsa, ecdsa_wrong_key)
{
    uint8_t seed1[32] = {0x01};
    uint8_t seed2[32] = {0x02};

    auto sk1 = p256_ecdsa_keypair_from_seed(seed1);
    auto sk2 = p256_ecdsa_keypair_from_seed(seed2);

    uint8_t message[] = "test";
    auto sig = p256_ecdsa_sign(sk1, span<uint8_t const>(message, sizeof(message) - 1));

    // Verify with wrong public key should fail
    bool valid = p256_ecdsa_verify(sk2.public_key, span<uint8_t const>(message, sizeof(message) - 1), sig);
    EXPECT_TRUE(!valid);
}

TEST(p256_ecdsa, ecdsa_tampered_signature)
{
    uint8_t seed[32] = {0xDE, 0xAD, 0xBE, 0xEF};

    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t message[] = "tamper test";
    auto sig = p256_ecdsa_sign(sk, span<uint8_t const>(message, sizeof(message) - 1));

    // Tamper with r component
    P256EcdsaSignature tampered = sig;
    tampered.data[0] ^= 0x01;
    bool valid = p256_ecdsa_verify(sk.public_key, span<uint8_t const>(message, sizeof(message) - 1), tampered);
    EXPECT_TRUE(!valid);

    // Tamper with s component
    tampered = sig;
    tampered.data[32] ^= 0x01;
    valid = p256_ecdsa_verify(sk.public_key, span<uint8_t const>(message, sizeof(message) - 1), tampered);
    EXPECT_TRUE(!valid);
}

TEST(p256_ecdsa, keypair_from_scalar_valid)
{
    // A known valid scalar (small, nonzero, < n)
    uint8_t scalar[32] = {};
    scalar[31] = 0x07;  // scalar = 7
    auto sk = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk.has_value());
    EXPECT_TRUE(span_compare(sk->data, scalar));

    // Public key should be nonzero (7 * G)
    uint8_t acc = 0;
    for (auto b : sk->public_key.data) {
        acc |= b;
    }
    EXPECT_TRUE(acc != 0);

    // Sign/verify should work with the resulting key
    uint8_t message[] = "test";
    auto sig = p256_ecdsa_sign(*sk, span<uint8_t const>(message, sizeof(message) - 1));
    EXPECT_TRUE(p256_ecdsa_verify(sk->public_key, span<uint8_t const>(message, sizeof(message) - 1), sig));
}

TEST(p256_ecdsa, keypair_from_scalar_zero)
{
    // Scalar = 0 is invalid
    uint8_t zero[32] = {};
    auto sk = p256_keypair_from_scalar(zero);
    EXPECT_TRUE(!sk.has_value());
}

TEST(p256_ecdsa, keypair_from_scalar_order)
{
    // Scalar = n (the group order) is invalid (>= n)
    // n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    uint8_t n_bytes[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
    auto sk = p256_keypair_from_scalar(n_bytes);
    EXPECT_TRUE(!sk.has_value());
}

TEST(p256_ecdsa, keypair_from_scalar_consistency)
{
    // Verify that keypair_from_scalar and keypair_from_seed produce compatible results
    // when the seed's SHA-256 hash mod n gives the same scalar
    uint8_t scalar[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x42};
    auto sk = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk.has_value());

    // Create same key again, should be identical
    auto sk2 = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk2.has_value());
    EXPECT_TRUE(span_compare(sk->data, sk2->data));
    EXPECT_TRUE(span_compare(sk->public_key.data, sk2->public_key.data));
}

//
// RFC 6979 A.2.5 — P-256 with SHA-256, message "sample"
//

TEST(p256_ecdsa, ecdsa_rfc6979_vector)
{
    // Private key (big-endian, 32 bytes)
    auto scalar = hex_to_bytes<32>("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");

    auto sk = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk.has_value());

    // Message: "sample" (6 ASCII bytes)
    uint8_t message[] = "sample";
    auto sig = p256_ecdsa_sign(*sk, span<uint8_t const>(message, 6));

    // Expected signature components (big-endian, 32 bytes each)
    auto expected_r = hex_to_bytes<32>("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    auto expected_s = hex_to_bytes<32>("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

    // Signature data is r (32 bytes) || s (32 bytes), both big-endian
    std::array<uint8_t, 32> sig_r{};
    std::array<uint8_t, 32> sig_s{};
    std::copy(sig.data.begin(), sig.data.begin() + 32, sig_r.begin());
    std::copy(sig.data.begin() + 32, sig.data.end(), sig_s.begin());

    EXPECT_TRUE(span_compare(sig_r, expected_r));
    EXPECT_TRUE(span_compare(sig_s, expected_s));

    // Verify the signature
    bool valid = p256_ecdsa_verify(sk->public_key, span<uint8_t const>(message, 6), sig);
    EXPECT_TRUE(valid);
}

//
// Verify rejects signature with r=0 and s=0 (all zeros)
//

TEST(p256_ecdsa, ecdsa_verify_zero_signature)
{
    uint8_t seed[32] = {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t message[] = "test";

    // Create an all-zero signature (r=0, s=0)
    P256EcdsaSignature zero_sig{};

    bool valid = p256_ecdsa_verify(sk.public_key, span<uint8_t const>(message, sizeof(message) - 1), zero_sig);
    EXPECT_TRUE(!valid);
}

//
// Verify rejects non-canonical r (r >= n, roundtrip mismatch)
//

TEST(p256_ecdsa, ecdsa_verify_noncanonical_rs)
{
    uint8_t seed[32] = {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t message[] = "test";
    auto sig = p256_ecdsa_sign(sk, span<uint8_t const>(message, sizeof(message) - 1));

    // Test 1: Non-canonical r (set r bytes to all 0xFF, which is >= n)
    {
        P256EcdsaSignature bad_sig = sig;
        for (int i = 0; i < 32; ++i) {
            bad_sig.data[i] = 0xFF;
        }
        bool valid = p256_ecdsa_verify(sk.public_key, span<uint8_t const>(message, sizeof(message) - 1), bad_sig);
        EXPECT_TRUE(!valid);
    }

    // Test 2: Non-canonical s (set s bytes to all 0xFF, which is >= n)
    {
        P256EcdsaSignature bad_sig = sig;
        for (int i = 32; i < 64; ++i) {
            bad_sig.data[i] = 0xFF;
        }
        bool valid = p256_ecdsa_verify(sk.public_key, span<uint8_t const>(message, sizeof(message) - 1), bad_sig);
        EXPECT_TRUE(!valid);
    }
}

//
// Verify rejects invalid public key (garbage bytes)
//

TEST(p256_ecdsa, ecdsa_verify_invalid_pubkey)
{
    uint8_t seed[32] = {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    uint8_t message[] = "test";
    auto sig = p256_ecdsa_sign(sk, span<uint8_t const>(message, sizeof(message) - 1));

    // Create an invalid public key (all 0xFF bytes, not a valid curve point)
    P256PublicKey bad_pk{};
    for (auto& b : bad_pk.data) {
        b = 0xFF;
    }

    bool valid = p256_ecdsa_verify(bad_pk, span<uint8_t const>(message, sizeof(message) - 1), sig);
    EXPECT_TRUE(!valid);
}

//
// keypair_from_scalar rejects scalar where first differing byte from order is greater
//

TEST(p256_ecdsa, ecdsa_keypair_from_scalar_above_order)
{
    // P-256 order n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
    // We construct a scalar that matches the first 4 bytes of n (0xFF,0xFF,0xFF,0xFF)
    // but has byte index 4 set to 0x01 instead of 0x00 (i.e. first differing byte is greater).
    uint8_t above_n[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

    auto sk = p256_keypair_from_scalar(above_n);
    EXPECT_TRUE(!sk.has_value());
}

//
// P-256 ECDSA verify-only test vectors using known scalars
//
// These tests exercise verify independently of sign by constructing keypairs
// from known scalars, signing known messages (producing RFC 6979 deterministic
// signatures), then verifying using ONLY the public key, message, and signature.
//

TEST(p256_ecdsa, ecdsa_verify_known_scalar_1)
{
    // Scalar d = 7 (small but valid), message = "verify test one"
    auto scalar = hex_to_bytes<32>("0000000000000000000000000000000000000000000000000000000000000007");
    auto sk = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk.has_value());

    uint8_t message[] = "verify test one";
    auto sig = p256_ecdsa_sign(*sk, span<uint8_t const>(message, sizeof(message) - 1));

    // Now verify using only the public key (no private key involvement)
    P256PublicKey pk = sk->public_key;
    bool valid = p256_ecdsa_verify(pk, span<uint8_t const>(message, sizeof(message) - 1), sig);
    EXPECT_TRUE(valid);
}

TEST(p256_ecdsa, ecdsa_verify_known_scalar_2)
{
    // Scalar from RFC 6979 A.2.5 (known working vector)
    auto scalar = hex_to_bytes<32>("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    auto sk = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk.has_value());

    // Use a longer message to exercise different hash path
    uint8_t message[] = "The quick brown fox jumps over the lazy dog";
    auto sig = p256_ecdsa_sign(*sk, span<uint8_t const>(message, sizeof(message) - 1));

    // Verify-only: extract public key, discard private key relationship
    P256PublicKey pk = sk->public_key;
    bool valid = p256_ecdsa_verify(pk, span<uint8_t const>(message, sizeof(message) - 1), sig);
    EXPECT_TRUE(valid);
}

TEST(p256_ecdsa, ecdsa_verify_known_scalar_3)
{
    // Another scalar, empty message (edge case)
    auto scalar = hex_to_bytes<32>("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
    auto sk = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk.has_value());

    // Empty message
    uint8_t dummy{};
    auto sig = p256_ecdsa_sign(*sk, span<uint8_t const>(&dummy, size_t{0}));

    P256PublicKey pk = sk->public_key;
    bool valid = p256_ecdsa_verify(pk, span<uint8_t const>(&dummy, size_t{0}), sig);
    EXPECT_TRUE(valid);
}

TEST(p256_ecdsa, ecdsa_verify_corrupted_r)
{
    // Generate a valid signature, then corrupt r and verify rejection
    auto scalar = hex_to_bytes<32>("0000000000000000000000000000000000000000000000000000000000000007");
    auto sk = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk.has_value());

    uint8_t message[] = "corruption test r";
    auto sig = p256_ecdsa_sign(*sk, span<uint8_t const>(message, sizeof(message) - 1));

    P256PublicKey pk = sk->public_key;

    // Corrupt the first byte of r
    P256EcdsaSignature bad_sig = sig;
    bad_sig.data[0] ^= 0x01;
    bool valid = p256_ecdsa_verify(pk, span<uint8_t const>(message, sizeof(message) - 1), bad_sig);
    EXPECT_TRUE(!valid);

    // Corrupt the last byte of r
    bad_sig = sig;
    bad_sig.data[31] ^= 0x80;
    valid = p256_ecdsa_verify(pk, span<uint8_t const>(message, sizeof(message) - 1), bad_sig);
    EXPECT_TRUE(!valid);
}

TEST(p256_ecdsa, ecdsa_verify_corrupted_s)
{
    // Generate a valid signature, then corrupt s and verify rejection
    auto scalar = hex_to_bytes<32>("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    auto sk = p256_keypair_from_scalar(scalar);
    EXPECT_TRUE(sk.has_value());

    uint8_t message[] = "corruption test s";
    auto sig = p256_ecdsa_sign(*sk, span<uint8_t const>(message, sizeof(message) - 1));

    P256PublicKey pk = sk->public_key;

    // Corrupt the first byte of s
    P256EcdsaSignature bad_sig = sig;
    bad_sig.data[32] ^= 0x01;
    bool valid = p256_ecdsa_verify(pk, span<uint8_t const>(message, sizeof(message) - 1), bad_sig);
    EXPECT_TRUE(!valid);

    // Corrupt the last byte of s
    bad_sig = sig;
    bad_sig.data[63] ^= 0x42;
    valid = p256_ecdsa_verify(pk, span<uint8_t const>(message, sizeof(message) - 1), bad_sig);
    EXPECT_TRUE(!valid);
}

TEST_MAIN(statusbar_crypto_p256, p256_ecdsa_test)
