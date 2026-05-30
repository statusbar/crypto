// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// P-256 ECDH tests

#include "statusbar/crypto/p256/p256_ecdh.hpp"

#include "statusbar/crypto/p256/p256_ecdsa.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"
#include "statusbar/test/test_util.hpp"

#include <array>
#include <cstdint>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using statusbar::crypto::internal::span_copy;

TEST(p256_ecdh, ecdh_basic)
{
    // Alice and Bob generate keypairs
    uint8_t seed_a[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                          0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    uint8_t seed_b[32] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    auto sk_a = p256_ecdsa_keypair_from_seed(seed_a);
    auto sk_b = p256_ecdsa_keypair_from_seed(seed_b);

    // Alice computes shared secret with Bob's public key
    auto shared_ab = p256_ecdh(sk_a, sk_b.public_key);

    // Bob computes shared secret with Alice's public key
    auto shared_ba = p256_ecdh(sk_b, sk_a.public_key);

    // Both should arrive at the same shared secret
    EXPECT_TRUE(span_compare(shared_ab, shared_ba));

    // Shared secret should be nonzero
    uint8_t acc = 0;
    for (auto b : shared_ab) {
        acc |= b;
    }
    EXPECT_TRUE(acc != 0);
}

TEST(p256_ecdh, ecdh_different_keys)
{
    uint8_t seed_a[32] = {0x01};
    uint8_t seed_b[32] = {0x02};
    uint8_t seed_c[32] = {0x03};

    auto sk_a = p256_ecdsa_keypair_from_seed(seed_a);
    auto sk_b = p256_ecdsa_keypair_from_seed(seed_b);
    auto sk_c = p256_ecdsa_keypair_from_seed(seed_c);

    auto shared_ab = p256_ecdh(sk_a, sk_b.public_key);
    auto shared_ac = p256_ecdh(sk_a, sk_c.public_key);

    // Different peers should give different shared secrets
    EXPECT_TRUE(!span_compare(shared_ab, shared_ac));
}

TEST(p256_ecdh, ecdh_invalid_public_key)
{
    uint8_t seed[32] = {0x01};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    // All-zeros public key (not a valid point)
    P256PublicKey bad_pk{};
    auto result = p256_ecdh(sk, bad_pk);

    // Should return all-zeros (failure)
    uint8_t acc = 0;
    for (auto b : result) {
        acc |= b;
    }
    EXPECT_TRUE(acc == 0);
}

TEST(p256_ecdh, ecdh_garbage_public_key)
{
    uint8_t seed[32] = {0x42};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    // Random garbage that's almost certainly not on the curve
    P256PublicKey garbage_pk{};
    for (size_t i = 0; i < 64; ++i) {
        garbage_pk.data[i] = static_cast<uint8_t>(i + 0xDE);
    }
    auto result = p256_ecdh(sk, garbage_pk);

    // Should return all-zeros (invalid point)
    uint8_t acc = 0;
    for (auto b : result) {
        acc |= b;
    }
    EXPECT_TRUE(acc == 0);
}

TEST(p256_ecdh, ecdh_zero_private_key)
{
    uint8_t seed[32] = {0x01};
    auto peer = p256_ecdsa_keypair_from_seed(seed);

    // Construct a private key with zero scalar
    P256PrivateKey zero_sk{};
    auto result = p256_ecdh(zero_sk, peer.public_key);

    // Should return all-zeros (zero scalar rejected)
    uint8_t acc = 0;
    for (auto b : result) {
        acc |= b;
    }
    EXPECT_TRUE(acc == 0);
}

TEST(p256_ecdh, invalid_peer)
{
    // Generate a valid private key
    uint8_t seed[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    auto sk = p256_ecdsa_keypair_from_seed(seed);

    // Create an invalid peer public key: use a valid x-coordinate but corrupt y
    // so the point is NOT on the curve
    P256PublicKey bad_pk{};
    // Copy x from a valid key, then corrupt y
    span_copy(std::span<uint8_t, 32>(bad_pk.data.data(), 32), std::span<uint8_t const, 32>(sk.public_key.data.data(), 32));
    // Set y to all 0x01 (almost certainly not on curve)
    for (size_t i = 32; i < 64; ++i) {
        bad_pk.data[i] = 0x01;
    }

    auto result = p256_ecdh(sk, bad_pk);
    // All-zero result means failure
    uint8_t acc = 0;
    for (auto b : result) {
        acc |= b;
    }
    EXPECT_TRUE(acc == 0);
}

//
// NIST SP 800-56A ECDH test vector
// Source: NIST Cryptographic Algorithm Validation Program (CAVP) ECC CDH
//

TEST(p256_ecdh, ecdh_nist_vector)
{
    // NIST SP 800-56A / CAVP ECC CDH P-256 test vector
    // dIUT (local private key scalar)
    auto d_bytes = hex_to_bytes<32>("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");

    // QsX, QsY (peer public key)
    auto peer_x = hex_to_bytes<32>("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287");
    auto peer_y = hex_to_bytes<32>("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");

    // ZIUT (expected shared secret, x-coordinate of d * Q)
    auto expected_shared = hex_to_bytes<32>("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");

    // Construct private key from scalar
    auto sk = p256_keypair_from_scalar(d_bytes);
    EXPECT_TRUE(sk.has_value());

    // Construct peer public key
    P256PublicKey peer_pk{};
    std::copy(peer_x.begin(), peer_x.end(), peer_pk.data.begin());
    std::copy(peer_y.begin(), peer_y.end(), peer_pk.data.begin() + 32);

    // Compute shared secret
    auto shared = p256_ecdh(*sk, peer_pk);

    // Verify it matches the expected value
    EXPECT_TRUE(span_compare(shared, expected_shared));
}

TEST_MAIN(statusbar_crypto_p256, p256_ecdh_test)
