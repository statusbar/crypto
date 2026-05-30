// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - RFC 7748 Section 6.1: https://www.rfc-editor.org/rfc/rfc7748#section-6.1

#include "statusbar/crypto/25519/x25519.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"
#include "statusbar/test/test_util.hpp"

#include <array>
#include <cstdint>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;

//
// RFC 7748 Section 6.1 — Alice and Bob ECDH key agreement
//

TEST(x25519, alice_bob)
{
    // Alice's private key (seed)
    auto alice_seed = hex_to_bytes<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

    // Alice's expected public key
    auto alice_expected_pk = hex_to_bytes<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

    // Bob's private key (seed)
    auto bob_seed = hex_to_bytes<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    // Bob's expected public key
    auto bob_expected_pk = hex_to_bytes<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    // Expected shared secret
    auto expected_shared = hex_to_bytes<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    // Generate keypairs
    auto alice_sk = x25519_keypair_from_seed(alice_seed);
    auto bob_sk = x25519_keypair_from_seed(bob_seed);

    // Verify public keys
    EXPECT_TRUE(span_compare(alice_sk.public_key.data, alice_expected_pk));
    EXPECT_TRUE(span_compare(bob_sk.public_key.data, bob_expected_pk));

    // Compute shared secrets from both sides
    auto shared_ab = x25519(alice_sk, bob_sk.public_key);
    auto shared_ba = x25519(bob_sk, alice_sk.public_key);

    // Verify shared secret matches expected value
    EXPECT_TRUE(span_compare(shared_ab, expected_shared));
    EXPECT_TRUE(span_compare(shared_ba, expected_shared));

    // Verify commutativity: X25519(a, B) == X25519(b, A)
    EXPECT_TRUE(span_compare(shared_ab, shared_ba));
}

//
// x25519_shared_secret_is_valid — zero and non-zero checks
//

TEST(x25519, zero_check)
{
    // All-zero shared secret should be rejected (low-order point)
    std::array<uint8_t, 32> zero{};
    EXPECT_TRUE(!x25519_shared_secret_is_valid(zero));

    // Non-zero shared secret should be accepted
    std::array<uint8_t, 32> nonzero{};
    nonzero[0] = 1;
    EXPECT_TRUE(x25519_shared_secret_is_valid(nonzero));

    // Single non-zero byte at the end
    std::array<uint8_t, 32> tail_nonzero{};
    tail_nonzero[31] = 0x42;
    EXPECT_TRUE(x25519_shared_secret_is_valid(tail_nonzero));
}

//
// RFC 7748 Section 6.1 — Basepoint iteration (1 iteration)
// Start with k = u = 9, compute k_new = X25519(k, u)
// After 1 iteration: 422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
//

TEST(x25519, basepoint_iter)
{
    // k = 9 as a seed, u = 9 as a public key
    std::array<uint8_t, 32> seed{};
    seed[0] = 9;

    auto expected = hex_to_bytes<32>("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

    // Generate keypair from seed=9 and verify the public key matches
    // the 1-iteration result (since public_key = X25519(seed, basepoint_9))
    auto sk = x25519_keypair_from_seed(seed);
    EXPECT_TRUE(span_compare(sk.public_key.data, expected));
}

//

TEST_MAIN(statusbar_crypto_25519, x25519_test)
