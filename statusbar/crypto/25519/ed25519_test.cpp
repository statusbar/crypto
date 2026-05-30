// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - RFC 8032 Section 7.1: https://www.rfc-editor.org/rfc/rfc8032#section-7.1

#include "statusbar/crypto/25519/ed25519.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"
#include "statusbar/test/test_util.hpp"

#include <array>
#include <cstdint>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

//
// RFC 8032 Section 7.1 — Test Vector 1 (empty message)
//

TEST(ed25519, vector1)
{
    // Secret key (seed):
    // 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    uint8_t seed[] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };

    // Public key:
    // d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    uint8_t expected_pk[] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    };

    // Signature (over empty message):
    // e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
    // 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
    uint8_t expected_sig[] = {
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    };

    auto sk = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed, 32));
    auto pk = ed25519_public_key(sk);
    EXPECT_TRUE(span_compare(pk.data, expected_pk));

    auto sig = ed25519_sign(sk, span<uint8_t const>{});
    EXPECT_TRUE(span_compare(sig.data, expected_sig));

    bool ok = ed25519_verify(pk, span<uint8_t const>{}, sig);
    EXPECT_TRUE(ok);
}

//
// RFC 8032 Section 7.1 — Test Vector 2 (1-byte message: 0x72)
//

TEST(ed25519, vector2)
{
    // Secret key (seed):
    // 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
    uint8_t seed[] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    };

    // Public key:
    // 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    uint8_t expected_pk[] = {
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
        0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
    };

    // Message: 72
    uint8_t msg[] = {0x72};

    // Signature:
    // 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
    // 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
    uint8_t expected_sig[] = {
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
        0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
        0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
        0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
    };

    auto sk = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed, 32));
    auto pk = ed25519_public_key(sk);
    EXPECT_TRUE(span_compare(pk.data, expected_pk));

    auto sig = ed25519_sign(sk, span<uint8_t const>(msg, 1));
    EXPECT_TRUE(span_compare(sig.data, expected_sig));

    bool ok = ed25519_verify(pk, span<uint8_t const>(msg, 1), sig);
    EXPECT_TRUE(ok);
}

//
// RFC 8032 Section 7.1 — Test Vector 3 (2-byte message: 0xaf82)
//

TEST(ed25519, vector3)
{
    // Secret key (seed):
    // c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
    uint8_t seed[] = {
        0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
        0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
    };

    // Public key:
    // fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
    uint8_t expected_pk[] = {
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
        0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
    };

    // Message: af82
    uint8_t msg[] = {0xaf, 0x82};

    // Signature:
    // 6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac
    // 18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a
    uint8_t expected_sig[] = {
        0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01, 0xa3,
        0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac,
        0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59,
        0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d, 0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
    };

    auto sk = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed, 32));
    auto pk = ed25519_public_key(sk);
    EXPECT_TRUE(span_compare(pk.data, expected_pk));

    auto sig = ed25519_sign(sk, span<uint8_t const>(msg, 2));
    EXPECT_TRUE(span_compare(sig.data, expected_sig));

    bool ok = ed25519_verify(pk, span<uint8_t const>(msg, 2), sig);
    EXPECT_TRUE(ok);
}

//
// RFC 8032 Section 7.1 — Test Vector 4 (1023-byte message)
//

TEST(ed25519, vector4)
{
    auto seed = hex_to_bytes<32>("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");

    auto expected_pk = hex_to_bytes<32>("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");

    // 1023-byte message
    auto msg = hex_to_bytes<1023>("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
                                  "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
                                  "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
                                  "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
                                  "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
                                  "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
                                  "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
                                  "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
                                  "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
                                  "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
                                  "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
                                  "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
                                  "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
                                  "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
                                  "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
                                  "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
                                  "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
                                  "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
                                  "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
                                  "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
                                  "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
                                  "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
                                  "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
                                  "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
                                  "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
                                  "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
                                  "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
                                  "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
                                  "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
                                  "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
                                  "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
                                  "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0");

    auto expected_sig = hex_to_bytes<64>("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
                                         "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");

    auto sk = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed));
    auto pk = ed25519_public_key(sk);
    EXPECT_TRUE(span_compare(pk.data, expected_pk));

    auto sig = ed25519_sign(sk, span<uint8_t const>(msg));
    EXPECT_TRUE(span_compare(sig.data, expected_sig));

    bool ok = ed25519_verify(pk, span<uint8_t const>(msg), sig);
    EXPECT_TRUE(ok);
}

//
// Verify fails with corrupted signature
//

TEST(ed25519, verify_bad_sig)
{
    // Use test vector 1 seed/key
    uint8_t seed[] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };

    auto sk = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed, 32));
    auto pk = ed25519_public_key(sk);

    // Sign empty message, then corrupt one byte of the signature
    auto sig = ed25519_sign(sk, span<uint8_t const>{});
    sig.data[0] ^= 0x01;

    bool ok = ed25519_verify(pk, span<uint8_t const>{}, sig);
    EXPECT_TRUE(!ok);
}

//
// Verify fails with wrong message
//

TEST(ed25519, verify_bad_msg)
{
    // Use test vector 2 seed/key
    uint8_t seed[] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    };

    uint8_t msg[] = {0x72};
    uint8_t wrong_msg[] = {0x73};  // Different message

    auto sk = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed, 32));
    auto pk = ed25519_public_key(sk);

    // Sign the correct message
    auto sig = ed25519_sign(sk, span<uint8_t const>(msg, 1));

    // Verify with the wrong message
    bool ok = ed25519_verify(pk, span<uint8_t const>(wrong_msg, 1), sig);
    EXPECT_TRUE(!ok);
}

//
// Ed25519 to X25519 key conversion — self-consistency check
// The conversion uses u = (1+y)/(1-y) mod p where y is the Ed25519 point's
// y-coordinate. We verify:
//   1. Conversion produces a non-zero X25519 public key
//   2. Two different Ed25519 keys produce different X25519 keys
//   3. Private key conversion also produces a non-zero result
//

TEST(ed25519, key_conversion)
{
    // Use test vector 1 seed
    uint8_t seed1[] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };

    // Use test vector 2 seed
    uint8_t seed2[] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    };

    auto sk1 = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed1, 32));
    auto pk1 = ed25519_public_key(sk1);

    auto sk2 = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed2, 32));
    auto pk2 = ed25519_public_key(sk2);

    // Convert Ed25519 public keys to X25519 public keys
    auto x_pk1 = ed25519_pk_to_x25519_pk(pk1);
    auto x_pk2 = ed25519_pk_to_x25519_pk(pk2);
    EXPECT_TRUE(x_pk1.has_value());
    EXPECT_TRUE(x_pk2.has_value());

    // Verify the X25519 public keys are not all zeros
    std::array<uint8_t, 32> zeros{};
    EXPECT_TRUE(x_pk1->data != zeros);
    EXPECT_TRUE(x_pk2->data != zeros);

    // Verify different Ed25519 keys produce different X25519 keys
    EXPECT_TRUE(x_pk1->data != x_pk2->data);

    // Convert Ed25519 private keys to X25519 private keys
    auto x_sk1 = ed25519_sk_to_x25519_sk(sk1);
    auto x_sk2 = ed25519_sk_to_x25519_sk(sk2);

    // Verify the X25519 private keys are not all zeros
    EXPECT_TRUE(x_sk1.data != zeros);
    EXPECT_TRUE(x_sk2.data != zeros);

    // Verify different Ed25519 private keys produce different X25519 private keys
    EXPECT_TRUE(x_sk1.data != x_sk2.data);

    // Verify determinism: converting the same key twice gives the same result
    auto x_pk1_again = ed25519_pk_to_x25519_pk(pk1);
    EXPECT_TRUE(x_pk1_again.has_value());
    EXPECT_TRUE(x_pk1->data == x_pk1_again->data);

    auto x_sk1_again = ed25519_sk_to_x25519_sk(sk1);
    EXPECT_TRUE(x_sk1.data == x_sk1_again.data);

    // Verify identity point (y=1) is rejected
    Ed25519PublicKey identity_pk{};
    identity_pk.data[0] = 0x01;  // y = 1 in little-endian (identity point)
    auto x_identity = ed25519_pk_to_x25519_pk(identity_pk);
    EXPECT_TRUE(!x_identity.has_value());
}

//
// Verify fails with invalid public key (all 0xFF, not a valid curve point)
//

TEST(ed25519, verify_invalid_pubkey)
{
    // Use test vector 1 seed to generate a valid signature
    uint8_t seed[] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };

    auto sk = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed, 32));
    auto sig = ed25519_sign(sk, span<uint8_t const>{});

    // Public key with y=2 (non-square u/v, ge_from_bytes returns false)
    Ed25519PublicKey bad_pk{};
    bad_pk.data[0] = 0x02;

    // Verify should fail because ge_from_bytes rejects the non-decodable point
    bool ok = ed25519_verify(bad_pk, span<uint8_t const>{}, sig);
    EXPECT_TRUE(!ok);
}

//
// Verify fails with non-canonical S (S == L and S > L)
//

TEST(ed25519, verify_noncanonical_s)
{
    // Use test vector 1 seed to generate a valid signature
    uint8_t seed[] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };

    auto sk = ed25519_keypair_from_seed(span<uint8_t const, 32>(seed, 32));
    auto pk = ed25519_public_key(sk);
    auto sig = ed25519_sign(sk, span<uint8_t const>{});

    // Test 1: Set S to exactly L (the group order, little-endian)
    // L = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    //       0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    //       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
    {
        Ed25519Signature sig_eq_L = sig;
        uint8_t L[] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        };
        // S is in bytes 32..63 of the signature
        for (int i = 0; i < 32; ++i) {
            sig_eq_L.data[32 + i] = L[i];
        }
        bool ok = ed25519_verify(pk, span<uint8_t const>{}, sig_eq_L);
        EXPECT_TRUE(!ok);
    }

    // Test 2: Set S to all 0xFF (much larger than L)
    {
        Ed25519Signature sig_gt_L = sig;
        for (int i = 32; i < 64; ++i) {
            sig_gt_L.data[i] = 0xFF;
        }
        bool ok = ed25519_verify(pk, span<uint8_t const>{}, sig_gt_L);
        EXPECT_TRUE(!ok);
    }
}

//

TEST_MAIN(statusbar_crypto_25519, ed25519_test)
