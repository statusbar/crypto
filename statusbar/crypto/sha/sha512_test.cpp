// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - FIPS 180-4: https://csrc.nist.gov/publications/detail/fips/180/4/final
// - NIST CSRC examples: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

#include "statusbar/crypto/sha/sha512.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <cstring>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

//
// FIPS 180-4 — SHA-512("abc")
//

TEST(sha512, abc)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto digest = sha512_sw(span<uint8_t const>(msg, 3));

    // Expected: ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a
    //           2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f
    uint8_t expected[] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// FIPS 180-4 — SHA-512("") (empty message)
//

TEST(sha512, empty)
{
    auto digest = sha512_sw({});

    // Expected: cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce
    //           47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e
    uint8_t expected[] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// FIPS 180-4 — SHA-512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno
//                        ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
// Two-block message (896 bits = 112 bytes)
//

TEST(sha512, two_blocks)
{
    uint8_t msg[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                    "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    // strlen = 112, don't include null terminator
    auto digest = sha512_sw(span<uint8_t const>(msg, 112));

    // Expected: 8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018
    //           501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909
    uint8_t expected[] = {
        0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
        0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
        0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
        0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// Incremental hashing — verify update in parts matches one-shot
//

TEST(sha512, incremental)
{
    uint8_t msg[] = {'a', 'b', 'c'};

    Sha512Context ctx;
    sha512_init_sw(ctx);
    sha512_update_sw(ctx, span<uint8_t const>(msg, 1));
    sha512_update_sw(ctx, span<uint8_t const>(msg + 1, 1));
    sha512_update_sw(ctx, span<uint8_t const>(msg + 2, 1));
    auto digest = sha512_final_sw(ctx);

    auto oneshot = sha512_sw(span<uint8_t const>(msg, 3));
    EXPECT_TRUE(digest == oneshot);
}

//
// SHA-512 of a single 'a' character
//

TEST(sha512, single_a)
{
    uint8_t msg[] = {'a'};
    auto digest = sha512_sw(span<uint8_t const>(msg, 1));

    // SHA-512("a") = 1f40fc92da241694 750979ee6cf582f2 d5d7d28e18335de0 5abc54d0560e0f53
    //               02860c652bf08d56 0252aa5e74210546 f369fbbbce8c12cf c7957b2652fe9a75
    uint8_t expected[] = {
        0x1f, 0x40, 0xfc, 0x92, 0xda, 0x24, 0x16, 0x94, 0x75, 0x09, 0x79, 0xee, 0x6c, 0xf5, 0x82, 0xf2,
        0xd5, 0xd7, 0xd2, 0x8e, 0x18, 0x33, 0x5d, 0xe0, 0x5a, 0xbc, 0x54, 0xd0, 0x56, 0x0e, 0x0f, 0x53,
        0x02, 0x86, 0x0c, 0x65, 0x2b, 0xf0, 0x8d, 0x56, 0x02, 0x52, 0xaa, 0x5e, 0x74, 0x21, 0x05, 0x46,
        0xf3, 0x69, 0xfb, 0xbb, 0xce, 0x8c, 0x12, 0xcf, 0xc7, 0x95, 0x7b, 0x26, 0x52, 0xfe, 0x9a, 0x75,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// Secure variants — verify they produce the same digest as the non-secure versions
//

TEST(sha512, secure)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto digest = sha512_sw(span<uint8_t const>(msg, 3));
    auto secure_digest = sha512_secure_sw(span<uint8_t const>(msg, 3));

    EXPECT_TRUE(digest == secure_digest);
}

TEST(sha512, final_secure)
{
    uint8_t msg[] = {'a', 'b', 'c'};

    Sha512Context ctx;
    sha512_init_sw(ctx);
    sha512_update_sw(ctx, span<uint8_t const>(msg, 3));
    auto secure_digest = sha512_final_secure_sw(ctx);

    auto oneshot = sha512_sw(span<uint8_t const>(msg, 3));
    EXPECT_TRUE(oneshot == secure_digest);
}

//

TEST_MAIN(statusbar_crypto_sha, sha512_test)
