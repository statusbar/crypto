// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-512 hardware-accelerated tests
// Runs the same FIPS 180-4 test vectors through the _hw functions
// and cross-validates against the software implementation.

#include "statusbar/crypto/sha/sha512_hw.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <cstring>
#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

//
// FIPS 180-4 — SHA-512 test vectors via _hw
//

TEST(sha512_hw, sha512_abc_hw)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto digest = sha512_hw(span<uint8_t const>(msg, 3));

    uint8_t expected[] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

TEST(sha512_hw, sha512_empty_hw)
{
    auto digest = sha512_hw({});

    uint8_t expected[] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

TEST(sha512_hw, sha512_two_blocks_hw)
{
    uint8_t msg[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                    "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    auto digest = sha512_hw(span<uint8_t const>(msg, 112));

    uint8_t expected[] = {
        0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
        0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
        0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
        0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// Incremental hashing via _hw
//

TEST(sha512_hw, sha512_incremental_hw)
{
    uint8_t msg[] = {'a', 'b', 'c'};

    Sha512Context ctx;
    sha512_init_hw(ctx);
    sha512_update_hw(ctx, span<uint8_t const>(msg, 1));
    sha512_update_hw(ctx, span<uint8_t const>(msg + 1, 1));
    sha512_update_hw(ctx, span<uint8_t const>(msg + 2, 1));
    auto digest = sha512_final_hw(ctx);

    auto oneshot = sha512_hw(span<uint8_t const>(msg, 3));
    EXPECT_TRUE(digest == oneshot);
}

//
// Cross-validate: _hw results must match software
//

TEST(sha512_hw, cross_validate)
{
    for (size_t len : {0, 1, 63, 64, 100, 127, 128, 129, 256, 1000}) {
        std::vector<uint8_t> msg(len);
        for (size_t i = 0; i < len; ++i) {
            msg[i] = static_cast<uint8_t>(i * 53 + 11);
        }
        auto sw = sha512_sw(msg);
        auto hw = sha512_hw(msg);
        EXPECT_TRUE(sw == hw);
    }
}

//
// Secure variants — verify _hw secure produces same digest as _hw non-secure
//

TEST(sha512_hw, sha512_secure_hw)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto digest = sha512_hw(span<uint8_t const>(msg, 3));
    auto secure_digest = sha512_secure_hw(span<uint8_t const>(msg, 3));

    EXPECT_TRUE(digest == secure_digest);
}

TEST(sha512_hw, sha512_final_secure_hw)
{
    uint8_t msg[] = {'a', 'b', 'c'};

    Sha512Context ctx;
    sha512_init_hw(ctx);
    sha512_update_hw(ctx, span<uint8_t const>(msg, 3));
    auto secure_digest = sha512_final_secure_hw(ctx);

    auto oneshot = sha512_hw(span<uint8_t const>(msg, 3));
    EXPECT_TRUE(oneshot == secure_digest);
}

TEST(sha512_hw, sha512_secure_cross_validate)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto sw = sha512_secure_sw(span<uint8_t const>(msg, 3));
    auto hw = sha512_secure_hw(span<uint8_t const>(msg, 3));
    EXPECT_TRUE(sw == hw);
}

//

TEST_MAIN(statusbar_crypto_sha, sha512_hw_test)
