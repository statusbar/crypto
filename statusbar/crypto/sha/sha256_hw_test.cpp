// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-256 hardware-accelerated tests
// Runs the same FIPS 180-4 / RFC 4231 test vectors through the _hw functions
// and cross-validates against the software implementation.

#include "statusbar/crypto/sha/sha256_hw.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <cstring>
#include <vector>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

//
// FIPS 180-4 — SHA-256 test vectors via _hw
//

TEST(sha256_hw, sha256_abc_hw)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto digest = sha256_hw(span<uint8_t const>(msg, 3));

    uint8_t expected[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

TEST(sha256_hw, sha256_empty_hw)
{
    auto digest = sha256_hw({});

    uint8_t expected[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

TEST(sha256_hw, sha256_two_blocks_hw)
{
    uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto digest = sha256_hw(span<uint8_t const>(msg, 56));

    uint8_t expected[] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// RFC 4231 — HMAC-SHA-256 via _hw
//

TEST(sha256_hw, sha256_hmac_rfc4231_1_hw)
{
    uint8_t key[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint8_t data[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};

    auto mac = sha256_hmac_hw(span<uint8_t const>(key, 20), span<uint8_t const>(data, 8));

    uint8_t expected[] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    EXPECT_TRUE(span_compare(mac, expected));
}

TEST(sha256_hw, sha256_hmac_rfc4231_2_hw)
{
    uint8_t key[] = {'J', 'e', 'f', 'e'};
    uint8_t data[] = "what do ya want for nothing?";

    auto mac = sha256_hmac_hw(span<uint8_t const>(key, 4), span<uint8_t const>(data, 28));

    uint8_t expected[] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    EXPECT_TRUE(span_compare(mac, expected));
}

//
// sha256_secure_hw — returns SecureArray<32>
//

TEST(sha256_hw, sha256_secure_hw)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto digest = sha256_secure_hw(span<uint8_t const>(msg, 3));

    // Must match the standard sha256_hw result
    auto expected = sha256_hw(span<uint8_t const>(msg, 3));
    EXPECT_TRUE(span_compare(span<uint8_t const, 32>(digest.data(), 32), expected));
}

//
// Two-message HMAC-SHA-256 via _hw: hmac(key, m1, m2) == hmac(key, m1||m2)
//

TEST(sha256_hw, sha256_hmac_two_message_hw)
{
    uint8_t key[] = {'J', 'e', 'f', 'e'};
    uint8_t data[] = "what do ya want for nothing?";

    size_t split = 10;
    auto mac_single = sha256_hmac_hw(span<uint8_t const>(key, 4), span<uint8_t const>(data, 28));
    auto mac_two = sha256_hmac_hw(
        span<uint8_t const>(key, 4), span<uint8_t const>(data, split), span<uint8_t const>(data + split, 28 - split));

    EXPECT_TRUE(span_compare(mac_single, mac_two));
}

TEST(sha256_hw, sha256_hmac_two_message_empty_second_hw)
{
    uint8_t key[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint8_t data[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};

    auto mac_single = sha256_hmac_hw(span<uint8_t const>(key, 20), span<uint8_t const>(data, 8));
    auto mac_two = sha256_hmac_hw(span<uint8_t const>(key, 20), span<uint8_t const>(data, 8), span<uint8_t const>{});

    EXPECT_TRUE(span_compare(mac_single, mac_two));
}

//
// Cross-validate: _hw results must match software
//

TEST(sha256_hw, cross_validate)
{
    // Various message lengths
    for (size_t len : {0, 1, 31, 32, 55, 56, 63, 64, 65, 100, 128, 256, 1000}) {
        std::vector<uint8_t> msg(len);
        for (size_t i = 0; i < len; ++i) {
            msg[i] = static_cast<uint8_t>(i * 41 + 7);
        }
        auto sw = sha256_sw(msg);
        auto hw = sha256_hw(msg);
        EXPECT_TRUE(sw == hw);
    }

    // HMAC cross-validation
    uint8_t key[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t msg[] = "test message for hmac cross validation";
    auto sw = sha256_hmac_sw(span<uint8_t const>(key, 6), span<uint8_t const>(msg, 38));
    auto hw = sha256_hmac_hw(span<uint8_t const>(key, 6), span<uint8_t const>(msg, 38));
    EXPECT_TRUE(sw == hw);
}

//

TEST(sha256_hw, sha256_hmac_two_message_fills_buffer_hw)
{
    // Exercise the partial buffer compression path in sha256_hw_update.
    // After ipad (64 bytes, buffer_len=0), msg1 (40 bytes, buffer_len=40),
    // then msg2 (30 bytes): first 24 bytes fill buffer to 64 → compress,
    // remaining 6 bytes buffered.
    uint8_t key[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    // 70-byte message (40 + 30)
    uint8_t msg[70];
    for (int i = 0; i < 70; ++i) {
        msg[i] = static_cast<uint8_t>(i);
    }

    // One-shot HMAC
    auto mac_single = sha256_hmac_hw(span<uint8_t const>(key, 20), span<uint8_t const>(msg, 70));
    // Two-message HMAC: split at 40/30
    auto mac_two = sha256_hmac_hw(span<uint8_t const>(key, 20), span<uint8_t const>(msg, 40), span<uint8_t const>(msg + 40, 30));

    EXPECT_TRUE(span_compare(mac_single, mac_two));
}

TEST_MAIN(statusbar_crypto_sha, sha256_hw_test)
