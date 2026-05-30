// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - FIPS 180-4: https://csrc.nist.gov/publications/detail/fips/180/4/final
// - RFC 4231 (HMAC-SHA-256): https://www.rfc-editor.org/rfc/rfc4231

#include "statusbar/crypto/sha/sha256.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <algorithm>
#include <cstring>

using namespace statusbar::crypto;
using statusbar::crypto::internal::span_compare;
using std::span;

//
// FIPS 180-4 — SHA-256("abc")
//

TEST(sha256, abc)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto digest = sha256_sw(span<uint8_t const>(msg, 3));

    // Expected: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    uint8_t expected[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// FIPS 180-4 — SHA-256("") (empty)
//

TEST(sha256, empty)
{
    auto digest = sha256_sw({});

    // Expected: e3b0c44298fc1c14 9afbf4c8996fb924 27ae41e4649b934c a495991b7852b855
    uint8_t expected[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// FIPS 180-4 — SHA-256(two-block message)
// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
//

TEST(sha256, two_blocks)
{
    uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto digest = sha256_sw(span<uint8_t const>(msg, 56));

    // Expected: 248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1
    uint8_t expected[] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    EXPECT_TRUE(span_compare(digest, expected));
}

//
// RFC 4231 Test Case 1 — HMAC-SHA-256
// Key  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
// Data = "Hi There"
//

TEST(sha256, hmac_rfc4231_1)
{
    uint8_t key[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint8_t data[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};

    auto mac = sha256_hmac_sw(span<uint8_t const>(key, 20), span<uint8_t const>(data, 8));

    // Expected: b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7
    uint8_t expected[] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    EXPECT_TRUE(span_compare(mac, expected));
}

//
// RFC 4231 Test Case 2 — HMAC-SHA-256
// Key  = "Jefe" (4 bytes)
// Data = "what do ya want for nothing?"
//

TEST(sha256, hmac_rfc4231_2)
{
    uint8_t key[] = {'J', 'e', 'f', 'e'};
    uint8_t data[] = "what do ya want for nothing?";

    auto mac = sha256_hmac_sw(span<uint8_t const>(key, 4), span<uint8_t const>(data, 28));

    // Expected: 5bdcc146bf60754e6a042426089575c7 5a003f089d2739839dec58b964ec3843
    uint8_t expected[] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    EXPECT_TRUE(span_compare(mac, expected));
}

//
// RFC 4231 Test Case 3 — HMAC-SHA-256
// Key  = aaaaaaaaaa... (20 bytes of 0xaa)
// Data = dddddddddd... (50 bytes of 0xdd)
//

TEST(sha256, hmac_rfc4231_3)
{
    uint8_t key[20];
    std::fill_n(key, 20, static_cast<uint8_t>(0xaa));
    uint8_t data[50];
    std::fill_n(data, 50, static_cast<uint8_t>(0xdd));

    auto mac = sha256_hmac_sw(span<uint8_t const>(key, 20), span<uint8_t const>(data, 50));

    // Expected: 773ea91e36800e46854db8ebd09181a7 2959098b3ef8c122d9635514ced565fe
    uint8_t expected[] = {
        0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
        0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
    };
    EXPECT_TRUE(span_compare(mac, expected));
}

//
// sha256_secure — returns SecureArray<32> instead of std::array
//

TEST(sha256, secure_abc)
{
    uint8_t msg[] = {'a', 'b', 'c'};
    auto digest = sha256_secure_sw(span<uint8_t const>(msg, 3));

    // Must match the standard sha256 result
    auto expected = sha256_sw(span<uint8_t const>(msg, 3));
    EXPECT_TRUE(span_compare(span<uint8_t const, 32>(digest.data(), 32), expected));
}

TEST(sha256, secure_empty)
{
    auto digest = sha256_secure_sw({});

    auto expected = sha256_sw({});
    EXPECT_TRUE(span_compare(span<uint8_t const, 32>(digest.data(), 32), expected));
}

//
// Two-message HMAC-SHA-256: hmac(key, m1, m2) == hmac(key, m1||m2)
//

TEST(sha256, hmac_two_message)
{
    uint8_t key[] = {'J', 'e', 'f', 'e'};
    uint8_t data[] = "what do ya want for nothing?";

    // Split the message at an arbitrary point
    size_t split = 10;
    auto mac_single = sha256_hmac_sw(span<uint8_t const>(key, 4), span<uint8_t const>(data, 28));
    auto mac_two = sha256_hmac_sw(
        span<uint8_t const>(key, 4), span<uint8_t const>(data, split), span<uint8_t const>(data + split, 28 - split));

    EXPECT_TRUE(span_compare(mac_single, mac_two));
}

TEST(sha256, hmac_two_message_empty_second)
{
    uint8_t key[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint8_t data[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};

    auto mac_single = sha256_hmac_sw(span<uint8_t const>(key, 20), span<uint8_t const>(data, 8));
    auto mac_two = sha256_hmac_sw(span<uint8_t const>(key, 20), span<uint8_t const>(data, 8), span<uint8_t const>{});

    EXPECT_TRUE(span_compare(mac_single, mac_two));
}

TEST(sha256, hmac_long_key)
{
    // RFC 4231 Test Case 6: key longer than block size (131 bytes of 0xaa)
    uint8_t key[131];
    std::fill_n(key, 131, static_cast<uint8_t>(0xaa));
    uint8_t data[] = "Test Using Larger Than Block-Size Key - Hash Key First";

    auto mac = sha256_hmac_sw(span<uint8_t const>(key, 131), span<uint8_t const>(data, 54));

    // Expected: 60e431591ee0b67f0d8a26aacbf5b77f 8e0bc6213728c5140546040f0ee37f54
    uint8_t expected[] = {
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
        0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
    };
    EXPECT_TRUE(span_compare(mac, expected));
}

//
// RFC 4231 Test Case 4 — HMAC-SHA-256
// Key  = 0102030405...19 (25 bytes)
// Data = cdcdcdcd... (50 bytes of 0xcd)
//

TEST(sha256, hmac_rfc4231_4)
{
    uint8_t key[25];
    for (int i = 0; i < 25; ++i) {
        key[i] = static_cast<uint8_t>(i + 1);
    }
    uint8_t data[50];
    std::fill_n(data, 50, static_cast<uint8_t>(0xcd));

    auto mac = sha256_hmac_sw(span<uint8_t const>(key, 25), span<uint8_t const>(data, 50));

    // Expected: 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b
    uint8_t expected[] = {
        0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
        0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b,
    };
    EXPECT_TRUE(span_compare(mac, expected));
}

//
// RFC 4231 Test Case 5 — HMAC-SHA-256 (truncated to 128 bits)
// Key  = 0c0c0c0c... (20 bytes of 0x0c)
// Data = "Test With Truncation" (20 bytes)
//

TEST(sha256, hmac_rfc4231_5)
{
    uint8_t key[20];
    std::fill_n(key, 20, static_cast<uint8_t>(0x0c));
    uint8_t data[] = "Test With Truncation";

    auto mac = sha256_hmac_sw(span<uint8_t const>(key, 20), span<uint8_t const>(data, 20));

    // Expected first 16 bytes: a3b6167473100ee06e0c796c2955552b
    uint8_t expected_first16[] = {
        0xa3,
        0xb6,
        0x16,
        0x74,
        0x73,
        0x10,
        0x0e,
        0xe0,
        0x6e,
        0x0c,
        0x79,
        0x6c,
        0x29,
        0x55,
        0x55,
        0x2b,
    };
    EXPECT_TRUE(span_compare(span<uint8_t const>(mac).first(16), span<uint8_t const>(expected_first16, 16)));
}

//
// RFC 4231 Test Case 7 — HMAC-SHA-256
// Key  = aaaa... (131 bytes of 0xaa)
// Data = "This is a test using a larger than block-size key and a larger
//         than block-size data. The key needs to be hashed before being
//         used by the HMAC algorithm." (152 bytes)
//

TEST(sha256, hmac_rfc4231_7)
{
    uint8_t key[131];
    std::fill_n(key, 131, static_cast<uint8_t>(0xaa));
    uint8_t data[] = "This is a test using a larger than block-size key and a "
                     "larger than block-size data. The key needs to be hashed "
                     "before being used by the HMAC algorithm.";

    auto mac = sha256_hmac_sw(span<uint8_t const>(key, 131), span<uint8_t const>(data, 152));

    // Expected: 9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2
    uint8_t expected[] = {
        0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
        0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2,
    };
    EXPECT_TRUE(span_compare(mac, expected));
}

TEST(sha256, hmac_two_message_fills_buffer)
{
    // Exercise the partial buffer compression path in sha256_ctx_update.
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
    auto mac_single = sha256_hmac_sw(span<uint8_t const>(key, 20), span<uint8_t const>(msg, 70));
    // Two-message HMAC: split at 40/30
    auto mac_two = sha256_hmac_sw(span<uint8_t const>(key, 20), span<uint8_t const>(msg, 40), span<uint8_t const>(msg + 40, 30));

    EXPECT_TRUE(span_compare(mac_single, mac_two));
}

TEST_MAIN(statusbar_crypto_sha, sha256_test)
