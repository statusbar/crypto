// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// GHASH over POLYVAL (RFC 8452 Appendix A) against the GCM specification's
// test case 2 (McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)",
// Appendix B; the same case is NIST SP 800-38D's AES-128 example with
// K = 0^128, IV = 0^96, P = 0^128), whose intermediate values are published:
// H = 66e94bd4ef8a2c3b884cfa59ca342b2e, C = 0388dace60b6a392f328c2b971b2fe78,
// GHASH(H, {}, C) = f38cbb1ad69223dcc3457ae5b6b0f885.

#include "statusbar/crypto/aes_gcm/ghash_internal.hpp"

#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <algorithm>
#include <array>
#include <vector>

using namespace statusbar::crypto;
using namespace statusbar::crypto::internal;
using statusbar::crypto::internal::span_compare;

namespace {

constexpr std::array<uint8_t, 16> kat_h{
    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};
constexpr std::array<uint8_t, 16> kat_c{
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
// [len(A)]64 || [len(C)]64 = 0 || 128 bits
constexpr std::array<uint8_t, 16> kat_lengths{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80};
constexpr std::array<uint8_t, 16> kat_ghash{
    0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0, 0xf8, 0x85};

}  // namespace

TEST(ghash, gcm_spec_case_2_one_shot)
{
    std::array<uint8_t, 32> blocks{};
    span_copy(std::span<uint8_t>(blocks).first<16>(), std::span<uint8_t const, 16>(kat_c));
    span_copy(std::span<uint8_t>(blocks).last<16>(), std::span<uint8_t const, 16>(kat_lengths));
    EXPECT_TRUE(span_compare(ghash(kat_h, blocks), kat_ghash));
}

TEST(ghash, gcm_spec_case_2_incremental)
{
    auto const key = ghash_key(kat_h);
    std::array<uint8_t, 16> accumulator{};
    ghash_update_padded(key, {}, accumulator);  // empty AAD adds nothing
    ghash_update_padded(key, kat_c, accumulator);
    ghash_update_lengths(key, 0, 16, accumulator);
    EXPECT_TRUE(span_compare(ghash_final(accumulator), kat_ghash));
}

// RFC 8452 Appendix A: mulX_POLYVAL(9c98c04df9387ded828175a92ba652d8) = 3931819bf271fada0503eb52574ca572.
// ghash_key(H) is mulX_POLYVAL(ByteReverse(H)), so feed it the byte-reversed input.
TEST(ghash, key_conversion_matches_rfc8452_mulx_example)
{
    constexpr std::array<uint8_t, 16> input{
        0x9c, 0x98, 0xc0, 0x4d, 0xf9, 0x38, 0x7d, 0xed, 0x82, 0x81, 0x75, 0xa9, 0x2b, 0xa6, 0x52, 0xd8};
    constexpr std::array<uint8_t, 16> expected{
        0x39, 0x31, 0x81, 0x9b, 0xf2, 0x71, 0xfa, 0xda, 0x05, 0x03, 0xeb, 0x52, 0x57, 0x4c, 0xa5, 0x72};
    std::array<uint8_t, 16> reversed{};
    std::reverse_copy(input.begin(), input.end(), reversed.begin());
    EXPECT_TRUE(span_compare(ghash_key(reversed).polyval.data, expected));
}

TEST(ghash, empty_input_hashes_to_zero)
{
    std::array<uint8_t, 16> const zero{};
    EXPECT_TRUE(span_compare(ghash(kat_h, {}), zero));
}

// Chunked absorption (16 blocks at a time) must equal the one-shot value, and the
// zero padding of a partial block must equal hashing the explicitly padded data.
TEST(ghash, chunking_and_padding_are_transparent)
{
    std::vector<uint8_t> data(16 * 16 + 37);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    std::vector<uint8_t> padded = data;
    padded.resize(16 * 16 + 48, 0);

    auto const key = ghash_key(kat_h);
    std::array<uint8_t, 16> accumulator{};
    ghash_update_padded(key, data, accumulator);
    EXPECT_TRUE(span_compare(ghash_final(accumulator), ghash(kat_h, padded)));
}

//

TEST_MAIN(statusbar_crypto_aes_gcm, ghash_internal_test)
