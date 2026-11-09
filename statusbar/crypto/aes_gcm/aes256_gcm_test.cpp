// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", Appendix B,
//   test cases 13-16 (AES-256, 96-bit IV); NIST SP 800-38D cites the same set.
// - Project Wycheproof aes_gcm_test.json (aes_gcm_wycheproof_vectors.hpp).

#include "statusbar/crypto/aes_gcm/aes256_gcm.hpp"

#include "statusbar/crypto/aes_gcm/aes_gcm_test_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <vector>

using namespace statusbar::crypto;
using namespace statusbar::crypto::gcm_test;
using statusbar::crypto::internal::span_compare;

namespace {

auto key_from(std::string_view hex) -> Aes256Key
{
    Aes256Key key{};
    internal::span_copy(key.data, std::span<uint8_t const>(from_hex(hex)));
    return key;
}

constexpr std::string_view spec_key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
constexpr std::string_view spec_iv = "cafebabefacedbaddecaf888";
constexpr std::string_view spec_plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                                            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
constexpr std::string_view spec_aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
constexpr std::string_view spec_ciphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                                             "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";

void check_spec_case(
    std::string_view key_hex,
    std::string_view iv_hex,
    std::string_view plaintext_hex,
    std::string_view aad_hex,
    std::string_view ciphertext_hex,
    std::string_view tag_hex)
{
    auto const key = key_from(key_hex);
    auto const nonce = fixed<aes_gcm_nonce_size>(from_hex(iv_hex));
    auto const aad = from_hex(aad_hex);
    auto buffer = from_hex(plaintext_hex);
    auto const tag = aes256_gcm_encrypt(key, nonce, buffer, aad);
    EXPECT_TRUE(buffer == from_hex(ciphertext_hex));
    EXPECT_TRUE(tag == fixed<aes_gcm_tag_size>(from_hex(tag_hex)));
    EXPECT_TRUE(aes256_gcm_decrypt(key, nonce, buffer, tag, aad));
    EXPECT_TRUE(buffer == from_hex(plaintext_hex));
}

}  // namespace

TEST(aes256_gcm, spec_case_13_empty)
{
    check_spec_case(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b");
}

TEST(aes256_gcm, spec_case_14_one_zero_block)
{
    check_spec_case(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919");
}

TEST(aes256_gcm, spec_case_15_four_blocks_no_aad)
{
    check_spec_case(spec_key, spec_iv, spec_plaintext, "", spec_ciphertext, "b094dac5d93471bdec1a502270e3cc6c");
}

TEST(aes256_gcm, spec_case_16_partial_block_with_aad)
{
    check_spec_case(
        spec_key,
        spec_iv,
        spec_plaintext.substr(0, 120),
        spec_aad,
        spec_ciphertext.substr(0, 120),
        "76fc6ece0f4e1768cddf8853bb2d551b");
}

TEST(aes256_gcm, wycheproof_vectors)
{
    auto const failures = count_failures<Aes256Key>(
        wycheproof::aes256_gcm,
        [](auto const& key, auto nonce, auto buffer, auto aad) { return aes256_gcm_encrypt(key, nonce, buffer, aad); },
        [](auto const& key, auto nonce, auto buffer, auto const& tag, auto aad) {
            return aes256_gcm_decrypt(key, nonce, buffer, tag, aad);
        });
    EXPECT_EQ(failures, size_t{0});
}

//

TEST_MAIN(statusbar_crypto_aes_gcm, aes256_gcm_test)
