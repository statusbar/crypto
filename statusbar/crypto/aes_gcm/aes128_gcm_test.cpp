// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Test vectors from:
// - McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", Appendix B,
//   test cases 1-4 (AES-128, 96-bit IV); NIST SP 800-38D cites the same set.
// - Project Wycheproof aes_gcm_test.json (aes_gcm_wycheproof_vectors.hpp).

#include "statusbar/crypto/aes_gcm/aes128_gcm.hpp"

#include "statusbar/crypto/aes_gcm/aes_gcm_test_internal.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <vector>

using namespace statusbar::crypto;
using namespace statusbar::crypto::gcm_test;
using statusbar::crypto::internal::span_compare;

namespace {

auto key_from(std::string_view hex) -> Aes128Key
{
    Aes128Key key{};
    internal::span_copy(key.data, std::span<uint8_t const>(from_hex(hex)));
    return key;
}

constexpr std::string_view spec_key = "feffe9928665731c6d6a8f9467308308";
constexpr std::string_view spec_iv = "cafebabefacedbaddecaf888";
constexpr std::string_view spec_plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                                            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
constexpr std::string_view spec_aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
constexpr std::string_view spec_ciphertext = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                                             "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";

// Encrypt @p plaintext_hex, compare with @p ciphertext_hex and @p tag_hex, then round-trip.
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
    auto const tag = aes128_gcm_encrypt(key, nonce, buffer, aad);
    EXPECT_TRUE(buffer == from_hex(ciphertext_hex));
    EXPECT_TRUE(tag == fixed<aes_gcm_tag_size>(from_hex(tag_hex)));
    EXPECT_TRUE(aes128_gcm_decrypt(key, nonce, buffer, tag, aad));
    EXPECT_TRUE(buffer == from_hex(plaintext_hex));
}

}  // namespace

TEST(aes128_gcm, spec_case_1_empty)
{
    check_spec_case("00000000000000000000000000000000", "000000000000000000000000", "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
}

TEST(aes128_gcm, spec_case_2_one_zero_block)
{
    check_spec_case(
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf");
}

TEST(aes128_gcm, spec_case_3_four_blocks_no_aad)
{
    check_spec_case(spec_key, spec_iv, spec_plaintext, "", spec_ciphertext, "4d5c2af327cd64a62cf35abd2ba6fab4");
}

TEST(aes128_gcm, spec_case_4_partial_block_with_aad)
{
    check_spec_case(
        spec_key,
        spec_iv,
        spec_plaintext.substr(0, 120),
        spec_aad,
        spec_ciphertext.substr(0, 120),
        "5bc94fbc3221a5db94fae95ae7121a47");
}

TEST(aes128_gcm, wycheproof_vectors)
{
    auto const failures = count_failures<Aes128Key>(
        wycheproof::aes128_gcm,
        [](auto const& key, auto nonce, auto buffer, auto aad) { return aes128_gcm_encrypt(key, nonce, buffer, aad); },
        [](auto const& key, auto nonce, auto buffer, auto const& tag, auto aad) {
            return aes128_gcm_decrypt(key, nonce, buffer, tag, aad);
        });
    EXPECT_EQ(failures, size_t{0});
}

//

TEST_MAIN(statusbar_crypto_aes_gcm, aes128_gcm_test)
