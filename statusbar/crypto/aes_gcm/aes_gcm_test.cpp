// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Behavioural tests shared by both AES-GCM flavours: round trips across block
// boundaries, rejection (and zeroing) on any tampering, and the two key sizes
// producing different outputs.

#include "statusbar/crypto/aes_gcm/aes128_gcm.hpp"
#include "statusbar/crypto/aes_gcm/aes256_gcm.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"
#include "statusbar/test/test.hpp"

#include <array>
#include <vector>

using namespace statusbar::crypto;

namespace {

auto pattern(size_t n, uint8_t seed) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out(n);
    for (size_t i = 0; i < n; ++i) {
        out[i] = static_cast<uint8_t>(seed + i * 13);
    }
    return out;
}

auto key128() -> Aes128Key
{
    Aes128Key key{};
    for (size_t i = 0; i < key.data.size(); ++i) {
        key.data[i] = static_cast<uint8_t>(0xA0 + i);
    }
    return key;
}

auto key256() -> Aes256Key
{
    Aes256Key key{};
    for (size_t i = 0; i < key.data.size(); ++i) {
        key.data[i] = static_cast<uint8_t>(0x50 + i);
    }
    return key;
}

constexpr std::array<uint8_t, aes_gcm_nonce_size> nonce{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};

// Encrypt then decrypt every length from empty to 4 blocks + 3, with and without AAD.
template <typename Key, typename Encrypt, typename Decrypt>
auto round_trips(Key const& key, Encrypt encrypt, Decrypt decrypt) -> bool
{
    for (size_t n = 0; n <= 67; ++n) {  // NOLINT(statusbar-block-statements) one round trip per length
        auto const aad = pattern(n % 23, 0x80);
        auto const plaintext = pattern(n, 0x01);
        auto buffer = plaintext;
        auto const tag = encrypt(key, nonce, std::span<uint8_t>(buffer), std::span<uint8_t const>(aad));
        bool const same = (buffer == plaintext);
        bool const ok = decrypt(key, nonce, std::span<uint8_t>(buffer), tag, std::span<uint8_t const>(aad));
        if ((n > 0 && same) || !ok || buffer != plaintext) {
            return false;
        }
    }
    return true;
}

auto encrypt128 = [](auto const& k, auto n, auto buf, auto aad) { return aes128_gcm_encrypt(k, n, buf, aad); };
auto decrypt128 = [](auto const& k, auto n, auto buf, auto const& tag, auto aad) {
    return aes128_gcm_decrypt(k, n, buf, tag, aad);
};
auto encrypt256 = [](auto const& k, auto n, auto buf, auto aad) { return aes256_gcm_encrypt(k, n, buf, aad); };
auto decrypt256 = [](auto const& k, auto n, auto buf, auto const& tag, auto aad) {
    return aes256_gcm_decrypt(k, n, buf, tag, aad);
};

}  // namespace

TEST(aes_gcm, round_trips_all_lengths)
{
    EXPECT_TRUE(round_trips(key128(), encrypt128, decrypt128));
    EXPECT_TRUE(round_trips(key256(), encrypt256, decrypt256));
}

TEST(aes_gcm, tampering_is_rejected_and_buffer_zeroed)
{
    auto const key = key256();
    auto const plaintext = pattern(45, 0x33);
    auto const aad = pattern(7, 0x99);
    auto ciphertext = plaintext;
    auto const tag = aes256_gcm_encrypt(key, nonce, ciphertext, aad);
    std::vector<uint8_t> const zeros(ciphertext.size(), 0);

    auto flipped_ct = ciphertext;
    flipped_ct[20] ^= 0x01;
    EXPECT_FALSE(aes256_gcm_decrypt(key, nonce, flipped_ct, tag, aad));
    EXPECT_TRUE(flipped_ct == zeros);

    auto buffer = ciphertext;
    auto bad_tag = tag;
    bad_tag[15] ^= 0x80;
    EXPECT_FALSE(aes256_gcm_decrypt(key, nonce, buffer, bad_tag, aad));
    EXPECT_TRUE(buffer == zeros);

    buffer = ciphertext;
    auto bad_aad = aad;
    bad_aad[0] ^= 0x01;
    EXPECT_FALSE(aes256_gcm_decrypt(key, nonce, buffer, tag, bad_aad));
    EXPECT_TRUE(buffer == zeros);

    buffer = ciphertext;
    auto bad_nonce = nonce;
    bad_nonce[11] ^= 0x01;
    EXPECT_FALSE(aes256_gcm_decrypt(key, bad_nonce, buffer, tag, aad));
    EXPECT_TRUE(buffer == zeros);

    buffer = ciphertext;
    EXPECT_TRUE(aes256_gcm_decrypt(key, nonce, buffer, tag, aad));
    EXPECT_TRUE(buffer == plaintext);
}

TEST(aes_gcm, empty_message_still_authenticates_aad)
{
    auto const key = key128();
    auto const aad = pattern(31, 0x42);
    auto const tag = aes128_gcm_encrypt(key, nonce, {}, aad);
    EXPECT_TRUE(aes128_gcm_decrypt(key, nonce, {}, tag, aad));
    auto bad_aad = aad;
    bad_aad[30] ^= 0x04;
    EXPECT_FALSE(aes128_gcm_decrypt(key, nonce, {}, tag, bad_aad));
}

TEST(aes_gcm, key_sizes_differ)
{
    Aes128Key k128{};
    Aes256Key k256{};  // the 128-bit key zero-extended is a different key
    auto a = pattern(32, 0x11);
    auto b = a;
    auto const tag_a = aes128_gcm_encrypt(k128, nonce, a, {});
    auto const tag_b = aes256_gcm_encrypt(k256, nonce, b, {});
    EXPECT_FALSE(a == b);
    EXPECT_FALSE(tag_a == tag_b);
}

//

TEST_MAIN(statusbar_crypto_aes_gcm, aes_gcm_test)
