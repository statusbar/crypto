// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes_gcm_test_internal.hpp
/// @brief Shared pieces of the AES-GCM tests: hex decoding and the Wycheproof vector runner.

#pragma once

#include "statusbar/crypto/aes_gcm/aes_gcm.hpp"
#include "statusbar/crypto/aes_gcm/aes_gcm_wycheproof_vectors.hpp"
#include "statusbar/crypto/util/crypto_util_internal.hpp"

#include <array>
#include <cstdint>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace statusbar::crypto::gcm_test {

inline auto from_hex(std::string_view hex) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(std::stoul(std::string(hex.substr(2 * i, 2)), nullptr, 16));
    }
    return out;
}

template <size_t N>
auto fixed(std::vector<uint8_t> const& bytes) -> std::array<uint8_t, N>
{
    std::array<uint8_t, N> out{};
    internal::span_copy(std::span<uint8_t>(out), std::span<uint8_t const>(bytes).first(N));
    return out;
}

/// A vector's fields decoded from hex.
struct Decoded
{
    std::vector<uint8_t> key;
    std::array<uint8_t, aes_gcm_nonce_size> nonce;
    std::vector<uint8_t> aad;
    std::vector<uint8_t> msg;
    std::vector<uint8_t> ct;
    std::array<uint8_t, aes_gcm_tag_size> tag;
};

inline auto decode(wycheproof::AeadVector const& v) -> Decoded
{
    return Decoded{
        from_hex(v.key),
        fixed<aes_gcm_nonce_size>(from_hex(v.iv)),
        from_hex(v.aad),
        from_hex(v.msg),
        from_hex(v.ct),
        fixed<aes_gcm_tag_size>(from_hex(v.tag))};
}

/// encrypt(key, nonce, buffer, aad) -> tag reproduces the vector's ciphertext and tag.
template <typename Key, typename Encrypt>
auto encrypt_matches(Decoded const& d, Key const& key, Encrypt encrypt) -> bool
{
    auto buffer = d.msg;
    auto const tag = encrypt(key, d.nonce, std::span<uint8_t>(buffer), std::span<uint8_t const>(d.aad));
    return buffer == d.ct && tag == d.tag;
}

/// decrypt(key, nonce, buffer, tag, aad) -> bool gives the vector's verdict, with the
/// plaintext back on acceptance and a zeroed buffer on rejection.
template <typename Key, typename Decrypt>
auto decrypt_matches(Decoded const& d, Key const& key, Decrypt decrypt, bool const valid) -> bool
{
    auto buffer = d.ct;
    bool const accepted = decrypt(key, d.nonce, std::span<uint8_t>(buffer), d.tag, std::span<uint8_t const>(d.aad));
    return accepted == valid && (accepted ? buffer == d.msg : buffer == std::vector<uint8_t>(d.ct.size(), 0));
}

/// One Wycheproof vector against an AEAD, @p Key constructed from the key bytes.
/// @return true when the implementation agrees with the vector's verdict.
template <typename Key, typename Encrypt, typename Decrypt>
auto check_vector(wycheproof::AeadVector const& v, Encrypt encrypt, Decrypt decrypt) -> bool
{
    auto const d = decode(v);
    Key key{};
    internal::span_copy(key.data, std::span<uint8_t const>(d.key));
    return (!v.valid || encrypt_matches(d, key, encrypt)) && decrypt_matches(d, key, decrypt, v.valid);
}

/// Every vector of @p vectors; prints the ones that disagree and returns how many did.
template <typename Key, size_t N, typename Encrypt, typename Decrypt>
auto count_failures(std::array<wycheproof::AeadVector, N> const& vectors, Encrypt encrypt, Decrypt decrypt) -> size_t
{
    size_t failures = 0;
    for (auto const& v : vectors) {
        if (!check_vector<Key>(v, encrypt, decrypt)) {
            std::println("  wycheproof tcId {} ({}; {}) disagrees", v.tc_id, v.comment, v.flags);
            ++failures;
        }
    }
    return failures;
}

}  // namespace statusbar::crypto::gcm_test
