// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes256_gcm.cpp
/// @brief AES-256-GCM: the shared GCM core over the AES-256 block cipher.

#include "statusbar/crypto/aes_gcm/aes256_gcm.hpp"

#include "statusbar/crypto/aes/aes256_hw.hpp"
#include "statusbar/crypto/aes_gcm/aes_gcm_internal.hpp"

namespace statusbar::crypto {

namespace {

auto block_cipher(Aes256RoundKeys const& rk)
{
    return [&rk](std::span<uint8_t, aes256_block_size> block) { aes256_encrypt_block_hw(rk, block); };
}

}  // namespace

auto aes256_gcm_encrypt(
    Aes256Key const& key,
    std::span<uint8_t const, aes_gcm_nonce_size> nonce,
    std::span<uint8_t> plaintext_to_ciphertext,
    std::span<uint8_t const> aad) -> std::array<uint8_t, aes_gcm_tag_size>
{
    auto const rk = aes256_expand_key_hw(key);
    return internal::gcm_encrypt(block_cipher(rk), nonce, plaintext_to_ciphertext, aad);
}

auto aes256_gcm_decrypt(
    Aes256Key const& key,
    std::span<uint8_t const, aes_gcm_nonce_size> nonce,
    std::span<uint8_t> ciphertext_to_plaintext,
    std::span<uint8_t const, aes_gcm_tag_size> tag,
    std::span<uint8_t const> aad) -> bool
{
    auto const rk = aes256_expand_key_hw(key);
    return internal::gcm_decrypt(block_cipher(rk), nonce, ciphertext_to_plaintext, tag, aad);
}

}  // namespace statusbar::crypto
