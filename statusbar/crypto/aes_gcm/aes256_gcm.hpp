// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes256_gcm.hpp
/// @brief AES-256-GCM authenticated encryption with associated data (NIST SP 800-38D, RFC 5116 AEAD_AES_256_GCM).
///
/// 96-bit nonce, 128-bit tag. GCM is NOT nonce-misuse resistant: encrypting two
/// messages under the same (key, nonce) reveals the XOR of the plaintexts and
/// lets an attacker recover the hash subkey and forge tags. Every nonce under a
/// key must be unique; use aes256_gcm_siv where that cannot be guaranteed.
///
/// @see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

#pragma once

#include "statusbar/crypto/aes_gcm/aes_gcm.hpp"
#include "statusbar/crypto/keys.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief AES-256-GCM encrypt (SP 800-38D 7.1).
///
/// Encrypts the plaintext in place and returns the tag over the AAD and the
/// ciphertext. The (key, nonce) pair MUST be unique for every call.
///
/// @param key                     The 256-bit AES key.
/// @param nonce                   12-byte nonce, unique per key.
/// @param plaintext_to_ciphertext Buffer encrypted in place (at most aes_gcm_max_plaintext_size bytes).
/// @param aad                     Additional authenticated data (integrity-protected, not encrypted).
/// @return 16-byte authentication tag; all zeros (nothing encrypted) when the plaintext is too long.
auto aes256_gcm_encrypt(
    Aes256Key const& key,
    std::span<uint8_t const, aes_gcm_nonce_size> nonce,
    std::span<uint8_t> plaintext_to_ciphertext,
    std::span<uint8_t const> aad) -> std::array<uint8_t, aes_gcm_tag_size>;

/// @brief AES-256-GCM decrypt (SP 800-38D 7.2).
///
/// Verifies the tag over the AAD and ciphertext in constant time, then decrypts
/// in place. On verification failure the buffer is zeroed and false returned,
/// so unauthenticated bytes are never handed back.
///
/// @param key                     The 256-bit AES key used to encrypt.
/// @param nonce                   The 12-byte nonce used to encrypt.
/// @param ciphertext_to_plaintext Buffer decrypted in place.
/// @param tag                     The 16-byte tag produced by encrypt.
/// @param aad                     The additional authenticated data passed to encrypt.
/// @return true when the tag verifies and the buffer now holds the plaintext.
auto aes256_gcm_decrypt(
    Aes256Key const& key,
    std::span<uint8_t const, aes_gcm_nonce_size> nonce,
    std::span<uint8_t> ciphertext_to_plaintext,
    std::span<uint8_t const, aes_gcm_tag_size> tag,
    std::span<uint8_t const> aad) -> bool;

}  // namespace statusbar::crypto
