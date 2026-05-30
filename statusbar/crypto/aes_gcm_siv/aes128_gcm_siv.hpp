// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file aes128_gcm_siv.hpp
/// @brief AES-128-GCM-SIV authenticated encryption with nonce-misuse resistance (RFC 8452).
///
/// Provides encrypt and decrypt operations using AES-128-GCM-SIV, a nonce-misuse
/// resistant AEAD scheme. The algorithm proceeds as:
///   1. Key derivation: derive per-message authentication and encryption keys from
///      the master key and nonce (RFC 8452 Section 4).
///   2. POLYVAL tag computation: hash AAD and plaintext to produce an authentication tag.
///   3. AES-CTR encryption: encrypt plaintext using the tag as the initial counter.
///
/// The nonce-misuse resistance property ensures that reusing a nonce only reveals
/// whether the same plaintext was encrypted twice, without compromising authenticity.
///
/// @see https://www.rfc-editor.org/rfc/rfc8452

#pragma once

#include "statusbar/crypto/aes/aes128.hpp"
#include "statusbar/crypto/aes_gcm_siv/aes_gcm_siv.hpp"
#include "statusbar/crypto/keys.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief AES-128-GCM-SIV encrypt (RFC 8452).
///
/// Encrypts plaintext in place and computes an authentication tag over
/// both the AAD and plaintext. The nonce-misuse resistance property
/// ensures that reusing a nonce only leaks whether the same plaintext
/// was encrypted twice, without compromising authenticity.
///
/// WARNING: Nonce Uniqueness Required
/// While GCM-SIV provides misuse resistance, nonce reuse WILL LEAK INFORMATION:
/// - If the same nonce is reused with the SAME key AND plaintext, the ciphertext
///   will be IDENTICAL, allowing an attacker to detect plaintext repetition.
/// - For maximum security, ensure each (key, nonce) pair is used at most once.
/// - In AVTP context, derive nonce from monotonic sequence number to guarantee uniqueness.
///
/// @param key                    The 128-bit AES key.
/// @param nonce                  12-byte nonce (MUST be unique per key for full confidentiality).
/// @param plaintext_to_ciphertext Buffer encrypted in place.
/// @param aad                    Additional authenticated data (integrity-protected but not encrypted).
/// @return 16-byte authentication tag.
auto aes128_gcm_siv_encrypt(
    Aes128Key const& key,
    std::span<uint8_t const, aes_gcm_siv_nonce_size> nonce,
    std::span<uint8_t> plaintext_to_ciphertext,
    std::span<uint8_t const> aad) -> std::array<uint8_t, aes_gcm_siv_tag_size>;

/// @brief AES-128-GCM-SIV decrypt (RFC 8452).
///
/// Decrypts ciphertext in place and verifies the authentication tag.
/// Returns true if the tag is valid (message is authentic), false otherwise.
/// On authentication failure the plaintext buffer is zeroed for safety,
/// preventing use of unauthenticated data.
///
/// WARNING: Nonce Reuse Leaks Plaintext Equality
/// If the same (key, nonce) combination is used to decrypt two different ciphertexts,
/// and both authentication checks pass, an attacker can determine whether they
/// encrypt the same plaintext (ciphertexts will be identical).
///
/// @param key                      The 128-bit AES key (same key used for encryption).
/// @param nonce                    12-byte nonce used during encryption (MUST be unique per key).
/// @param ciphertext_to_plaintext  Buffer decrypted in place.
/// @param tag                      16-byte authentication tag produced by encrypt.
/// @param aad                      Additional authenticated data (must match what was passed to encrypt).
/// @return true if authentication succeeds; false if tag verification fails (buffer zeroed).
auto aes128_gcm_siv_decrypt(
    Aes128Key const& key,
    std::span<uint8_t const, aes_gcm_siv_nonce_size> nonce,
    std::span<uint8_t> ciphertext_to_plaintext,
    std::span<uint8_t const, aes_gcm_siv_tag_size> tag,
    std::span<uint8_t const> aad) -> bool;

}  // namespace statusbar::crypto
