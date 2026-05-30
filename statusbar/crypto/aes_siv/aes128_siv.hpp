// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-128-SIV authenticated encryption (RFC 5297)
//
// References:
// - RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption
//   https://www.rfc-editor.org/rfc/rfc5297

#pragma once

#include "statusbar/crypto/aes/aes128.hpp"
#include "statusbar/crypto/keys.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Encrypt and authenticate using AES-128-SIV (RFC 5297).
///
/// The 32-byte key is split: first 16 bytes for S2V (CMAC authentication),
/// last 16 bytes for AES-CTR encryption. Plaintext is encrypted in place.
/// @param key 32-byte combined SIV key (K1 || K2).
/// @param plaintext_to_ciphertext Buffer encrypted in place.
/// @param aad Additional authenticated data (not encrypted).
/// @return 16-byte SIV (synthetic initialization vector / authentication tag).
auto aes128_siv_encrypt(Aes128SivKey const& key, std::span<uint8_t> plaintext_to_ciphertext, std::span<uint8_t const> aad)
    -> std::array<uint8_t, aes128_block_size>;

/// @brief Decrypt and verify using AES-128-SIV (RFC 5297).
///
/// Ciphertext is decrypted in place. On authentication failure the buffer
/// is zeroed and false is returned.
/// @param key 32-byte combined SIV key (K1 || K2).
/// @param ciphertext_to_plaintext Buffer decrypted in place.
/// @param siv 16-byte SIV tag from encryption.
/// @param aad Additional authenticated data used during encryption.
/// @return true if authentication succeeds, false otherwise.
auto aes128_siv_decrypt(
    Aes128SivKey const& key,
    std::span<uint8_t> ciphertext_to_plaintext,
    std::span<uint8_t const, aes128_block_size> siv,
    std::span<uint8_t const> aad) -> bool;

}  // namespace statusbar::crypto
