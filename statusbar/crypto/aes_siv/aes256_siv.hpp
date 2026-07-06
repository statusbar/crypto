// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// AES-256-SIV authenticated encryption (RFC 5297)
//
// References:
// - RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption
//   https://www.rfc-editor.org/rfc/rfc5297

#pragma once

#include "statusbar/crypto/aes/aes256.hpp"
#include "statusbar/crypto/keys.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Encrypt and authenticate using AES-256-SIV (RFC 5297).
///
/// The 64-byte key is split: first 32 bytes for S2V (CMAC authentication),
/// last 32 bytes for AES-CTR encryption. Plaintext is encrypted in place.
/// Maximum plaintext size is 2^35 bytes (32 GB); larger plaintexts are
/// rejected and return an empty tag. This limit arises from the CTR counter:
/// the SIV construction clears one bit in each of the two middle counter
/// words (RFC 5297 §2.6), leaving 2^31 usable blocks * 16 bytes/block.
/// @param key 64-byte combined SIV key (K1 || K2).
/// @param plaintext_to_ciphertext Buffer encrypted in place (must be <= 2^35 bytes).
/// @param aad Additional authenticated data (not encrypted).
/// @return 16-byte SIV (synthetic initialization vector / authentication tag), or empty array if plaintext exceeds 2^35 bytes.
auto aes256_siv_encrypt(Aes256SivKey const& key, std::span<uint8_t> plaintext_to_ciphertext, std::span<uint8_t const> aad)
    -> std::array<uint8_t, aes256_block_size>;

/// @brief Decrypt and verify using AES-256-SIV (RFC 5297).
///
/// Ciphertext is decrypted in place. On authentication failure the buffer
/// is zeroed and false is returned. Maximum ciphertext size is 2^35 bytes (32 GB);
/// larger ciphertexts are rejected.
/// @param key 64-byte combined SIV key (K1 || K2).
/// @param ciphertext_to_plaintext Buffer decrypted in place (must be <= 2^35 bytes).
/// @param siv 16-byte SIV tag from encryption.
/// @param aad Additional authenticated data used during encryption.
/// @return true if authentication succeeds and ciphertext size is valid, false otherwise.
auto aes256_siv_decrypt(
    Aes256SivKey const& key,
    std::span<uint8_t> ciphertext_to_plaintext,
    std::span<uint8_t const, aes256_block_size> siv,
    std::span<uint8_t const> aad) -> bool;

}  // namespace statusbar::crypto
