// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-256 (FIPS 180-4 Section 6.2) and HMAC-SHA-256 (RFC 2104)
// References:
// - https://csrc.nist.gov/publications/detail/fips/180/4/final
// - https://www.rfc-editor.org/rfc/rfc2104

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief SHA-256 input block size in bytes (512 bits).
inline constexpr size_t sha256_block_size = 64;

/// @brief SHA-256 output digest size in bytes (256 bits).
inline constexpr size_t sha256_digest_size = 32;

/// @brief Compute the SHA-256 hash of a message (FIPS 180-4 Section 6.2).
///
/// Performs a one-shot SHA-256 digest computation over the entire input message.
/// Maximum supported message size is 2^61 - 1 bytes (the 64-bit bit-length
/// field in the padding would overflow beyond this).
///
/// @param message The input data to hash.
/// @return A 32-byte array containing the SHA-256 digest.
auto sha256_sw(std::span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>;

/// @brief Compute HMAC-SHA-256 over a message with the given key (RFC 2104 / FIPS 198-1).
///
/// If the key is longer than the block size (64 bytes), it is first hashed with SHA-256.
/// The HMAC is computed as: SHA-256((key XOR opad) || SHA-256((key XOR ipad) || message)).
///
/// @param key  The HMAC key. Keys longer than 64 bytes are hashed to 32 bytes first.
/// @param message The input data to authenticate.
/// @return A 32-byte array containing the HMAC-SHA-256 tag.
auto sha256_hmac_sw(std::span<uint8_t const> key, std::span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>;

/// @brief Compute HMAC-SHA-256 over two message spans concatenated (RFC 2104 / FIPS 198-1).
///
/// Equivalent to sha256_hmac(key, message1 || message2) but avoids needing a
/// contiguous buffer for the concatenated message.
///
/// @param key  The HMAC key. Keys longer than 64 bytes are hashed to 32 bytes first.
/// @param message1 First part of the input data.
/// @param message2 Second part of the input data.
/// @return A 32-byte array containing the HMAC-SHA-256 tag.
auto sha256_hmac_sw(std::span<uint8_t const> key, std::span<uint8_t const> message1, std::span<uint8_t const> message2)
    -> std::array<uint8_t, sha256_digest_size>;

/// @brief Compute SHA-256 in one call, returning a SecureArray.
///
/// Same computation as sha256, but the result is securely zeroed when it
/// goes out of scope. Use this when the digest is secret.
/// @param message The input data to hash.
/// @return SecureArray<32> containing the SHA-256 digest.
auto sha256_secure_sw(std::span<uint8_t const> message) -> SecureArray<sha256_digest_size>;

}  // namespace statusbar::crypto
