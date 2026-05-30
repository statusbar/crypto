// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file sha256_hw.hpp
/// @brief SHA-256 hardware-accelerated hash and HMAC.
///
/// Mirrors the software API in sha256.hpp with @c _hw suffix on all function names.
/// Uses hardware acceleration when available, falls back to software otherwise.
///   - ARM64: ARMv8 SHA-2 Crypto Extensions (SHA256H/SHA256H2/SHA256SU0/SHA256SU1)
///   - x86-64: SHA-NI (SHA256RNDS2/SHA256MSG1/SHA256MSG2)
///
/// @see sha256.hpp for the software-only implementations.

#pragma once

#include "statusbar/crypto/sha/sha256.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Compute the SHA-256 hash of a message (FIPS 180-4 Section 6.2).
///
/// Uses hardware-accelerated SHA-256 compression when available.
/// @param message The input data to hash.
/// @return A 32-byte array containing the SHA-256 digest.
auto sha256_hw(std::span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>;

/// @brief Compute HMAC-SHA-256 over a message with the given key (RFC 2104 / FIPS 198-1).
///
/// If the key is longer than the block size (64 bytes), it is first hashed with SHA-256.
/// The HMAC is computed as: SHA-256((key XOR opad) || SHA-256((key XOR ipad) || message)).
/// Uses hardware-accelerated SHA-256 compression when available.
/// @param key  The HMAC key. Keys longer than 64 bytes are hashed to 32 bytes first.
/// @param message The input data to authenticate.
/// @return A 32-byte array containing the HMAC-SHA-256 tag.
auto sha256_hmac_hw(std::span<uint8_t const> key, std::span<uint8_t const> message) -> std::array<uint8_t, sha256_digest_size>;

/// @brief Compute HMAC-SHA-256 over two message spans concatenated (RFC 2104 / FIPS 198-1).
///
/// Equivalent to sha256_hmac_hw(key, message1 || message2) but avoids needing a
/// contiguous buffer for the concatenated message.
/// Uses hardware-accelerated SHA-256 compression when available.
/// @param key  The HMAC key. Keys longer than 64 bytes are hashed to 32 bytes first.
/// @param message1 First part of the input data.
/// @param message2 Second part of the input data.
/// @return A 32-byte array containing the HMAC-SHA-256 tag.
auto sha256_hmac_hw(std::span<uint8_t const> key, std::span<uint8_t const> message1, std::span<uint8_t const> message2)
    -> std::array<uint8_t, sha256_digest_size>;

/// @brief Compute SHA-256 in one call, returning a SecureArray.
///
/// Same computation as sha256_hw, but the result is securely zeroed when it
/// goes out of scope. Use this when the digest is secret.
/// Uses hardware-accelerated SHA-256 compression when available.
/// @param message The input data to hash.
/// @return SecureArray<32> containing the SHA-256 digest.
auto sha256_secure_hw(std::span<uint8_t const> message) -> SecureArray<sha256_digest_size>;

}  // namespace statusbar::crypto
