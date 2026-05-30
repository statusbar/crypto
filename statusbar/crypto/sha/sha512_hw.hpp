// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// @file sha512_hw.hpp
/// @brief SHA-512 hardware-accelerated hash.
///
/// Mirrors the software API in sha512.hpp with @c _hw suffix on all function names.
/// Uses hardware acceleration when available, falls back to software otherwise.
///   - ARM64: ARMv8.2-A SHA-512 Crypto Extensions (SHA512H/SHA512H2/SHA512SU0/SHA512SU1)
///   - x86-64: no SHA-512 hardware support; always falls back to software implementation
///
/// @see sha512.hpp for the software-only implementations.

#pragma once

#include "statusbar/crypto/sha/sha512.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Initialize a SHA-512 context with the standard initial hash values.
///
/// Must be called before the first sha512_update_hw.
/// Uses hardware-accelerated initialization when available.
/// @param ctx The SHA-512 context to initialize.
void sha512_init_hw(Sha512Context& ctx);

/// @brief Feed data into an initialized SHA-512 context.
///
/// May be called multiple times to hash data incrementally.
/// Uses hardware-accelerated SHA-512 compression when available.
/// @param ctx  The SHA-512 context (must have been initialized with sha512_init_hw).
/// @param data The input data chunk to process.
void sha512_update_hw(Sha512Context& ctx, std::span<uint8_t const> data);

/// @brief Finalize the SHA-512 hash and produce the 64-byte digest.
///
/// Applies FIPS 180-4 padding and returns the final hash. The context should
/// not be reused after this call without re-initialization.
/// Uses hardware-accelerated SHA-512 compression when available.
/// @param ctx The SHA-512 context to finalize.
/// @return A 64-byte array containing the SHA-512 digest.
auto sha512_final_hw(Sha512Context& ctx) -> std::array<uint8_t, sha512_digest_size>;

/// @brief Compute the SHA-512 hash of a message in one call (FIPS 180-4 Section 6.4).
///
/// Convenience wrapper that calls sha512_init_hw, sha512_update_hw, and sha512_final_hw.
/// Uses hardware-accelerated SHA-512 compression when available.
/// @param message The input data to hash.
/// @return A 64-byte array containing the SHA-512 digest.
auto sha512_hw(std::span<uint8_t const> message) -> std::array<uint8_t, sha512_digest_size>;

/// @brief Finalize SHA-512 and produce a 64-byte digest in a SecureArray.
///
/// Same computation as sha512_final_hw, but the result is securely zeroed when it
/// goes out of scope. Use this when the digest is secret (e.g. Ed25519 key derivation).
/// Uses hardware-accelerated SHA-512 compression when available.
/// @param ctx The SHA-512 context to finalize.
/// @return SecureArray<64> containing the SHA-512 digest.
auto sha512_final_secure_hw(Sha512Context& ctx) -> SecureArray<sha512_digest_size>;

/// @brief Compute SHA-512 in one call, returning a SecureArray.
///
/// Same computation as sha512_hw, but the result is securely zeroed when it
/// goes out of scope. Use this when the digest is secret.
/// Uses hardware-accelerated SHA-512 compression when available.
/// @param message The input data to hash.
/// @return SecureArray<64> containing the SHA-512 digest.
auto sha512_secure_hw(std::span<uint8_t const> message) -> SecureArray<sha512_digest_size>;

}  // namespace statusbar::crypto
