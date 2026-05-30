// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// SHA-512 (FIPS 180-4 Section 6.4)
// Reference: https://csrc.nist.gov/publications/detail/fips/180/4/final

#pragma once

#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief SHA-512 input block size in bytes (1024 bits).
inline constexpr size_t sha512_block_size = 128;

/// @brief SHA-512 output digest size in bytes (512 bits).
inline constexpr size_t sha512_digest_size = 64;

/// @brief Incremental SHA-512 hashing context for multi-part message processing.
///
/// Maintains the running hash state so data can be fed in chunks via
/// sha512_init / sha512_update / sha512_final.
struct Sha512Context
{
    /// Running hash state words H0..H7 (eight 64-bit values).
    std::array<uint64_t, 8> state{};
    /// Partial block buffer; accumulates bytes until a full 128-byte block is ready.
    std::array<uint8_t, sha512_block_size> buffer{};
    /// Number of bytes currently stored in the partial block buffer.
    size_t buffer_len{};
    /// Total number of message bytes fed so far (used for final padding).
    uint64_t total_len{};

    /// Securely zero state and buffer on destruction to prevent sensitive
    /// data (e.g. HMAC key material) from lingering on the stack.
    ~Sha512Context() { internal::secure_zero(*this); }
};

/// @brief Initialize a SHA-512 context with the standard initial hash values.
///
/// Must be called before the first sha512_update.
///
/// @param ctx The SHA-512 context to initialize.
void sha512_init_sw(Sha512Context& ctx);

/// @brief Feed data into an initialized SHA-512 context.
///
/// May be called multiple times to hash data incrementally.
///
/// @param ctx  The SHA-512 context (must have been initialized with sha512_init).
/// @param data The input data chunk to process.
void sha512_update_sw(Sha512Context& ctx, std::span<uint8_t const> data);

/// @brief Finalize the SHA-512 hash and produce the 64-byte digest.
///
/// Applies FIPS 180-4 padding and returns the final hash. The context should
/// not be reused after this call without re-initialization.
///
/// @param ctx The SHA-512 context to finalize.
/// @return A 64-byte array containing the SHA-512 digest.
auto sha512_final_sw(Sha512Context& ctx) -> std::array<uint8_t, sha512_digest_size>;

/// @brief Compute the SHA-512 hash of a message in one call (FIPS 180-4 Section 6.4).
///
/// Convenience wrapper that calls sha512_init, sha512_update, and sha512_final.
/// Maximum supported message size is 2^61 - 1 bytes. The FIPS 180-4 specification
/// allows messages up to 2^128 - 1 bits, but this implementation tracks message
/// length with a uint64_t (total_len in Sha512Context), which limits input to
/// 2^61 - 1 bytes before the 8-bit shift (bit_len = total_len * 8) would overflow.
/// This is not a practical limitation for any real-world use case.
///
/// @param message The input data to hash (must be < 2^61 bytes).
/// @return A 64-byte array containing the SHA-512 digest.
auto sha512_sw(std::span<uint8_t const> message) -> std::array<uint8_t, sha512_digest_size>;

/// @brief Finalize SHA-512 and produce a 64-byte digest in a SecureArray.
///
/// Same computation as sha512_final, but the result is securely zeroed when it
/// goes out of scope. Use this when the digest is secret (e.g. Ed25519 key derivation).
/// @param ctx The SHA-512 context to finalize.
/// @return SecureArray<64> containing the SHA-512 digest.
auto sha512_final_secure_sw(Sha512Context& ctx) -> SecureArray<sha512_digest_size>;

/// @brief Compute SHA-512 in one call, returning a SecureArray.
///
/// Same computation as sha512, but the result is securely zeroed when it
/// goes out of scope. Use this when the digest is secret.
/// @param message The input data to hash.
/// @return SecureArray<64> containing the SHA-512 digest.
auto sha512_secure_sw(std::span<uint8_t const> message) -> SecureArray<sha512_digest_size>;

}  // namespace statusbar::crypto
