// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// X25519 ECDH key agreement (RFC 7748 Section 5)
// Reference: https://www.rfc-editor.org/rfc/rfc7748

#pragma once

#include "statusbar/crypto/keys.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// @brief Size of X25519 shared secret in bytes (32).
inline constexpr size_t x25519_shared_secret_size = 32;

/// @brief Generate X25519 keypair from 32-byte seed.
///
/// Scalar clamping is applied inside curve25519_scalar_mult.
/// Public key = X25519(seed, basepoint_9).
///
/// @param seed 32-byte random seed.
/// @return Private key with precomputed public key.
auto x25519_keypair_from_seed(std::span<uint8_t const, X25519PrivateKey::LENGTH> seed) -> X25519PrivateKey;

/// @brief Compute X25519 ECDH shared secret (RFC 7748 Section 5).
///
/// Performs scalar multiplication of the local private key scalar against
/// the remote public key point on Curve25519. The result must be validated
/// with x25519_shared_secret_is_valid() before use.
///
/// @param sk Local private key.
/// @param pk Remote public key.
/// @return 32-byte shared secret. Must be validated with x25519_shared_secret_is_valid().
auto x25519(X25519PrivateKey const& sk, X25519PublicKey const& pk) -> std::array<uint8_t, x25519_shared_secret_size>;

/// @brief Check that a shared secret is not all-zero (RFC 7748 low-order point rejection).
///
/// All-zero output indicates the peer's public key has small order, which means
/// no meaningful key agreement occurred. Callers must reject such results.
///
/// @param shared_secret The 32-byte result from x25519().
/// @return true if the shared secret is valid (non-zero).
auto x25519_shared_secret_is_valid(std::span<uint8_t const, x25519_shared_secret_size> shared_secret) -> bool;

}  // namespace statusbar::crypto
