// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Ed25519 sign/verify (RFC 8032 Section 5.1)
// Reference: https://www.rfc-editor.org/rfc/rfc8032

#pragma once

#include "statusbar/crypto/keys.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

/// @brief Size of an Ed25519 seed in bytes (32).
inline constexpr size_t ed25519_seed_size = 32;

/// @brief Generate Ed25519 keypair from 32-byte seed per RFC 8032 Section 5.1.5.
///
/// The seed is hashed with SHA-512 to produce 64 bytes. The first 32 bytes are
/// clamped to form the private scalar; the last 32 bytes become the nonce prefix
/// used during signing. The public key A = [scalar]B is precomputed and stored.
///
/// @param seed 32-byte random seed.
/// @return Private key containing clamped scalar, nonce prefix, and precomputed public key.
auto ed25519_keypair_from_seed(std::span<uint8_t const, ed25519_seed_size> seed) -> Ed25519PrivateKey;

/// @brief Extract the embedded public key from a private key (no computation).
///
/// The public key was precomputed during keypair generation and is simply returned.
///
/// @param sk The private key.
/// @return The 32-byte compressed public key.
auto ed25519_public_key(Ed25519PrivateKey const& sk) -> Ed25519PublicKey;

/// @brief PureEdDSA signature (RFC 8032 Section 5.1.6).
///
/// Produces a deterministic 64-byte signature. The nonce is derived from the
/// private key's nonce prefix and the message, making signatures reproducible
/// and immune to bad randomness.
/// @precondition sk must be a valid Ed25519 private key (generated with ed25519_keypair_from_seed)
/// @precondition message can be any length, including empty (empty message produces valid signature)
/// @param sk The signer's private key.
/// @param message Data to sign (arbitrary length, can be empty).
/// @return 64-byte signature (R || S). R: 32-byte point on Edwards curve, S: 32-byte scalar (little-endian)
auto ed25519_sign(Ed25519PrivateKey const& sk, std::span<uint8_t const> message) -> Ed25519Signature;

/// @brief PureEdDSA verification (RFC 8032 Section 5.1.7).
///
/// Checks S < L (canonicality), decodes R and A, verifies [S]B == R + [H(R||A||M)]A.
/// The verification equation is computed as [H](-A) + [S]B and compared with R,
/// using the negation trick to avoid a separate [H]A computation.
/// @precondition pk must be a valid 32-byte Ed25519 public key
/// @precondition signature.data must contain 64 bytes: 32-byte R (point) || 32-byte S (scalar)
/// @precondition message can be any length, including empty (empty message is valid)
/// @precondition Signature must have been created with ed25519_sign (or must be in valid Ed25519 format)
/// @param pk The signer's public key (32 bytes).
/// @param message The signed data (arbitrary length, can be empty).
/// @param signature The 64-byte signature to verify (R || S format).
/// @return true if the signature is valid and canonical, false otherwise (including non-canonical S)
auto ed25519_verify(Ed25519PublicKey const& pk, std::span<uint8_t const> message, Ed25519Signature const& signature) -> bool;

/// @brief Convert Ed25519 public key to X25519 public key.
///
/// Computes u = (1+y)/(1-y) to map from twisted Edwards to Montgomery form.
/// Only the y-coordinate (encoded in the public key) is needed for this conversion.
///
/// Returns std::nullopt if the Ed25519 key encodes the identity point (y=1), which would
/// produce an all-zero X25519 key (a low-order point unsuitable for ECDH).
///
/// @param ed_pk Ed25519 public key.
/// @return The X25519 public key, or std::nullopt if the input is the identity point.
auto ed25519_pk_to_x25519_pk(Ed25519PublicKey const& ed_pk) -> std::optional<X25519PublicKey>;

/// @brief Convert Ed25519 private key to X25519 private key.
///
/// The clamped scalar from SHA-512(seed) serves as the X25519 scalar. This works
/// because the Ed25519 and Curve25519 groups have the same order.
///
/// @param ed_sk Ed25519 private key.
/// @return Corresponding X25519 private key with computed public key.
auto ed25519_sk_to_x25519_sk(Ed25519PrivateKey const& ed_sk) -> X25519PrivateKey;

}  // namespace statusbar::crypto
