// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// ECDSA over NIST P-256 with SHA-256
//
// Implements ECSP-DSA (sign) and ECVP-DSA (verify) per IEEE 1363-2000
// with EMSA1 message encoding (hash directly with SHA-256).
// Uses RFC 6979 for deterministic nonce generation.
//
// References:
// - IEEE 1722-2016 clause 16: ECSSA_DSA_EMSA1_SHA256
// - FIPS 186-4 Section 6: ECDSA
// - RFC 6979: Deterministic Usage of DSA and ECDSA

#pragma once

#include "statusbar/crypto/keys.hpp"
#include "statusbar/crypto/p256/p256.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

/// Extract the embedded public key from a P-256 private key (no computation).
///
/// The public key was precomputed during keypair generation and is simply returned.
/// This mirrors ed25519_public_key() and enables the P256SigningKey concept.
/// @param sk The P-256 private key.
/// @return The 64-byte uncompressed public key (x || y).
auto p256_public_key(P256PrivateKey const& sk) -> P256PublicKey;

/// Generate a P-256 keypair from a 32-byte seed.
/// The seed is hashed with SHA-256 and reduced mod n to produce scalar d.
/// @param seed 32-byte random seed.
/// @return Private key with embedded public key Q = d * G.
auto p256_ecdsa_keypair_from_seed(std::span<uint8_t const, p256_scalar_size> seed) -> P256PrivateKey;

/// Construct a P256PrivateKey from a raw 32-byte scalar (big-endian).
/// Unlike p256_ecdsa_keypair_from_seed, this takes the scalar d directly
/// (no hashing). Computes the public key Q = d * G.
/// @param scalar_bytes 32-byte big-endian private scalar d.
/// @return The private key, or std::nullopt if scalar is zero or >= n.
auto p256_keypair_from_scalar(std::span<uint8_t const, p256_scalar_size> scalar_bytes) -> std::optional<P256PrivateKey>;

/// ECDSA sign a message using SHA-256 with deterministic nonce (RFC 6979).
/// @param sk The signer's private key.
/// @param message The message to sign.
/// @return 64-byte signature (r || s), each 32 bytes big-endian.
auto p256_ecdsa_sign(P256PrivateKey const& sk, std::span<uint8_t const> message) -> P256EcdsaSignature;

/// ECDSA verify a signature on a message.
/// @param pk The signer's public key.
/// @param message The message that was signed.
/// @param signature The 64-byte ECDSA signature to verify.
/// @return true if the signature is valid, false otherwise.
auto p256_ecdsa_verify(P256PublicKey const& pk, std::span<uint8_t const> message, P256EcdsaSignature const& signature) -> bool;

}  // namespace statusbar::crypto
