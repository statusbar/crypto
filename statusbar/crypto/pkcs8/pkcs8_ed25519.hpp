// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// PKCS#8 (RFC 8410) and SPKI (RFC 8410) encoding for Ed25519 keys
//
// Export produces minimal DER encoding. Import accepts both minimal
// and formats with an optional [1] publicKey attribute.
//
// References:
// - RFC 8410: Algorithm Identifiers for Ed25519, Ed448, X25519, X448
// - RFC 5958: Asymmetric Key Packages (PKCS#8 v2 / OneAsymmetricKey)
// - RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)

#pragma once

#include "statusbar/crypto/keys.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

/// DER size of an Ed25519 SubjectPublicKeyInfo (44 bytes).
inline constexpr size_t spki_ed25519_der_size = 44;

/// DER size of a minimal Ed25519 PKCS#8 PrivateKeyInfo (48 bytes).
inline constexpr size_t pkcs8_ed25519_der_size = 48;

/// Export an Ed25519 public key as SubjectPublicKeyInfo DER.
/// @param pk The Ed25519 public key (32 bytes).
/// @return 44-byte DER encoding.
auto spki_export_ed25519(Ed25519PublicKey const& pk) -> std::array<uint8_t, spki_ed25519_der_size>;

/// Import an Ed25519 public key from SubjectPublicKeyInfo DER.
/// @param der DER-encoded SubjectPublicKeyInfo.
/// @return The public key, or std::nullopt on parse failure.
auto spki_import_ed25519(std::span<uint8_t const> der) -> std::optional<Ed25519PublicKey>;

/// Export an Ed25519 seed as PKCS#8 PrivateKeyInfo DER (minimal form).
/// The seed is the 32-byte random value passed to ed25519_keypair_from_seed().
/// Note: Ed25519PrivateKey stores the expanded key (SHA-512 of seed), not the
/// original seed, so this function takes the seed directly.
/// @param seed 32-byte Ed25519 seed.
/// @return 48-byte DER encoding.
auto pkcs8_export_ed25519(std::span<uint8_t const, 32> seed) -> std::array<uint8_t, pkcs8_ed25519_der_size>;

/// Import an Ed25519 private key from PKCS#8 PrivateKeyInfo DER.
/// Accepts both minimal (48-byte) and formats with [1] publicKey.
/// Calls ed25519_keypair_from_seed() internally to expand the seed.
/// @param der DER-encoded PKCS#8 PrivateKeyInfo.
/// @return The private key, or std::nullopt on parse failure.
auto pkcs8_import_ed25519(std::span<uint8_t const> der) -> std::optional<Ed25519PrivateKey>;

}  // namespace statusbar::crypto
