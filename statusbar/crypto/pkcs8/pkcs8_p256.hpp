// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// PKCS#8 (RFC 5958) and SPKI (RFC 5280) encoding for NIST P-256 keys
//
// Export produces minimal DER encoding (no optional publicKey in ECPrivateKey).
// Import accepts both minimal and OpenSSL-style (with [1] publicKey) formats.
//
// References:
// - RFC 5958: Asymmetric Key Packages (PKCS#8 v2)
// - RFC 5480: ECC SubjectPublicKeyInfo
// - RFC 5915: ECPrivateKey structure
// - SEC 1 v2: Elliptic Curve Cryptography

#pragma once

#include "statusbar/crypto/keys.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace statusbar::crypto {

/// DER size of a P-256 SubjectPublicKeyInfo (91 bytes).
inline constexpr size_t spki_p256_der_size = 91;

/// DER size of a minimal P-256 PKCS#8 PrivateKeyInfo (67 bytes).
inline constexpr size_t pkcs8_p256_der_size = 67;

/// Export a P-256 public key as SubjectPublicKeyInfo DER.
/// @param pk The P-256 public key (64 bytes: x || y, uncompressed).
/// @return 91-byte DER encoding.
auto spki_export_p256(P256PublicKey const& pk) -> std::array<uint8_t, spki_p256_der_size>;

/// Import a P-256 public key from SubjectPublicKeyInfo DER.
/// Validates that the point is on the P-256 curve.
/// @param der DER-encoded SubjectPublicKeyInfo.
/// @return The public key, or std::nullopt on parse failure or invalid point.
auto spki_import_p256(std::span<uint8_t const> der) -> std::optional<P256PublicKey>;

/// Export a P-256 private key as PKCS#8 PrivateKeyInfo DER (minimal form).
/// @param sk The P-256 private key.
/// @return 67-byte DER encoding (no optional publicKey field).
auto pkcs8_export_p256(P256PrivateKey const& sk) -> std::array<uint8_t, pkcs8_p256_der_size>;

/// Import a P-256 private key from PKCS#8 PrivateKeyInfo DER.
/// Accepts both minimal (67-byte) and OpenSSL-style (with public key) formats.
/// Re-derives the public key Q = d * G from the scalar.
/// @param der DER-encoded PKCS#8 PrivateKeyInfo.
/// @return The private key, or std::nullopt on parse failure or invalid scalar.
auto pkcs8_import_p256(std::span<uint8_t const> der) -> std::optional<P256PrivateKey>;

}  // namespace statusbar::crypto
