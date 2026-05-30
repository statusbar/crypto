// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// ECDH over NIST P-256 (ECSVDP-DHC)
//
// Implements Elliptic Curve Secret Value Derivation Primitive,
// Diffie-Hellman with Cofactor (IEEE 1363-2000 Section 7.2.2).
// For P-256 the cofactor h = 1, so this is identical to plain ECDH.
//
// References:
// - IEEE 1722-2016 clause 17.3.1: ECSVDP-DHC
// - IEEE 1363-2000 Section 7.2.2

#pragma once

#include "statusbar/crypto/keys.hpp"
#include "statusbar/crypto/p256/p256.hpp"
#include "statusbar/crypto/util/secure_array.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace statusbar::crypto {

/// Compute P-256 ECDH shared secret.
///
/// Performs scalar multiplication: shared_secret = [sk] * peer_pk, then extracts
/// the x-coordinate (32 bytes, big-endian) as the shared secret.
/// @precondition sk must be a valid P-256 private key (32-byte scalar, big-endian).
/// @precondition peer_pk must be a valid P-256 public key (64-byte uncompressed point: x || y, no leading 0x04).
///               If from untrusted source, validate with p256_ecdh_validate_peer_public_key first.
/// @param sk The local private key (32-byte scalar d).
/// @param peer_pk The peer's public key (64-byte uncompressed point Q = x || y, no leading 0x04).
/// @return 32-byte big-endian x-coordinate of [sk] * peer_pk (shared secret), or all-zeros on failure.
///         Returned as SecureArray so the shared secret is securely zeroed on destruction.
auto p256_ecdh(P256PrivateKey const& sk, P256PublicKey const& peer_pk) -> SecureArray<p256_field_element_size>;

}  // namespace statusbar::crypto
