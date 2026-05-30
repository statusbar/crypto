// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Ed25519 PKCS#8 and SPKI DER encoding constants
// DER-encoded AlgorithmIdentifier and key format prefixes for Ed25519 (RFC 8410).

#pragma once

#include <cstdint>

namespace statusbar::crypto {
namespace constants {

// Ed25519 AlgorithmIdentifier (complete TLV, 7 bytes):
//   SEQUENCE { OID 1.3.101.112 (id-EdDSA / Ed25519) }
//
// The OID 1.3.101.112 is defined in RFC 8410 Section 3 for Ed25519 keys.
// This is the complete DER-encoded AlgorithmIdentifier with no parameters.
//
// @see https://www.rfc-editor.org/rfc/rfc8410#section-3
inline constexpr uint8_t ed25519_algorithm_id[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70};

// Ed25519 SubjectPublicKeyInfo DER prefix (12 bytes before the 32-byte key):
//   SEQUENCE (42 bytes) {
//     AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 }
//     BIT STRING (33 bytes, 0 unused bits) { <32-byte public key> }
//   }
//
// Defined by RFC 8410 Section 4, using the SubjectPublicKeyInfo structure
// from RFC 5280 Section 4.1.
//
// @see https://www.rfc-editor.org/rfc/rfc8410#section-4
inline constexpr uint8_t spki_ed25519_prefix[] = {
    0x30,
    0x2A,  // SEQUENCE (42 bytes)
    0x30,
    0x05,  // SEQUENCE (5 bytes) AlgorithmIdentifier
    0x06,
    0x03,
    0x2B,
    0x65,
    0x70,  // OID 1.3.101.112 (Ed25519)
    0x03,
    0x21,   // BIT STRING (33 bytes)
    0x00};  // 0 unused bits

// Ed25519 PKCS#8 PrivateKeyInfo DER prefix (16 bytes before the 32-byte seed):
//   SEQUENCE (46 bytes) {
//     INTEGER version = 0
//     AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 }
//     OCTET STRING (34 bytes) {
//       CurvePrivateKey: OCTET STRING (32 bytes) { <32-byte seed> }
//     }
//   }
//
// Defined by RFC 8410 Section 7, using the OneAsymmetricKey / PrivateKeyInfo
// structure from RFC 5958 (successor to RFC 5208 PKCS#8).
//
// @see https://www.rfc-editor.org/rfc/rfc8410#section-7
inline constexpr uint8_t pkcs8_ed25519_prefix[] = {
    0x30,
    0x2E,  // SEQUENCE (46 bytes)
    0x02,
    0x01,
    0x00,  // INTEGER version = 0
    0x30,
    0x05,  // SEQUENCE (5 bytes) AlgorithmIdentifier
    0x06,
    0x03,
    0x2B,
    0x65,
    0x70,  // OID 1.3.101.112 (Ed25519)
    0x04,
    0x22,  // OCTET STRING (34 bytes)
    0x04,
    0x20};  // OCTET STRING (32 bytes) CurvePrivateKey

}  // namespace constants
}  // namespace statusbar::crypto
