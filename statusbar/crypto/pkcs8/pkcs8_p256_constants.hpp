// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// P-256 PKCS#8 and SPKI DER encoding constants
// DER-encoded AlgorithmIdentifier and key format prefixes for NIST P-256 (RFC 5480).

#pragma once

#include <cstdint>

namespace statusbar::crypto {
namespace constants {

// P-256 AlgorithmIdentifier (complete TLV, 21 bytes):
//   SEQUENCE {
//     OID 1.2.840.10045.2.1 (id-ecPublicKey),
//     OID 1.2.840.10045.3.1.7 (prime256v1 / secp256r1)
//   }
//
// The OID 1.2.840.10045.2.1 identifies the key type as an elliptic curve
// public key (RFC 5480 Section 2.1.1). The namedCurve parameter OID
// 1.2.840.10045.3.1.7 identifies the NIST P-256 curve (SEC 2 / RFC 5480 Section 2.1.1.1).
//
// @see https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
inline constexpr uint8_t p256_algorithm_id[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                                                0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

// P-256 SubjectPublicKeyInfo DER prefix (27 bytes before the 64-byte x||y):
//   SEQUENCE (89 bytes) {
//     AlgorithmIdentifier: SEQUENCE { OID ecPublicKey, OID prime256v1 }
//     BIT STRING (66 bytes, 0 unused bits) {
//       0x04 (uncompressed point marker)
//       <32-byte x> || <32-byte y>
//     }
//   }
//
// The uncompressed point format (0x04 prefix) is defined by SEC 1 Section 2.3.3.
//
// @see https://www.rfc-editor.org/rfc/rfc5480#section-2
inline constexpr uint8_t spki_p256_prefix[] = {0x30, 0x59,  // SEQUENCE (89 bytes)
                                               0x30, 0x13,  // SEQUENCE (19 bytes) AlgorithmIdentifier
                                               0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,        // OID ecPublicKey
                                               0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,  // OID prime256v1
                                               0x03, 0x42,                                                  // BIT STRING (66 bytes)
                                               0x00,                                                        // 0 unused bits
                                               0x04};  // uncompressed point marker

// P-256 PKCS#8 PrivateKeyInfo DER prefix (35 bytes before the 32-byte scalar):
//   SEQUENCE (65 bytes) {
//     INTEGER version = 0
//     AlgorithmIdentifier: SEQUENCE { OID ecPublicKey, OID prime256v1 }
//     OCTET STRING (39 bytes) {
//       ECPrivateKey: SEQUENCE (37 bytes) {
//         INTEGER version = 1
//         OCTET STRING (32 bytes) { <32-byte scalar> }
//       }
//     }
//   }
//
// Uses the ECPrivateKey structure from RFC 5915 Section 3, wrapped in a
// PrivateKeyInfo structure from RFC 5958 (PKCS#8).
//
// @see https://www.rfc-editor.org/rfc/rfc5915#section-3
// @see https://www.rfc-editor.org/rfc/rfc5958#section-2
inline constexpr uint8_t pkcs8_p256_prefix[] = {0x30, 0x41,        // SEQUENCE (65 bytes)
                                                0x02, 0x01, 0x00,  // INTEGER version = 0
                                                0x30, 0x13,        // SEQUENCE (19 bytes) AlgorithmIdentifier
                                                0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,        // OID ecPublicKey
                                                0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,  // OID prime256v1
                                                0x04, 0x27,        // OCTET STRING (39 bytes)
                                                0x30, 0x25,        // SEQUENCE (37 bytes) ECPrivateKey
                                                0x02, 0x01, 0x01,  // INTEGER version = 1
                                                0x04, 0x20};       // OCTET STRING (32 bytes)

}  // namespace constants
}  // namespace statusbar::crypto
