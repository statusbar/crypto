# statusbar-crypto documentation

The `statusbar-crypto` package is a self-contained C++23 cryptographic
toolkit covering symmetric ciphers (AES-128 / AES-256 with CBC, SIV, and
GCM-SIV modes), hashes (SHA-256 / SHA-512 / HMAC), key-derivation
functions (HKDF, KDF2), elliptic-curve primitives (Curve25519 / Ed25519
/ X25519 / P-256), DL/ECIES, and PKCS#8 / SPKI DER encoding. Each module
is documented in its own overview file; pick a module to get a
two-minute orientation, then dive into its headers under
`statusbar/crypto/<module>/`.

## Module overviews

| Module       | Purpose                                                                             | Link                                       |
|--------------|-------------------------------------------------------------------------------------|--------------------------------------------|
| aes          | AES-128 / AES-256 block cipher and AES-CMAC with SW + HW implementations.           | [AES_MODULE.md](AES_MODULE.md)             |
| aes_cbc      | AES-256-CBC with a null IV and PKCS#7 padding (IEEE 1363a-2004 §14.3.2).            | [AES_CBC_MODULE.md](AES_CBC_MODULE.md)     |
| aes_gcm_siv  | AES-128 / AES-256 GCM-SIV nonce-misuse-resistant AEAD (RFC 8452).                   | [AES_GCM_SIV_MODULE.md](AES_GCM_SIV_MODULE.md) |
| aes_siv      | AES-128 / AES-256 SIV deterministic authenticated encryption (RFC 5297).            | [AES_SIV_MODULE.md](AES_SIV_MODULE.md)     |
| sha          | SHA-256 / SHA-512 hashes and HMAC-SHA-256 (FIPS 180-4, RFC 2104).                   | [SHA_MODULE.md](SHA_MODULE.md)             |
| polyval      | POLYVAL GF(2^128) universal hash used by AES-GCM-SIV (RFC 8452 §3).                 | [POLYVAL_MODULE.md](POLYVAL_MODULE.md)     |
| hkdf         | HKDF-SHA-256 extract / expand / one-shot key derivation (RFC 5869).                 | [HKDF_MODULE.md](HKDF_MODULE.md)           |
| kdf2         | KDF2-SHA-256 counter-mode key derivation (IEEE 1363a-2004 §13.2).                   | [KDF2_MODULE.md](KDF2_MODULE.md)           |
| 25519        | Curve25519 field/group ops, Ed25519 sign/verify, X25519 ECDH (RFC 7748 / 8032).     | [25519_MODULE.md](25519_MODULE.md)         |
| p256         | NIST P-256 field/group ops, ECDH, and ECDSA sign/verify (FIPS 186-4, SEC 2).        | [P256_MODULE.md](P256_MODULE.md)           |
| ecies        | DL/ECIES hybrid encryption over P-256 (IEEE 1363a-2004 §11.3, IEEE 1722-2016 §17).  | [ECIES_MODULE.md](ECIES_MODULE.md)         |
| pkcs8        | PKCS#8 / SPKI DER import & export for Ed25519 and P-256 keys (RFC 5958 / 8410).     | [PKCS8_MODULE.md](PKCS8_MODULE.md)         |
| util         | Secure-zero RAII containers, signing-key concepts, int128 detection, test helpers.  | [UTIL_MODULE.md](UTIL_MODULE.md)           |

## Topic guides

In-depth references that go beyond the per-module overviews:

- [HARDWARE_ACCELERATION.md](HARDWARE_ACCELERATION.md) — which primitives use ARMv8 Crypto / AES-NI / PCLMUL / SHA-NI vs the SW fallback.
- [FUZZING.md](FUZZING.md) — what each `*_fuzzer.cpp` harness covers; how to run a focused campaign.
- [AES128_VS_AES256_REPORT.md](AES128_VS_AES256_REPORT.md) — design rationale for choosing AES-128 vs AES-256 in AVB stream encryption.
