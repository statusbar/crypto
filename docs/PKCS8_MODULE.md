[← back to module index](README.md)

# pkcs8

DER encoding and decoding for asymmetric keys: PKCS#8 `PrivateKeyInfo`
and X.509 `SubjectPublicKeyInfo` for Ed25519 (RFC 8410) and NIST P-256
(RFC 5915 wrapped in RFC 5958). No encryption, no PEM — raw DER bytes
in, raw DER bytes out.

## Overview

PKCS#8 is the standard ASN.1 envelope for an unencrypted private key:
an algorithm OID identifying the curve, plus the algorithm-specific
key bytes wrapped in an `OCTET STRING`. Public keys travel in
`SubjectPublicKeyInfo` (the same `AlgorithmIdentifier` plus a
`BIT STRING` holding the public key). Both modules in this directory
expose a four-function shape — `spki_export_*`, `spki_import_*`,
`pkcs8_export_*`, `pkcs8_import_*` — over fixed-size `std::array`s
sized to the **minimal** DER encoding the curve admits.

There are two curve profiles:

1. **Ed25519** (`pkcs8_ed25519.hpp`). Algorithm OID
   `1.3.101.112` per RFC 8410. The PKCS#8 `privateKey` payload is the
   32-byte **seed** (the value originally fed to
   `ed25519_keypair_from_seed`), not the SHA-512-expanded
   `Ed25519PrivateKey` that the rest of the codebase uses; import
   re-expands the seed via the keypair function. SPKI is 44 B,
   PKCS#8 is 48 B (minimal `OneAsymmetricKey` v1, no `[1] publicKey`
   attribute). Import accepts both minimal and `publicKey`-attribute
   forms.

2. **NIST P-256** (`pkcs8_p256.hpp`). Algorithm OID
   `1.2.840.10045.2.1` (`id-ecPublicKey`) with parameter
   `1.2.840.10045.3.1.7` (`prime256v1`). The PKCS#8 `privateKey`
   payload is an RFC 5915 `ECPrivateKey` structure carrying the
   32-byte big-endian scalar `d`; the public key Q is **not** stored
   and is recomputed on import as `Q = d · G`. SPKI is 91 B, minimal
   PKCS#8 is 67 B (no optional `[1] publicKey` field on the inner
   ECPrivateKey). Import accepts the OpenSSL-style 138-byte form with
   the public key included.

DER parsing is shared via `der_internal.hpp` (`der_read_length`) — an
internal-only helper header, not part of
the public API.

## Key types

- `spki_export_ed25519` / `spki_import_ed25519` — `pkcs8_ed25519.hpp`. 44-byte fixed-size SPKI DER for Ed25519 public keys.
- `pkcs8_export_ed25519(seed)` / `pkcs8_import_ed25519` — `pkcs8_ed25519.hpp`. 48-byte minimal PKCS#8 for Ed25519. Export takes the **seed**, not the expanded private key; import calls `ed25519_keypair_from_seed` internally.
- `spki_export_p256` / `spki_import_p256` — `pkcs8_p256.hpp`. 91-byte fixed-size SPKI DER for P-256 public keys. Import validates the point lies on the curve.
- `pkcs8_export_p256` / `pkcs8_import_p256` — `pkcs8_p256.hpp`. 67-byte minimal PKCS#8 for P-256. Import re-derives Q = d · G, rejects zero / out-of-range scalars, and accepts both minimal and OpenSSL-style (138 B with `[1] publicKey`) inputs.
- `spki_ed25519_der_size` (44) / `pkcs8_ed25519_der_size` (48) / `spki_p256_der_size` (91) / `pkcs8_p256_der_size` (67) — compile-time DER sizes used to size export return types and import buffers.

## Public headers

- `statusbar/crypto/pkcs8/pkcs8_ed25519.hpp` — Ed25519 SPKI / PKCS#8 (RFC 8410 + RFC 5958).
- `statusbar/crypto/pkcs8/pkcs8_p256.hpp` — P-256 SPKI / PKCS#8 (RFC 5480 + RFC 5915 + RFC 5958).

## Dependencies

- **Statusbar modules:**
  - [`25519`](25519_MODULE.md) — `Ed25519PrivateKey` / `Ed25519PublicKey`, and `ed25519_keypair_from_seed` to re-expand the seed on import.
  - [`p256`](P256_MODULE.md) — `P256PrivateKey` / `P256PublicKey`, and `p256_keypair_from_scalar` / scalar validation on import.
  - [`util`](UTIL_MODULE.md) — `SecureArray<N>` and constant-time scrubbing for the scalar / seed bytes lifted out of DER.
- **System / external:** `<array>`, `<span>`, `<optional>`, `<cstdint>`, `<cstddef>` from the C++23 standard library.

## Notes & caveats

- **Pre-release, unaudited.** The DER parser is hand-rolled and has
  not had a third-party security review. It does length-bounds-check
  every tag/length and rejects non-minimal DER lengths, but pathological
  encodings should be assumed to be exploitable until proven otherwise.
  See [`FUZZING.md`](FUZZING.md) — `pkcs8_fuzzer.cpp` exists.
- **Constant-time posture.** PKCS#8 / SPKI is a format layer over
  public bytes — there is no secret-dependent branching during
  encoding or decoding. The secret material itself (seeds, scalars)
  is held in `SecureArray` after parsing and zeroed on destruction.
  No side-channel mitigation is claimed for the DER parse itself
  because none is needed.
- **Minimal DER only on export.** Both export paths produce the
  shortest legal DER (no optional `[1] publicKey` attribute, no
  `version 1` markers beyond what RFC 5958 / RFC 5915 mandate).
  Round-tripping through OpenSSL is supported by the **import**
  side, which accepts the optional public-key attribute and ignores it:
  the private key is always recovered from the seed (Ed25519) or
  re-derived as `Q = d · G` (P-256); the embedded public key is not
  read back or cross-checked.
- **Ed25519 seed vs. expanded key.** The PKCS#8 envelope for Ed25519
  per RFC 8032 carries the **32-byte seed**, not the 64-byte
  expanded `(scalar || nonce_prefix)`. Because the codebase's
  `Ed25519PrivateKey` stores only the expansion, `pkcs8_export_ed25519`
  takes the seed as input (the caller must have kept it).
- **P-256 import validation.** `pkcs8_import_p256` rejects scalars
  that are zero or ≥ `n`; `spki_import_p256` calls
  `p256_point_on_curve` and refuses points that fail.
- **No PEM, no encryption.** This module handles raw DER only.
  PEM armoring (Base64 + `-----BEGIN …-----`) and password-based
  PKCS#8 encryption (`EncryptedPrivateKeyInfo` / PBES2) are out of
  scope.
- **Threadsafety.** Pure functions over by-value / `const&` /
  `std::span` inputs; safe under concurrency.

## Further reading

- [`25519`](25519_MODULE.md) — Ed25519 keys carried by `pkcs8_ed25519`.
- [`p256`](P256_MODULE.md) — P-256 keys carried by `pkcs8_p256`.
- [`util`](UTIL_MODULE.md) — `SecureArray<N>` and secure scrubbing.
- [`FUZZING.md`](FUZZING.md) — `pkcs8_fuzzer.cpp` coverage of DER parse paths.
- [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) — Algorithm Identifiers for Ed25519, Ed448, X25519, X448.
- [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958) — Asymmetric Key Packages (PKCS#8 v2 / `OneAsymmetricKey`).
- [RFC 5915](https://www.rfc-editor.org/rfc/rfc5915) — Elliptic Curve Private Key Structure.
- [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480) — ECC `SubjectPublicKeyInfo`.
- [RFC 5208](https://www.rfc-editor.org/rfc/rfc5208) — original PKCS#8 v1.
