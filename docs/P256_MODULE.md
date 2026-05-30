[← back to module index](README.md)

# p256

NIST P-256 (secp256r1 / prime256v1) elliptic curve: ECDH key agreement
per SP 800-56A r3 and ECDSA-SHA-256 signatures per FIPS 186-5 with
RFC 6979 deterministic nonces. Pure software, constant-time scalar
multiplication on secret inputs.

## Overview

P-256 is `y^2 = x^3 − 3x + b` over the Solinas prime
`p = 2^256 − 2^224 + 2^192 + 2^96 − 1`, group order `n` with
cofactor 1. This module factors the implementation into four
independently testable layers so the same primitives can be reused
across ECDH, ECDSA, ECIES, and PKCS#8 without duplication.

The layers, bottom-up:

1. **Field arithmetic.** `P256FieldElement` — 4 × 64-bit limbs over
   `__uint128_t` (reference); `P256FieldElement32` — 8 × 32-bit limbs
   over `uint64_t` (portable). Both implement the NIST Solinas
   reduction `T + 2S1 + 2S2 + S3 + S4 − D1 − D2 − D3 − D4 (mod p)` and
   are cross-checked operation-for-operation by `p256_fe32_test.cpp`.
2. **Scalar arithmetic mod n.** `P256Scalar` (4 × 64) and
   `P256Scalar32` (8 × 32). Since `n` has no Solinas structure, wide
   reduction folds the high half via `2^256 mod n` until it clears.
   `p256_sc_inv` uses Fermat (`a^(n-2)`) with a public exponent —
   constant-time even for secret scalars.
3. **Group operations.** `P256JacobianPoint` (X, Y, Z) with `Z = 0`
   marking the identity, plus an affine `P256AffinePoint` for I/O.
   `p256_point_double` is the dedicated `a = −3` doubling formula;
   `p256_point_add` is the complete addition formula that handles all
   edge cases. Scalar multiplication: `p256_scalar_mult_base` for
   fixed-base, `p256_scalar_mult` for variable-base,
   `p256_double_scalar_mult` (Shamir's trick) for verify.
4. **Protocol primitives.** `p256_ecdh.hpp` (ECDH per SP 800-56A r3
   §5.7, ECSVDP-DHC with cofactor 1) and `p256_ecdsa.hpp` (sign/verify
   per FIPS 186-5 using SHA-256 + RFC 6979 deterministic nonce).
   `p256_wire_constants.hpp` exposes the curve domain parameters as
   32-byte big-endian arrays for wire formats (IEEE 1722.1-2021).

The 32-bit reduced-radix port (`p256_fe32`, `p256_sc32`,
`p256_jac32`) lets the entire P-256 stack — field, scalar, group,
scalar multiplication, key generation, point encoding — run on a
32-bit ALU without `__int128`. It is always compiled.

## Key types

- `P256FieldElement` / `P256FieldElement32` — `p256.hpp` / `p256_fe32.hpp`. Field elements over GF(p); 4 × 64 and 8 × 32 limbs respectively, zeroed on destruction.
- `P256Scalar` / `P256Scalar32` — `p256.hpp` / `p256_sc32.hpp`. Scalars in Z_n; zeroed on destruction so private keys and nonces don't linger on the stack.
- `P256JacobianPoint` / `P256AffinePoint` — `p256.hpp`. Jacobian coords (`x = X/Z^2`, `y = Y/Z^3`) for arithmetic; affine for I/O. `P256JacobianPoint32` analogue in `p256_jac32.hpp`.
- `P256PrivateKey` / `P256PublicKey` / `P256EcdsaSignature` — `keys.hpp`. Private key carries the precomputed public point Q = d · G.
- `p256_scalar_mult_base` / `p256_scalar_mult` / `p256_double_scalar_mult` — `p256.hpp`. Constant-time fixed-base, constant-time variable-base, and Shamir-trick double-scalar (used in ECDSA verify, all public inputs).
- `p256_ecdh` — `p256_ecdh.hpp`. Returns `SecureArray<32>` containing the x-coordinate of `[d] · Q_peer` (big-endian).
- `p256_ecdsa_sign` / `p256_ecdsa_verify` — `p256_ecdsa.hpp`. RFC 6979 deterministic ECDSA-SHA-256. Signature is `r || s`, each 32 bytes big-endian.
- `p256_keypair_from_seed` / `p256_keypair_from_scalar` / `p256_ecdsa_keypair_from_seed` — `p256.hpp` / `p256_ecdsa.hpp`. Seed-driven keygen (SHA-256 + reduce mod n) and raw-scalar import.
- `p256_encode_point_x` / `p256_decode_point_x` / `p256_encode_point_uncompressed` / `p256_decode_point_uncompressed` — `p256.hpp`. EC2OSP-X (0x01 || x) and bare uncompressed (x || y) encodings; the standard `0x04` SEC 1 prefix is **not** added.

## Public headers

- `statusbar/crypto/p256/p256.hpp` — field, scalar, group, keygen, point encoding.
- `statusbar/crypto/p256/p256_ecdh.hpp` — ECDH (SP 800-56A r3 §5.7).
- `statusbar/crypto/p256/p256_ecdsa.hpp` — ECDSA-SHA-256 sign/verify (FIPS 186-5 + RFC 6979).
- `statusbar/crypto/p256/p256_fe32.hpp` / `p256_sc32.hpp` / `p256_jac32.hpp` — 32-bit reduced-radix port; always compiled.
- `statusbar/crypto/p256/p256_constants.hpp` — domain parameters as field/scalar values.
- `statusbar/crypto/p256/p256_wire_constants.hpp` — domain parameters as 32-byte big-endian byte arrays for on-wire use.

## Dependencies

- **Statusbar modules:**
  - [`util`](UTIL_MODULE.md) — `SecureArray<N>` and `internal::secure_zero` (ECDH shared secret, scalars, field limbs).
  - [`sha`](SHA_MODULE.md) — SHA-256 for ECDSA message digest and RFC 6979 nonce HMAC; also for seed → scalar reduction in keygen.
- **System / external:** `<array>`, `<span>`, `<optional>`, `<utility>`, `<cstdint>` from the C++23 standard library; `__uint128_t` / `__int128_t` for the 4 × 64-bit field on 64-bit targets (the `*_32` variants need only `uint64_t`).

## Notes & caveats

- **Pre-release, unaudited.** No third-party review of the field,
  group, or RFC 6979 implementations. Treat as experimental.
- **Constant-time on secrets.** `p256_fe_cmov` / `p256_sc_*` /
  `p256_scalar_mult` / `p256_scalar_mult_base` / `p256_sc_inv` /
  `p256_fe_inv` all run in constant time with respect to secret
  inputs (private scalar `d`, ECDSA nonce `k`). `p256_fe_sqrt` uses a
  public exponent `(p+1)/4` and is invoked only during point
  decompression on public x-coordinates — not on secrets.
- **Variable-time paths.** `p256_double_scalar_mult` is documented as
  Shamir's trick for ECDSA verify; both scalars and the peer point are
  public there. Do not call it on secrets.
- **Cofactor 1.** P-256 has `h = 1`, so ECSVDP-DH and ECSVDP-DHC
  coincide. The cofactor multiplication step in SP 800-56A r3 §5.7.1.2
  is a no-op.
- **Deterministic ECDSA.** Signing uses RFC 6979 nonce derivation
  (HMAC-DRBG over the message + private key) — no RNG needed at sign
  time, and same `(d, m)` always produces the same `(r, s)`.
  Eliminates the catastrophic-nonce-reuse failure mode of FIPS 186-5
  random-`k` ECDSA.
- **Test vectors.** ECDH is checked against NIST CAVP ECC CDH
  (SP 800-56A) P-256 vectors. ECDSA is checked against RFC 6979 A.2.5
  (P-256 + SHA-256, message "sample") and re-sign/verify
  consistency.
- **Point encoding.** This module's `p256_encode_point_uncompressed`
  emits raw `x || y` (64 B) **without** the SEC 1 `0x04` prefix —
  that prefix is added by callers (PKCS#8, ECIES, wire formats) when
  needed. `p256_encode_point_x` uses the EC2OSP-X tag `0x01 || x`
  (33 B), matching IEEE 1722.1.
- **Threadsafety.** All entry points are pure; safe under
  concurrency.

## Further reading

- [`25519`](25519_MODULE.md) — sister curve: X25519 ECDH / Ed25519 EdDSA.
- [`ecies`](ECIES_MODULE.md) — hybrid encryption built on P-256 (and X25519).
- [`pkcs8`](PKCS8_MODULE.md) — DER key encoding for P-256 (RFC 5915 / RFC 5958).
- [`sha`](SHA_MODULE.md) — SHA-256 used by ECDSA and RFC 6979.
- [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) — Digital Signature Standard.
- [SP 800-56A Rev. 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf) — Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography.
- [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) — Deterministic Usage of DSA and ECDSA.
