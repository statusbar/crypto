[← back to module index](README.md)

# 25519

X25519 ECDH key agreement (RFC 7748) and Ed25519 EdDSA signatures
(RFC 8032), built on a shared Curve25519 field-arithmetic core. Pure
software, constant-time scalar multiplication, no hardware path.

## Overview

Curve25519 is the underlying elliptic curve. The X25519 entry points
operate on its Montgomery form via the ladder; the Ed25519 entry
points operate on the birationally equivalent twisted Edwards form via
extended (X, Y, Z, T) coordinates. The shared field is GF(2^255 − 19),
and the same scalar field (mod L = 2^252 + …) is used for Ed25519
nonces and signature scalars.

There are three layers in the module:

1. **Field & group core** (`curve25519.hpp`). `Fe25519` (5 × 51-bit
   limbs, radix 2^51) and `GeP3` extended-coordinate points, plus all
   the constant-time field operations (`fe25519_add`, `fe25519_mul`,
   `fe25519_sq`, `fe25519_invert`, `fe25519_cmov`), Edwards group ops
   (`ge_p3_add`, `ge_p3_dbl`, `ge_scalar_mult_base`,
   `ge_double_scalar_mult_vartime`), scalar-field reduction (`sc_reduce`,
   `sc_mul_add`), and the Montgomery ladder (`curve25519_scalar_mult`).
   `*_secure` variants return `SecureArray<32>` so signing nonces and
   private scalars zero on destruction.
2. **Public primitives** (`x25519.hpp`, `ed25519.hpp`).
   `x25519_keypair_from_seed`, `x25519`, and the low-order rejection
   helper `x25519_shared_secret_is_valid`; `ed25519_keypair_from_seed`,
   `ed25519_sign`, `ed25519_verify`, and the Edwards-to-Montgomery key
   conversions `ed25519_pk_to_x25519_pk` / `ed25519_sk_to_x25519_sk`.
3. **32-bit ALU port** (`curve25519_fe32.hpp`, `x25519_32.hpp`,
   `ed25519_ge32.hpp`). A reduced-radix 32-bit-limb counterpart of
   the field/group/ladder, always compiled and cross-checked against
   the 5×51-bit reference by `*_32_test.cpp`. Lets X25519 and Ed25519
   run on 32-bit targets without `__uint128_t`.

Ed25519 signatures are **deterministic** (RFC 8032 §5.1.6): the nonce
is derived from the private key's nonce prefix and the message, so
signing requires no RNG and is immune to bad randomness. X25519 needs
randomness only for the seed at keypair generation.

## Key types

- `Fe25519` — `curve25519.hpp`. Field element in GF(2^255 − 19), 5 × 51-bit limbs; zeroed on destruction.
- `GeP3` — `curve25519.hpp`. Twisted Edwards point in extended coordinates (X, Y, Z, T).
- `X25519PrivateKey` / `X25519PublicKey` — `keys.hpp`. Private key carries the precomputed public key.
- `Ed25519PrivateKey` / `Ed25519PublicKey` / `Ed25519Signature` — `keys.hpp`. Private key is the SHA-512(seed) expansion: clamped scalar (32 B) + nonce prefix (32 B), with the precomputed public point.
- `x25519_keypair_from_seed` / `x25519` — `x25519.hpp`. Keygen and ECDH; clamps per RFC 7748 §5 internally.
- `x25519_shared_secret_is_valid` — `x25519.hpp`. All-zero-output check; rejects small-order peer keys.
- `ed25519_keypair_from_seed` / `ed25519_sign` / `ed25519_verify` — `ed25519.hpp`. PureEdDSA per RFC 8032 §5.1.6 / §5.1.7. Verify enforces canonical S < L.
- `ed25519_pk_to_x25519_pk` / `ed25519_sk_to_x25519_sk` — `ed25519.hpp`. Reuse an Ed25519 identity for ECDH; the pk conversion returns `std::nullopt` for the identity point.
- `curve25519_scalar_mult` / `curve25519x32_scalar_mult` — `curve25519.hpp` / `x25519_32.hpp`. 64-bit and 32-bit Montgomery-ladder implementations of the same X25519 primitive.

## Public headers

- `statusbar/crypto/25519/x25519.hpp` — X25519 ECDH public API.
- `statusbar/crypto/25519/ed25519.hpp` — Ed25519 sign/verify public API and Edwards↔Montgomery key conversions.
- `statusbar/crypto/25519/curve25519.hpp` — shared field, group, and ladder primitives (64-bit reference implementation).
- `statusbar/crypto/25519/curve25519_fe32.hpp` — 32-bit reduced-radix field arithmetic (portable counterpart).
- `statusbar/crypto/25519/x25519_32.hpp` — X25519 over the 32-bit field.
- `statusbar/crypto/25519/ed25519_ge32.hpp` — Ed25519 group operations over the 32-bit field.
- `statusbar/crypto/25519/curve25519_constants.hpp` / `ed25519_constants.hpp` — base-point and group-order constants.

## Dependencies

- **Statusbar modules:**
  - [`util`](UTIL_MODULE.md) — `SecureArray<N>` and `internal::secure_zero` for stack/value scrubbing.
  - [`sha`](SHA_MODULE.md) — SHA-512 for Ed25519 seed expansion (RFC 8032 §5.1.5) and per-signature hashing.
- **System / external:** `<array>`, `<span>`, `<cstdint>`, `<optional>` from the C++23 standard library; `__uint128_t` on 64-bit targets for the 5×51 field arithmetic.

## Notes & caveats

- **Pre-release, unaudited.** No third-party security review. Treat as
  experimental until that lands.
- **Constant-time scalar mult.** `curve25519_scalar_mult` (X25519
  ladder), `ge_scalar_mult_base` (Ed25519 fixed-base), and the
  `fe25519_cmov` / `fe25519x32_cmov` selection primitives run in
  constant time with respect to secret scalars. The 32-bit
  reduced-radix variants match. The double-scalar verifier
  `ge_double_scalar_mult_vartime` is **deliberately variable-time** —
  call it only with public inputs (signature verification).
- **RFC 7748 §5 clamping** is applied inside `curve25519_scalar_mult`,
  not at keygen — callers passing raw scalars don't need to pre-clamp.
- **Low-order peer keys.** `x25519` returns the raw ladder output;
  callers **must** check `x25519_shared_secret_is_valid` (all-zero
  rejection) before using the secret. RFC 7748 §6.1 leaves this to the
  protocol layer.
- **Verification semantics.** `ed25519_verify` enforces canonical `S < L`
  (rejecting signature malleability) and uses the cofactorless
  encoding-equality check (`[S]B == R + [H(R‖A‖M)]A`, comparing the
  re-encoded `R` byte-for-byte). It does **not** additionally reject
  non-canonical `y` encodings (`y ≥ p`) or small-order public keys, so it
  is permissive rather than strict per RFC 8032 §5.1.7 — results can
  differ from a strict verifier on adversarially-encoded keys/signatures.
- **Test vectors.** X25519 is checked against RFC 7748 §6.1 (Alice/Bob
  ECDH, basepoint iteration); Ed25519 against RFC 8032 §7.1 vectors
  1–4 (empty, 1-byte, 2-byte, 1023-byte). The 32-bit port is
  cross-checked operation-for-operation against the 64-bit reference.
- **Secure scrubbing.** `Fe25519` and `P256*` analogues zero their
  limbs on destruction. Secret intermediate scalars use
  `sc_reduce_secure` / `sc_mul_add_secure` to return `SecureArray<32>`.
- **Threadsafety.** All entry points are pure functions over by-value
  / `const&` inputs; safe to call concurrently from different threads.

## Further reading

- [`p256`](P256_MODULE.md) — sister module: NIST P-256 ECDH/ECDSA.
- [`ecies`](ECIES_MODULE.md) — hybrid encryption built on X25519 (and P-256).
- [`pkcs8`](PKCS8_MODULE.md) — DER key encoding for Ed25519 (RFC 8410).
- [`sha`](SHA_MODULE.md) — SHA-512 used in Ed25519 key expansion and signing.
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — Elliptic Curves for Security (X25519, X448).
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) — Edwards-Curve Digital Signature Algorithm (EdDSA).
