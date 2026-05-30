[← back to module index](README.md)

# ecies

Integrated public-key encryption: ECDH key encapsulation + KDF +
authenticated symmetric encryption, in one call. Two flavors — a
P-256 build matching IEEE 1722-2016 clause 17.3.1 (DL/ECIES) and an
X25519 build using HKDF-SHA-256.

## Overview

ECIES is a hybrid scheme: encrypt fresh ephemeral key material with
the recipient's public key (via ECDH), expand the shared secret into
a symmetric encryption key and MAC key with a KDF, then encrypt and
authenticate the actual payload with that symmetric key. Decryption
runs the same ECDH from the other side and verifies before
decrypting.

This module ships two concrete profiles, both producing
`V || C || T` on the wire (ephemeral public key, ciphertext, MAC tag):

| Flavor              | Curve  | ECDH      | KDF           | AEAD              | MAC          | V size | T size |
|---------------------|--------|-----------|---------------|-------------------|--------------|--------|--------|
| `ecies` (P-256)     | P-256  | ECSVDP-DHC| KDF2-SHA-256  | AES-256-CBC-IV0   | HMAC-SHA-256 | 33 B   | 32 B   |
| `x25519_ecies`      | X25519 | X25519    | HKDF-SHA-256  | AES-256-CBC-IV0   | HMAC-SHA-256 | 32 B   | 32 B   |

Both use **AES-256-CBC with a fixed null IV** and PKCS#7 padding for
the bulk cipher, with the symmetric and MAC keys derived freshly per
message from the ephemeral ECDH output. The MAC covers the
ciphertext (encrypt-then-MAC). The P-256 profile follows IEEE
1722-2016 clause 17.3.1 (`enc=0`) using DHAES mode (KDF input is
`V || Z`) and EC2OSP-X point encoding (0x01 || x, 33 B). The X25519
profile follows IEEE 1722-2016 (`enc=1`) with HKDF-SHA-256, a
domain-separated `info` string (`"X25519-ECIES" || V`), and the
native 32-byte X25519 public key as `V`.

Both `encrypt` calls take a caller-supplied 32-byte `entropy` span
for the ephemeral keypair — the module never reads an RNG itself.
Outputs are written into caller-owned buffers; allocate using the
`ecies_output_size(plaintext_len)` / `x25519_ecies_output_size(...)`
constexpr helpers.

Other AEAD/KDF combinations (HKDF + AES-GCM-SIV, KDF2 + AES-SIV,
etc.) are **not** exposed as ECIES profiles — those AEADs are
available standalone (see [`aes_gcm_siv`](AES_GCM_SIV_MODULE.md),
[`aes_siv`](AES_SIV_MODULE.md)) and KDFs ([`hkdf`](HKDF_MODULE.md),
[`kdf2`](KDF2_MODULE.md)) but the ECIES module wires only the two
profiles above.

## Key types

- `ecies_encrypt` / `ecies_decrypt` — `ecies.hpp`. P-256 ECIES per IEEE 1722-2016 §17.3.1. Output layout `V(33) || C || T(32)`; ciphertext block-padded to 16 B.
- `x25519_ecies_encrypt` / `x25519_ecies_decrypt` — `x25519_ecies.hpp`. X25519 ECIES. Output layout `V(32) || C || T(32)`.
- `ecies_output_size(plaintext_len)` / `x25519_ecies_output_size(plaintext_len)` — constexpr buffer-sizing helpers.
- `ecies_fixed_overhead` (65 B) / `x25519_ecies_fixed_overhead` (64 B) — constants for V + T.
- `ecies_ephemeral_key_size`, `x25519_ecies_ephemeral_key_size`, `ecies_mac_tag_size`, `x25519_ecies_mac_tag_size` — V and T sizes.

## Public headers

- `statusbar/crypto/ecies/ecies.hpp` — P-256 / IEEE 1722-2016 §17.3.1 ECIES.
- `statusbar/crypto/ecies/x25519_ecies.hpp` — X25519 / HKDF-SHA-256 ECIES.

## Dependencies

- **Statusbar modules:**
  - [`p256`](P256_MODULE.md) — ECDH (`p256_ecdh`) and point encoding for the P-256 profile.
  - [`25519`](25519_MODULE.md) — X25519 ECDH and low-order-secret rejection for the X25519 profile.
  - [`kdf2`](KDF2_MODULE.md) — KDF2-SHA-256 used by the P-256 profile (DHAES input ordering).
  - [`hkdf`](HKDF_MODULE.md) — HKDF-SHA-256 used by the X25519 profile, with a domain-separated `info` string.
  - [`aes_cbc`](AES_CBC_MODULE.md) — AES-256-CBC-IV0 bulk cipher (PKCS#7 padding); both profiles.
  - [`sha`](SHA_MODULE.md) — HMAC-SHA-256 for the MAC tag and KDF compression.
  - [`util`](UTIL_MODULE.md) — `SecureArray<N>` and constant-time compare for tag verification.
- **System / external:** `<span>`, `<array>`, `<cstdint>`, `<cstddef>` from the C++23 standard library.

## Notes & caveats

- **Pre-release, unaudited.** No third-party review. Wire-format
  conformance to IEEE 1722-2016 §17.3.1 has been tested by the
  in-tree test suite; full interop with other ECIES implementations
  beyond that has not been validated.
- **Constant-time posture is bounded by the AES backend.** ECDH,
  KDF, and HMAC layers are constant-time. AES-256-CBC delegates to
  the [`aes`](AES_MODULE.md) module, which is constant-time **only**
  when an AES-NI / ARMv8 Crypto Extensions hardware path is
  available. On platforms without hardware AES the software T-table
  is potentially vulnerable to cache-timing side channels (Prime+
  Probe, Spectre-class). Verify your platform's capability before
  using ECIES for high-value key material — see
  [`HARDWARE_ACCELERATION.md`](HARDWARE_ACCELERATION.md).
- **Encrypt-then-MAC.** Decryption verifies the HMAC tag **before**
  unpadding / returning the plaintext, with a constant-time
  comparator. Padding-oracle attacks against AES-CBC-IV0 are
  prevented as long as the MAC is checked first; the public API
  enforces that ordering.
- **Fixed null IV is safe here.** The AES key is derived freshly per
  message from the ephemeral ECDH output, so the IV-reuse concern
  that plagues general AES-CBC does not apply: every encryption uses
  a unique key.
- **Caller-supplied entropy.** Both `*_encrypt` calls require 32 B of
  entropy for the ephemeral keypair. Pass cryptographically secure
  randomness; reusing entropy across encryptions destroys the
  scheme.
- **Low-order peer keys.** The X25519 profile rejects all-zero ECDH
  outputs (RFC 7748 §6.1) before deriving keys. The P-256 profile
  validates the peer point lies on the curve during ECDH; cofactor 1
  means there are no low-order subgroups to guard against.
- **Threadsafety.** All entry points are pure; safe under
  concurrency given independent input/output buffers.

## Further reading

- [`25519`](25519_MODULE.md) — X25519 ECDH used by `x25519_ecies`.
- [`p256`](P256_MODULE.md) — P-256 ECDH used by `ecies`.
- [`hkdf`](HKDF_MODULE.md) — KDF for the X25519 profile.
- [`kdf2`](KDF2_MODULE.md) — KDF for the P-256 profile.
- [`aes_cbc`](AES_CBC_MODULE.md) — AES-256-CBC-IV0 bulk cipher used by both profiles.
- [`aes_gcm_siv`](AES_GCM_SIV_MODULE.md) / [`aes_siv`](AES_SIV_MODULE.md) — alternative AEADs, **not** wired into the ECIES profiles here.
- [`HARDWARE_ACCELERATION.md`](HARDWARE_ACCELERATION.md) — AES cache-timing posture per platform.
- [IEEE 1722-2016 clause 17.3.1](https://standards.ieee.org/standard/1722-2016.html) — DL/ECIES profile (P-256 flavor).
- [IEEE 1363a-2004 §11.3](https://standards.ieee.org/standard/1363a-2004.html) — DL/ECIES scheme.
