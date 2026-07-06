[← back to module index](README.md)

# aes_gcm_siv

AES-GCM-SIV nonce-misuse-resistant authenticated encryption with associated
data, per RFC 8452. Single-pass AEAD built from AES counter mode and POLYVAL
(a GF(2¹²⁸) universal hash). AES-128 and AES-256 flavours; 12-byte nonce,
16-byte tag.

> **Pre-release — unaudited.** See the disclaimer in [`README.md`](README.md).
> Implementation tracks RFC 8452 and passes the RFC and POLYVAL test vectors
> listed below, but has not been third-party audited or fuzzed with
> constant-time tooling.

## Overview

AES-GCM-SIV is a nonce-misuse-resistant AEAD: reusing a `(key, nonce)` pair
does not catastrophically destroy confidentiality the way it does in plain
AES-GCM. It merely leaks whether two encryptions covered identical
`(plaintext, AAD)` inputs. The construction is RFC 8452; this submodule
provides both flavours from the RFC — AES-128-GCM-SIV (16-byte key) and
AES-256-GCM-SIV (32-byte key).

Both flavours use the same nonce and tag size: 12 bytes (`aes_gcm_siv_nonce_size`)
and 16 bytes (`aes_gcm_siv_tag_size`) respectively. These constants live in
`aes_gcm_siv.hpp` and are shared between the two key sizes.

Algorithm sketch (RFC 8452 §4):

1. **Per-message key derivation.** Encrypt counter blocks under the master
   key to derive two subkeys — a 16-byte POLYVAL authentication key plus an
   encryption key (16 bytes for AES-128-GCM-SIV, 32 bytes for AES-256-GCM-SIV).
   The counter blocks bind the derived keys to the supplied nonce.
2. **POLYVAL tag computation.** Hash AAD ‖ pad ‖ plaintext ‖ pad ‖ lengths
   under the auth subkey to produce a 16-byte tag candidate; XOR in the
   nonce, mask the top bit, encrypt under the encryption subkey to obtain
   the final authentication tag. The tag depends on the entire plaintext
   and AAD, which is what gives the scheme its misuse resistance.
3. **AES-CTR encryption.** Encrypt the plaintext under the encryption
   subkey using the authentication tag (with its top bit set) as the
   initial counter. The 32-bit little-endian counter increments per block.

Decrypt inverts the steps: derive keys, run CTR over the ciphertext, run
POLYVAL over the recovered plaintext, and compare against the supplied tag
in constant time. On verification failure the plaintext buffer is zeroed
before `false` is returned so callers cannot accidentally consume
unauthenticated bytes.

The submodule layers as:

- `aes_gcm_siv.hpp` — shared constants and a re-export of the POLYVAL
  software types from [`polyval`](POLYVAL_MODULE.md). Backward-compat shim;
  consumers usually `#include` the key-size-specific header directly.
- `aes128_gcm_siv.hpp` / `aes256_gcm_siv.hpp` — the encrypt/decrypt entry
  points. Each header pulls in the matching key size from
  [`aes`](AES_MODULE.md) (`aes128.hpp` / `aes256.hpp`) and the shared
  constants header above.

Block-cipher calls go through the `*_hw` wrappers in `aes/` and inherit
runtime hardware dispatch (AES-NI on x86-64; ARMv8 Crypto Extensions on
aarch64). POLYVAL itself ships hardware paths in [`polyval`](POLYVAL_MODULE.md)
using PCLMULQDQ on x86-64 and `vmull_p64` on aarch64.

## Key types

- `aes_gcm_siv_nonce_size` — `12` (`constexpr size_t`); nonce length, both flavours.
- `aes_gcm_siv_tag_size` — `16` (`constexpr size_t`); authentication tag length.
- `aes128_gcm_siv_encrypt(Aes128Key const&, std::span<uint8_t const, 12> nonce, std::span<uint8_t> plaintext_to_ciphertext, std::span<uint8_t const> aad) -> std::array<uint8_t, 16>` — in-place encrypt; returns tag.
- `aes128_gcm_siv_decrypt(Aes128Key const&, …, std::span<uint8_t const, 16> tag, std::span<uint8_t const> aad) -> bool` — in-place decrypt; verifies tag, zeros plaintext buffer on failure.
- `aes256_gcm_siv_encrypt` / `aes256_gcm_siv_decrypt` — identical shape, `Aes256Key` instead of `Aes128Key`. Key derivation step extends to 6 counter blocks (48 bytes) so the encryption subkey is 32 bytes.

## Public headers

- `statusbar/crypto/aes_gcm_siv/aes_gcm_siv.hpp` — shared constants, POLYVAL re-export.
- `statusbar/crypto/aes_gcm_siv/aes128_gcm_siv.hpp` — AES-128-GCM-SIV encrypt / decrypt.
- `statusbar/crypto/aes_gcm_siv/aes256_gcm_siv.hpp` — AES-256-GCM-SIV encrypt / decrypt.

## Dependencies

- **Statusbar modules:** [`aes`](AES_MODULE.md) — block cipher + key expansion for both key sizes; [`polyval`](POLYVAL_MODULE.md) — GF(2¹²⁸) hash; [`util`](UTIL_MODULE.md) — `secure_zero`, span helpers; [`keys`](../statusbar/crypto/keys.hpp) — `Aes128Key` / `Aes256Key`.
- **System / external:** `<array>`, `<cstdint>`, `<span>`, `<cstddef>`.

## Notes & caveats

- **Nonce uniqueness still matters.** Misuse resistance is *graceful degradation*, not a licence to reuse nonces. Reusing `(key, nonce)` with the same `(plaintext, AAD)` produces identical ciphertext+tag and lets an attacker detect repetition; reusing with different inputs is safe for authenticity but weakens confidentiality below the design's full strength. Both headers carry an explicit `WARNING` to that effect. The AVTP usage pattern derives the 12-byte nonce from a monotonic sequence number.
- **Per-key message volume.** RFC 8452's security proof degrades after roughly 2³² messages under a single key with random nonces (extendable to 2⁴⁸ with deterministic nonces). For long-lived session keys, see the comparison with AES-SIV in [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md).
- **Per-message size.** Bounded per RFC 8452 §6 at 2³⁶ bytes of plaintext and 2³⁶ bytes of AAD, each independently. The implementation enforces these at the entry point (plus a 32-bit CTR-counter bound on the plaintext/ciphertext length); oversize inputs return an all-zero tag from `encrypt` and `false` from `decrypt`.
- **128 vs 256 key.** No difference in nonce/tag size or data-volume limits; both are gated by the 128-bit AES block size and the POLYVAL field. The 256-bit key adds quantum margin (see [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md)).
- **Constant-time posture.** Tag comparison uses constant-time equality. Hardware AES + PCLMUL paths are inherently constant-time; software fallbacks (S-box, soft POLYVAL) are not — verify your platform exposes AES-NI / ARMv8 AES if you care about side channels. See [`HARDWARE_ACCELERATION.md`](HARDWARE_ACCELERATION.md).
- **Zeroisation on decrypt failure.** The plaintext span is wiped before `decrypt()` returns `false`, so a caller cannot accidentally use unauthenticated bytes.
- **Key material lifetime.** `Aes128Key` / `Aes256Key` zero on destruction; the per-message derived subkeys are local to the encrypt/decrypt frames and not exposed.
- **Test conformance.** `aes_gcm_siv_test.cpp` covers RFC 8452 Appendix A (POLYVAL) and the dot-product test vector; `aes128_gcm_siv_test.cpp` and `aes256_gcm_siv_test.cpp` cover RFC 8452 Appendix C.1 / C.2 known-answer vectors (including the C.1 test 2 POLYVAL intermediate value). Cross-checked against `pycryptodome` in `python/crypto/`.
- **Fuzz coverage.** `aes_gcm_siv_fuzzer.cpp`, `aes128_gcm_siv_fuzzer.cpp` cover the decrypt parsers. See [`FUZZING.md`](FUZZING.md). (No standalone `aes256_gcm_siv_fuzzer.cpp` is present — the shared fuzzer exercises both key sizes via the common path.)
- **Thread-safety.** Stateless; concurrent calls with distinct buffers are safe.

## Further reading

- [`AES`](AES_MODULE.md) — block cipher and key expansion used in key derivation and CTR.
- [`POLYVAL`](POLYVAL_MODULE.md) — GF(2¹²⁸) universal hash used for the auth step.
- [`AES-SIV`](AES_SIV_MODULE.md) — alternative nonce-misuse-resistant AEAD; CMAC-based instead of POLYVAL-based; higher per-key message budget but two-pass.
- [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md) — design note on choosing between key sizes and between SIV / GCM-SIV.
- [`HARDWARE_ACCELERATION.md`](HARDWARE_ACCELERATION.md) — AES-NI / ARMv8 / PCLMUL feature detection.
- [RFC 8452 — AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc8452.html)
