[← back to module index](README.md)

# aes_siv

AES-SIV deterministic / nonce-misuse-resistant authenticated encryption per
RFC 5297. Two-pass AEAD built from AES-CMAC (for the synthetic IV) and AES-CTR
(for encryption). AES-128-SIV (32-byte combined key, two AES-128 keys) and
AES-256-SIV (64-byte combined key, two AES-256 keys) flavours; 16-byte SIV
tag.

> **Pre-release — unaudited.** See the disclaimer in [`README.md`](README.md).
> Implementation tracks RFC 5297 and passes the RFC test vectors plus
> cross-checks against the Python `cryptography` reference, but it has not
> been third-party audited and is not constant-time-validated with
> `ctgrind` / `dudect`.

## Overview

AES-SIV is the original nonce-misuse-resistant AEAD construction: by deriving
the encryption IV synthetically from the input itself (via CMAC), it
guarantees that encrypting two distinct messages — even under the *same*
nonce, or with *no* nonce at all — yields independent ciphertexts whose
authentication tag still holds. It is the strongest of the misuse-resistant
modes in this package for long-lived keys (see the per-key message budget
comparison in [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md)).

This submodule provides both RFC 5297 flavours. The combined key is split in
half: the first half (`K1`) drives the S2V CMAC-based authentication step,
and the second half (`K2`) drives the AES-CTR encryption step. For
AES-128-SIV that is 16 + 16 = 32 bytes of key material (`Aes128SivKey`,
two independent AES-128 keys); for AES-256-SIV it is 32 + 32 = 64 bytes
(`Aes256SivKey`, two independent AES-256 keys). The key structs are
defined in [`keys.hpp`](../statusbar/crypto/keys.hpp) and zero their bytes
on destruction.

Algorithm sketch (RFC 5297 §2):

1. **S2V derivation.** Compute a 16-byte synthetic IV (the "SIV") from a
   sequence of associated-data strings and the plaintext, using CMAC keyed
   with `K1`. The construction starts with `D = CMAC(K1, 0¹²⁸)` and
   accumulates each AD string via `D = dbl(D) xor CMAC(K1, AD_i)`. For the
   final input (the plaintext when ≥ 16 bytes), the helper
   `cmac_xorend` from [`aes`](AES_MODULE.md) folds `D` into the last block
   without copying the plaintext.
2. **AES-CTR encryption.** Clear the two reserved bits in the SIV
   (per RFC 5297 §2.6) to produce the CTR initial counter, then encrypt
   the plaintext in place under `K2` using a 32-bit big-endian counter.
3. **Output.** The SIV doubles as the authentication tag and is returned
   directly from `encrypt()`; the caller transmits both the tag and the
   ciphertext.

Decrypt inverts the process: run CTR with the supplied SIV as the counter
seed, then recompute S2V over the recovered plaintext and AAD, then
constant-time-compare against the supplied SIV. On mismatch the plaintext
buffer is zeroed and `false` is returned so callers cannot consume
unauthenticated bytes.

Per-key budgets and message-size limits are different from AES-GCM-SIV:
~2⁶⁴ messages per key (deterministic SIV, 128-bit birthday bound) versus
2³² for AES-GCM-SIV. AES-256-SIV explicitly bounds plaintext at 2³⁶ bytes
(64 GB) — this matches the AES-CTR 32-bit-counter limit and is enforced
at the entry point: oversize inputs return an all-zero SIV and decrypt
rejects oversize ciphertexts.

## Key types

- `Aes128SivKey` — 32-byte combined key, declared in `keys.hpp`; bytes 0..15 = CMAC key, bytes 16..31 = CTR key. Zeroed on destruction.
- `Aes256SivKey` — 64-byte combined key; bytes 0..31 = CMAC key, bytes 32..63 = CTR key. Zeroed on destruction.
- `aes128_siv_encrypt(Aes128SivKey const&, std::span<uint8_t> plaintext_to_ciphertext, std::span<uint8_t const> aad) -> std::array<uint8_t, 16>` — in-place encrypt; returns the 16-byte SIV tag.
- `aes128_siv_decrypt(Aes128SivKey const&, …, std::span<uint8_t const, 16> siv, std::span<uint8_t const> aad) -> bool` — in-place decrypt; constant-time tag check; plaintext is zeroed on failure.
- `aes256_siv_encrypt` / `aes256_siv_decrypt` — same shape; AES-256-CTR + AES-256-CMAC under the hood. Enforces the 2³⁶-byte plaintext limit (returns an empty SIV / `false` if exceeded).

## Public headers

- `statusbar/crypto/aes_siv/aes128_siv.hpp` — AES-128-SIV encrypt / decrypt.
- `statusbar/crypto/aes_siv/aes256_siv.hpp` — AES-256-SIV encrypt / decrypt.

(No shared umbrella header; each key size is independent.)

## Dependencies

- **Statusbar modules:** [`aes`](AES_MODULE.md) — block cipher, key expansion, CMAC, and especially `aes*_cmac_xorend_hw` for the S2V final-block fold; [`util`](UTIL_MODULE.md) — `secure_zero`, span helpers; [`keys`](../statusbar/crypto/keys.hpp) — `Aes128SivKey` / `Aes256SivKey`.
- **System / external:** `<array>`, `<cstdint>`, `<span>`.

## Notes & caveats

- **Single string of associated data.** The public API exposes one AAD span, not a vector of AD strings. RFC 5297's S2V is defined over an ordered list; callers that need multiple AD components must concatenate (and pin the framing) themselves. This is the same shape `pyca/cryptography`'s `AESSIV` uses for cross-validation.
- **Per-key message budget (~2⁶⁴).** SIV's per-message authentication tag is derived deterministically from the input, so the birthday bound on tag collisions is 2⁶⁴ messages under a single key. For AVB streaming this is effectively unlimited — see [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md) for the comparison with AES-GCM-SIV's 2³² budget.
- **Per-message size limit.** AES-256-SIV enforces 2³⁶ bytes (64 GB) at the entry point per RFC 5297 §2.4; oversize inputs return an empty SIV from `encrypt()` and `false` from `decrypt()`. AES-128-SIV inherits the same algorithmic limit but does not currently include the explicit guard — keep messages well below 64 GB regardless.
- **128 vs 256 keys.** The 128-bit AES block size — not the key size — bounds the per-key message count and per-message size. The 256-bit variant only adds key-strength margin (and quantum resistance). See [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md).
- **Constant-time posture.** Tag comparison uses `internal::constant_time_equal`. Hardware AES paths are constant-time by construction; software fallbacks use S-box lookups and are not. Prefer hosts with AES-NI or ARMv8 Crypto Extensions for any side-channel-sensitive deployment.
- **Zeroisation on decrypt failure.** The plaintext buffer is wiped before `decrypt()` returns `false`.
- **Test conformance.** `aes128_siv_test.cpp` covers RFC 5297 Appendix A.1 (the deterministic-authenticated-encryption vector). `aes256_siv_test.cpp` uses test vectors generated from the Python `cryptography` library's `AESSIV` primitive (RFC 5297 does not publish AES-256-SIV vectors directly). Both are cross-checked end-to-end via `python/crypto/`.
- **Fuzz coverage.** `aes_siv_fuzzer.cpp` and `aes128_siv_fuzzer.cpp` exercise the decrypt parsers. See [`FUZZING.md`](FUZZING.md).
- **Thread-safety.** Stateless; concurrent calls with distinct buffers are safe.

## Further reading

- [`AES`](AES_MODULE.md) — block cipher, CMAC, and `cmac_xorend` helper consumed by the S2V step.
- [`AES-GCM-SIV`](AES_GCM_SIV_MODULE.md) — alternative nonce-misuse-resistant AEAD; POLYVAL-based; lower per-key message budget but single-pass.
- [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md) — when to pick which key size and which mode.
- [`HARDWARE_ACCELERATION.md`](HARDWARE_ACCELERATION.md) — AES feature detection.
- [RFC 5297 — Synthetic Initialization Vector (SIV) Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc5297.html)
- [RFC 4493 — The AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493.html) (underlying authenticator).
