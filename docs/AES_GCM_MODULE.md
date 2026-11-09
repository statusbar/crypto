[← back to module index](README.md)

# aes_gcm

AES-GCM authenticated encryption with associated data, per NIST SP 800-38D:
AES in counter mode with a GHASH authentication tag. AES-128 and AES-256
flavours; 96-bit nonce, 128-bit tag — the AEAD_AES_128_GCM / AEAD_AES_256_GCM
profile of RFC 5116 that RFC 9180 (HPKE) registers as AEAD ids 0x0001 and
0x0002.

> **Pre-release — unaudited.** See the disclaimer in [`README.md`](README.md).
> Implementation tracks SP 800-38D and passes the GCM specification's test
> cases and Project Wycheproof's AES-GCM vectors listed below, but has not
> been third-party audited or fuzzed with constant-time tooling.

## Overview

GCM (SP 800-38D clause 7) encrypts with AES-CTR and authenticates with GHASH,
a polynomial hash over GF(2¹²⁸):

1. **Hash subkey.** `H = E_K(0¹²⁸)`.
2. **Counter block.** For the 96-bit nonce this module offers,
   `J0 = IV || 0³¹ || 1`; block *i* of the message is XORed with
   `E_K(inc32ⁱ(J0))`, `inc32` adding one to the last 32 bits big-endian.
3. **Tag.** `T = GHASH_H(pad(A) || pad(C) || [len(A)]₆₄ || [len(C)]₆₄) ⊕ E_K(J0)`,
   lengths in bits, big-endian.

Decryption verifies `T` over the received ciphertext in constant time before
running CTR (7.2 steps 5–8 before step 4), so a forged message never yields
plaintext; the buffer is zeroed and `false` returned instead.

**GCM is not nonce-misuse resistant.** Two messages under one `(key, nonce)`
reveal the XOR of their plaintexts and let an attacker recover `H` and forge
tags for that key. Every nonce under a key must be unique (SP 800-38D 8.2);
where that cannot be guaranteed use [`aes_gcm_siv`](AES_GCM_SIV_MODULE.md).
A single plaintext is limited to `aes_gcm_max_plaintext_size` = 2³⁹ − 256
bits (2³² − 2 blocks) so the counter never returns to `J0`; longer inputs
are rejected (all-zero tag, nothing encrypted; decrypt returns `false`).

### GHASH over POLYVAL

GHASH and POLYVAL ([`polyval`](POLYVAL_MODULE.md), the universal hash of
AES-GCM-SIV) are the same GF(2¹²⁸) multiplication read with opposite bit
orders, and RFC 8452 Appendix A gives the exact relation:

    GHASH_H(X₁, …, Xₙ) = ByteReverse(POLYVAL_H'(ByteReverse(X₁), …, ByteReverse(Xₙ)))
    H' = mulX_POLYVAL(ByteReverse(H))

`ghash_internal.hpp` implements GHASH as that adapter: the key is converted
once, each block is byte-reversed on the way in, and the accumulator is
byte-reversed on the way out. The carry-less multiplication, its PMULL /
PCLMULQDQ hardware paths and the constant-time software fallback all stay in
the POLYVAL module.

The submodule layers as:

- `aes_gcm.hpp` — the shared constants.
- `ghash_internal.hpp` — GHASH key conversion, block / padded / length-block
  absorption, finalisation (internal namespace).
- `aes_gcm_internal.hpp` — the GCM-AE / GCM-AD core, a template over the
  block-encrypt callable (internal namespace).
- `aes128_gcm.hpp` / `aes256_gcm.hpp` — the public entry points, binding the
  core to the `*_hw` block ciphers of [`aes`](AES_MODULE.md) (AES-NI on
  x86-64, ARMv8 Crypto Extensions on aarch64, software fallback otherwise).

## Key types

- `aes_gcm_nonce_size` — `12` (`constexpr size_t`); nonce length, both flavours.
- `aes_gcm_tag_size` — `16` (`constexpr size_t`); authentication tag length.
- `aes_gcm_max_plaintext_size` — `2^36 - 32` bytes (`constexpr uint64_t`); the per-message limit.
- `aes128_gcm_encrypt(Aes128Key const&, std::span<uint8_t const, 12> nonce, std::span<uint8_t> plaintext_to_ciphertext, std::span<uint8_t const> aad) -> std::array<uint8_t, 16>` — in-place encrypt; returns the tag.
- `aes128_gcm_decrypt(Aes128Key const&, …, std::span<uint8_t const, 16> tag, std::span<uint8_t const> aad) -> bool` — verifies, then decrypts in place; zeros the buffer on failure.
- `aes256_gcm_encrypt` / `aes256_gcm_decrypt` — identical shape with `Aes256Key`.

## Public headers

- `statusbar/crypto/aes_gcm/aes_gcm.hpp` — shared constants.
- `statusbar/crypto/aes_gcm/aes128_gcm.hpp` — AES-128-GCM encrypt / decrypt.
- `statusbar/crypto/aes_gcm/aes256_gcm.hpp` — AES-256-GCM encrypt / decrypt.

## Dependencies

- [`aes`](AES_MODULE.md) — key schedule and block encryption (`*_hw` dispatchers).
- [`polyval`](POLYVAL_MODULE.md) — the GF(2¹²⁸) multiplication behind GHASH.
- [`util`](UTIL_MODULE.md) — `secure_zero`, byte-order loads / stores, the constant-time 16-byte compare.

## Testing

- `ghash_internal_test.cpp` — GHASH against the GCM specification's test case 2
  (H, C and GHASH value published), the RFC 8452 `mulX_POLYVAL` example, and
  chunking / padding transparency.
- `aes128_gcm_test.cpp` / `aes256_gcm_test.cpp` — McGrew & Viega test cases
  1–4 and 13–16 (the SP 800-38D examples), then every Project Wycheproof
  `aes_gcm_test.json` vector with a 96-bit IV and 128-bit tag for that key size
  (67 and 66 vectors: known-answer, pseudorandom, counter wrap inside the
  message, modified tags, special-case GHASH inputs). The vectors live in the
  generated `aes_gcm_wycheproof_vectors.hpp`; regenerate with
  `uv run crypto/python/crypto/gen_aes_gcm_kats.py <aes_gcm_test.json>`.
- `aes_gcm_test.cpp` — round trips over every length up to four blocks plus
  three, rejection and zeroing on a flipped ciphertext bit, tag, AAD or nonce,
  AAD-only messages, and the two key sizes diverging.
- `aes_gcm_fuzzer.cpp` — libFuzzer harness (round trip, flipped bit, dropped AAD).
- Python: `statusbar_crypto.py` exposes the same four functions on top of the
  `cryptography` package for cross-checks.

## Notes & caveats

- 96-bit nonces only; other IV lengths (which GCM hashes through GHASH) and
  truncated tags are deliberately not offered.
- The key schedule runs on every call; a context type that keeps the expanded
  key and `H` across messages can be added when a caller (HPKE) needs it.
- Nonce uniqueness is the caller's responsibility; the module cannot detect reuse.

## Further reading

- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*.
- D. McGrew, J. Viega, *The Galois/Counter Mode of Operation (GCM)*, Appendix B test cases.
- RFC 5116, *An Interface and Algorithms for Authenticated Encryption*, section 5.
- RFC 8452, *AES-GCM-SIV*, Appendix A (GHASH / POLYVAL relation).
- Project Wycheproof, `testvectors_v1/aes_gcm_test.json`.
