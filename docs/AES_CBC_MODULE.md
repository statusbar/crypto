[← back to module index](README.md)

# aes_cbc

AES-256 in Cipher Block Chaining mode with an all-zero IV and PKCS#7 padding,
as specified in IEEE 1363a-2004 §14.3.2 and used by IEEE 1722-2016 §17.3.1
for ECIES key wrapping. Encrypt and decrypt only; **not authenticated**.

> **Pre-release — unaudited.** See the disclaimer in [`README.md`](README.md).
> CBC is unauthenticated by design; pair it with an explicit MAC, prefer
> AES-SIV / AES-GCM-SIV for general use, and keep this entry point reserved
> for the IEEE 1363a-2004 ECIES profile it was written for.

## Overview

The `aes_cbc` submodule is intentionally narrow: it exposes exactly one
encrypt/decrypt pair, both pinned to AES-256, both pinned to the **CBC-IV0**
profile (initialisation vector = sixteen zero bytes) and PKCS#7 padding. No
other key size, no caller-supplied IV, no streaming API. This is the shape
required by the ECIES construction in IEEE 1363a-2004 §14.3.2 — see also
IEEE 1722-2016 clause 17.3.1, the AVTP key-wrapping context that motivates
its inclusion in this package.

PKCS#7 padding is unconditional. For any plaintext length `n`, ciphertext
length is `((n / 16) + 1) * 16` — always a multiple of sixteen, always at
least one full block of padding (so a 16-byte plaintext expands to 32 bytes
of ciphertext). The padding byte value equals the padding length, ranging
from `0x01` through `0x10`. `aes_cbc_iv0_ciphertext_size()` is `constexpr`
so callers can size output buffers at compile time when the plaintext size
is known.

Both functions defer all block work to `aes256_expand_key_hw` and
`aes256_encrypt_block_hw` / `aes256_decrypt_block_hw` from the
[`aes`](AES_MODULE.md) submodule. On hosts with AES-NI or ARMv8 Crypto
Extensions, that means cache-timing-resistant block operations; on hosts
without, it means the software S-box fallback (see caveats below).

The encrypt path emits ciphertext into a caller-provided span and chains
sequentially: `C[0] = AES(K, P[0] xor 0)`, `C[i] = AES(K, P[i] xor C[i-1])`,
with the padding block appended after the plaintext. The decrypt path
inverts that chain, verifies the PKCS#7 padding in constant time, and
returns a span pointing at the unpadded plaintext on success or an empty
span on failure.

## Key types

- `aes_cbc_iv0_ciphertext_size(size_t plaintext_len)` — `constexpr`; returns the post-padding ciphertext length.
- `aes256_cbc_iv0_encrypt(Aes256Key const&, std::span<uint8_t const> plaintext, std::span<uint8_t> ciphertext)` — encrypts with PKCS#7 padding; returns a const-view of the written ciphertext, or an empty span if the output buffer is too small.
- `aes256_cbc_iv0_decrypt(Aes256Key const&, std::span<uint8_t const> ciphertext, std::span<uint8_t> plaintext)` — decrypts and verifies PKCS#7 padding; returns the plaintext span on success or an empty span on padding failure. Computation is constant-time but the empty-vs-non-empty return distinguishes success from failure.

## Public headers

- `statusbar/crypto/aes_cbc/aes_cbc.hpp` — the only header; declares the encrypt/decrypt pair plus the size helper.

## Dependencies

- **Statusbar modules:** [`aes`](AES_MODULE.md) — `Aes256RoundKeys`, `aes256_expand_key_hw`, `aes256_encrypt_block_hw`, `aes256_decrypt_block_hw`. [`util`](UTIL_MODULE.md) — `internal::span_copy`, `internal::span_fill`. [`keys`](../statusbar/crypto/keys.hpp) — `Aes256Key`.
- **System / external:** `<cstddef>`, `<cstdint>`, `<span>`, `<cstring>`.

## Notes & caveats

- **Unauthenticated.** CBC provides confidentiality only; an attacker who controls the ciphertext can flip plaintext bits in predictable ways. Always pair with an integrity check appropriate to the surrounding protocol — for ECIES, the outer construction's MAC fills that role; for general use, prefer [AES-SIV](AES_SIV_MODULE.md) or [AES-GCM-SIV](AES_GCM_SIV_MODULE.md).
- **All-zero IV.** This is the IEEE 1363a-2004 "CBC-IV0" profile, *not* general-purpose CBC. Encrypting two distinct plaintexts with the same key under this entry point leaks whether they share a common prefix at block granularity. Safe only when the key is freshly derived for one message (which is exactly the IEEE 1363a ECIES usage pattern).
- **Padding-oracle posture.** Decrypt returns an empty span on padding failure; the padding check and the empty-span computation are constant-time *internally*, but the return value itself is a one-bit oracle. Callers must not amplify it — no different error messages, no different latency in caller-side handling. The header carries a `@warning` to that effect; see also `aes_cbc.hpp` lines 60–67.
- **Hardware-vs-software side channels.** Block ops dispatch through `*_hw` wrappers and inherit AES-NI / ARMv8 constant-time guarantees where available; on software fallback they are exposed to cache-timing attacks. See [`HARDWARE_ACCELERATION.md`](HARDWARE_ACCELERATION.md) and the caveats in [`AES_MODULE.md`](AES_MODULE.md).
- **No AES-128 variant** is provided. The protocol that drives this submodule (IEEE 1722 / IEEE 1363a ECIES) standardises on AES-256 for the symmetric envelope. If you need AES-128-CBC for a different protocol, prefer AES-SIV / GCM-SIV instead — adding another CBC entry point is a deliberate non-goal.
- **Test posture.** `aes_cbc_test.cpp` covers round-trip encrypt/decrypt, block-aligned input (forcing a full padding block), and varied lengths through Python `cryptography` cross-checks (see `python/crypto/`). The implementation does **not** ship inline RFC 3602 / NIST CAVP test vectors — conformance is validated through round-trip plus the Python reference cross-check; add fixed KATs here if the CAVP set becomes a hard requirement.
- **Fuzz coverage.** `aes_cbc_fuzzer.cpp` drives the decrypt path with arbitrary input. See [`FUZZING.md`](FUZZING.md).
- **Thread-safety.** Stateless; safe to call concurrently with distinct buffers. The `Aes256Key` and the per-call `Aes256RoundKeys` are caller-local.

## Further reading

- [`AES`](AES_MODULE.md) — underlying block cipher and key expansion.
- [`AES-SIV`](AES_SIV_MODULE.md), [`AES-GCM-SIV`](AES_GCM_SIV_MODULE.md) — authenticated alternatives; prefer these for any new design.
- [`ECIES`](ECIES_MODULE.md) — the IEEE 1363a-2004 ECIES envelope this submodule was written for.
- [`HARDWARE_ACCELERATION.md`](HARDWARE_ACCELERATION.md) — runtime AES feature detection.
- [IEEE 1363a-2004](https://standards.ieee.org/ieee/1363a/2747/) §14.3.2 — CBC-IV0 with PKCS#7 padding.
- [IEEE 1722-2016](https://standards.ieee.org/ieee/1722/5806/) §17.3.1 — AVTP key-wrap usage.
- [RFC 3602](https://www.rfc-editor.org/rfc/rfc3602) — AES-CBC test vectors (general reference; not embedded in this module's tests).
- [FIPS 81](https://csrc.nist.gov/csrc/media/publications/fips/81/archive/1980-12-02/documents/fips81.pdf) — original DES modes of operation, including CBC.
