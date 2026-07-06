[← back to module index](README.md)

# aes

AES-128 and AES-256 block cipher per FIPS 197, plus AES-CMAC per NIST SP 800-38B
/ RFC 4493. Runtime-dispatched hardware acceleration on ARMv8 Crypto Extensions
and x86-64 AES-NI, with constant-time-as-possible software fallbacks.

> **Pre-release — unaudited.** Mirrors the disclaimer in [`README.md`](README.md):
> the implementation tracks the published standards and passes the NIST/RFC
> known-answer vectors below, but it has not been third-party audited and has
> not been validated with `ctgrind` / `dudect`. Prefer a vetted library for
> production deployments with strong cryptographic requirements.

## Overview

The `aes` submodule is the lowest-level symmetric primitive in `statusbar-crypto`.
Every higher-level construction in the package — CBC, SIV, GCM-SIV, CMAC-based
key derivation — is built on the block-cipher and CMAC entry points exposed
here. The submodule supplies two key sizes (128-bit / 10 rounds and 256-bit /
14 rounds) and exposes them through a uniform pair of headers: `aes128.hpp` /
`aes256.hpp` for the software implementations and `aes128_hw.hpp` /
`aes256_hw.hpp` for the hardware-accelerated wrappers.

A round-key struct (`Aes128RoundKeys` / `Aes256RoundKeys`) carries the expanded
key schedule. These structs are move-only, zero their backing storage on
destruction (via `internal::secure_zero` from
[`util`](UTIL_MODULE.md)), and are produced by `aes*_expand_key_sw` /
`aes*_expand_key_hw`. The same struct feeds both software and hardware
block functions — the round-key bytes are identical; only the consumer differs.

Hardware paths are compiled per target architecture: `aes128_hw_arm64.cpp` /
`aes256_hw_arm64.cpp` use the ARMv8 `AESE` / `AESMC` (encrypt) and `AESD` /
`AESIMC` (decrypt) intrinsics; `aes128_hw_amd64.cpp` / `aes256_hw_amd64.cpp`
use AES-NI (`_mm_aesenc_si128`, `_mm_aesdec_si128`, `_mm_aeskeygenassist_si128`).
On x86-64 the dispatcher consults CPUID leaf 1, ECX bit 25 once (cached in a
function-local `static`) and routes per-call to AES-NI or the software fallback;
ARMv8 paths rely on the build target having `__ARM_FEATURE_AES`. Where the
host lacks acceleration, every `_hw` entry point silently degrades to the
software path so callers never need to branch. A pipelined four-block helper
(`aes128_encrypt_blocks_x4_hw`) is exposed so CTR-mode and GHASH workloads can
saturate the AES execution units.

AES-CMAC (RFC 4493 / NIST SP 800-38B) is co-located with the block cipher
because it is essentially a CBC-MAC variant that needs only `encrypt_block`.
The CMAC core (`internal::cmac_core`, `cmac_xorend_core`, `cmac_verify_core`
in `aes_common_internal.hpp`) is a template parameterised on the encrypt
function, so each key size and dispatch path reuses one tested implementation.
The `cmac_xorend` variant is the helper RFC 5297 §2.4 needs for AES-SIV's S2V
construction; tag verification uses `internal::constant_time_equal` over
fixed-size 16-byte spans.

The shared software state — S-box, inverse S-box, `xtime`, `gf_mul`,
`ShiftRows` / `MixColumns` etc. — lives in `aes_common_internal.hpp` so the
AES-128 and AES-256 software encoders share one set of tables. That header
carries an explicit cache-timing warning: table-based AES is the fallback,
not the preferred path, and is only reached when no hardware AES is present.

The design rationale for offering both key sizes (and when to pick which) is
documented separately in [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md).

## Key types

- `Aes128Key`, `Aes256Key` — POD key structs from [`keys.hpp`](../statusbar/crypto/keys.hpp); zeroed on destruction.
- `Aes128RoundKeys`, `Aes256RoundKeys` — expanded key schedules; move-only, zeroed on destruction. 11 round keys for AES-128, 15 for AES-256.
- `aes128_expand_key_sw` / `aes128_expand_key_hw` (and 256-bit equivalents) — produce a `*RoundKeys` from a raw key. The `_hw` variants share the software key schedule on ARM64; on x86-64 AES-NI uses `AESKEYGENASSIST`.
- `aes128_encrypt_block_sw` / `aes128_encrypt_block_hw` / `aes128_decrypt_block_*` — single 16-byte block, encrypted/decrypted in place. AES-256 has the same set.
- `aes128_encrypt_blocks_x4_hw` — interleaved four-block encrypt for CTR-style workloads.
- `aes128_cmac_sw` / `aes128_cmac_hw` — RFC 4493 CMAC tag; arbitrary-length input. AES-256 variants live in `aes256.hpp` / `aes256_hw.hpp`.
- `aes128_cmac_xorend_*` — CMAC over a message with the last 16 bytes XORed against a caller-supplied mask, without copying the message (used by AES-SIV's S2V).
- `aes128_cmac_verify_*` — constant-time tag comparison wrapping `cmac_core`.
- `internal::cmac_core`, `cmac_xorend_core`, `cmac_verify_core`, `cmac_derive_subkeys`, `constant_time_equal` — shared internals in `aes_common_internal.hpp`.

## Public headers

- `statusbar/crypto/aes/aes128.hpp` — software AES-128 block + CMAC; `Aes128RoundKeys`, round/block-size constants.
- `statusbar/crypto/aes/aes128_hw.hpp` — hardware-accelerated AES-128 (same API, `_hw` suffix) plus the four-block pipelined helper.
- `statusbar/crypto/aes/aes256.hpp` — software AES-256 block + CMAC; `Aes256RoundKeys`.
- `statusbar/crypto/aes/aes256_hw.hpp` — hardware-accelerated AES-256.
- `statusbar/crypto/aes/aes_common_internal.hpp` — internal: S-box tables, `State`, CMAC subkey derivation, templated CMAC cores. Not part of the public API; documented here only because every higher-level CMAC user reaches it via the `_sw` / `_hw` wrappers.

## Dependencies

- **Statusbar modules:** [`core`](../../core/docs/) — `statusbar/buffer/span_utils.hpp` for `span_copy`; [`util`](UTIL_MODULE.md) — `internal::secure_zero`, `span_fill`, `secure_array`.
- **System / external:** `<array>`, `<cstdint>`, `<span>`, `<cstring>`. On x86-64: `<cpuid.h>`, `<immintrin.h>`, `<wmmintrin.h>` (AES-NI / SSE2). On aarch64: `<arm_neon.h>` (ARMv8 Crypto Extensions).

## Notes & caveats

- **Hardware-vs-software side channels.** AES-NI and ARMv8 `AESE` / `AESD` are constant-time by construction. The software fallback uses 256-byte S-box lookups and is therefore exposed to cache-timing attacks (Prime+Probe, Flush+Reload, Spectre-class observers). `aes_common_internal.hpp` carries a `@warning` to that effect. Verify hardware AES is available if you care about side channels. On x86-64 the backend does a runtime CPUID probe (AES-NI) and falls back to software when absent; on ARM64 selection is compile-time only (`__ARM_FEATURE_AES`), with no runtime probe — a build with the extension must run only on cores that have it. Neither is surfaced as a public "hardware active" predicate.
- **Round-key lifetime.** `Aes*RoundKeys` is non-copyable, move-only, and zeros its bytes both on destructive move and on destruction. Treat each schedule as bound to one logical key.
- **CMAC subkey derivation is constant-time.** `cmac_derive_subkeys` masks on the MSB of `L` instead of branching, matching RFC 4493 / SP 800-38B without leaking the top bit.
- **Tag verification.** `aes*_cmac_verify_*` uses `constant_time_equal` over a fixed 16-byte span; never reach for `std::memcmp` against a tag.
- **Test conformance.** `aes128_test.cpp` covers FIPS 197 Appendix B (encrypt/decrypt + key expansion against Appendix A.1) and RFC 4493 CMAC Examples 1–4 (lengths 0 / 16 / 40 / 64). `aes256_test.cpp` covers FIPS 197 Appendix C.3 plus NIST SP 800-38B AES-256-CMAC vectors and Appendix A.3 key-expansion vectors. `aes*_hw_test.cpp` cross-checks the hardware path against the software path for both key sizes; `aes_common_internal_test.cpp` exercises `xtime`, `gf_mul`, the state load/store, and the constant-time comparator.
- **Fuzz harnesses.** `aes_fuzzer.cpp` and `aes_cmac_fuzzer.cpp` drive arbitrary-length inputs through the public API. See [`FUZZING.md`](FUZZING.md).
- **Thread-safety.** No global mutable state; one `Aes*RoundKeys` per thread per key is the intended usage. The CPUID cache on x86-64 is a function-local `static` initialised once.
- **Block size is fixed at 128 bits** for both key sizes (FIPS 197). Padding, IVs, and chaining are entirely the caller's (or higher mode's) responsibility — this submodule does single-block ECB and CMAC, nothing more.

## Further reading

- [`AES128_VS_AES256_REPORT.md`](AES128_VS_AES256_REPORT.md) — design note on when to choose 128 vs 256 keys for AVB / streaming workloads (key size, performance, quantum margin, data-volume limits).
- [`AES-CBC`](AES_CBC_MODULE.md) — AES-256-CBC-IV0 chaining mode (no authentication).
- [`AES-SIV`](AES_SIV_MODULE.md) — RFC 5297 deterministic AEAD; consumes `aes*_cmac_xorend_*` from this module.
- [`AES-GCM-SIV`](AES_GCM_SIV_MODULE.md) — RFC 8452 nonce-misuse-resistant AEAD; consumes block + CTR from this module and POLYVAL from [`polyval`](POLYVAL_MODULE.md).
- [Hardware acceleration overview](HARDWARE_ACCELERATION.md) — runtime feature detection across the whole package.
- [FIPS 197 — Advanced Encryption Standard](https://csrc.nist.gov/publications/detail/fips/197/final)
- [RFC 4493 — The AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493)
- [NIST SP 800-38B — Recommendation for Block Cipher Modes of Operation: The CMAC Mode](https://csrc.nist.gov/publications/detail/sp/800-38b/final)
