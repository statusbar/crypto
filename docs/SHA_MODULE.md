[← back to module index](README.md)

# sha

SHA-256 and SHA-512 hash functions per FIPS 180-4, plus HMAC-SHA-256 per
FIPS 198-1 / RFC 2104. Each algorithm ships both a portable software path
and a hardware-accelerated path that uses CPU crypto extensions when
present.

## Overview

`sha` is the hashing foundation everything else in `statusbar-crypto`
builds on. The package's HKDF, KDF2, ECIES, and PKCS#8 modules all
funnel through this module for digest and PRF operations, and the AVB
key-transport flow leans on HMAC-SHA-256 specifically.

The module exposes two sibling APIs per algorithm: `_sw` (pure C++,
portable, FIPS 180-4 verbatim) and `_hw` (the same surface area with
`_hw` suffixes). The `_hw` entry points dispatch to a CPU-specific
compression function — ARMv8 SHA-2 crypto extensions
(`SHA256H`/`SHA256H2`/`SHA256SU0`/`SHA256SU1`) on aarch64, Intel SHA-NI
(`SHA256RNDS2`/`SHA256MSG1`/`SHA256MSG2`) on x86-64 — and fall back to
the software compression function on hosts that lack the extension.
SHA-512 has an aarch64 path (ARMv8.2-A SHA-512 instructions
`SHA512H`/`SHA512H2`/`SHA512SU0`/`SHA512SU1`); there is no x86-64 SHA-512
hardware extension, so `sha512_hw*` on x86-64 reuses the software
compression directly.

SHA-256 is exposed as a one-shot API only — there is no public
streaming context. SHA-512 ships a public incremental context
(`Sha512Context` with `init` / `update` / `final`) plus a one-shot
wrapper, because Ed25519 key derivation needs to feed the digest in
pieces. Both algorithms have secure (`_secure_*`) variants that return a
`SecureArray<N>` so the digest is zeroed on scope exit when it is
secret (e.g. an Ed25519 expansion).

HMAC-SHA-256 follows the FIPS 198-1 / RFC 2104 construction
`H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ msg))`. Long keys (> 64 bytes) are
pre-hashed; short keys are zero-padded to the block size. A two-span
overload concatenates `message1 ‖ message2` without requiring callers to
materialize the joined buffer — HKDF and ECIES rely on this.

The compression functions zero working variables (`a`..`h`) on every
scope exit via `SecureZeroRef`, and contexts zero their state in their
destructors, so HMAC keys never linger on the stack after a digest
completes.

## Key types

- `sha256_sw(span) -> array<uint8_t, 32>` (`sha256.hpp`) — one-shot SHA-256.
- `sha256_hw(span) -> array<uint8_t, 32>` (`sha256_hw.hpp`) — same, hardware-accelerated when available.
- `sha256_hmac_sw(key, msg)` / `sha256_hmac_sw(key, msg1, msg2)` (`sha256.hpp`) — HMAC-SHA-256, software path; `sha256_hmac_hw` mirrors the API.
- `sha256_secure_sw` / `sha256_secure_hw` — return `SecureArray<32>` for secret digests.
- `Sha512Context` (`sha512.hpp`) — incremental hash state (state words, 128-byte block buffer, total length); destructor securely zeroes itself.
- `sha512_init_sw` / `sha512_update_sw` / `sha512_final_sw` (`sha512.hpp`) — streaming SHA-512; `_hw` siblings in `sha512_hw.hpp`.
- `sha512_sw(span)` / `sha512_hw(span)` — one-shot wrappers around the streaming API.
- `sha512_final_secure_sw` / `sha512_final_secure_hw` — return `SecureArray<64>`.
- `sha256_block_size = 64`, `sha256_digest_size = 32`, `sha512_block_size = 128`, `sha512_digest_size = 64` — public constants.
- `internal::sha256_hmac_generic<Ctx, …>` (`sha256_hmac.hpp`) — template that factors the HMAC construction across SW/ARM64/x86-64 backends; internal header, not for direct use.

## Public headers

- `statusbar/crypto/sha/sha256.hpp` — SHA-256 + HMAC-SHA-256, software API.
- `statusbar/crypto/sha/sha256_hw.hpp` — SHA-256 + HMAC-SHA-256, hardware-dispatch API.
- `statusbar/crypto/sha/sha512.hpp` — SHA-512 incremental + one-shot, software API.
- `statusbar/crypto/sha/sha512_hw.hpp` — SHA-512, hardware-dispatch API.

## Dependencies

- **Statusbar modules:** [`util`](UTIL_MODULE.md) — `SecureArray`, `SecureWorkArray`, `SecureZeroRef`, `secure_zero`, big-endian load/store helpers from `crypto_util_internal.hpp`.
- **System / external:** `<span>`, `<array>`, `<cstdint>`, `<cstddef>`. ARM64 paths additionally include `<arm_neon.h>` under `__aarch64__ && __ARM_FEATURE_SHA2` (SHA-256) / `__ARM_FEATURE_SHA512` (SHA-512); x86-64 includes `<immintrin.h>` under `__SHA__`.

## Notes & caveats

- **Pre-release, unaudited.** Mirror the package-level caveat: these implementations conform to the published test vectors but have not been third-party audited or run under `ctgrind`/`dudect`. For production where strong guarantees matter, prefer a vetted library.
- **Test vectors.** `sha256_test.cpp` and `sha512_test.cpp` exercise the FIPS 180-4 examples (`"abc"`, the two-block 56-byte string, the empty string, the one-million-`a` stream); HMAC-SHA-256 is covered by the RFC 4231 vectors. The `_hw_test.cpp` files re-run the same vectors through the hardware path and cross-check against the software path on the same input.
- **Constant-time posture.** SHA itself processes only public data; the compression function is data-independent in both `_sw` and `_hw` paths. HMAC's data-dependent step is the key-pad XOR, which is straight-line. No table lookups indexed by secret data.
- **Runtime HW detection.** Selection happens at compile time via `__ARM_FEATURE_SHA2` / `__SHA__`. The umbrella ships separate translation units (`sha256_hw_arm64.cpp`, `sha256_hw_amd64.cpp`) that compile to no-ops on the wrong architecture, leaving the SW fallback live. There is no runtime CPUID probe yet.
- **Maximum message length.** Both algorithms track total length in a `uint64_t`, capping inputs at `2^61 − 1` bytes (the bit-length field would otherwise overflow). FIPS 180-4 allows SHA-512 inputs up to `2^128 − 1` bits; that range is not exposed here.
- **Thread safety.** All free functions are reentrant. `Sha512Context` is not thread-safe — one context per thread.
- **`SecureArray` return.** The `_secure_*` variants are the right choice whenever the digest is itself a key (HKDF PRK, Ed25519 expansion, HMAC tag re-used as a derivation input). The non-secure variants are cheaper when the digest is public output (file integrity, transcript hashing).

## Further reading

- [`hkdf`](HKDF_MODULE.md) — RFC 5869 extract-then-expand, built directly on HMAC-SHA-256 from this module.
- [`kdf2`](KDF2_MODULE.md) — IEEE 1363a / X9.63 KDF, calls `sha256_hw` per counter block.
- [`ecies`](ECIES_MODULE.md) — uses HMAC-SHA-256 as MAC and KDF2/HKDF for key expansion.
- [Hardware acceleration overview](HARDWARE_ACCELERATION.md) — cross-module rundown of which CPU extensions each algorithm consumes.
- [FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/publications/detail/fips/180/4/final).
- [FIPS 198-1 — HMAC](https://csrc.nist.gov/publications/detail/fips/198/1/final).
- [RFC 2104 — HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104).
- [RFC 4231 — Test vectors for HMAC-SHA-2](https://www.rfc-editor.org/rfc/rfc4231).
- [NIST CAVP — Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).
