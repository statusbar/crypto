[← back to module index](README.md)

# polyval

POLYVAL universal hash over GF(2^128), per RFC 8452 §3. The
authentication primitive consumed by AES-GCM-SIV; not a general-purpose
MAC. Ships a portable software path plus carry-less-multiply
acceleration on ARMv8 (PMULL/PMULL2) and x86-64 (PCLMULQDQ).

## Overview

POLYVAL is a polynomial hash whose only consumer in this codebase is
[`aes-gcm-siv`](AES_GCM_SIV_MODULE.md). It is exposed as a standalone
module because the math, the test vectors, and the hardware-acceleration
story are independent of the AEAD that wraps it.

POLYVAL is **not** GHASH. The two functions operate over the same field
GF(2^128) with the same irreducible polynomial
`x^128 + x^127 + x^126 + x^121 + 1`, but POLYVAL uses a reflected
(little-endian) bit ordering — bits 0..127 within each 16-byte block
run in the opposite direction from GHASH's big-endian convention. The
two are related by byte-reversal and a single field multiplication, so
mixing them up will silently produce wrong tags. The accumulation step
is `S_i = dot(S_{i-1} XOR X_i, H)`, where `X_i` are successive 16-byte
input blocks and `H` is the per-message hash key.

The software fallback implements the dot product as a `U128 × U128 →
U128` carry-less multiplication using a right-shift shift-and-XOR loop
that folds in the reduction as it goes, so the `x^-128` (Montgomery)
factor inherent to POLYVAL's `dot` is produced directly rather than as a
separate reduction step (see `polyval_sw.cpp`). The hardware paths replace the multiplication with
single CPU instructions — PMULL/PMULL2 on ARMv8 (gated on
`__ARM_FEATURE_AES`, since PMULL ships in the AES extension feature
set) and PCLMULQDQ on x86-64 — and apply the same reduction with two
further carry-less multiplies by the constant `0xc200000000000000`.

The API is a one-shot `polyval_*(H, input)` plus an incremental
`polyval_update_*(H, input, accumulator)` that XOR-folds new blocks into
a caller-provided 16-byte state. AES-GCM-SIV uses the incremental form
to absorb AAD, plaintext, and the trailing length block in three
separate calls without copying.

Input must be a whole number of 16-byte blocks; partial blocks are the
caller's responsibility to zero-pad (AES-GCM-SIV does this before
calling). `polyval_can_update(input)` exists as a pre-check helper —
the implementations themselves assert the precondition.

## Key types

- `PolyvalKey` (`polyval_sw.hpp`) — 16-byte hash key `H`, stored little-endian. Destructor securely zeroes the bytes. Derived per-message by the AES-GCM-SIV key schedule, never reused across messages.
- `polyval_block_size = 16` — public constant (POLYVAL operates on 128-bit blocks).
- `polyval_can_update(input) -> bool` (`polyval_sw.hpp`) — `true` iff `input.size() % 16 == 0`.
- `polyval_sw(H, input) -> array<uint8_t, 16>` — one-shot software hash.
- `polyval_update_sw(H, input, accumulator)` — incremental software update; accumulator is in/out.
- `polyval_hw(H, input)` / `polyval_update_hw(H, input, accumulator)` (`polyval_hw.hpp`) — hardware-accelerated variants with identical semantics.

## Public headers

- `statusbar/crypto/polyval/polyval_sw.hpp` — type definitions (`PolyvalKey`, constants, `polyval_can_update`) and software API.
- `statusbar/crypto/polyval/polyval_hw.hpp` — hardware-dispatch API; includes `polyval_sw.hpp` for the shared types.

## Dependencies

- **Statusbar modules:** [`util`](UTIL_MODULE.md) — `secure_zero`, `SecureArray`, little-endian load/store helpers (`load_le64` / `store_le64`); [`status`](../../core/docs/STATUS_MODULE.md) — `statusbar_assert.hpp` for the precondition check on block-aligned input.
- **System / external:** `<span>`, `<array>`, `<cstdint>`, `<cstddef>`. ARM64 path includes `<arm_neon.h>` under `__aarch64__ && __ARM_FEATURE_AES`; x86-64 path includes `<wmmintrin.h>` / `<immintrin.h>` under `__PCLMUL__`.

## Notes & caveats

- **Pre-release, unaudited.** This module shares the package-level caveat. POLYVAL is a particularly easy target for subtle bit-ordering bugs — trust the RFC 8452 vectors, not your intuition.
- **Test vectors.** `polyval_sw_test.cpp` and `polyval_hw_test.cpp` cover the RFC 8452 Appendix A example plus the dot-product reference values; the HW tests also cross-check against the SW path on the same inputs.
- **Constant-time posture.** The hardware paths (PMULL, PCLMULQDQ) are constant-time by design on every CPU known to ship them. The software shift-and-XOR fallback has no secret-dependent branches and no secret-indexed table lookups, but as the `polyval_hw.hpp` header warns, the compiler is not strictly required to keep it data-independent. For deployments where this matters, prefer hosts with hardware CLMUL and verify dispatch at runtime.
- **Bit ordering.** `PolyvalKey::data` is little-endian. AES-GCM-SIV stores the derived hash key in the same convention; do not byte-reverse before passing it in.
- **Block alignment.** `polyval_*` and `polyval_update_*` require `input.size() % 16 == 0`. Partial blocks must be zero-padded by the caller; the implementations assert.
- **Runtime HW detection.** The x86-64 backend performs a cached runtime CPUID probe (PCLMULQDQ) and falls back to software when the instruction is absent. The ARM64 backend is compile-time gated with no runtime probe. Translation units for the wrong architecture compile to no-ops, leaving the software path live.
- **Thread safety.** All free functions are reentrant. The `PolyvalKey` and accumulator are caller-owned and stack-allocatable — there is no global state.

## Further reading

- [`aes-gcm-siv`](AES_GCM_SIV_MODULE.md) — the AEAD that consumes this module. The per-message hash key derivation lives there.
- [`aes`](AES_MODULE.md) — the block cipher that AES-GCM-SIV pairs POLYVAL with.
- [Hardware acceleration overview](HARDWARE_ACCELERATION.md) — cross-module rundown of CPU-extension usage.
- [RFC 8452 — AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc8452). §3 is POLYVAL; Appendix A is the test-vector source.
- ["The design and evolution of OCB" / "POLYVAL"](https://eprint.iacr.org/2017/168) — design rationale for the reflected polynomial.
