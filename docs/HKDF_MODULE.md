[← back to module index](README.md)

# hkdf

HKDF-SHA-256 per RFC 5869: the two-stage **extract-then-expand** key
derivation function, plus a one-shot wrapper that runs both stages back
to back. Implemented in terms of HMAC-SHA-256 from the
[`sha`](SHA_MODULE.md) module.

## Overview

HKDF is the workhorse KDF for symmetric-key derivation. It is built on
top of HMAC, and its security argument depends on HMAC behaving like a
PRF: do **not** swap in a bare hash. This module instantiates HKDF with
SHA-256 (`HashLen = 32`), which is the only variant the rest of
`statusbar-crypto` needs.

The construction has two stages. **Extract** takes optional salt and
input keying material (IKM) of arbitrary length and emits a fixed-length
pseudorandom key (PRK):
`PRK = HMAC-SHA-256(salt, IKM)`. If `salt` is empty, RFC 5869 §2.2
specifies a default salt of `HashLen` (32) zero bytes — this
implementation follows the spec. **Expand** takes the PRK and an
optional `info` context string and stretches the PRK to the requested
output length using iterative HMAC:
`T(i) = HMAC-SHA-256(PRK, T(i−1) ‖ info ‖ i)` for `i = 1..N`, where
`N = ceil(L / 32)`. The output is the first `L` bytes of
`T(1) ‖ T(2) ‖ … ‖ T(N)`. Because the counter `i` is a single octet, the
maximum output is `255 × 32 = 8160` bytes; longer requests are
rejected.

The PRK is returned as a `SecureArray<32>` so it is securely zeroed when
it leaves scope. The internal HMAC scratch buffer in `hkdf_sha256_expand`
is also a `SecureArray`, so neither `T(i−1)` nor the assembled HMAC
input survives past the iteration that produced it.

The module's primary consumer inside `statusbar-crypto` is
[`ecies`](ECIES_MODULE.md): newer ECIES profiles use HKDF to expand the
ECDH shared secret into encryption and MAC keys. AVB key transport also
uses HKDF — `build_ed25519_transport_key_info` and
`build_p256_transport_key_info` (declared elsewhere in the package)
produce fixed-width `info` strings to feed into `hkdf_sha256_expand`,
which is why the module hard-caps `info` at 256 bytes and exposes that
as `hkdf_sha256_max_info_size`.

## Key types

- `hkdf_sha256_extract(salt, ikm) -> SecureArray<32>` (`hkdf.hpp`) — RFC 5869 §2.2; empty salt is auto-padded to 32 zero bytes.
- `hkdf_sha256_expand(prk, info, okm) -> bool` (`hkdf.hpp`) — RFC 5869 §2.3; fills `okm`, returns `false` on length-overflow or empty output.
- `hkdf_sha256(salt, ikm, info, okm) -> bool` (`hkdf.hpp`) — one-shot extract-then-expand convenience wrapper.
- `hkdf_sha256_prk_size = 32` — public constant; size of the PRK (= SHA-256 digest size).
- `hkdf_sha256_max_info_size = 256` — public cap on the `info` length; larger inputs are rejected to keep the internal scratch buffer fixed-size.

## Public headers

- `statusbar/crypto/hkdf/hkdf.hpp` — the whole API: extract, expand, one-shot, and the two size constants.

## Dependencies

- **Statusbar modules:** [`sha`](SHA_MODULE.md) — every HKDF call goes through `sha256_hmac_hw` from this module. [`util`](UTIL_MODULE.md) — `SecureArray`, `span_copy`, `make_const_span`.
- **System / external:** `<span>`, `<array>`, `<cstdint>`, `<cstddef>`, `<algorithm>`.

## Notes & caveats

- **Pre-release, unaudited.** Mirror the package-level caveat. HKDF is structurally simple, but the security argument leans entirely on HMAC-SHA-256 being a PRF — this module inherits whatever caveats apply to the [`sha`](SHA_MODULE.md) implementation.
- **Test vectors.** `hkdf_test.cpp` runs the three RFC 5869 Appendix A test cases for HKDF-SHA-256 (Case 1: basic; Case 2: longer inputs/outputs; Case 3: zero-length salt/info), checking both the intermediate PRK and the final OKM byte-for-byte.
- **Constant-time posture.** The HKDF construction itself is straight-line code over public-length values; secret-dependent timing is confined to the underlying HMAC-SHA-256, which is itself data-independent.
- **Hardware backend.** `hkdf.cpp` calls `sha256_hmac_hw` rather than `_sw`. On hosts without SHA-NI / ARMv8 SHA-2 the `_hw` entry point dispatches to the software fallback automatically.
- **Output length limit.** The expand step enforces `L ≤ 255 × 32 = 8160` bytes; requests above that return `false`. Empty output also returns `false`. Callers should check the return value.
- **`info` length limit.** Capped at 256 bytes. This is an implementation choice (fixed-size internal `SecureArray` scratch buffer), not a spec limit. AVB key derivation stays well under it.
- **Thread safety.** Reentrant. No global state. The `SecureArray` PRK is a value type — pass it by value or by `std::span<uint8_t const, 32>` for the expand step.
- **Don't reuse for non-secret expansion.** The `_secure_*` machinery and the return-by-value PRK assume the output is sensitive. That's a feature, not overhead worth circumventing — the cost is dominated by the HMAC calls.

## Further reading

- [`sha`](SHA_MODULE.md) — HMAC-SHA-256 is the only primitive HKDF calls.
- [`kdf2`](KDF2_MODULE.md) — the older single-step KDF used by some ECIES profiles.
- [`ecies`](ECIES_MODULE.md) — the primary in-tree consumer; modern profiles use HKDF here.
- [RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869). Appendix A holds the test vectors.
- [NIST SP 800-56C Rev. 2 — Recommendation for Key-Derivation Methods in Key-Establishment Schemes](https://csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final) — the formal NIST endorsement of the HKDF construction.
