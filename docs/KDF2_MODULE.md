[← back to module index](README.md)

# kdf2

KDF2 with SHA-256: the single-step counter-based key derivation function
from ANSI X9.63 / IEEE 1363a-2004 §13.2 (also reproduced in SEC 1). One
function, one hash, fixed counter format — the simplest KDF in the
package.

## Overview

KDF2 predates HKDF and is the KDF baked into older ECIES profiles. The
construction is a single iterated hash with no separate extract step:

```
counter = 1, 2, ..., ceil(outLen / 32)
Hash_i  = SHA-256(Z ‖ I2OSP(counter, 4) ‖ P)
output  = (Hash_1 ‖ Hash_2 ‖ …) truncated to outLen
```

`Z` is the shared secret (the input keying material — typically the
`x`-coordinate of an ECDH point), `P` is an optional parameter string
(domain-separation context), and `I2OSP(counter, 4)` is the 32-bit
big-endian encoding of the counter starting from 1. The output is the
left-truncated concatenation of the per-counter SHA-256 digests.

There is no salt and no extract phase; KDF2 takes the secret directly
into the hash. That makes it less robust than HKDF when `Z` is not
already uniformly random — for ECDH outputs this is acceptable in the
profiles that specify KDF2, but it is the reason newer ECIES variants
prefer HKDF. The module exists because IEEE 1722-2016 clause 17.3.1
specifies KDF2-with-SHA-256 for AVTP symmetric-key derivation from
ECDH, and that is the protocol `statusbar-avb` targets.

The implementation is one source file. It composes a single fixed-size
`SecureWorkArray<256>` containing `Z ‖ counter ‖ P`, patches the
counter in place across iterations, calls `sha256_hw` per counter
block, and copies up to 32 bytes per iteration into the output. The
scratch buffer is securely zeroed on scope exit so the shared secret
does not linger on the stack.

The only hard input limit is `|Z| + 4 + |P| ≤ 256`. Larger inputs are
rejected with `false`; the function does not allocate. Output length is
otherwise unbounded (no `255 × HashLen` cap as in HKDF — KDF2's counter
is 32-bit).

## Key types

- `kdf2_sha256(shared_secret, params, output) -> bool` (`kdf2.hpp`) — single entry point. Fills `output` with the KDF2 output; returns `false` only if the combined input would exceed the 256-byte internal scratch buffer.

## Public headers

- `statusbar/crypto/kdf2/kdf2.hpp` — one declaration; the entire public surface.

## Dependencies

- **Statusbar modules:** [`sha`](SHA_MODULE.md) — `sha256_hw` is called once per output block. [`util`](UTIL_MODULE.md) — `SecureWorkArray`, `span_copy`.
- **System / external:** `<span>`, `<cstdint>`, `<cstring>`.

## Notes & caveats

- **Pre-release, unaudited.** Mirror the package-level caveat. KDF2 is trivial to implement but trivial to misuse — in particular, using it where HKDF is required (or vice versa) will silently produce the wrong key.
- **Test vectors.** `kdf2_test.cpp` pins the output against an independent reference: five known-answer vectors generated from `cryptography.hazmat.primitives.kdf.x963kdf.X963KDF` (algorithmically identical to KDF2 with SHA-256), covering single-block, multi-block, partial-block, with-info, and empty-info cases. The Python cross-check (`statusbar_crypto_test.py::TestKdf2Sha256::test_matches_x963kdf`) validates the Python implementation against the same reference on every test run, and the helper `crypto/python/crypto/gen_kdf2_kats.py` regenerates the C++ KATs reproducibly. The original X9.63 appendix examples remain paywalled; X963KDF is the recognised open substitute used by BoringSSL, OpenSSL, and `cryptography`.
- **Constant-time posture.** Straight-line over public-length values; secret-dependent timing is confined to the underlying `sha256_hw`. No table lookups indexed by secret data.
- **Input cap.** The 256-byte internal buffer is sized for IEEE 1722's ECDH secret + small param strings. P-256 `Z` is 32 bytes, P-521 would be 66 — both fit comfortably. If you have a use case that needs more, that's a signal to switch to HKDF.
- **Counter encoding.** Big-endian 32-bit, starts at 1. Some legacy specs start the counter at 0 — KDF2 does not. Some specs (NIST SP 800-56A KDF) put the counter first; KDF2 puts `Z` first. The byte layout is `Z ‖ counter(BE,4) ‖ P` and that is load-bearing for interop.
- **No salt.** If you want salt, you want HKDF. Do not try to retrofit it by prepending bytes to `Z`.
- **Thread safety.** Reentrant. No global state. The scratch buffer is stack-local.
- **Hardware backend.** Uses `sha256_hw` per block; on hosts without SHA-NI / ARMv8 SHA-2 that dispatches to the software path automatically.

## Further reading

- [`sha`](SHA_MODULE.md) — the SHA-256 implementation KDF2 calls per output block.
- [`hkdf`](HKDF_MODULE.md) — the modern alternative; prefer for new protocols.
- [`ecies`](ECIES_MODULE.md) — the primary in-tree consumer; ECIES profiles split between KDF2 (legacy) and HKDF (modern).
- [IEEE Std 1363a-2004 — Standard Specifications for Public-Key Cryptography: Additional Techniques](https://standards.ieee.org/ieee/1363a/2060/). §13.2 defines KDF2.
- [SEC 1: Elliptic Curve Cryptography (v2.0)](https://www.secg.org/sec1-v2.pdf) — §3.6.1 reproduces KDF2.
- [ANSI X9.63-2011 — Public Key Cryptography for the Financial Services Industry: Key Agreement and Key Transport Using Elliptic Curve Cryptography](https://webstore.ansi.org/standards/ascx9/ansix9632011r2017) — the original KDF2 normative source.
- [IEEE 1722-2016 clause 17.3.1](https://standards.ieee.org/ieee/1722/5077/) — the AVTP-specific profile this module targets.
