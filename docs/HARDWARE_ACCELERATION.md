[← back to docs index](README.md)

# Hardware acceleration

`statusbar-crypto` ships both a portable C++23 software implementation
(`*_sw` functions) and a hardware-accelerated path (`*_hw` functions)
for the symmetric primitives that benefit most: AES, SHA-256, SHA-512,
and POLYVAL. The `_hw` entry points always exist — on a CPU without the
relevant instructions they delegate to the `_sw` implementation, so
callers never need to write platform `#ifdef`s.

## What HW is used where

| Primitive          | ARM64                                | x86-64                              | SW fallback                         |
|--------------------|--------------------------------------|-------------------------------------|-------------------------------------|
| AES-128 block      | ARMv8 Crypto (AESE / AESMC / AESD / AESIMC) | AES-NI (AESENC / AESENCLAST / AESDEC / AESDECLAST) | Constant-time-ish table lookup AES |
| AES-256 block      | ARMv8 Crypto (14 rounds)             | AES-NI (14 rounds)                  | Same SW core, 14-round schedule     |
| AES-128/256 ×4 pipeline | ARMv8 Crypto interleaved        | AES-NI interleaved                  | Four sequential SW block calls      |
| SHA-256            | ARMv8.0 SHA-2 (SHA256H / SHA256H2 / SHA256SU0 / SHA256SU1) | SHA-NI (SHA256RNDS2 / SHA256MSG1 / SHA256MSG2) | Portable round-loop SW              |
| SHA-512            | ARMv8.2-A SHA-512 (SHA512H / SHA512H2 / SHA512SU0 / SHA512SU1) — *currently delegates to SW pending validation* | None (x86 has no SHA-512 ISA — delegates to SW) | Portable round-loop SW |
| POLYVAL            | PMULL / PMULL2 (carry-less mul, part of ARMv8 AES feature set) | PCLMULQDQ                | GF(2^128) shift-and-XOR loops       |

CMAC, GCM-SIV, SIV, ECIES, and the KDFs do not have dedicated HW paths
of their own — they inherit acceleration through the AES, SHA, and
POLYVAL primitives they consume.

## How dispatch works

There are two distinct dispatch styles in the codebase. **Read this
section before assuming runtime detection is uniform.**

**x86-64 — runtime CPUID probe.** The amd64 `_hw` files implement an
internal `cpu_has_aes_ni()` / `cpu_has_sha_ni()` / `cpu_has_pclmulqdq()`
helper that runs `__cpuid()` once, caches the result in a function-local
`static`, and dispatches per call:

```cpp
if (cpu_has_aes_ni()) { aes128_encrypt_block_ni(...); }
else                  { aes128_encrypt_block_sw(...); }
```

This means a single binary runs on both an AES-NI-capable Skylake and a
pre-Westmere CPU without re-linking — useful for distro packaging.

**ARM64 — compile-time gating.** The arm64 `_hw` files guard their
entire HW body on `defined(__aarch64__) && defined(__ARM_FEATURE_AES)`
(or `__ARM_FEATURE_SHA2`, `__ARM_FEATURE_SHA512`). If the compiler was
not invoked with a flag that enables those features (e.g.
`-march=armv8-a+crypto`), the file compiles to a pure-SW fallback. The
umbrella sets `STATUSBAR_CRYPTO_ARCH_FLAGS` to `-mcpu=native+aes+sha2+sha3`
on a native build and `-march=armv8-a+crypto` on a cross-build (see
`crypto/statusbar/crypto/CMakeLists.txt`), so the AES, SHA-256 and
PMULL features are reliably enabled on all the targets the package
ships for (Cortex-A72 / A76 / Apple Silicon / Graviton). No runtime
probe is performed on ARM64; the assumption is that if you built with
`+crypto`, your deploy hardware has it.

## SW fallback

The `_sw` functions are written in portable C++23 with no inline asm
and no intrinsics. They are the only path on:

- 32-bit targets (i386, ARM32, RISC-V32 — no `__int128`, no NEON crypto,
  no AES-NI). These targets also lose the high-level elliptic-curve
  wrappers — see `STATUSBAR_CRYPTO_HAS_INT128` in
  [`util`](UTIL_MODULE.md).
- ARM64 builds compiled without `+crypto` / `+sha2` / `+sha512`.
- x86-64 CPUs predating AES-NI (pre-Westmere), SHA-NI (pre-Goldmont /
  pre-Ice Lake client), or PCLMULQDQ (pre-Westmere).

The AES SW path uses S-box table lookups and is **not**
cache-timing-safe; the headers (`aes_cbc.hpp`, `ecies.hpp`) document
this and recommend verifying HW support before processing sensitive key
material on shared-tenant hardware. POLYVAL SW uses shift-and-XOR loops
that are constant-time in algorithm but not guaranteed so by the
optimizer.

## Performance posture

Benchmarks live in `statusbar-crypto-bench` (built only when
`STATUSBAR_HAS_INT128` is set) and run via `cmake --build build --target
run-all-benches`. Expect the HW path to be roughly 3–10× faster than SW
for AES and SHA-256, and substantially more for POLYVAL where SW has no
parallelism to extract. The `aes*_encrypt_blocks_x4_hw` pipelined
variants exist specifically because AESENC has 3–4 cycle latency but
1-cycle throughput on modern cores — issuing four independent block
operations keeps the AES unit fed.

## Disabling HW

There is no dedicated `ENABLE_HW=OFF` switch. To force the SW path:

- **Configure-time**, ARM64: pass `-DSTATUSBAR_CRYPTO_ARCH_FLAGS=` (empty
  string) to remove the `+crypto`/`+sha2` flags so the `__ARM_FEATURE_*`
  macros are not defined and every `_hw` file compiles to its SW
  fallback.
- **Configure-time**, x86-64: same idea, set `STATUSBAR_CRYPTO_ARCH_FLAGS`
  to a value that omits `-maes`, `-msha`, `-mpclmul`. The runtime
  CPUID dispatch will then never see the HW code paths because the
  `__AES__` / `__SHA__` / `__PCLMUL__` macros that gate the intrinsics
  are undefined.
- **Source-level**: call the `_sw` functions directly. The headers
  (`aes128.hpp`, `sha256.hpp`, `polyval_sw.hpp`, …) declare them as
  first-class public API alongside their `_hw` counterparts.

The fuzzer harnesses generally call `_sw` directly (see
[FUZZING.md](FUZZING.md)) so that a single corpus exercises a
deterministic implementation regardless of host CPU; the POLYVAL
fuzzer additionally cross-checks `_sw` against `_hw` for equivalence.

## Further reading

- [`aes`](AES_MODULE.md), [`sha`](SHA_MODULE.md), [`polyval`](POLYVAL_MODULE.md)
  — per-primitive overviews with their `_sw` / `_hw` function tables.
- [FUZZING.md](FUZZING.md) — fuzzer harnesses and how they treat HW vs SW.
- [`util`](UTIL_MODULE.md) — `STATUSBAR_CRYPTO_HAS_INT128`, the other
  feature-gate that affects which curve implementations are built.
