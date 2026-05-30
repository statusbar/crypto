[← back to module index](README.md)

# util

Shared internals for every other crypto module: RAII secure-zeroing
containers for key material, the `STATUSBAR_CRYPTO_HAS_INT128` feature
toggle that gates the 64-bit elliptic-curve implementations, ADL-driven
C++23 concepts for pluggable signing/key-agreement back ends, endian
load/store helpers, and a tiny self-registered test harness.

## Overview

`util/` is not a public-facing API in the same sense as `aes/` or
`sha/`. Most of its contents live in `statusbar::crypto::internal`
and are pulled in by sibling modules via `crypto_util_internal.hpp`.
What *is* public are the secure-storage types (`SecureArray<N>`,
`SecureWorkArray<T, N>`, `SecureZeroRef<T>`), the signing-key concepts
in `crypto_concepts.hpp`, and the `STATUSBAR_CRYPTO_HAS_INT128`
macro from `crypto_has_int128.hpp`.

`SecureArray<N>` inherits from `std::array<uint8_t, N>` so it slots
into any API expecting `std::array`, but its destructor calls
`internal::secure_zero()` to overwrite the bytes on scope exit.
The implementation uses `explicit_bzero()` on Linux/BSD and a
`volatile uint8_t*` write loop everywhere else, so the writes survive
dead-store elimination — a portable C++23 substitute for
`memset_explicit` (which is not yet ubiquitous in libc++).

`crypto_has_int128.hpp` is the single point of truth for whether the
compiler provides a usable `__int128`. The Curve25519 5×51-bit and
P-256 4×64-bit field arithmetic both depend on 64×64 → 128 multiplies
and are skipped on 32-bit targets (i386, ARM32, RISC-V32) in favour of
the reduced-radix `*32` implementations. The flag can be forced off on
a 64-bit host (`-DSTATUSBAR_CRYPTO_HAS_INT128=0`) to exercise the 32-bit
code path during testing.

`crypto_concepts.hpp` provides the C++23 concept machinery
(`Ed25519SigningKey`, `X25519KeyAgreement`, `P256SigningKey`) that lets
client code substitute hardware-backed enclave key types via ADL-visible
overloads without touching the call sites. `static_assert`s confirm the
software key types satisfy the concepts at compile time.

`test.hpp` is the tiny harness reused by every `*_test.cpp` in the
package: a global `failures` counter, a `check(cond, name)` macro-free
helper, a `report(name)` summary, and a `do_not_optimize()` barrier
backed by inline asm. It is intentionally minimal — heavier test
infrastructure lives in `statusbar-core`'s `test/` module.

## Key types

- `SecureArray<N>` — `std::array<uint8_t, N>` subclass whose destructor
  performs a constant-time zero wipe. Used for all key material in the
  AES, AES-SIV, AES-GCM-SIV, HKDF, ECIES, and PKCS#8 paths.
- `SecureWorkArray<T, N>` — RAII container of `T[N]` that zeroes on
  destruction. Used for scratch buffers (message schedules, scalar
  limbs, intermediates) whose contents may include sensitive material.
- `SecureZeroRef<T>` — RAII *reference* (not a value); zero-wipes the
  referenced object on scope exit. Useful for caller-owned stack
  variables that need cleanup at a specific scope boundary.
- `Ed25519SigningKey`, `X25519KeyAgreement`, `P256SigningKey` —
  concepts in `crypto_concepts.hpp`. A user-defined key type satisfies
  them by providing ADL-visible overloads of `ed25519_sign()`,
  `ed25519_public_key()`, `x25519()`, `p256_ecdsa_sign()`, or
  `p256_public_key()`; the templated APIs then accept it with no
  virtual dispatch.
- `internal::Uint128` / `internal::Int128` — `__uint128_t` / `__int128_t`
  aliases, defined only when `STATUSBAR_CRYPTO_HAS_INT128` is set.
- `test::check()`, `test::report()`, `test::do_not_optimize()` — the
  test-helper trio used by every `*_test.cpp` and several
  `*_fuzzer.cpp` files.

## Public headers

- `statusbar/crypto/util/secure_array.hpp` — `SecureArray`,
  `SecureWorkArray`, `SecureZeroRef`, and `internal::secure_zero()`.
- `statusbar/crypto/util/crypto_concepts.hpp` — the signing/key-agreement
  concepts plus `static_assert`s for the software key types.
- `statusbar/crypto/util/crypto_has_int128.hpp` — defines
  `STATUSBAR_CRYPTO_HAS_INT128` (1 or 0) from `__SIZEOF_INT128__`.
- `statusbar/crypto/util/crypto_util_internal.hpp` — internal grab-bag:
  `Uint128`/`Int128`, `SecureArray` overloads for `span_copy` etc.,
  little/big-endian load/store helpers, `dbl()` for GF(2^128) doubling,
  and re-exports of `statusbar::span_*` utilities into the
  `internal::` namespace.
- `statusbar/crypto/util/test.hpp` — `test::check()`, `test::report()`,
  `test::do_not_optimize()`.

## Dependencies

- **Statusbar modules:** [`buffer`](../../core/docs/BUFFER_MODULE.md)
  (`span_utils.hpp` — `make_span`, `span_copy`, `span_load`,
  `span_compare_constant_time`, etc.); the elliptic-curve and signing
  headers transitively pulled in by `crypto_concepts.hpp`
  ([`25519`](25519_MODULE.md), [`p256`](P256_MODULE.md)).
- **System / external:** `<array>`, `<concepts>`, `<span>`, `<bit>`,
  `<type_traits>`; `<string.h>` for `explicit_bzero()` on Linux/BSD;
  `__int128` from GCC/Clang on 64-bit targets only.

## Notes & caveats

- `SecureArray::~SecureArray()` zeros the bytes through a `volatile`
  pointer; the optimizer is forbidden from eliding the writes, but the
  compiler is still free to copy the value elsewhere in memory before
  destruction. Avoid passing a `SecureArray` by value through
  uncontrolled call chains.
- `internal::secure_zero()` early-returns on empty spans because
  `explicit_bzero(nullptr, 0)` is undefined behaviour (argument 1 is
  declared `nonnull`).
- `STATUSBAR_CRYPTO_HAS_INT128` is *the* gate for the high-level
  curve, ECIES, and PKCS#8 wrappers — they `#if`-guard their entire
  bodies on it. Code paths that need to run on 32-bit hosts must use
  the explicit `*32` implementations (`x25519_32`, `p256_fe32`, …).
- `test.hpp` lives in the public header tree because fuzzers and tests
  in sibling modules consume it. `standalone_driver.cpp` in this
  directory is the macOS fuzzer driver (see [FUZZING.md](FUZZING.md));
  it is intentionally not a header.
- The ADL-based concepts mean enclave key types must define their
  overloads in the *same namespace* as the key struct, not in
  `statusbar::crypto`.

## Further reading

- [HARDWARE_ACCELERATION.md](HARDWARE_ACCELERATION.md) — how the
  `_hw` paths gate on `STATUSBAR_CRYPTO_HAS_INT128` and CPU feature macros.
- [FUZZING.md](FUZZING.md) — `standalone_driver.cpp` and how `test.hpp`
  is reused by the fuzzer harnesses.
- [`buffer`](../../core/docs/BUFFER_MODULE.md) — source of the
  `span_*` helpers re-exported into `statusbar::crypto::internal`.
