# statusbar-crypto

Cryptography toolkit — AES (block, CBC, GCM-SIV, SIV, CMAC), SHA-2, POLYVAL, HKDF/KDF2, Curve25519 (X25519/Ed25519) and NIST P-256 (ECDH/ECDSA), ECIES, and PKCS#8. Hardware-accelerated where the CPU supports it (ARMv8 Crypto Extensions; AES-NI/PCLMUL/SHA-NI on x86-64), with portable software fallbacks for everything.

Status: pre-release.

> Portions of this repository were developed with assistance from Claude,
> an AI model by Anthropic. All reference material used in this process
> came from my own original open source implementations of these
> cryptographic primitives, with Claude assisting in refactoring and in
> validating conformance against the published RFC, FIPS, and NIST CAVP
> test vectors. All architectural decisions, final implementations, and
> engineering judgments are my own, and any errors are mine alone.

> **Status: pre-release — unaudited.** This library has not been independently
> audited. While care has been taken with constant-time operations, side-channel
> resistance, and conformance to standards (RFCs, FIPS, NIST CAVP test vectors),
> the cryptographic implementations have not been validated by third-party
> review or by automated constant-time tooling (`ctgrind` / `dudect`). For
> production use where strong cryptographic guarantees matter, prefer a vetted
> library such as libsodium, BoringSSL, or OpenSSL.

## Overview

`statusbar-crypto` is a from-scratch C++23 cryptography toolkit covering the
primitives a modern secure-transport stack needs: the AES family (block, CBC,
GCM-SIV, SIV, CMAC), SHA-2 and POLYVAL hashing, HKDF/KDF2 key derivation, and
public-key cryptography over Curve25519 (X25519, Ed25519) and NIST P-256
(ECDH, ECDSA), plus ECIES and PKCS#8 key encoding. It builds as a single
module on top of `statusbar-core`.

Performance and portability are first-class: hot paths use hardware
acceleration where the CPU offers it (ARMv8 Crypto Extensions; AES-NI /
PCLMUL / SHA-NI on x86-64) and fall back to constant-time portable software
everywhere else. Implementations are checked against RFC, FIPS, and NIST CAVP
test vectors, cross-validated against a Python reference (`cryptography` +
`pycryptodome`), and every byte parser carries a libFuzzer harness.

It was written largely to authenticate AVTP control traffic in
`statusbar-avb`, but works as a general-purpose toolkit. Note the pre-release
and unaudited caveat above — for production use where strong guarantees
matter, prefer a vetted library.

This package can be built standalone (see below).

## Quick start

```bash
# Local build + unit tests (Clang+libc++ toolchain is mandatory; applied automatically)
./local-build.sh && ctest --test-dir build

# Reproducible Debian .deb in ../deb-output/ (statusbar-core .debs must already be there)
./container-build.sh

# Sanitizers (mutually exclusive — use separate build dirs)
./local-build.sh -DENABLE_ASAN=ON     # AddressSanitizer
./local-build.sh -DENABLE_UBSAN=ON    # UndefinedBehaviorSanitizer
./local-build.sh -DENABLE_TSAN=ON     # ThreadSanitizer

# Fuzzing (libFuzzer harnesses)
./local-build.sh -DENABLE_FUZZING=ON
cmake --build build --target fuzz-smoke   # quick CI pass
cmake --build build --target fuzz-all     # per-harness libFuzzer campaign
```

Depends on `statusbar-core`. See the sections below for details.

## Modules

- `crypto` — single library exposing AES-128/256 (block, CBC, GCM-SIV, SIV, CMAC),
  SHA-256/512, POLYVAL, HKDF, KDF2, Curve25519 (X25519, Ed25519), NIST P-256
  (ECDH, ECDSA), ECIES (X25519- and P-256-based), and PKCS#8 key encoding.

## Building

This package depends on other statusbar packages. Export every
package into one directory so the trees sit side by side, then
build the dependencies first — each builds on its own (see its
README) — in this order:

    statusbar-core -> statusbar-crypto

This package then finds each dependency through its **local
build tree** — nothing is installed, so your system stays clean.

**Quick path:** run `./local-build.sh`. It looks for each dependency's
build dir in a sibling checkout (`../<dep>/build/`), threads the `-Dstatusbar-<dep>_DIR`
flags into cmake automatically, and falls back to `$STATUSBAR_<DEP>_DIR`
when the layout differs. Extra args are forwarded to cmake configure
(`./local-build.sh -DENABLE_ASAN=ON`). The script echoes its final cmake
invocation via `set -x` so users configuring an IDE can copy the exact
flags.

**Manual / IDE configuration.** The explicit cmake invocation is:

```
cmake -S . -B build -G Ninja --toolchain cmake/toolchain-clang.cmake \
  -Dstatusbar-core_DIR=../core/build
cmake --build build
ctest --test-dir build
```

Each `-Dstatusbar-<dep>_DIR=<path>` points `find_package` at a
dependency's build directory; the package exports its build tree,
so it need not be installed. The `../<dep>/build` paths
assume the packages were exported as siblings — use absolute paths
otherwise. In an IDE's CMake settings, add one cache entry per
dependency (`statusbar-core_DIR`, `statusbar-crypto_DIR`, …) pointing
at each dep's build directory; this is exactly what the script
generates.

## Benchmarks

Micro-benchmark executables ship with crypto:

| Binary | Source | CMake target |
|---|---|---|
| `statusbar-crypto-bench` | `statusbar/crypto/crypto_bench_tool.cpp` | `run-crypto-bench` |

Run via CMake (rebuilds if stale, then executes):

```
cmake --build build --target run-crypto-bench
```

Or directly after a build:

```
./build/statusbar/crypto/statusbar-crypto-bench
```

The bench prints mean / median / std-dev / min / max / p95 / p99 for every
named case across AES (block, CBC, GCM-SIV, SIV, CMAC), SHA-2, POLYVAL,
HKDF/KDF2, X25519, Ed25519, P-256 (ECDH, ECDSA), ECIES, and PKCS#8.

## Coverage

Line/region coverage is wired through LLVM source-based profiling
(`-fprofile-instr-generate -fcoverage-mapping`). Enable via
`-DENABLE_COVERAGE=ON`, ideally in a separate build directory:

```
cmake -S . -B build-cov -G Ninja --toolchain cmake/toolchain-clang.cmake \
  -DENABLE_COVERAGE=ON
```

Three CMake custom targets become available after configure (they
require `llvm-profdata` and `llvm-cov` on `PATH`):

| Target | What it does |
|---|---|
| `coverage-collect` | Builds and runs `statusbar_test`, merges `.profraw` into `combined.profdata` |
| `coverage-report` | Prints a text line-coverage report |
| `coverage-html`   | Generates an HTML report under `build-cov/coverage/html/` |

Each target depends on the previous, so a single invocation runs the
whole pipeline:

```
cmake --build build-cov --target coverage-html
xdg-open build-cov/coverage/html/index.html   # or `open` on macOS
```

`*_test.cpp` / `test.hpp` files are excluded by default. Override with
`-DSTATUSBAR_COVERAGE_IGNORE='<regex>'` if you want a different filter.

## Fuzz testing

Every byte parser that consumes untrusted input has a libFuzzer harness
(`*_fuzzer.cpp`). When the compiler is Clang (the toolchain default),
`-DENABLE_FUZZING=ON` is automatic; the harnesses build with
`-fsanitize=fuzzer,address,undefined`.

Two aggregate targets sweep every `*_fuzzer` executable in the build tree:

| Target | What it does |
|---|---|
| `fuzz-smoke` | Runs each fuzzer once with a 256-byte random seed. Quick check; CI-friendly. |
| `fuzz-all`   | Extended run (Linux: 30 s of libFuzzer mutation per fuzzer with a persistent corpus; macOS: 1000 random inputs per fuzzer via the standalone driver). |

```
cmake --build build                          # builds the fuzzers
cmake --build build --target fuzz-smoke      # smoke pass
cmake --build build --target fuzz-all        # extended pass
```

Or run a single fuzzer directly with any libFuzzer arguments:

```
./build/.../some_fuzzer -max_total_time=60 -max_len=4096
```

Persistent corpora live under `build/fuzz/corpus/<fuzzer_name>/`.

To disable: `-DENABLE_FUZZING=OFF`.

## Python validation

`python/crypto/` contains a Python mirror of the C++ crypto API plus a
cross-validation harness that drives the C++ CLI tools against Python
reference outputs from `cryptography` + `pycryptodome`. Useful for sanity
checks against external reference implementations.

Both scripts use [`uv`](https://docs.astral.sh/uv/) for inline-deps Python
execution (PEP 723):

```
# Pure-Python self-tests of the Python mirror
uv run python/crypto/statusbar_crypto_test.py

# Cross-check Python reference vectors against the C++ avtp_crypto_tool
# (requires the avb package to be built — that's where the CLI lives)
uv run python/crypto/avtp_crypto_cross_check.py --build-dir ../avb/build
```

A CMake target wraps the cross-check when the C++ build has produced
`statusbar-avtp-crypto-tool` (available in cross-package builds that
include `statusbar-avb`, or when `avb` is built side-by-side):

```
cmake --build build --target python-crypto-tests
```

## Sanitizers

`cmake/sanitizers.cmake` exposes three mutually exclusive sanitizer options.
Use a **separate build directory per sanitizer** — the instrumentation
flags change ABI / runtime expectations:

```
cmake -S . -B build-asan -G Ninja --toolchain cmake/toolchain-clang.cmake \
  -DENABLE_ASAN=ON
cmake --build build-asan
ctest --test-dir build-asan
```

| Option | Adds | Use for |
|---|---|---|
| `-DENABLE_ASAN=ON`  | `-fsanitize=address`                       | Out-of-bounds, use-after-free, leaks |
| `-DENABLE_UBSAN=ON` | `-fsanitize=undefined -fno-sanitize-recover` | Integer overflow, alignment, UB |
| `-DENABLE_TSAN=ON`  | `-fsanitize=thread`                        | Data races (useful for SPSC + triple-buffer code) |

Enabling more than one of the three at configure time is a hard error.

## Static analysis (clang-tidy)

Two modes are available:

**In-compile** — `clang-tidy` runs as part of every translation unit:

```
cmake -S . -B build-tidy -G Ninja --toolchain cmake/toolchain-clang.cmake \
  -DENABLE_CLANG_TIDY=ON
cmake --build build-tidy
```

Slow (every TU lints), but findings show up alongside the compile output.

**Separate aggregate run** — runs `clang-tidy` in parallel against the
existing build's `compile_commands.json`:

```
cmake --build build                         # normal build first
cmake --build build --target clang-tidy     # runs against build/compile_commands.json
```

The `clang-tidy` target uses `cmake/run-clang-tidy-all.sh` to fan out
across cores (8 jobs by default), skips `*_test.cpp` / `*_tool.cpp` /
`*_example.cpp` / `*_fuzzer.cpp`, and writes combined findings to
`build/clang-tidy-findings.txt`. The `.clang-tidy` config at the
submodule root drives check selection.

## Installing

```
cmake --install build --prefix <prefix>
```

## Packaging

A standalone build configures CPack — TGZ and ZIP archives on every
platform, plus DEB and (when `rpmbuild` is present) RPM on Linux.
Run `cpack` from the build directory:

```
cd build && cpack
```

This produces `statusbar-crypto` (runtime: tools) and `statusbar-crypto-dev` / `-devel` (headers, static libraries, CMake config).

### Reproducible Debian packages

`./container-build.sh` builds this package's `.deb`s inside a Debian
container — no local toolchain needed. Output lands in `../deb-output/`
(override with `DEB_OUTPUT`); the base image is configurable with
`DEBIAN_VERSION=...`.

The `statusbar-core` `.deb`s must already be present in
`../deb-output/` — build them by running `./container-build.sh` in a
sibling clone of the `statusbar-core` repo first.
