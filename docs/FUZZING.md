[← back to docs index](README.md)

# Fuzzing

`statusbar-crypto` ships 17 libFuzzer-style harnesses, one per
cryptographic primitive. Each `*_fuzzer.cpp` defines
`LLVMFuzzerTestOneInput(data, size)`, parses the byte buffer into the
inputs the primitive expects, runs the operation (typically a
round-trip plus a corruption test), and calls `__builtin_trap()` on
any invariant violation. On Linux the harnesses are linked against
clang's `-fsanitize=fuzzer` runtime; on macOS they link against the
standalone driver in [`util/standalone_driver.cpp`](../statusbar/crypto/util/standalone_driver.cpp)
which reads each command-line argument as a file and feeds it to the
same `LLVMFuzzerTestOneInput`.

## Harnesses

| Harness                          | Module        | What the fuzz input feeds                                                      |
|----------------------------------|---------------|--------------------------------------------------------------------------------|
| `aes_fuzzer`                     | `aes/`        | 16-byte AES-128 key + 16-byte plaintext (and 32-byte / 16-byte for AES-256); asserts encrypt→decrypt round-trip. |
| `aes_cmac_fuzzer`                | `aes/`        | 32-byte key + arbitrary message; asserts `aes128_cmac` / `aes256_cmac` verify, and that a 1-bit-flipped tag fails. |
| `aes_cbc_fuzzer`                 | `aes_cbc/`    | 32-byte AES-256 key + plaintext; round-trips CBC encrypt/decrypt and feeds malformed ciphertext to padding validation. |
| `aes_siv_fuzzer`                 | `aes_siv/`    | 64-byte AES-256-SIV key + AAD/plaintext split; checks RFC 5297 round-trip, wrong-AAD rejection, tag-flip rejection, and decrypts raw fuzz bytes. |
| `aes128_siv_fuzzer`              | `aes_siv/`    | 32-byte AES-128-SIV key + AAD/plaintext split; same invariants as `aes_siv_fuzzer` for the 128-bit variant. |
| `aes_gcm_siv_fuzzer`             | `aes_gcm_siv/`| 32-byte key + 12-byte nonce + AAD/plaintext split; round-trips RFC 8452 AES-256-GCM-SIV with AAD. |
| `aes128_gcm_siv_fuzzer`          | `aes_gcm_siv/`| 16-byte key + 12-byte nonce + AAD/plaintext split; same as above for AES-128-GCM-SIV. |
| `sha256_fuzzer`                  | `sha/`        | Arbitrary bytes; computes SHA-256, SHA-512, HMAC-SHA-256 and cross-checks the `_secure_*` variants against the regular ones. |
| `polyval_fuzzer`                 | `polyval/`    | 16-byte POLYVAL key + 16-byte-multiple input; cross-checks `polyval_sw` against `polyval_hw` for bit-identical results. |
| `hkdf_fuzzer`                    | `hkdf/`       | First two bytes split the buffer into salt / IKM / info; exercises extract, expand, and the one-shot wrapper. |
| `kdf2_fuzzer`                    | `kdf2/`       | First byte splits into shared-secret / params; iterates several output sizes; checks that valid inputs succeed. |
| `x25519_fuzzer`                  | `25519/`      | Two 32-byte seeds; asserts ECDH symmetry and validates the shared secret rejects low-order points. |
| `ed25519_fuzzer`                 | `25519/`      | 32-byte seed + message; signs, verifies, and confirms a 1-bit-flipped signature fails. |
| `p256_ecdh_fuzzer`               | `p256/`       | Two 32-byte seeds; asserts P-256 ECDH symmetry and feeds fuzz-derived public keys to ensure no crash. |
| `p256_ecdsa_fuzzer`              | `p256/`       | 32-byte seed + message; signs, verifies, and confirms a 1-bit-flipped (r,s) fails. |
| `ecies_fuzzer`                   | `ecies/`      | 32-byte recipient seed + 32-byte sender entropy + plaintext; round-trips ECIES encrypt/decrypt. |
| `pkcs8_fuzzer`                   | `pkcs8/`      | Arbitrary bytes fed to all four DER importers (`spki_import_ed25519`, `pkcs8_import_ed25519`, `spki_import_p256`, `pkcs8_import_p256`); export-then-import round-trip on 32-byte prefix. |

The six fuzzers in the lower half of the table (`x25519`, `ed25519`,
`p256_*`, `ecies`, `pkcs8`) are gated on `STATUSBAR_CRYPTO_HAS_INT128`
and stub out their `main` body on 32-bit hosts — see [`util`](UTIL_MODULE.md).

## Building with fuzzers enabled

```
./local-build.sh -DENABLE_FUZZING=ON
```

The umbrella's [`cmake/fuzzing.cmake`](../../cmake/fuzzing.cmake) wires
the toolchain. The option defaults **ON** on Linux when the C++ compiler
is clang (the project's required toolchain), and **OFF** on Apple
platforms — Homebrew's libFuzzer runtime has an ABI mismatch with the
project's libc++ build, so the macOS path uses the standalone driver
instead of `-fsanitize=fuzzer`. Pass `-DENABLE_FUZZING=ON` explicitly to
opt into the macOS standalone build.

On Linux each fuzzer is built with
`-fsanitize=fuzzer,address,undefined`; on macOS with
`-fsanitize=address,undefined` plus the standalone driver supplying
`main()`. Either way the fuzz binaries land directly under
`build/` next to the test binary.

## Running

Two umbrella CMake targets are registered automatically once fuzzing is
enabled:

```
cmake --build build --target fuzz-smoke   # one random 256-byte seed per fuzzer
cmake --build build --target fuzz-all     # 30 s libFuzzer campaign on Linux,
                                          # 1000 random inputs per fuzzer on macOS
```

`fuzz-smoke` is the CI-friendly check: it runs each `*_fuzzer` binary
with `-runs=1 -timeout=5` over a freshly generated random seed, so a
full pass takes seconds. `fuzz-all` is the actual campaign — it shells
out to [`cmake/fuzz-all.sh`](../../cmake/fuzz-all.sh) which discovers
every `*_fuzzer` under the build tree and runs them with persistent
corpora.

## Running a single fuzzer

Each fuzzer is a normal libFuzzer-compatible binary; on Linux call it
directly with the usual flags:

```
./build/aes_cbc_fuzzer -max_total_time=60 -max_len=4096 \
    build/fuzz/corpus/aes_cbc_fuzzer
```

On macOS the standalone driver takes input *files* as positional
arguments:

```
./build/aes_cbc_fuzzer corpus/seed1.bin corpus/seed2.bin
```

The driver reads each file (up to 10 MB) and invokes
`LLVMFuzzerTestOneInput` once per file.

## Corpora

`fuzz-all.sh` creates one persistent corpus per fuzzer:

```
build/fuzz/corpus/<fuzzer_name>/
```

These directories survive between runs so libFuzzer can grow the corpus
incrementally. `fuzz-smoke` writes its one-off random seeds to
`build/fuzz/seeds/` instead.

## macOS standalone driver

`crypto/statusbar/crypto/util/standalone_driver.cpp` provides a minimal
`main()` that links into every fuzz binary on macOS. It exists because
the Homebrew-LLVM libFuzzer runtime is incompatible with the libc++
stdlib the rest of the project uses — see the comment block at the top
of [`cmake/fuzzing.cmake`](../../cmake/fuzzing.cmake). The driver loops
over `argv[1..]`, reads each file into a `std::vector<uint8_t>`, and
calls `LLVMFuzzerTestOneInput`. There is no mutation, scheduling, or
coverage feedback — it is a deterministic replay tool. For real
mutation-based fuzzing, run on Linux.

## Further reading

- [HARDWARE_ACCELERATION.md](HARDWARE_ACCELERATION.md) — the fuzzers
  generally call `_sw` so a single corpus is portable across CPUs;
  the POLYVAL fuzzer additionally cross-checks `_sw` against `_hw`.
- [`util`](UTIL_MODULE.md) — `test::do_not_optimize()` used by several
  harnesses to prevent the compiler from eliding the operation being
  fuzzed; `STATUSBAR_CRYPTO_HAS_INT128` gates the EC-based fuzzers.
- [`cmake/fuzz-smoke.sh`](../../cmake/fuzz-smoke.sh),
  [`cmake/fuzz-all.sh`](../../cmake/fuzz-all.sh) — the shell drivers
  invoked by the CMake targets above.
