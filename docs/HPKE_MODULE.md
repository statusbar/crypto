[← back to module index](README.md)

# hpke

Hybrid Public Key Encryption per RFC 9180, for the cipher suite family
DHKEM(P-256, HKDF-SHA256) `0x0010` / HKDF-SHA256 `0x0001` / AES-128-GCM
`0x0001` or AES-256-GCM `0x0002`, in all four modes: base, psk, auth and
auth_psk.

> **Pre-release — unaudited.** See the disclaimer in [`README.md`](README.md).
> Implementation tracks RFC 9180 and reproduces the CFRG test vectors for
> every suite and mode it offers, but has not been third-party audited or
> fuzzed with constant-time tooling.

## Overview

HPKE is the IETF's standard hybrid encryption (TLS Encrypted Client Hello,
MLS, Oblivious HTTP all use it). A KEM encapsulates a fresh shared secret to
the recipient's public key, a key schedule turns it into an AEAD key, a base
nonce and an exporter secret, and the resulting context seals any number of
messages, each under the nonce `base_nonce XOR seq`.

It is the one hybrid scheme with published end-to-end known answers: RFC
9180 Appendix A and the CFRG vector grid give the ephemeral and recipient
key pairs, the encapsulated key, every key-schedule intermediate, the
ciphertexts at chosen sequence numbers and the exports. That is what makes
it the candidate for an IEEE 1722 EECF `enc` value beside ECC1, whose option
set has no published vectors (see [`ECIES_MODULE.md`](ECIES_MODULE.md)).

The pieces, with RFC section numbers:

- **DHKEM(P-256, HKDF-SHA256)** (7.1). `Encap` derives an ephemeral P-256
  key pair, runs ECDH with the recipient key and feeds `enc || pkRm` (plus
  `pkSm` and a second ECDH with the sender's static key in the auth modes)
  through `LabeledExtract` / `LabeledExpand` to a 32-byte shared secret.
  Public keys are SEC1 uncompressed (`0x04 || x || y`, 65 bytes).
  `DeriveKeyPair` (7.1.3) is the RFC's deterministic key derivation from
  input keying material; it is how a sender's ephemeral key comes from fresh
  random bytes and how the test vectors' key pairs are reproduced.
- **Key schedule** (5.1). `key_schedule_context = mode || psk_id_hash ||
  info_hash`; `secret = LabeledExtract(shared_secret, "secret", psk)`; then
  `key`, `base_nonce` and `exporter_secret` by `LabeledExpand`.
- **Context operations** (5.2, 5.3). `Seal` and `Open` run the AEAD under
  `ComputeNonce(seq)` and increment `seq` only on success; `Export` is
  `LabeledExpand(exporter_secret, "sec", exporter_context, L)`.

`LabeledExtract` is computed directly as the two-part
`HMAC-SHA-256(salt, "HPKE-v1" || suite_id || label, ikm)`, so `info` and
`psk_id` are not size-limited. `LabeledExpand` goes through
[`hkdf`](HKDF_MODULE.md) and inherits its 256-byte info buffer, which bounds
only an `exporter_context` (`hpke_max_exporter_context_size`).

## Key types

- `HpkeMode` — `base` (0), `psk` (1), `auth` (2), `auth_psk` (3).
- `HpkeAead` — `aes128_gcm` (0x0001), `aes256_gcm` (0x0002); `hpke_aead_key_size(aead)` is Nk.
- Sizes: `hpke_p256_public_key_size` 65 (Npk = Nenc), `hpke_p256_private_key_size` 32, `hpke_shared_secret_size` 32, `hpke_hash_size` 32, `hpke_nonce_size` 12, `hpke_tag_size` 16, `hpke_min_psk_size` 32, `hpke_min_ikm_size` 32, `hpke_max_export_size` 8160, `hpke_max_exporter_context_size` 234.
- `hpke_p256_derive_key_pair(ikm) -> std::optional<P256PrivateKey>` — DeriveKeyPair; nullopt when ikm is under 32 bytes.
- `hpke_p256_serialize_public_key(pk)` / `hpke_p256_deserialize_public_key(bytes)` — SEC1 uncompressed; deserialisation rejects a bad prefix or an off-curve point.
- `HpkeContext` — `aead`, `key` (first Nk bytes), `base_nonce`, `exporter_secret`, `seq`. Plain fields so tests can pin them and a transport can resume a context at a given `seq`; the secrets zero themselves on destruction.
- `HpkeSenderSetup` — `enc` (65 bytes, to transmit) and the sender's `HpkeContext`.
- `hpke_setup_base_s(aead, pk_r, info, ikm_e)` / `hpke_setup_base_r(aead, enc, sk_r, info)`, and the `psk`, `auth`, `auth_psk` pairs with `psk, psk_id` and/or `sk_s` / `pk_s` in the RFC's argument order. All return `std::optional`; nullopt on an invalid public key, a degenerate ECDH result or inconsistent psk inputs.
- `hpke_seal(context, aad, plaintext_to_ciphertext) -> std::optional<tag>` — in place; nullopt (nothing encrypted) at the message limit or over `aes_gcm_max_plaintext_size`.
- `hpke_open(context, aad, ciphertext_to_plaintext, tag) -> bool` — verify, decrypt in place, then increment `seq`; false (buffer zeroed, `seq` unchanged) on a bad tag.
- `hpke_export(context, exporter_context, out) -> bool`.

## Public headers

- `statusbar/crypto/hpke/hpke.hpp` — everything above.

## Dependencies

- [`p256`](P256_MODULE.md) — ECDH, key pair from scalar, point decoding (so the module builds only where the 128-bit-integer P-256 implementation does, like `ecies`).
- [`hkdf`](HKDF_MODULE.md) and [`sha`](SHA_MODULE.md) — LabeledExpand and LabeledExtract.
- [`aes_gcm`](AES_GCM_MODULE.md) — the AEADs.

## Testing

`hpke_test.cpp` runs the eight CFRG vectors for this suite family (both
AEADs, four modes; `hpke_vectors.hpp`, generated by
`python/crypto/gen_hpke_kats.py` from the CFRG `test-vectors.json`): every
`DeriveKeyPair`, the sender's `enc` and context, the recipient's context,
the encryptions at seq 0, 1, 2, 4, 255 and 256 through both `Seal` and
`Open`, and all exports. Behaviour tests cover tampering (buffer zeroed,
`seq` kept), a wrong psk or sender key, psk input validation, malformed
`enc`, short ikm, export limits, a 1000-byte `info`, and the sequence limit.
`hpke_fuzzer.cpp` is the libFuzzer harness.

## Notes & caveats

- The sender's ephemeral key is `DeriveKeyPair(ikm_e)`: pass at least 32
  fresh random bytes per setup. Reusing `ikm_e` reuses the ephemeral key.
- Only P-256 and the two AES-GCM AEADs; no X25519 KEM, ChaCha20-Poly1305 or
  export-only AEAD yet, and no single-shot API — compose setup and seal.
- `seq` is 64-bit; `Seal`/`Open` refuse at `UINT64_MAX` rather than at the
  RFC's `2^(8*Nn) - 1`.

## Further reading

- RFC 9180, *Hybrid Public Key Encryption*.
- CFRG test vectors: https://github.com/cfrg/draft-irtf-cfrg-hpke (test-vectors.json).
- RFC 9849 (TLS ECH) and RFC 9420 (MLS) as deployed users of the same construction.
