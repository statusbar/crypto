<!-- Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com> -->

# AES-128 vs AES-256 for AVB Stream Encryption

## Reasons to use AES-128 variants (SIV or GCM-SIV)

1. **Performance**: AES-128 uses 10 rounds vs 14 for AES-256 — roughly 40% faster in software. On hardware with AES-NI, the difference is smaller but still measurable at high throughput (relevant for audio/video streams).

2. **Smaller key material**: 16-byte keys (or 32 bytes for AES-128-SIV which needs two sub-keys) means less data to distribute via ECIES, smaller AUTH_ADD_KEY_NONCE payloads, and less key storage per stream.

3. **Sufficient security margin**: AES-128 provides 128-bit security. The best known attack on AES-128 is ~126.1 bits (biclique), which is completely infeasible. No practical attack exists or is foreseeable.

4. **Constrained endpoints**: AVB talkers/listeners may be embedded devices (microcontrollers, FPGAs, DSPs) where key storage, RAM, and cycle budget matter. AES-128 is friendlier to these environments.

5. **Hardware availability**: Some low-cost embedded crypto accelerators only support AES-128.

## Reasons to prefer AES-256 variants

1. **Post-quantum margin**: Grover's algorithm theoretically halves the effective key strength. AES-256 retains 128-bit security against a quantum adversary; AES-128 drops to ~64-bit, which is breakable. This is the primary argument for AES-256.

2. **Regulatory/compliance**: Some standards (CNSA Suite, certain government requirements) mandate 256-bit symmetric keys.

3. **Defense in depth**: If a weakness in AES were found that reduced effective security by a few bits, AES-256 has more margin to absorb it.

## Risks of AES-128-SIV / AES-128-GCM-SIV specifically

- **Quantum threat**: The only realistic risk. If large-scale quantum computers become available during the lifetime of the encrypted streams, AES-128 keyed material could theoretically be broken. For real-time AV streams this is largely irrelevant — the data is ephemeral and not worth storing for future cryptanalysis.

- **Multi-key attacks**: With 2^64 streams each using independent AES-128 keys, an attacker could find *some* key with 2^64 work. In practice AVB networks don't approach anywhere near this scale.

- **No practical classical risk**: There is zero known classical attack that makes AES-128 insecure. The security margin is enormous.

## SIV vs GCM-SIV consideration

This is orthogonal to key size, but worth noting:

- **AES-SIV** (RFC 5297): Two-pass (one for IV derivation, one for encryption). Nonce-misuse resistant. Slightly higher latency due to two passes.
- **AES-GCM-SIV** (RFC 8452): Single-pass-ish, also nonce-misuse resistant, better performance for long messages. Uses a plain AES key (not a doubled key pair).

Both provide nonce-misuse resistance, which matters for AVB where sequence numbers might wrap or be reused after rekeying.

## Data volume limits: AES-SIV vs AES-GCM-SIV

### AES-SIV (RFC 5297, enc=0)

AES-SIV uses AES-CMAC for the synthetic IV and AES-CTR for encryption. The critical limits:

- **Per-key data limit**: AES-CTR has a birthday bound on the counter/IV space. In SIV, the 128-bit synthetic IV is derived deterministically from the plaintext and associated data, so each unique message gets a unique IV. The risk is IV collision across different messages — if two distinct messages produce the same SIV, confidentiality degrades (but authentication still holds due to misuse resistance).
- **Birthday bound**: ~2^64 messages under a single key before SIV collision probability becomes concerning (128-bit IV, birthday at 2^64).
- **Per-message size**: AES-CTR with a 128-bit block cipher can encrypt up to 2^128 blocks per IV, but the practical limit is ~2^32 blocks (64 GB) per message to avoid CTR overflow within the SIV-derived counter space.
- **AES-128-SIV vs AES-256-SIV**: No difference in these data limits. The limits come from the 128-bit block size of AES (shared by both), not the key size. Key size only affects brute-force resistance.

### AES-GCM-SIV (RFC 8452, enc=1)

AES-GCM-SIV uses POLYVAL (a GF(2^128) polynomial MAC) and AES-CTR. The limits are tighter:

- **Per-key message limit**: The security proof degrades after ~2^32 messages under a single key with random nonces. With deterministic nonces (which AVB can provide via sequence numbers), this extends to 2^48 nonces, but the POLYVAL forgery bound still applies.
- **Per-message size limit**: Strictly limited to 2^36 - 32 bytes (~64 GB) per message. In practice, RFC 8452 recommends keeping messages well below this.
- **POLYVAL forgery probability**: Increases as message length grows. For messages of L blocks, forgery advantage is proportional to L/2^128 per attempt, but multi-key/multi-message scenarios compound this.
- **AES-128-GCM-SIV vs AES-256-GCM-SIV**: Again, no difference in data limits. Same 128-bit block, same POLYVAL field.

### Practical comparison for AVB

| Limit | AES-SIV | AES-GCM-SIV |
|---|---|---|
| Max messages per key | ~2^64 | ~2^32 (random nonce) |
| Max message size | ~64 GB | ~64 GB |
| Nonce-misuse resistance | Full (SIV is deterministic) | Partial (leaks equality of plaintexts) |
| Performance | 2-pass | ~1-pass (faster) |
| 128 vs 256 key effect on limits | None | None |

The key difference for AVB: AES-SIV allows ~2^64 messages per key vs ~2^32 for AES-GCM-SIV. For a 48 kHz audio stream sending one packet per sample period, 2^32 messages is about 24 hours. That's tight — you'd want to rekey daily. AES-SIV at 2^64 messages would last billions of years at the same rate.

In practice, AVB packets are typically sent at class intervals (125 us or 1 ms), so:
- At 8000 packets/sec (class A): 2^32 = ~6.2 days per key with GCM-SIV
- At 8000 packets/sec: 2^64 = ~73 million years per key with SIV

### Hardware key size support

Every hardware AES implementation supports all three standard key sizes (128, 192, 256). The AES specification (FIPS 197) defines all three as part of the single algorithm. This includes AES-NI (Intel/AMD), ARMv8 Crypto Extensions, hardware security modules, secure enclaves, and FPGA crypto IP. The argument for AES-128 on constrained hardware is purely about performance and key storage, not availability.

## Bottom line

For AVB streaming where data is ephemeral and real-time, **AES-128 is perfectly safe** and offers concrete performance benefits on constrained endpoints. The only scenario where AES-256 is meaningfully better is if you need quantum resistance or must satisfy a compliance checkbox — neither of which typically applies to real-time AV transport on a LAN.

**AES-SIV has a much more comfortable margin** for long-lived session keys (~2^64 messages vs ~2^32 for GCM-SIV). AES-GCM-SIV is faster but requires more frequent rekeying. The 128 vs 256 key size makes no difference to data volume limits — they are all bounded by the 128-bit AES block size.
