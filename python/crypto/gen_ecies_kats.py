#!/usr/bin/env python3
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography>=43.0"]
# ///
"""Generate independent ECIES known-answer vectors.

Written from IEEE 1363a-2004 11.3.2 (P-256 ECSVDP-DHC, KDF2-SHA-256,
AES-256-CBC-IV0, HMAC-SHA-256, DHAES mode, EC2OSP-X, P1 = P2 = empty — the
IEEE 1722-2025 17.3.1 ECC1 options) and from the x25519_ecies.hpp profile
description, on top of the `cryptography` package only: nothing here imports
statusbar_crypto, so the vectors are independent of the C++ and Python
libraries they test. In particular they pin the key order of 11.3.2 step 10a:
K1 = leftmost 32 bytes is the AES key, K2 = the rest is the MAC key.

Emits C++ array literals for `statusbar/crypto/ecies/ecies_test.cpp` and
`x25519_ecies_test.cpp`; the same bytes are in
`statusbar_crypto_test.py::TestEciesKnownAnswer`.

Usage:
    uv run crypto/python/crypto/gen_ecies_kats.py
"""

import hashlib, hmac, struct, sys
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def p256_from_seed(seed):  # statusbar p256_keypair_from_seed: d = SHA-256(seed) mod n
    d = int.from_bytes(hashlib.sha256(seed).digest(), "big") % N
    assert d != 0
    return ec.derive_private_key(d, ec.SECP256R1())


def kdf2_sha256(
    Z, P1, out_len
):  # 1363a 13.2: Hash(Z || I2OSP(counter,4) || P1), counter from 1
    out = b""
    counter = 1
    while len(out) < out_len:
        out += hashlib.sha256(Z + struct.pack(">I", counter) + P1).digest()
        counter += 1
    return out[:out_len]


def aes256_cbc_iv0(K1, M):  # 1363a 14.3.2, PKCS#7 padding, null IV
    pad = 16 - (len(M) % 16)
    enc = Cipher(algorithms.AES(K1), modes.CBC(b"\0" * 16)).encryptor()
    return enc.update(M + bytes([pad]) * pad) + enc.finalize()


def mac1(K2, C, P2):  # 1363a 11.3.2 steps 11-12, DHAES: L2 = I2OSP(len_bits(P2), 8)
    L2 = struct.pack(">Q", len(P2) * 8)
    return hmac.new(K2, C + P2 + L2, hashlib.sha256).digest()


def ecies_p256(recipient_seed, entropy, M, P1=b"", P2=b""):
    recipient = p256_from_seed(recipient_seed)
    eph = p256_from_seed(entropy)
    Z = eph.exchange(ec.ECDH(), recipient.public_key())  # FE2OSP(x), 32 octets
    x = eph.public_key().public_numbers().x.to_bytes(32, "big")
    V = b"\x01" + x  # EC2OSP-X (5.5.6.3)
    K = kdf2_sha256(V + Z, P1, 64)  # DHAES: VZ = V || Z
    K1, K2 = K[:32], K[32:]  # step 10a: K1 leftmost
    C = aes256_cbc_iv0(K1, M)
    T = mac1(K2, C, P2)
    return V + C + T


def ecies_x25519(recipient_seed, entropy, M):
    recipient = x25519.X25519PrivateKey.from_private_bytes(recipient_seed)
    eph = x25519.X25519PrivateKey.from_private_bytes(entropy)
    V = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    Z = eph.exchange(recipient.public_key())
    K = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"X25519-ECIES" + V
    ).derive(Z)
    K1, K2 = K[:32], K[32:]
    C = aes256_cbc_iv0(K1, M)
    T = hmac.new(K2, C + struct.pack(">Q", 0), hashlib.sha256).digest()
    return V + C + T


def cxx(name, b, per_line=16):
    lines = []
    for i in range(0, len(b), per_line):
        lines.append(
            "    " + ", ".join(f"0x{x:02X}" for x in b[i : i + per_line]) + ","
        )
    return (
        f"constexpr std::array<uint8_t, {len(b)}> {name}{{\n"
        + "\n".join(lines)
        + "\n}};"
    )


seed = bytes(range(1, 33))
entropy = bytes(
    [
        0xDE,
        0xAD,
        0xBE,
        0xEF,
        0xCA,
        0xFE,
        0xBA,
        0xBE,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
    ]
)
for label, fn in (("p256", ecies_p256), ("x25519", ecies_x25519)):
    for mname, M in (("hello", b"Hello, DL/ECIES!"), ("short", b"test data")):
        out = fn(seed, entropy, M)
        print(f"// {label} {mname}: {len(out)} bytes")
        print(cxx(f"kat_{label}_{mname}", out))
        print()
