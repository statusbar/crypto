#!/usr/bin/env python3
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# SPDX-License-Identifier: MIT
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography>=43.0"]
# ///
"""Generate independent KDF2-SHA256 known-answer vectors.

ANSI X9.63 KDF (as exposed by `cryptography.hazmat.primitives.kdf.x963kdf`)
is algorithmically identical to IEEE 1363a-2004 §13.2 KDF2 when the hash
is byte-aligned (SHA-256 is). Emits C++ array literals suitable for
pasting into `crypto/statusbar/crypto/kdf2/kdf2_test.cpp`.

Usage:
    uv run crypto/python/crypto/gen_kdf2_kats.py
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF


def derive(z: bytes, p: bytes, length: int) -> bytes:
    kdf = X963KDF(algorithm=hashes.SHA256(), length=length, sharedinfo=p)
    return kdf.derive(z)


def cppbytes(b: bytes, indent: str = "    ") -> str:
    hexes = [f"0x{x:02X}" for x in b]
    rows = [", ".join(hexes[i : i + 8]) for i in range(0, len(hexes), 8)]
    return ",\n".join(indent + r for r in rows)


# Each vector exercises a different shape of the algorithm.
VECTORS = [
    # (name, Z, P, output_length)
    ("kat1_single_block", bytes([0x01, 0x02, 0x03, 0x04]), b"", 32),
    ("kat2_with_info", bytes([0xAA, 0xBB, 0xCC, 0xDD]), bytes([0x01, 0x02, 0x03]), 32),
    ("kat3_two_blocks", bytes([0x42] * 16), b"", 64),
    ("kat4_partial_block", bytes(range(32)), b"label", 40),
    (
        "kat5_ecdh_typical",
        bytes.fromhex(
            "9858efbacc36b14d70d2e9c91e3c95f1c14e9d1eedbcdaa5e1bd4eaa46b71fe1"
        ),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        48,
    ),
]


def emit_one(name: str, z: bytes, p: bytes, length: int) -> None:
    out = derive(z, p, length)
    print(f"    // {name}: Z={z.hex()} P={p.hex() or '<empty>'} len={length}")
    print(f"    constexpr std::array<uint8_t, {len(z)}> {name}_Z{{")
    print(cppbytes(z, indent="        "))
    print("    };")
    if p:
        print(f"    constexpr std::array<uint8_t, {len(p)}> {name}_P{{")
        print(cppbytes(p, indent="        "))
        print("    };")
    print(f"    constexpr std::array<uint8_t, {length}> {name}_expected{{")
    print(cppbytes(out, indent="        "))
    print("    };")
    print()


def main() -> None:
    for name, z, p, length in VECTORS:
        emit_one(name, z, p, length)


if __name__ == "__main__":
    main()
