#!/usr/bin/env python3
# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "cryptography>=43.0",
#     "pycryptodome>=3.20",
# ]
# ///
"""
Test vector generator for statusbar_crypto library.

Generates known-answer test vectors for all cryptographic algorithms
implemented in statusbar_crypto. Output is JSON with hex-encoded binary data.

Usage:
    uv run avtp_crypto_vectors.py                          # All algorithms
    uv run avtp_crypto_vectors.py --algorithm aes128_siv   # Single algorithm
    uv run avtp_crypto_vectors.py --list                   # List algorithms
"""

import argparse
import hashlib
import hmac
import json
import sys


def hex_encode(data: bytes) -> str:
    return data.hex()


#
# AES-128 block cipher (FIPS 197)
#


def gen_aes128_block():
    from Crypto.Cipher import AES

    vectors = []

    # FIPS 197 Appendix B
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    vectors.append(
        {
            "name": "fips197_appendix_b",
            "key": hex_encode(key),
            "plaintext": hex_encode(plaintext),
            "ciphertext": hex_encode(ciphertext),
        }
    )

    # NIST SP 800-38A F.1.1 block 1
    plaintext2 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ciphertext2 = cipher.encrypt(plaintext2)
    vectors.append(
        {
            "name": "nist_sp800_38a_f1_1_block1",
            "key": hex_encode(key),
            "plaintext": hex_encode(plaintext2),
            "ciphertext": hex_encode(ciphertext2),
        }
    )

    return {"algorithm": "aes128_block", "standard": "FIPS 197", "vectors": vectors}


#
# AES-256 block cipher (FIPS 197)
#


def gen_aes256_block():
    from Crypto.Cipher import AES

    vectors = []

    # FIPS 197 Appendix C.3
    key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    )
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    vectors.append(
        {
            "name": "fips197_appendix_c3_block1",
            "key": hex_encode(key),
            "plaintext": hex_encode(plaintext),
            "ciphertext": hex_encode(ciphertext),
        }
    )

    return {"algorithm": "aes256_block", "standard": "FIPS 197", "vectors": vectors}


#
# AES-128 CMAC (RFC 4493)
#


def gen_aes128_cmac():
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    vectors = []

    # RFC 4493 Example 1: empty
    c = CMAC.new(key, ciphermod=AES)
    c.update(b"")
    vectors.append(
        {
            "name": "rfc4493_example1_empty",
            "key": hex_encode(key),
            "message": "",
            "tag": hex_encode(c.digest()),
        }
    )

    # RFC 4493 Example 2: 16 bytes
    msg16 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg16)
    vectors.append(
        {
            "name": "rfc4493_example2_16bytes",
            "key": hex_encode(key),
            "message": hex_encode(msg16),
            "tag": hex_encode(c.digest()),
        }
    )

    # RFC 4493 Example 3: 40 bytes
    msg40 = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411"
    )
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg40)
    vectors.append(
        {
            "name": "rfc4493_example3_40bytes",
            "key": hex_encode(key),
            "message": hex_encode(msg40),
            "tag": hex_encode(c.digest()),
        }
    )

    # RFC 4493 Example 4: 64 bytes
    msg64 = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg64)
    vectors.append(
        {
            "name": "rfc4493_example4_64bytes",
            "key": hex_encode(key),
            "message": hex_encode(msg64),
            "tag": hex_encode(c.digest()),
        }
    )

    return {"algorithm": "aes128_cmac", "standard": "RFC 4493", "vectors": vectors}


#
# AES-256 CMAC
#


def gen_aes256_cmac():
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES

    key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    )
    vectors = []

    # Empty message
    c = CMAC.new(key, ciphermod=AES)
    c.update(b"")
    vectors.append(
        {
            "name": "empty",
            "key": hex_encode(key),
            "message": "",
            "tag": hex_encode(c.digest()),
        }
    )

    # 16-byte message
    msg16 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg16)
    vectors.append(
        {
            "name": "16bytes",
            "key": hex_encode(key),
            "message": hex_encode(msg16),
            "tag": hex_encode(c.digest()),
        }
    )

    # 40-byte message
    msg40 = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411"
    )
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg40)
    vectors.append(
        {
            "name": "40bytes",
            "key": hex_encode(key),
            "message": hex_encode(msg40),
            "tag": hex_encode(c.digest()),
        }
    )

    return {
        "algorithm": "aes256_cmac",
        "standard": "RFC 4493 (AES-256)",
        "vectors": vectors,
    }


#
# AES-128-SIV (RFC 5297)
#


def gen_aes128_siv():
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    vectors = []

    # RFC 5297 Appendix A.1
    key = bytes.fromhex(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    )
    aad = bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")
    plaintext = bytes.fromhex("112233445566778899aabbccddee")

    cipher = AESSIV(key)
    ct = cipher.encrypt(plaintext, [aad])
    # AESSIV returns SIV (16 bytes) prepended to ciphertext
    siv = ct[:16]
    ciphertext = ct[16:]

    vectors.append(
        {
            "name": "rfc5297_a1",
            "key": hex_encode(key),
            "aad": hex_encode(aad),
            "plaintext": hex_encode(plaintext),
            "siv": hex_encode(siv),
            "ciphertext": hex_encode(ciphertext),
        }
    )

    # Empty plaintext, empty AAD
    # Note: [b""] = one empty AD component (S2V with 2 inputs), matching C++ API
    cipher = AESSIV(key)
    ct_empty = cipher.encrypt(b"", [b""])
    siv_empty = ct_empty[:16]
    ct_body_empty = ct_empty[16:]
    vectors.append(
        {
            "name": "empty_pt_empty_aad",
            "key": hex_encode(key),
            "aad": "",
            "plaintext": "",
            "siv": hex_encode(siv_empty),
            "ciphertext": hex_encode(ct_body_empty),
        }
    )

    # 20-byte plaintext with AAD
    key2 = bytes.fromhex(
        "0102030405060708091011121314151617181920212223242526272829303132"
    )
    aad2 = bytes.fromhex("aabbccdd")
    pt2 = bytes(range(20))
    cipher2 = AESSIV(key2)
    ct2 = cipher2.encrypt(pt2, [aad2])
    siv2 = ct2[:16]
    ct_body2 = ct2[16:]
    vectors.append(
        {
            "name": "20byte_pt_with_aad",
            "key": hex_encode(key2),
            "aad": hex_encode(aad2),
            "plaintext": hex_encode(pt2),
            "siv": hex_encode(siv2),
            "ciphertext": hex_encode(ct_body2),
        }
    )

    # 16-byte plaintext (exactly one block), empty AAD
    pt3 = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher3 = AESSIV(key2)
    ct3 = cipher3.encrypt(pt3, [b""])
    siv3 = ct3[:16]
    ct_body3 = ct3[16:]
    vectors.append(
        {
            "name": "16byte_pt_no_aad",
            "key": hex_encode(key2),
            "aad": "",
            "plaintext": hex_encode(pt3),
            "siv": hex_encode(siv3),
            "ciphertext": hex_encode(ct_body3),
        }
    )

    return {"algorithm": "aes128_siv", "standard": "RFC 5297", "vectors": vectors}


#
# AES-256-SIV (RFC 5297)
#


def gen_aes256_siv():
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    vectors = []

    # 64-byte key (AES-256-SIV uses 512-bit key: 256 CMAC + 256 CTR)
    key = bytes.fromhex(
        "0102030405060708091011121314151617181920212223242526272829303132"
        "3334353637383940414243444546474849505152535455565758596061626364"
    )

    # 20-byte plaintext with 4-byte AAD
    aad = bytes.fromhex("aabbccdd")
    pt = bytes(range(20))
    cipher = AESSIV(key)
    ct = cipher.encrypt(pt, [aad])
    siv = ct[:16]
    ciphertext = ct[16:]
    vectors.append(
        {
            "name": "20byte_pt_with_aad",
            "key": hex_encode(key),
            "aad": hex_encode(aad),
            "plaintext": hex_encode(pt),
            "siv": hex_encode(siv),
            "ciphertext": hex_encode(ciphertext),
        }
    )

    # Empty plaintext, empty AAD
    # Note: [b""] = one empty AD component (S2V with 2 inputs), matching C++ API
    cipher2 = AESSIV(key)
    ct2 = cipher2.encrypt(b"", [b""])
    siv2 = ct2[:16]
    ct_body2 = ct2[16:]
    vectors.append(
        {
            "name": "empty_pt_empty_aad",
            "key": hex_encode(key),
            "aad": "",
            "plaintext": "",
            "siv": hex_encode(siv2),
            "ciphertext": hex_encode(ct_body2),
        }
    )

    # 16-byte plaintext (exactly one block), empty AAD
    pt3 = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher3 = AESSIV(key)
    ct3 = cipher3.encrypt(pt3, [b""])
    siv3 = ct3[:16]
    ct_body3 = ct3[16:]
    vectors.append(
        {
            "name": "16byte_pt_no_aad",
            "key": hex_encode(key),
            "aad": "",
            "plaintext": hex_encode(pt3),
            "siv": hex_encode(siv3),
            "ciphertext": hex_encode(ct_body3),
        }
    )

    # 48-byte plaintext (3 blocks), 12-byte AAD
    aad4 = bytes(range(12))
    pt4 = bytes(range(48))
    cipher4 = AESSIV(key)
    ct4 = cipher4.encrypt(pt4, [aad4])
    siv4 = ct4[:16]
    ct_body4 = ct4[16:]
    vectors.append(
        {
            "name": "48byte_pt_12byte_aad",
            "key": hex_encode(key),
            "aad": hex_encode(aad4),
            "plaintext": hex_encode(pt4),
            "siv": hex_encode(siv4),
            "ciphertext": hex_encode(ct_body4),
        }
    )

    return {"algorithm": "aes256_siv", "standard": "RFC 5297", "vectors": vectors}


#
# AES-128-GCM-SIV (RFC 8452)
#


def gen_aes128_gcm_siv():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

    vectors = []
    key = bytes.fromhex("01000000000000000000000000000000")
    nonce = bytes.fromhex("030000000000000000000000")

    # Empty plaintext, empty AAD (RFC 8452 C.1 test 1)
    cipher = AESGCMSIV(key)
    ct = cipher.encrypt(nonce, b"", b"")
    # AESGCMSIV returns ciphertext + 16-byte tag
    tag = ct[-16:]
    ciphertext = ct[:-16]
    vectors.append(
        {
            "name": "rfc8452_c1_empty",
            "key": hex_encode(key),
            "nonce": hex_encode(nonce),
            "aad": "",
            "plaintext": "",
            "ciphertext": hex_encode(ciphertext),
            "tag": hex_encode(tag),
        }
    )

    # 8-byte plaintext, empty AAD
    pt2 = bytes.fromhex("0100000000000000")
    cipher2 = AESGCMSIV(key)
    ct2 = cipher2.encrypt(nonce, pt2, b"")
    tag2 = ct2[-16:]
    ct_body2 = ct2[:-16]
    vectors.append(
        {
            "name": "rfc8452_c1_8bytes",
            "key": hex_encode(key),
            "nonce": hex_encode(nonce),
            "aad": "",
            "plaintext": hex_encode(pt2),
            "ciphertext": hex_encode(ct_body2),
            "tag": hex_encode(tag2),
        }
    )

    # 16-byte plaintext with 1-byte AAD
    aad3 = bytes.fromhex("01")
    pt3 = bytes.fromhex("02000000000000000000000000000000")
    cipher3 = AESGCMSIV(key)
    ct3 = cipher3.encrypt(nonce, pt3, aad3)
    tag3 = ct3[-16:]
    ct_body3 = ct3[:-16]
    vectors.append(
        {
            "name": "rfc8452_c1_16bytes_with_aad",
            "key": hex_encode(key),
            "nonce": hex_encode(nonce),
            "aad": hex_encode(aad3),
            "plaintext": hex_encode(pt3),
            "ciphertext": hex_encode(ct_body3),
            "tag": hex_encode(tag3),
        }
    )

    return {"algorithm": "aes128_gcm_siv", "standard": "RFC 8452", "vectors": vectors}


#
# AES-256-GCM-SIV (RFC 8452)
#


def gen_aes256_gcm_siv():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

    vectors = []

    # RFC 8452 Appendix C.2
    key = bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000000"
    )
    nonce = bytes.fromhex("030000000000000000000000")

    # Empty plaintext, empty AAD
    cipher = AESGCMSIV(key)
    ct = cipher.encrypt(nonce, b"", b"")
    tag = ct[-16:]
    ciphertext = ct[:-16]
    vectors.append(
        {
            "name": "rfc8452_c2_empty",
            "key": hex_encode(key),
            "nonce": hex_encode(nonce),
            "aad": "",
            "plaintext": "",
            "ciphertext": hex_encode(ciphertext),
            "tag": hex_encode(tag),
        }
    )

    # 8-byte plaintext, empty AAD
    pt2 = bytes.fromhex("0100000000000000")
    cipher2 = AESGCMSIV(key)
    ct2 = cipher2.encrypt(nonce, pt2, b"")
    tag2 = ct2[-16:]
    ct_body2 = ct2[:-16]
    vectors.append(
        {
            "name": "rfc8452_c2_8bytes",
            "key": hex_encode(key),
            "nonce": hex_encode(nonce),
            "aad": "",
            "plaintext": hex_encode(pt2),
            "ciphertext": hex_encode(ct_body2),
            "tag": hex_encode(tag2),
        }
    )

    # 16-byte plaintext with 1-byte AAD
    aad3 = bytes.fromhex("01")
    pt3 = bytes.fromhex("02000000000000000000000000000000")
    cipher3 = AESGCMSIV(key)
    ct3 = cipher3.encrypt(nonce, pt3, aad3)
    tag3 = ct3[-16:]
    ct_body3 = ct3[:-16]
    vectors.append(
        {
            "name": "rfc8452_c2_16bytes_with_aad",
            "key": hex_encode(key),
            "nonce": hex_encode(nonce),
            "aad": hex_encode(aad3),
            "plaintext": hex_encode(pt3),
            "ciphertext": hex_encode(ct_body3),
            "tag": hex_encode(tag3),
        }
    )

    return {"algorithm": "aes256_gcm_siv", "standard": "RFC 8452", "vectors": vectors}


#
# SHA-256 (FIPS 180-4)
#


def gen_sha256():
    vectors = []

    # SHA-256("abc")
    digest = hashlib.sha256(b"abc").digest()
    vectors.append(
        {
            "name": "fips180_abc",
            "message": hex_encode(b"abc"),
            "digest": hex_encode(digest),
        }
    )

    # SHA-256("") empty
    digest_empty = hashlib.sha256(b"").digest()
    vectors.append(
        {
            "name": "fips180_empty",
            "message": "",
            "digest": hex_encode(digest_empty),
        }
    )

    # SHA-256(two-block message)
    msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    digest_2block = hashlib.sha256(msg).digest()
    vectors.append(
        {
            "name": "fips180_two_blocks",
            "message": hex_encode(msg),
            "digest": hex_encode(digest_2block),
        }
    )

    return {"algorithm": "sha256", "standard": "FIPS 180-4", "vectors": vectors}


#
# SHA-512 (FIPS 180-4)
#


def gen_sha512():
    vectors = []

    # SHA-512("abc")
    digest = hashlib.sha512(b"abc").digest()
    vectors.append(
        {
            "name": "fips180_abc",
            "message": hex_encode(b"abc"),
            "digest": hex_encode(digest),
        }
    )

    # SHA-512("") empty
    digest_empty = hashlib.sha512(b"").digest()
    vectors.append(
        {
            "name": "fips180_empty",
            "message": "",
            "digest": hex_encode(digest_empty),
        }
    )

    return {"algorithm": "sha512", "standard": "FIPS 180-4", "vectors": vectors}


#
# HMAC-SHA-256 (RFC 4231)
#


def gen_sha256_hmac():
    vectors = []

    # RFC 4231 Test Case 1
    key1 = bytes(20 * [0x0B])
    data1 = b"Hi There"
    mac1 = hmac.new(key1, data1, hashlib.sha256).digest()
    vectors.append(
        {
            "name": "rfc4231_case1",
            "key": hex_encode(key1),
            "message": hex_encode(data1),
            "mac": hex_encode(mac1),
        }
    )

    # RFC 4231 Test Case 2
    key2 = b"Jefe"
    data2 = b"what do ya want for nothing?"
    mac2 = hmac.new(key2, data2, hashlib.sha256).digest()
    vectors.append(
        {
            "name": "rfc4231_case2",
            "key": hex_encode(key2),
            "message": hex_encode(data2),
            "mac": hex_encode(mac2),
        }
    )

    # RFC 4231 Test Case 3
    key3 = bytes(20 * [0xAA])
    data3 = bytes(50 * [0xDD])
    mac3 = hmac.new(key3, data3, hashlib.sha256).digest()
    vectors.append(
        {
            "name": "rfc4231_case3",
            "key": hex_encode(key3),
            "message": hex_encode(data3),
            "mac": hex_encode(mac3),
        }
    )

    return {"algorithm": "sha256_hmac", "standard": "RFC 4231", "vectors": vectors}


#
# HKDF-SHA-256 (RFC 5869)
#


def gen_hkdf():
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand, HKDF
    from cryptography.hazmat.primitives import hashes

    vectors = []

    # RFC 5869 Test Case 1
    ikm1 = bytes(22 * [0x0B])
    salt1 = bytes.fromhex("000102030405060708090a0b0c")
    info1 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")

    # Extract
    prk1 = hmac.new(salt1, ikm1, hashlib.sha256).digest()
    # Expand
    hkdf_expand1 = HKDFExpand(algorithm=hashes.SHA256(), length=42, info=info1)
    okm1 = hkdf_expand1.derive(prk1)
    vectors.append(
        {
            "name": "rfc5869_case1",
            "ikm": hex_encode(ikm1),
            "salt": hex_encode(salt1),
            "info": hex_encode(info1),
            "prk": hex_encode(prk1),
            "okm": hex_encode(okm1),
            "okm_length": 42,
        }
    )

    # RFC 5869 Test Case 3 — empty salt, empty info
    ikm3 = bytes(22 * [0x0B])
    default_salt = bytes(32)  # SHA-256 block of zeros
    prk3 = hmac.new(default_salt, ikm3, hashlib.sha256).digest()
    hkdf_expand3 = HKDFExpand(algorithm=hashes.SHA256(), length=42, info=b"")
    okm3 = hkdf_expand3.derive(prk3)
    vectors.append(
        {
            "name": "rfc5869_case3",
            "ikm": hex_encode(ikm3),
            "salt": "",
            "info": "",
            "prk": hex_encode(prk3),
            "okm": hex_encode(okm3),
            "okm_length": 42,
        }
    )

    return {"algorithm": "hkdf_sha256", "standard": "RFC 5869", "vectors": vectors}


#
# Ed25519 (RFC 8032)
#


def gen_ed25519():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        PrivateFormat,
        NoEncryption,
    )

    vectors = []

    # RFC 8032 Section 7.1 — Test Vector 1 (empty message)
    seed1 = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    sk1 = Ed25519PrivateKey.from_private_bytes(seed1)
    pk1 = sk1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig1 = sk1.sign(b"")
    vectors.append(
        {
            "name": "rfc8032_vector1_empty",
            "seed": hex_encode(seed1),
            "public_key": hex_encode(pk1),
            "message": "",
            "signature": hex_encode(sig1),
        }
    )

    # RFC 8032 Section 7.1 — Test Vector 2 (1-byte message: 0x72)
    seed2 = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    msg2 = bytes.fromhex("72")
    sk2 = Ed25519PrivateKey.from_private_bytes(seed2)
    pk2 = sk2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig2 = sk2.sign(msg2)
    vectors.append(
        {
            "name": "rfc8032_vector2",
            "seed": hex_encode(seed2),
            "public_key": hex_encode(pk2),
            "message": hex_encode(msg2),
            "signature": hex_encode(sig2),
        }
    )

    # RFC 8032 Section 7.1 — Test Vector 3 (2-byte message: 0xaf82)
    seed3 = bytes.fromhex(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
    )
    msg3 = bytes.fromhex("af82")
    sk3 = Ed25519PrivateKey.from_private_bytes(seed3)
    pk3 = sk3.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig3 = sk3.sign(msg3)
    vectors.append(
        {
            "name": "rfc8032_vector3",
            "seed": hex_encode(seed3),
            "public_key": hex_encode(pk3),
            "message": hex_encode(msg3),
            "signature": hex_encode(sig3),
        }
    )

    return {"algorithm": "ed25519", "standard": "RFC 8032", "vectors": vectors}


#
# X25519 (RFC 7748)
#


def gen_x25519():
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    vectors = []

    # RFC 7748 Section 6.1 — Alice and Bob
    alice_sk_bytes = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    bob_sk_bytes = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )

    alice_sk = X25519PrivateKey.from_private_bytes(alice_sk_bytes)
    bob_sk = X25519PrivateKey.from_private_bytes(bob_sk_bytes)

    alice_pk = alice_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    bob_pk = bob_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Shared secret: Alice's SK * Bob's PK
    shared = alice_sk.exchange(bob_sk.public_key())

    vectors.append(
        {
            "name": "rfc7748_section6_1",
            "alice_private_key": hex_encode(alice_sk_bytes),
            "alice_public_key": hex_encode(alice_pk),
            "bob_private_key": hex_encode(bob_sk_bytes),
            "bob_public_key": hex_encode(bob_pk),
            "shared_secret": hex_encode(shared),
        }
    )

    return {"algorithm": "x25519", "standard": "RFC 7748", "vectors": vectors}


#
# P-256 ECDSA (IEEE 1722-2016 clause 16)
#


def gen_p256_ecdsa():
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        derive_private_key,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    vectors = []
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    # Test vector 1: known seed
    seed1 = bytes(range(1, 33))
    h1 = hashlib.sha256(seed1).digest()
    d1 = int.from_bytes(h1, "big") % n
    sk1 = derive_private_key(d1, SECP256R1())
    pub1 = sk1.public_key().public_numbers()
    pk_bytes1 = pub1.x.to_bytes(32, "big") + pub1.y.to_bytes(32, "big")

    msg1 = b"test message"
    der_sig1 = sk1.sign(msg1, ECDSA(hashes.SHA256(), deterministic_signing=True))
    r1, s1 = decode_dss_signature(der_sig1)
    sig_bytes1 = r1.to_bytes(32, "big") + s1.to_bytes(32, "big")

    vectors.append(
        {
            "name": "seed_1_to_32",
            "seed": hex_encode(seed1),
            "public_key": hex_encode(pk_bytes1),
            "message": hex_encode(msg1),
            "signature": hex_encode(sig_bytes1),
        }
    )

    # Test vector 2: different seed, empty message
    seed2 = bytes.fromhex(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    )
    h2 = hashlib.sha256(seed2).digest()
    d2 = int.from_bytes(h2, "big") % n
    sk2 = derive_private_key(d2, SECP256R1())
    pub2 = sk2.public_key().public_numbers()
    pk_bytes2 = pub2.x.to_bytes(32, "big") + pub2.y.to_bytes(32, "big")

    msg2 = b""
    der_sig2 = sk2.sign(msg2, ECDSA(hashes.SHA256(), deterministic_signing=True))
    r2, s2 = decode_dss_signature(der_sig2)
    sig_bytes2 = r2.to_bytes(32, "big") + s2.to_bytes(32, "big")

    vectors.append(
        {
            "name": "rfc6979_seed_empty_msg",
            "seed": hex_encode(seed2),
            "public_key": hex_encode(pk_bytes2),
            "message": "",
            "signature": hex_encode(sig_bytes2),
        }
    )

    # Test vector 3: longer message
    seed3 = bytes(32)  # all zeros
    h3 = hashlib.sha256(seed3).digest()
    d3 = int.from_bytes(h3, "big") % n
    if d3 == 0:
        d3 = 1
    sk3 = derive_private_key(d3, SECP256R1())
    pub3 = sk3.public_key().public_numbers()
    pk_bytes3 = pub3.x.to_bytes(32, "big") + pub3.y.to_bytes(32, "big")

    msg3 = b"The quick brown fox jumps over the lazy dog"
    der_sig3 = sk3.sign(msg3, ECDSA(hashes.SHA256(), deterministic_signing=True))
    r3, s3 = decode_dss_signature(der_sig3)
    sig_bytes3 = r3.to_bytes(32, "big") + s3.to_bytes(32, "big")

    vectors.append(
        {
            "name": "zero_seed_long_msg",
            "seed": hex_encode(seed3),
            "public_key": hex_encode(pk_bytes3),
            "message": hex_encode(msg3),
            "signature": hex_encode(sig_bytes3),
        }
    )

    return {
        "algorithm": "p256_ecdsa",
        "standard": "FIPS 186-4 / RFC 6979",
        "vectors": vectors,
    }


#
# P-256 ECDH (IEEE 1722-2016 clause 17)
#


def gen_p256_ecdh():
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDH,
        SECP256R1,
        derive_private_key,
    )

    vectors = []
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    # Alice and Bob
    alice_seed = bytes(range(1, 33))
    bob_seed = bytes(range(33, 65))

    h_a = hashlib.sha256(alice_seed).digest()
    d_a = int.from_bytes(h_a, "big") % n
    alice_sk = derive_private_key(d_a, SECP256R1())
    alice_pub = alice_sk.public_key().public_numbers()
    alice_pk_bytes = alice_pub.x.to_bytes(32, "big") + alice_pub.y.to_bytes(32, "big")

    h_b = hashlib.sha256(bob_seed).digest()
    d_b = int.from_bytes(h_b, "big") % n
    bob_sk = derive_private_key(d_b, SECP256R1())
    bob_pub = bob_sk.public_key().public_numbers()
    bob_pk_bytes = bob_pub.x.to_bytes(32, "big") + bob_pub.y.to_bytes(32, "big")

    shared = alice_sk.exchange(ECDH(), bob_sk.public_key())

    vectors.append(
        {
            "name": "alice_bob",
            "alice_seed": hex_encode(alice_seed),
            "alice_public_key": hex_encode(alice_pk_bytes),
            "bob_seed": hex_encode(bob_seed),
            "bob_public_key": hex_encode(bob_pk_bytes),
            "shared_secret": hex_encode(shared),
        }
    )

    return {"algorithm": "p256_ecdh", "standard": "IEEE 1363-2000", "vectors": vectors}


#
# DL/ECIES (IEEE 1363a-2004 / IEEE 1722-2016 clause 17)
#


def gen_ecies():
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDH,
        SECP256R1,
        derive_private_key,
    )
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    def seed_to_p256(seed):
        h = hashlib.sha256(seed).digest()
        d = int.from_bytes(h, "big") % n
        if d == 0:
            d = 1
        sk = derive_private_key(d, SECP256R1())
        pub = sk.public_key().public_numbers()
        pk_bytes = pub.x.to_bytes(32, "big") + pub.y.to_bytes(32, "big")
        return sk, pk_bytes

    def kdf2_sha256(z, params, out_len):
        result = b""
        counter = 1
        while len(result) < out_len:
            result += hashlib.sha256(z + counter.to_bytes(4, "big") + params).digest()
            counter += 1
        return result[:out_len]

    vectors = []

    # Test 1: small plaintext ("Hello ECIES" = 11 bytes)
    recipient_seed = bytes(range(1, 33))
    entropy = bytes(range(33, 65))
    plaintext = b"Hello ECIES"

    recipient_sk, recipient_pk_bytes = seed_to_p256(recipient_seed)
    eph_sk, eph_pk_bytes = seed_to_p256(entropy)

    V = b"\x01" + eph_pk_bytes[:32]  # EC2OSP-X: 0x01 || x
    Z = eph_sk.exchange(ECDH(), recipient_sk.public_key())
    VZ = V + Z

    # Per IEEE 1363a-2004: K2 (MAC key) = K[0:32], K1 (encryption key) = K[32:64]
    kdf_out = kdf2_sha256(VZ, b"", 64)
    mac_key = kdf_out[:32]  # K2
    enc_key = kdf_out[32:]  # K1

    cipher = AES.new(enc_key, AES.MODE_CBC, iv=bytes(16))
    C = cipher.encrypt(pad(plaintext, 16))
    # HMAC over C || I2OSP(0, 8) per IEEE 1363a-2004
    T = hmac.new(mac_key, C + b"\x00" * 8, hashlib.sha256).digest()
    ciphertext = V + C + T

    vectors.append(
        {
            "name": "hello_ecies",
            "recipient_seed": hex_encode(recipient_seed),
            "recipient_public_key": hex_encode(recipient_pk_bytes),
            "entropy": hex_encode(entropy),
            "plaintext": hex_encode(plaintext),
            "ciphertext": hex_encode(ciphertext),
        }
    )

    # Test 2: exactly 16 bytes (one AES block, pads to two blocks)
    plaintext2 = bytes(range(16))
    entropy2 = bytes(range(65, 97))

    eph_sk2, eph_pk_bytes2 = seed_to_p256(entropy2)
    V2 = b"\x01" + eph_pk_bytes2[:32]
    Z2 = eph_sk2.exchange(ECDH(), recipient_sk.public_key())
    VZ2 = V2 + Z2

    kdf_out2 = kdf2_sha256(VZ2, b"", 64)
    mac_key2 = kdf_out2[:32]  # K2
    enc_key2 = kdf_out2[32:]  # K1

    cipher2 = AES.new(enc_key2, AES.MODE_CBC, iv=bytes(16))
    C2 = cipher2.encrypt(pad(plaintext2, 16))
    T2 = hmac.new(mac_key2, C2 + b"\x00" * 8, hashlib.sha256).digest()
    ciphertext2 = V2 + C2 + T2

    vectors.append(
        {
            "name": "16byte_plaintext",
            "recipient_seed": hex_encode(recipient_seed),
            "recipient_public_key": hex_encode(recipient_pk_bytes),
            "entropy": hex_encode(entropy2),
            "plaintext": hex_encode(plaintext2),
            "ciphertext": hex_encode(ciphertext2),
        }
    )

    return {"algorithm": "ecies", "standard": "IEEE 1363a-2004", "vectors": vectors}


#
# X25519 ECIES (IEEE 1722-2016 Clause 17, enc=1)
#


def gen_x25519_ecies():
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    vectors = []

    def x25519_ecies_vector(name, recipient_seed, entropy_seed, plaintext):
        """Generate one X25519 ECIES test vector using Python crypto primitives."""
        # Recipient keypair
        recip_sk = X25519PrivateKey.from_private_bytes(recipient_seed)
        recip_pk = recip_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Ephemeral keypair from entropy
        eph_sk = X25519PrivateKey.from_private_bytes(entropy_seed)
        V = eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        # X25519 shared secret
        Z = eph_sk.exchange(recip_sk.public_key())

        # HKDF-SHA-256: salt="", ikm=Z, info="X25519-ECIES"||V, length=64
        info = b"X25519-ECIES" + V
        kdf = HKDF(algorithm=SHA256(), length=64, salt=b"", info=info)
        K = kdf.derive(Z)
        mac_key = K[:32]  # K2
        enc_key = K[32:]  # K1

        # AES-256-CBC-IV0 encrypt with PKCS#7 padding
        cipher = AES.new(enc_key, AES.MODE_CBC, iv=bytes(16))
        C = cipher.encrypt(pad(plaintext, 16))

        # HMAC-SHA-256 over C || I2OSP(0, 8)
        T = hmac.new(mac_key, C + b"\x00" * 8, hashlib.sha256).digest()

        ciphertext = V + C + T

        return {
            "name": name,
            "recipient_seed": hex_encode(recipient_seed),
            "recipient_public_key": hex_encode(recip_pk),
            "entropy": hex_encode(entropy_seed),
            "plaintext": hex_encode(plaintext),
            "ciphertext": hex_encode(ciphertext),
        }

    # Test 1: small plaintext ("Hello X25519 ECIES!" = 20 bytes)
    recipient_seed1 = bytes(range(0x10, 0x30))  # 32 bytes, survives clamping
    entropy1 = bytes(range(0x30, 0x50))
    vectors.append(
        x25519_ecies_vector(
            "hello_x25519_ecies", recipient_seed1, entropy1, b"Hello X25519 ECIES!"
        )
    )

    # Test 2: exactly 16 bytes (one AES block, pads to two blocks)
    entropy2 = bytes(range(0x50, 0x70))
    vectors.append(
        x25519_ecies_vector(
            "16byte_plaintext", recipient_seed1, entropy2, bytes(range(16))
        )
    )

    # Test 3: empty plaintext
    entropy3 = bytes(range(0x70, 0x90))
    vectors.append(
        x25519_ecies_vector("empty_plaintext", recipient_seed1, entropy3, b"")
    )

    return {
        "algorithm": "x25519_ecies",
        "standard": "IEEE 1722-2016 Clause 17",
        "vectors": vectors,
    }


#
# Registry
#

GENERATORS = {
    "aes128_block": gen_aes128_block,
    "aes256_block": gen_aes256_block,
    "aes128_cmac": gen_aes128_cmac,
    "aes256_cmac": gen_aes256_cmac,
    "aes128_siv": gen_aes128_siv,
    "aes256_siv": gen_aes256_siv,
    "aes128_gcm_siv": gen_aes128_gcm_siv,
    "aes256_gcm_siv": gen_aes256_gcm_siv,
    "sha256": gen_sha256,
    "sha512": gen_sha512,
    "sha256_hmac": gen_sha256_hmac,
    "hkdf_sha256": gen_hkdf,
    "ed25519": gen_ed25519,
    "x25519": gen_x25519,
    "p256_ecdsa": gen_p256_ecdsa,
    "p256_ecdh": gen_p256_ecdh,
    "ecies": gen_ecies,
    "x25519_ecies": gen_x25519_ecies,
}


def main():
    parser = argparse.ArgumentParser(
        description="Generate test vectors for statusbar_crypto algorithms"
    )
    parser.add_argument(
        "--algorithm",
        "-a",
        help="Generate vectors for a specific algorithm only",
        choices=list(GENERATORS.keys()),
    )
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="List available algorithms",
    )
    args = parser.parse_args()

    if args.list:
        for name in sorted(GENERATORS.keys()):
            print(name)
        return

    results = []
    generators = (
        {args.algorithm: GENERATORS[args.algorithm]} if args.algorithm else GENERATORS
    )

    for name, gen_func in generators.items():
        try:
            result = gen_func()
            results.append(result)
        except ImportError as e:
            print(f"WARNING: Skipping {name}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"ERROR: {name}: {e}", file=sys.stderr)
            sys.exit(1)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
