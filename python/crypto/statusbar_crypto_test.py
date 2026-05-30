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
Unit tests for the statusbar_crypto Python library.

Covers key validation, known-answer tests, roundtrips, error paths,
and AVTP protocol types not exercised by the C++ cross-check.

Usage:
    uv run statusbar_crypto_test.py
    uv run statusbar_crypto_test.py -v          # verbose
    uv run statusbar_crypto_test.py TestSha256  # single class
"""

import sys
import unittest
from pathlib import Path

# Ensure we import the local statusbar_crypto module
sys.path.insert(0, str(Path(__file__).resolve().parent))
import statusbar_crypto as sc


# ---------------------------------------------------------------------------
# Deterministic seeds and key IDs reused across tests
# ---------------------------------------------------------------------------

SEED_A = bytes(range(1, 33))  # 0x01..0x20
SEED_B = bytes(range(33, 65))  # 0x21..0x40
SEED_C = bytes(range(65, 97))  # 0x41..0x60
KEY_ID_A = bytes(range(1, 9))  # 0x01..0x08
KEY_ID_B = bytes(range(9, 17))  # 0x09..0x10
KEY_ID_C = bytes(range(17, 25))  # 0x11..0x18


# ===================================================================
# 1. Key dataclass validation
# ===================================================================


class TestKeyDataclassValidation(unittest.TestCase):
    def test_aes128_key_valid(self):
        k = sc.Aes128Key(data=bytes(16))
        self.assertEqual(len(k.data), 16)

    def test_aes128_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.Aes128Key(data=bytes(15))
        with self.assertRaises(ValueError):
            sc.Aes128Key(data=bytes(17))

    def test_aes256_key_valid(self):
        k = sc.Aes256Key(data=bytes(32))
        self.assertEqual(len(k.data), 32)

    def test_aes256_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.Aes256Key(data=bytes(31))

    def test_aes128_siv_key_valid(self):
        k = sc.Aes128SivKey(data=bytes(32))
        self.assertEqual(len(k.data), 32)

    def test_aes128_siv_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.Aes128SivKey(data=bytes(16))

    def test_aes256_siv_key_valid(self):
        k = sc.Aes256SivKey(data=bytes(64))
        self.assertEqual(len(k.data), 64)

    def test_aes256_siv_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.Aes256SivKey(data=bytes(32))

    def test_ed25519_public_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.Ed25519PublicKey(data=bytes(31))

    def test_ed25519_signature_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.Ed25519Signature(data=bytes(63))

    def test_x25519_public_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.X25519PublicKey(data=bytes(33))

    def test_p256_public_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.P256PublicKey(data=bytes(63))

    def test_p256_private_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.P256PrivateKey(
                data=bytes(31), public_key=sc.P256PublicKey(data=bytes(64))
            )

    def test_p256_ecdsa_signature_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.P256EcdsaSignature(data=bytes(63))

    def test_polyval_key_valid(self):
        k = sc.PolyvalKey(data=bytes(16))
        self.assertEqual(len(k.data), 16)

    def test_polyval_key_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.PolyvalKey(data=bytes(15))

    def test_key_id_valid(self):
        k = sc.KeyId(data=bytes(8))
        self.assertEqual(len(k.data), 8)

    def test_key_id_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.KeyId(data=bytes(7))


# ===================================================================
# 2. SHA-256
# ===================================================================


class TestSha256(unittest.TestCase):
    """FIPS 180-4 known-answer tests."""

    def test_sha256_empty(self):
        expected = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        self.assertEqual(sc.sha256(b""), expected)

    def test_sha256_abc(self):
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        self.assertEqual(sc.sha256(b"abc"), expected)

    def test_sha256_long(self):
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        expected = bytes.fromhex(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
        self.assertEqual(sc.sha256(msg), expected)

    def test_sha256_hex(self):
        h = sc.sha256_hex(b"abc")
        self.assertIsInstance(h, str)
        self.assertEqual(
            h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )


# ===================================================================
# 3. SHA-512
# ===================================================================


class TestSha512(unittest.TestCase):
    def test_sha512_empty(self):
        expected = bytes.fromhex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        self.assertEqual(sc.sha512(b""), expected)

    def test_sha512_abc(self):
        expected = bytes.fromhex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        self.assertEqual(sc.sha512(b"abc"), expected)

    def test_sha512_hex(self):
        h = sc.sha512_hex(b"abc")
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 128)

    def test_sha512_incremental_single_update(self):
        ctx = sc.sha512_init()
        sc.sha512_update(ctx, b"abc")
        digest = sc.sha512_final(ctx)
        self.assertEqual(digest, sc.sha512(b"abc"))

    def test_sha512_incremental_multi_update(self):
        ctx = sc.sha512_init()
        sc.sha512_update(ctx, b"a")
        sc.sha512_update(ctx, b"b")
        sc.sha512_update(ctx, b"c")
        digest = sc.sha512_final(ctx)
        self.assertEqual(digest, sc.sha512(b"abc"))


# ===================================================================
# 4. HMAC-SHA-256
# ===================================================================


class TestHmacSha256(unittest.TestCase):
    def test_rfc4231_case1(self):
        """RFC 4231 Test Case 1."""
        key = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        data = b"Hi There"
        expected = bytes.fromhex(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        self.assertEqual(sc.sha256_hmac(key, data), expected)

    def test_rfc4231_case2(self):
        """RFC 4231 Test Case 2."""
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = bytes.fromhex(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        )
        self.assertEqual(sc.sha256_hmac(key, data), expected)

    def test_two_part_message(self):
        key = bytes(32)
        m1 = b"Hello, "
        m2 = b"World!"
        combined = sc.sha256_hmac(key, m1 + m2)
        two_part = sc.sha256_hmac(key, m1, m2)
        self.assertEqual(combined, two_part)

    def test_two_part_empty_second(self):
        key = bytes(32)
        msg = b"test message"
        self.assertEqual(sc.sha256_hmac(key, msg), sc.sha256_hmac(key, msg, b""))


# ===================================================================
# 5. AES block cipher
# ===================================================================


class TestAesBlock(unittest.TestCase):
    def test_aes128_encrypt_fips197(self):
        """FIPS 197 Appendix B known vector."""
        key = sc.Aes128Key(data=bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        ct = sc.aes128_block_encrypt(key, pt)
        expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(ct, expected)

    def test_aes128_roundtrip(self):
        key = sc.Aes128Key(data=bytes(16))
        pt = bytes(range(16))
        ct = sc.aes128_block_encrypt(key, pt)
        self.assertEqual(sc.aes128_block_decrypt(key, ct), pt)

    def test_aes128_wrong_block_size(self):
        key = sc.Aes128Key(data=bytes(16))
        with self.assertRaises(ValueError):
            sc.aes128_block_encrypt(key, bytes(15))

    def test_aes256_encrypt_fips197(self):
        """FIPS 197 Appendix C.3 known vector."""
        key = sc.Aes256Key(
            data=bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
        )
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = sc.aes256_block_encrypt(key, pt)
        expected = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(ct, expected)

    def test_aes256_roundtrip(self):
        key = sc.Aes256Key(data=bytes(32))
        pt = bytes(range(16))
        ct = sc.aes256_block_encrypt(key, pt)
        self.assertEqual(sc.aes256_block_decrypt(key, ct), pt)

    def test_aes256_wrong_block_size(self):
        key = sc.Aes256Key(data=bytes(32))
        with self.assertRaises(ValueError):
            sc.aes256_block_encrypt(key, bytes(17))


# ===================================================================
# 6. AES-CBC
# ===================================================================


class TestAesCbc(unittest.TestCase):
    def test_roundtrip_short(self):
        key = bytes(32)
        pt = b"short"
        ct = sc.aes256_cbc_encrypt(key, pt)
        self.assertEqual(sc.aes256_cbc_decrypt(key, ct), pt)

    def test_roundtrip_exact_block(self):
        key = bytes(32)
        pt = bytes(16)
        ct = sc.aes256_cbc_encrypt(key, pt)
        # PKCS#7 adds a full padding block when input is block-aligned
        self.assertEqual(len(ct), 32)
        self.assertEqual(sc.aes256_cbc_decrypt(key, ct), pt)

    def test_roundtrip_multi_block(self):
        key = bytes(32)
        pt = bytes(range(48))
        ct = sc.aes256_cbc_encrypt(key, pt)
        self.assertEqual(sc.aes256_cbc_decrypt(key, ct), pt)

    def test_decrypt_bad_padding(self):
        key = bytes(32)
        # 16 bytes of garbage won't have valid PKCS#7 padding
        with self.assertRaises(ValueError):
            sc.aes256_cbc_decrypt(key, bytes(16))


# ===================================================================
# 7. AES-CMAC
# ===================================================================


class TestAesCmac(unittest.TestCase):
    def test_aes128_cmac_rfc4493_empty(self):
        """RFC 4493 Example 1: CMAC of empty message."""
        key = sc.Aes128Key(data=bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
        expected = bytes.fromhex("bb1d6929e95937287fa37d129b756746")
        self.assertEqual(sc.aes128_cmac(key, b""), expected)

    def test_aes128_cmac_rfc4493_16bytes(self):
        """RFC 4493 Example 2: CMAC of 16-byte message."""
        key = sc.Aes128Key(data=bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
        msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected = bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")
        self.assertEqual(sc.aes128_cmac(key, msg), expected)

    def test_aes128_cmac_xorend_basic(self):
        key = sc.Aes128Key(data=bytes(16))
        msg = bytes(32)
        xor_end = bytes(range(16))
        result = sc.aes128_cmac_xorend(key, msg, xor_end)
        self.assertEqual(len(result), 16)
        # Verify it differs from plain CMAC
        plain = sc.aes128_cmac(key, msg)
        self.assertNotEqual(result, plain)

    def test_aes128_cmac_xorend_short_message(self):
        key = sc.Aes128Key(data=bytes(16))
        result = sc.aes128_cmac_xorend(key, bytes(8), bytes(16))
        self.assertEqual(result, bytes(16))

    def test_aes128_cmac_xorend_bad_xor_size(self):
        key = sc.Aes128Key(data=bytes(16))
        with self.assertRaises(ValueError):
            sc.aes128_cmac_xorend(key, bytes(32), bytes(15))

    def test_aes128_cmac_verify_valid(self):
        key = sc.Aes128Key(data=bytes(16))
        msg = b"test message"
        tag = sc.aes128_cmac(key, msg)
        self.assertTrue(sc.aes128_cmac_verify(key, msg, tag))

    def test_aes128_cmac_verify_invalid(self):
        key = sc.Aes128Key(data=bytes(16))
        msg = b"test message"
        self.assertFalse(sc.aes128_cmac_verify(key, msg, bytes(16)))

    def test_aes256_cmac_verify_wrong_tag_length(self):
        key = sc.Aes256Key(data=bytes(32))
        self.assertFalse(sc.aes256_cmac_verify(key, b"msg", bytes(15)))

    def test_aes256_cmac_xorend(self):
        key = sc.Aes256Key(data=bytes(32))
        msg = bytes(32)
        xor_end = bytes(range(16))
        result = sc.aes256_cmac_xorend(key, msg, xor_end)
        self.assertEqual(len(result), 16)

    def test_aes256_cmac_verify_valid(self):
        key = sc.Aes256Key(data=bytes(32))
        msg = b"test"
        tag = sc.aes256_cmac(key, msg)
        self.assertTrue(sc.aes256_cmac_verify(key, msg, tag))


# ===================================================================
# 8. HKDF-SHA-256
# ===================================================================


class TestHkdfSha256(unittest.TestCase):
    def test_rfc5869_case1(self):
        """RFC 5869 Test Case 1."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected_prk = bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        )
        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        prk = sc.hkdf_sha256_extract(salt, ikm)
        self.assertEqual(prk, expected_prk)
        okm = sc.hkdf_sha256_expand(prk, info, 42)
        self.assertEqual(okm, expected_okm)

    def test_one_shot_hkdf(self):
        ikm = bytes(32)
        salt = bytes(16)
        info = b"test"
        # One-shot should equal extract-then-expand
        prk = sc.hkdf_sha256_extract(salt, ikm)
        expected = sc.hkdf_sha256_expand(prk, info, 64)
        self.assertEqual(sc.hkdf_sha256(salt, ikm, info, 64), expected)

    def test_kdf2_sha256_basic(self):
        z = bytes(32)
        params = b"test"
        out = sc.kdf2_sha256(z, params, 32)
        self.assertEqual(len(out), 32)
        # Multi-block
        out64 = sc.kdf2_sha256(z, params, 64)
        self.assertEqual(len(out64), 64)
        # First 32 bytes should match single-block output
        self.assertEqual(out64[:32], out)


# ===================================================================
# 9. AES-SIV
# ===================================================================


class TestAesSiv(unittest.TestCase):
    def test_aes128_siv_roundtrip(self):
        key = sc.Aes128SivKey(data=bytes(32))
        pt = b"hello world 1234"
        aad = b"additional data"
        siv, ct = sc.aes128_siv_encrypt(key, pt, aad)
        ok, dec = sc.aes128_siv_decrypt(key, ct, siv, aad)
        self.assertTrue(ok)
        self.assertEqual(dec, pt)

    def test_aes128_siv_tampered_ciphertext(self):
        key = sc.Aes128SivKey(data=bytes(32))
        pt = b"plaintext here!!"
        siv, ct = sc.aes128_siv_encrypt(key, pt, b"")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        ok, dec = sc.aes128_siv_decrypt(key, bytes(tampered), siv, b"")
        self.assertFalse(ok)
        self.assertEqual(dec, bytes(len(ct)))

    def test_aes128_siv_wrong_aad(self):
        key = sc.Aes128SivKey(data=bytes(32))
        pt = b"test data here!!"
        siv, ct = sc.aes128_siv_encrypt(key, pt, b"aad1")
        ok, _ = sc.aes128_siv_decrypt(key, ct, siv, b"aad2")
        self.assertFalse(ok)

    def test_aes256_siv_roundtrip(self):
        key = sc.Aes256SivKey(data=bytes(64))
        pt = b"test plaintext!!"
        aad = b"aad"
        siv, ct = sc.aes256_siv_encrypt(key, pt, aad)
        ok, dec = sc.aes256_siv_decrypt(key, ct, siv, aad)
        self.assertTrue(ok)
        self.assertEqual(dec, pt)

    def test_aes256_siv_tampered_siv(self):
        key = sc.Aes256SivKey(data=bytes(64))
        siv, ct = sc.aes256_siv_encrypt(key, b"test data here!!", b"")
        tampered_siv = bytearray(siv)
        tampered_siv[0] ^= 0xFF
        ok, _ = sc.aes256_siv_decrypt(key, ct, bytes(tampered_siv), b"")
        self.assertFalse(ok)

    def test_aes256_siv_empty_plaintext(self):
        key = sc.Aes256SivKey(data=bytes(64))
        siv, ct = sc.aes256_siv_encrypt(key, b"", b"")
        self.assertEqual(len(ct), 0)
        ok, dec = sc.aes256_siv_decrypt(key, ct, siv, b"")
        self.assertTrue(ok)
        self.assertEqual(dec, b"")


# ===================================================================
# 10. AES-GCM-SIV
# ===================================================================


class TestAesGcmSiv(unittest.TestCase):
    def test_aes128_gcm_siv_roundtrip(self):
        key = sc.Aes128Key(data=bytes(16))
        nonce = bytes(12)
        pt = b"hello gcm-siv!!"
        aad = b"aad"
        tag, ct = sc.aes128_gcm_siv_encrypt(key, nonce, pt, aad)
        self.assertEqual(len(tag), 16)
        ok, dec = sc.aes128_gcm_siv_decrypt(key, nonce, ct, tag, aad)
        self.assertTrue(ok)
        self.assertEqual(dec, pt)

    def test_aes128_gcm_siv_tampered(self):
        key = sc.Aes128Key(data=bytes(16))
        nonce = bytes(12)
        tag, ct = sc.aes128_gcm_siv_encrypt(key, nonce, b"test data here!", b"")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        ok, dec = sc.aes128_gcm_siv_decrypt(key, nonce, bytes(tampered), tag, b"")
        self.assertFalse(ok)

    def test_aes256_gcm_siv_roundtrip(self):
        key = sc.Aes256Key(data=bytes(32))
        nonce = bytes(12)
        pt = b"test 256 gcmsiv"
        tag, ct = sc.aes256_gcm_siv_encrypt(key, nonce, pt, b"")
        ok, dec = sc.aes256_gcm_siv_decrypt(key, nonce, ct, tag, b"")
        self.assertTrue(ok)
        self.assertEqual(dec, pt)

    def test_aes256_gcm_siv_tampered_tag(self):
        key = sc.Aes256Key(data=bytes(32))
        nonce = bytes(12)
        tag, ct = sc.aes256_gcm_siv_encrypt(key, nonce, b"test data here!", b"aad")
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0xFF
        ok, _ = sc.aes256_gcm_siv_decrypt(key, nonce, ct, bytes(tampered_tag), b"aad")
        self.assertFalse(ok)

    def test_aes128_gcm_siv_empty(self):
        key = sc.Aes128Key(data=bytes(16))
        nonce = bytes(12)
        tag, ct = sc.aes128_gcm_siv_encrypt(key, nonce, b"", b"")
        self.assertEqual(len(ct), 0)
        ok, dec = sc.aes128_gcm_siv_decrypt(key, nonce, ct, tag, b"")
        self.assertTrue(ok)
        self.assertEqual(dec, b"")

    def test_aes256_gcm_siv_wrong_nonce(self):
        key = sc.Aes256Key(data=bytes(32))
        nonce1 = bytes(12)
        nonce2 = bytes([1]) + bytes(11)
        tag, ct = sc.aes256_gcm_siv_encrypt(key, nonce1, b"test data here!", b"")
        ok, _ = sc.aes256_gcm_siv_decrypt(key, nonce2, ct, tag, b"")
        self.assertFalse(ok)


# ===================================================================
# 11. POLYVAL
# ===================================================================


class TestPolyval(unittest.TestCase):
    def test_polyval_single_block(self):
        H = sc.PolyvalKey(data=bytes(range(16)))
        data = bytes(range(16))
        result = sc.polyval(H, data)
        self.assertEqual(len(result), 16)

    def test_polyval_multi_block_vs_incremental(self):
        H = sc.PolyvalKey(data=bytes(range(16)))
        data = bytes(range(32))
        one_shot = sc.polyval(H, data)
        acc = bytearray(16)
        sc.polyval_update(H, data[:16], acc)
        sc.polyval_update(H, data[16:], acc)
        self.assertEqual(one_shot, bytes(acc))

    def test_polyval_non_multiple_of_16(self):
        H = sc.PolyvalKey(data=bytes(16))
        with self.assertRaises(ValueError):
            sc.polyval(H, bytes(15))

    def test_polyval_update_bad_accumulator(self):
        H = sc.PolyvalKey(data=bytes(16))
        with self.assertRaises(ValueError):
            sc.polyval_update(H, bytes(16), bytearray(15))

    def test_polyval_empty_input(self):
        H = sc.PolyvalKey(data=bytes(range(16)))
        result = sc.polyval(H, b"")
        self.assertEqual(result, bytes(16))


# ===================================================================
# 12. Ed25519
# ===================================================================


class TestEd25519(unittest.TestCase):
    def test_keypair_from_seed(self):
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        self.assertEqual(len(sk.data), 64)
        self.assertEqual(len(sk.public_key.data), 32)
        self.assertEqual(sk._seed, SEED_A)

    def test_sign_verify_roundtrip(self):
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        msg = b"test message"
        sig = sc.ed25519_sign(sk, msg)
        self.assertTrue(sc.ed25519_verify(sk.public_key, msg, sig))

    def test_verify_wrong_message(self):
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        sig = sc.ed25519_sign(sk, b"correct")
        self.assertFalse(sc.ed25519_verify(sk.public_key, b"wrong", sig))

    def test_verify_wrong_signature(self):
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        bad_sig = sc.Ed25519Signature(data=bytes(64))
        self.assertFalse(sc.ed25519_verify(sk.public_key, b"msg", bad_sig))

    def test_public_key_extraction(self):
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        self.assertEqual(sc.ed25519_public_key(sk), sk.public_key)

    def test_keypair_wrong_seed_size(self):
        with self.assertRaises(ValueError):
            sc.ed25519_keypair_from_seed(bytes(31))


# ===================================================================
# 13. Ed25519 <-> X25519 conversion
# ===================================================================


class TestEd25519X25519Conversion(unittest.TestCase):
    def test_pk_conversion_deterministic(self):
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        x_pk1 = sc.ed25519_pk_to_x25519_pk(sk.public_key)
        x_pk2 = sc.ed25519_pk_to_x25519_pk(sk.public_key)
        self.assertEqual(x_pk1.data, x_pk2.data)

    def test_sk_conversion_matching_pk(self):
        ed_sk = sc.ed25519_keypair_from_seed(SEED_A)
        x_sk = sc.ed25519_sk_to_x25519_sk(ed_sk)
        x_pk_from_ed = sc.ed25519_pk_to_x25519_pk(ed_sk.public_key)
        self.assertEqual(x_sk.public_key.data, x_pk_from_ed.data)

    def test_converted_ecdh(self):
        ed_a = sc.ed25519_keypair_from_seed(SEED_A)
        ed_b = sc.ed25519_keypair_from_seed(SEED_B)
        x_a = sc.ed25519_sk_to_x25519_sk(ed_a)
        x_b = sc.ed25519_sk_to_x25519_sk(ed_b)
        ss1 = sc.x25519(x_a, x_b.public_key)
        ss2 = sc.x25519(x_b, x_a.public_key)
        self.assertEqual(ss1, ss2)
        self.assertTrue(sc.x25519_shared_secret_is_valid(ss1))

    def test_different_seeds_produce_different_keys(self):
        ed_a = sc.ed25519_keypair_from_seed(SEED_A)
        ed_b = sc.ed25519_keypair_from_seed(SEED_B)
        x_a = sc.ed25519_pk_to_x25519_pk(ed_a.public_key)
        x_b = sc.ed25519_pk_to_x25519_pk(ed_b.public_key)
        self.assertNotEqual(x_a.data, x_b.data)


# ===================================================================
# 14. X25519
# ===================================================================


class TestX25519(unittest.TestCase):
    def test_keypair_from_seed(self):
        sk = sc.x25519_keypair_from_seed(SEED_A)
        self.assertEqual(len(sk.data), 32)
        self.assertEqual(len(sk.public_key.data), 32)

    def test_ecdh_shared_secret(self):
        alice = sc.x25519_keypair_from_seed(SEED_A)
        bob = sc.x25519_keypair_from_seed(SEED_B)
        ss1 = sc.x25519(alice, bob.public_key)
        ss2 = sc.x25519(bob, alice.public_key)
        self.assertEqual(ss1, ss2)

    def test_shared_secret_is_valid(self):
        self.assertTrue(sc.x25519_shared_secret_is_valid(bytes(range(32))))

    def test_shared_secret_is_valid_all_zero(self):
        self.assertFalse(sc.x25519_shared_secret_is_valid(bytes(32)))


# ===================================================================
# 15. P-256 ECDSA
# ===================================================================


class TestP256Ecdsa(unittest.TestCase):
    def test_keypair_from_seed(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        self.assertEqual(len(sk.data), 32)
        self.assertEqual(len(sk.public_key.data), 64)

    def test_sign_verify_roundtrip(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        msg = b"test message"
        sig = sc.p256_ecdsa_sign(sk, msg)
        self.assertTrue(sc.p256_ecdsa_verify(sk.public_key, msg, sig))

    def test_verify_wrong_message(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        sig = sc.p256_ecdsa_sign(sk, b"correct")
        self.assertFalse(sc.p256_ecdsa_verify(sk.public_key, b"wrong", sig))

    def test_verify_wrong_signature(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        bad_sig = sc.P256EcdsaSignature(data=bytes(range(64)))
        self.assertFalse(sc.p256_ecdsa_verify(sk.public_key, b"msg", bad_sig))

    def test_public_key_extraction(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        self.assertEqual(sc.p256_public_key(sk), sk.public_key)

    def test_keypair_from_scalar_valid(self):
        # Use a known valid scalar (the one generated from SEED_A)
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        result = sc.p256_keypair_from_scalar(sk.data)
        self.assertIsNotNone(result)
        self.assertEqual(result.public_key.data, sk.public_key.data)

    def test_keypair_from_scalar_zero(self):
        self.assertIsNone(sc.p256_keypair_from_scalar(bytes(32)))

    def test_keypair_from_scalar_ge_n(self):
        # n for P-256
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        self.assertIsNone(sc.p256_keypair_from_scalar(n.to_bytes(32, "big")))
        self.assertIsNone(sc.p256_keypair_from_scalar((n + 1).to_bytes(32, "big")))


# ===================================================================
# 16. P-256 ECDH
# ===================================================================


class TestP256Ecdh(unittest.TestCase):
    def test_shared_secret_symmetric(self):
        alice = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        bob = sc.p256_ecdsa_keypair_from_seed(SEED_B)
        ss1 = sc.p256_ecdh(alice, bob.public_key)
        ss2 = sc.p256_ecdh(bob, alice.public_key)
        self.assertEqual(ss1, ss2)
        self.assertEqual(len(ss1), 32)

    def test_different_keys_different_secrets(self):
        a = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        b = sc.p256_ecdsa_keypair_from_seed(SEED_B)
        c = sc.p256_ecdsa_keypair_from_seed(SEED_C)
        ss_ab = sc.p256_ecdh(a, b.public_key)
        ss_ac = sc.p256_ecdh(a, c.public_key)
        self.assertNotEqual(ss_ab, ss_ac)


# ===================================================================
# 17. ECIES
# ===================================================================


class TestEcies(unittest.TestCase):
    def test_roundtrip(self):
        recipient = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        pt = b"secret message for ECIES!"
        ct = sc.ecies_encrypt(recipient.public_key, pt, SEED_B)
        dec = sc.ecies_decrypt(recipient, ct)
        self.assertEqual(dec, pt)

    def test_output_size(self):
        for pt_len in [0, 1, 15, 16, 17, 32, 48, 100]:
            expected = sc.ecies_output_size(pt_len)
            recipient = sc.p256_ecdsa_keypair_from_seed(SEED_A)
            ct = sc.ecies_encrypt(recipient.public_key, bytes(pt_len), SEED_B)
            self.assertEqual(
                len(ct), expected, f"output_size mismatch for pt_len={pt_len}"
            )

    def test_decrypt_too_short(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        with self.assertRaises(ValueError):
            sc.ecies_decrypt(sk, bytes(64))  # less than fixed_overhead + 16

    def test_decrypt_tampered_mac(self):
        recipient = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        ct = sc.ecies_encrypt(recipient.public_key, b"test message plaintext!", SEED_B)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF  # corrupt MAC tag
        with self.assertRaises(ValueError):
            sc.ecies_decrypt(recipient, bytes(tampered))

    def test_decrypt_bad_prefix(self):
        recipient = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        ct = sc.ecies_encrypt(recipient.public_key, b"test message plaintext!", SEED_B)
        tampered = bytearray(ct)
        tampered[0] = 0x04  # wrong EC2OSP-X prefix
        with self.assertRaises(ValueError):
            sc.ecies_decrypt(recipient, bytes(tampered))


# ===================================================================
# 18. KDF2
# ===================================================================


class TestKdf2Sha256(unittest.TestCase):
    def test_basic(self):
        out = sc.kdf2_sha256(bytes(32), b"params", 32)
        self.assertEqual(len(out), 32)

    def test_multi_block(self):
        out = sc.kdf2_sha256(bytes(32), b"params", 64)
        self.assertEqual(len(out), 64)
        # First block should match 32-byte output
        out32 = sc.kdf2_sha256(bytes(32), b"params", 32)
        self.assertEqual(out[:32], out32)

    def test_empty_params(self):
        out = sc.kdf2_sha256(bytes(32), b"", 32)
        self.assertEqual(len(out), 32)

    def test_matches_x963kdf(self):
        # Cross-check against cryptography.X963KDF, which is the same
        # algorithm as IEEE 1363a-2004 §13.2 KDF2 when the hash is
        # byte-aligned. This anchors the impl to an independent
        # reference rather than just self-consistency. Exercises:
        # empty info, non-empty info, single block, multi-block, and
        # partial-block truncation.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

        def x963(z: bytes, p: bytes, length: int) -> bytes:
            return X963KDF(
                algorithm=hashes.SHA256(), length=length, sharedinfo=p
            ).derive(z)

        cases = [
            (bytes([0x01, 0x02, 0x03, 0x04]), b"", 32),
            (bytes([0xAA, 0xBB, 0xCC, 0xDD]), bytes([0x01, 0x02, 0x03]), 32),
            (bytes([0x42] * 16), b"", 64),
            (bytes(range(32)), b"label", 40),
            (
                bytes.fromhex(
                    "9858efbacc36b14d70d2e9c91e3c95f1c14e9d1eedbcdaa5e1bd4eaa46b71fe1"
                ),
                bytes.fromhex("00112233445566778899aabbccddeeff"),
                48,
            ),
        ]
        for z, p, length in cases:
            with self.subTest(z=z.hex(), p=p.hex(), length=length):
                self.assertEqual(sc.kdf2_sha256(z, p, length), x963(z, p, length))


# ===================================================================
# 19. PKCS#8 / SPKI DER
# ===================================================================


class TestPkcs8SpkiDer(unittest.TestCase):
    def test_ed25519_spki_export_size(self):
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        der = sc.spki_export_ed25519(sk.public_key)
        self.assertEqual(len(der), sc.spki_ed25519_der_size)

    def test_ed25519_spki_roundtrip(self):
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        der = sc.spki_export_ed25519(sk.public_key)
        pk2 = sc.spki_import_ed25519(der)
        self.assertIsNotNone(pk2)
        self.assertEqual(pk2.data, sk.public_key.data)

    def test_ed25519_spki_import_bad_prefix(self):
        result = sc.spki_import_ed25519(bytes(44))
        self.assertIsNone(result)

    def test_ed25519_pkcs8_roundtrip(self):
        der = sc.pkcs8_export_ed25519(SEED_A)
        self.assertEqual(len(der), sc.pkcs8_ed25519_der_size)
        sk = sc.pkcs8_import_ed25519(der)
        self.assertIsNotNone(sk)
        expected = sc.ed25519_keypair_from_seed(SEED_A)
        self.assertEqual(sk.public_key.data, expected.public_key.data)

    def test_p256_spki_export_size(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        der = sc.spki_export_p256(sk.public_key)
        self.assertEqual(len(der), sc.spki_p256_der_size)

    def test_p256_spki_roundtrip(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        der = sc.spki_export_p256(sk.public_key)
        pk2 = sc.spki_import_p256(der)
        self.assertIsNotNone(pk2)
        self.assertEqual(pk2.data, sk.public_key.data)

    def test_p256_spki_import_bad_prefix(self):
        self.assertIsNone(sc.spki_import_p256(bytes(91)))

    def test_p256_pkcs8_roundtrip(self):
        sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        der = sc.pkcs8_export_p256(sk)
        self.assertEqual(len(der), sc.pkcs8_p256_der_size)
        sk2 = sc.pkcs8_import_p256(der)
        self.assertIsNotNone(sk2)
        self.assertEqual(sk2.public_key.data, sk.public_key.data)


# ===================================================================
# 20. KeyId, KeyType, KeyChainId
# ===================================================================


class TestKeyIdAndKeyType(unittest.TestCase):
    def test_key_id_is_static(self):
        # Byte 0 LSB = 0 -> static
        kid = sc.KeyId(data=b"\x00" + bytes(7))
        self.assertTrue(kid.is_static())
        self.assertFalse(kid.is_dynamic())

    def test_key_id_is_dynamic(self):
        # Byte 0 LSB = 1 -> dynamic
        kid = sc.KeyId(data=b"\x01" + bytes(7))
        self.assertFalse(kid.is_static())
        self.assertTrue(kid.is_dynamic())

    def test_key_type_data_size_all(self):
        expected = {
            sc.KeyType.aes128: 16,
            sc.KeyType.aes256: 32,
            sc.KeyType.ecc_public_256: 64,
            sc.KeyType.ecc_private_256: 32,
            sc.KeyType.aes128_siv: 32,
            sc.KeyType.aes256_siv: 64,
            sc.KeyType.ed25519_public: 32,
            sc.KeyType.ed25519_private: 32,
            sc.KeyType.x25519_public: 32,
            sc.KeyType.x25519_private: 32,
        }
        for kt, size in expected.items():
            self.assertEqual(sc.key_type_data_size(kt), size, f"KeyType.{kt.name}")

    def test_is_valid_key_type(self):
        for i in range(10):
            self.assertTrue(sc.is_valid_key_type(sc.KeyType(i)))

    def test_key_chain_id_values(self):
        self.assertEqual(sc.KeyChainId.entity_public, 0x0000)
        self.assertEqual(sc.KeyChainId.entity_private, 0x0001)
        self.assertEqual(sc.KeyChainId.manufacturer_public, 0x0002)
        self.assertEqual(sc.KeyChainId.controllers, 0x0003)
        self.assertEqual(sc.KeyChainId.transport, 0x0004)


# ===================================================================
# 21. Ed25519 signed public key entry
# ===================================================================


class TestEd25519SignedPublicKeyEntry(unittest.TestCase):
    def setUp(self):
        self.signer = sc.ed25519_keypair_from_seed(SEED_A)
        self.subject = sc.ed25519_keypair_from_seed(SEED_B)
        self.kid = sc.KeyId(data=KEY_ID_A)
        self.related_kid = sc.KeyId(data=KEY_ID_B)
        self.sig_kid = sc.KeyId(data=KEY_ID_C)

    def test_build_and_verify(self):
        entry = sc.build_ed25519_signed_public_key_entry(
            self.kid,
            self.related_kid,
            self.subject.public_key,
            self.sig_kid,
            self.signer,
        )
        self.assertTrue(
            sc.verify_ed25519_signed_public_key_entry(entry, self.signer.public_key)
        )

    def test_verify_wrong_signer(self):
        entry = sc.build_ed25519_signed_public_key_entry(
            self.kid,
            self.related_kid,
            self.subject.public_key,
            self.sig_kid,
            self.signer,
        )
        wrong = sc.ed25519_keypair_from_seed(SEED_C)
        self.assertFalse(
            sc.verify_ed25519_signed_public_key_entry(entry, wrong.public_key)
        )

    def test_serialize_size(self):
        entry = sc.build_ed25519_signed_public_key_entry(
            self.kid,
            self.related_kid,
            self.subject.public_key,
            self.sig_kid,
            self.signer,
        )
        wire = sc.serialize_ed25519_signed_public_key_entry(entry)
        self.assertEqual(len(wire), sc.ed25519_signed_public_key_entry_wire_size)

    def test_serialize_deserialize_roundtrip(self):
        entry = sc.build_ed25519_signed_public_key_entry(
            self.kid,
            self.related_kid,
            self.subject.public_key,
            self.sig_kid,
            self.signer,
        )
        wire = sc.serialize_ed25519_signed_public_key_entry(entry)
        entry2 = sc.deserialize_ed25519_signed_public_key_entry(wire)
        self.assertEqual(entry2.key_id.data, entry.key_id.data)
        self.assertEqual(entry2.public_key.data, entry.public_key.data)
        self.assertEqual(entry2.signature.data, entry.signature.data)

    def test_deserialize_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.deserialize_ed25519_signed_public_key_entry(bytes(119))

    def test_tampered_signature(self):
        entry = sc.build_ed25519_signed_public_key_entry(
            self.kid,
            self.related_kid,
            self.subject.public_key,
            self.sig_kid,
            self.signer,
        )
        # Flip a bit in the signature
        bad_sig = bytearray(entry.signature.data)
        bad_sig[0] ^= 0xFF
        tampered = sc.Ed25519SignedPublicKeyEntry(
            key_id=entry.key_id,
            related_key_id=entry.related_key_id,
            public_key=entry.public_key,
            signature_key_id=entry.signature_key_id,
            signature=sc.Ed25519Signature(data=bytes(bad_sig)),
        )
        self.assertFalse(
            sc.verify_ed25519_signed_public_key_entry(tampered, self.signer.public_key)
        )


# ===================================================================
# 21b. X25519 signed public key entry
# ===================================================================


class TestX25519SignedPublicKeyEntry(unittest.TestCase):
    def setUp(self):
        # Ed25519 authority key (signs the X25519 entries)
        self.signer = sc.ed25519_keypair_from_seed(SEED_A)
        # X25519 endpoint key
        self.x_sk = sc.x25519_keypair_from_seed(SEED_B)
        self.x_pk = self.x_sk.public_key
        self.kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x20")
        self.rkid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x21")
        self.skid = sc.KeyId(data=b"\x00\x1b\xc5\x00\x00\x00\x00\x01")
        self.entry = sc.build_x25519_signed_public_key_entry(
            self.kid, self.rkid, self.x_pk, self.skid, self.signer
        )

    def test_build_fields(self):
        self.assertEqual(self.entry.key_id, self.kid)
        self.assertEqual(self.entry.related_key_id, self.rkid)
        self.assertEqual(self.entry.public_key, self.x_pk)
        self.assertEqual(self.entry.signature_key_id, self.skid)

    def test_verify_correct_signer(self):
        self.assertTrue(
            sc.verify_x25519_signed_public_key_entry(self.entry, self.signer.public_key)
        )

    def test_reject_wrong_signer(self):
        other = sc.ed25519_keypair_from_seed(SEED_C)
        self.assertFalse(
            sc.verify_x25519_signed_public_key_entry(self.entry, other.public_key)
        )

    def test_reject_tampered_public_key(self):
        bad = bytearray(self.entry.public_key.data)
        bad[15] ^= 0xFF
        tampered = sc.X25519SignedPublicKeyEntry(
            key_id=self.entry.key_id,
            related_key_id=self.entry.related_key_id,
            public_key=sc.X25519PublicKey(data=bytes(bad)),
            signature_key_id=self.entry.signature_key_id,
            signature=self.entry.signature,
        )
        self.assertFalse(
            sc.verify_x25519_signed_public_key_entry(tampered, self.signer.public_key)
        )

    def test_serialize_deserialize_roundtrip(self):
        wire = sc.serialize_x25519_signed_public_key_entry(self.entry)
        self.assertEqual(len(wire), sc.x25519_signed_public_key_entry_wire_size)
        recovered = sc.deserialize_x25519_signed_public_key_entry(wire)
        self.assertEqual(recovered.key_id, self.entry.key_id)
        self.assertEqual(recovered.public_key, self.entry.public_key)
        self.assertEqual(recovered.signature, self.entry.signature)
        self.assertTrue(
            sc.verify_x25519_signed_public_key_entry(recovered, self.signer.public_key)
        )

    def test_deserialize_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.deserialize_x25519_signed_public_key_entry(b"\x00" * 100)


# ===================================================================
# 21c. P-256 signed public key entry
# ===================================================================


class TestP256SignedPublicKeyEntry(unittest.TestCase):
    def setUp(self):
        # P-256 authority key
        self.signer = sc.p256_keypair_from_scalar(SEED_A)
        self.assertIsNotNone(self.signer)
        self.signer_pk = sc.p256_public_key(self.signer)
        # P-256 endpoint key
        self.ep = sc.p256_keypair_from_scalar(SEED_B)
        self.assertIsNotNone(self.ep)
        self.ep_pk = sc.p256_public_key(self.ep)
        self.kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x30")
        self.rkid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x31")
        self.skid = sc.KeyId(data=b"\x00\x1b\xc5\x00\x00\x00\x00\x10")
        self.entry = sc.build_p256_signed_public_key_entry(
            self.kid, self.rkid, self.ep_pk, self.skid, self.signer
        )

    def test_build_fields(self):
        self.assertEqual(self.entry.key_id, self.kid)
        self.assertEqual(self.entry.related_key_id, self.rkid)
        self.assertEqual(self.entry.public_key, self.ep_pk)
        self.assertEqual(self.entry.signature_key_id, self.skid)

    def test_verify_correct_signer(self):
        self.assertTrue(
            sc.verify_p256_signed_public_key_entry(self.entry, self.signer_pk)
        )

    def test_reject_wrong_signer(self):
        self.assertFalse(sc.verify_p256_signed_public_key_entry(self.entry, self.ep_pk))

    def test_reject_tampered_public_key(self):
        bad = bytearray(self.entry.public_key.data)
        bad[15] ^= 0xFF
        tampered = sc.P256SignedPublicKeyEntry(
            key_id=self.entry.key_id,
            related_key_id=self.entry.related_key_id,
            public_key=sc.P256PublicKey(data=bytes(bad)),
            signature_key_id=self.entry.signature_key_id,
            signature=self.entry.signature,
        )
        self.assertFalse(
            sc.verify_p256_signed_public_key_entry(tampered, self.signer_pk)
        )

    def test_self_signed_root(self):
        root_entry = sc.build_p256_signed_public_key_entry(
            self.skid, self.skid, self.signer_pk, self.skid, self.signer
        )
        self.assertTrue(
            sc.verify_p256_signed_public_key_entry(root_entry, self.signer_pk)
        )

    def test_serialize_deserialize_roundtrip(self):
        wire = sc.serialize_p256_signed_public_key_entry(self.entry)
        self.assertEqual(len(wire), sc.p256_signed_public_key_entry_wire_size)
        recovered = sc.deserialize_p256_signed_public_key_entry(wire)
        self.assertEqual(recovered.key_id, self.entry.key_id)
        self.assertEqual(recovered.public_key, self.entry.public_key)
        self.assertEqual(recovered.signature, self.entry.signature)
        self.assertTrue(
            sc.verify_p256_signed_public_key_entry(recovered, self.signer_pk)
        )

    def test_deserialize_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.deserialize_p256_signed_public_key_entry(b"\x00" * 100)


# ===================================================================
# 21c2. P-256 signed X25519 public key entry
# ===================================================================


class TestP256SignedX25519PublicKeyEntry(unittest.TestCase):
    def setUp(self):
        # P-256 authority key
        self.signer = sc.p256_keypair_from_scalar(SEED_A)
        self.assertIsNotNone(self.signer)
        self.signer_pk = sc.p256_public_key(self.signer)
        # X25519 endpoint key
        self.x_sk = sc.x25519_keypair_from_seed(SEED_B)
        self.x_pk = self.x_sk.public_key
        self.kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x40")
        self.rkid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x41")
        self.skid = sc.KeyId(data=b"\x00\x1b\xc5\x00\x00\x00\x00\x10")
        self.entry = sc.build_p256_signed_x25519_public_key_entry(
            self.kid, self.rkid, self.x_pk, self.skid, self.signer
        )

    def test_build_fields(self):
        self.assertEqual(self.entry.key_id, self.kid)
        self.assertEqual(self.entry.related_key_id, self.rkid)
        self.assertEqual(self.entry.public_key, self.x_pk)
        self.assertEqual(self.entry.signature_key_id, self.skid)

    def test_verify_correct_signer(self):
        self.assertTrue(
            sc.verify_p256_signed_x25519_public_key_entry(self.entry, self.signer_pk)
        )

    def test_reject_wrong_signer(self):
        other = sc.p256_keypair_from_scalar(SEED_C)
        other_pk = sc.p256_public_key(other)
        self.assertFalse(
            sc.verify_p256_signed_x25519_public_key_entry(self.entry, other_pk)
        )

    def test_reject_tampered_public_key(self):
        bad = bytearray(self.entry.public_key.data)
        bad[15] ^= 0xFF
        tampered = sc.P256SignedX25519PublicKeyEntry(
            key_id=self.entry.key_id,
            related_key_id=self.entry.related_key_id,
            public_key=sc.X25519PublicKey(data=bytes(bad)),
            signature_key_id=self.entry.signature_key_id,
            signature=self.entry.signature,
        )
        self.assertFalse(
            sc.verify_p256_signed_x25519_public_key_entry(tampered, self.signer_pk)
        )

    def test_serialize_deserialize_roundtrip(self):
        wire = sc.serialize_p256_signed_x25519_public_key_entry(self.entry)
        self.assertEqual(len(wire), sc.p256_signed_x25519_public_key_entry_wire_size)
        recovered = sc.deserialize_p256_signed_x25519_public_key_entry(wire)
        self.assertEqual(recovered.key_id, self.entry.key_id)
        self.assertEqual(recovered.public_key, self.entry.public_key)
        self.assertEqual(recovered.signature, self.entry.signature)
        self.assertTrue(
            sc.verify_p256_signed_x25519_public_key_entry(recovered, self.signer_pk)
        )

    def test_deserialize_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.deserialize_p256_signed_x25519_public_key_entry(b"\x00" * 100)


# ===================================================================
# 21d. Private key entries
# ===================================================================


class TestPrivateKeyEntries(unittest.TestCase):
    def test_ed25519_private_key_entry(self):
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x50")
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        entry = sc.Ed25519PrivateKeyEntry(key_id=kid, private_key=sk)
        self.assertEqual(entry.key_id, kid)
        self.assertEqual(entry.private_key.public_key, sk.public_key)

    def test_x25519_private_key_entry(self):
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x50")
        sk = sc.x25519_keypair_from_seed(SEED_B)
        entry = sc.X25519PrivateKeyEntry(key_id=kid, private_key=sk)
        self.assertEqual(entry.key_id, kid)
        self.assertEqual(entry.private_key.public_key, sk.public_key)

    def test_p256_private_key_entry(self):
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x50")
        sk = sc.p256_keypair_from_scalar(SEED_C)
        self.assertIsNotNone(sk)
        entry = sc.P256PrivateKeyEntry(key_id=kid, private_key=sk)
        self.assertEqual(entry.key_id, kid)
        self.assertEqual(entry.private_key.public_key, sk.public_key)


# ===================================================================
# 21e. Transport key entries
# ===================================================================


class TestTransportKeyEntries(unittest.TestCase):
    def test_aes128_key_entry(self):
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x60")
        key = sc.Aes128Key(data=b"\xaa" * 16)
        entry = sc.Aes128KeyEntry(key_id=kid, key=key)
        self.assertEqual(entry.key_id, kid)
        self.assertEqual(entry.key.data, b"\xaa" * 16)

    def test_aes256_key_entry(self):
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x60")
        key = sc.Aes256Key(data=b"\xbb" * 32)
        entry = sc.Aes256KeyEntry(key_id=kid, key=key)
        self.assertEqual(entry.key_id, kid)
        self.assertEqual(entry.key.data, b"\xbb" * 32)

    def test_aes128_siv_key_entry(self):
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x60")
        key = sc.Aes128SivKey(data=b"\xcc" * 32)
        entry = sc.Aes128SivKeyEntry(key_id=kid, key=key)
        self.assertEqual(entry.key_id, kid)
        self.assertEqual(len(entry.key.data), 32)

    def test_aes256_siv_key_entry(self):
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x60")
        key = sc.Aes256SivKey(data=b"\xdd" * 64)
        entry = sc.Aes256SivKeyEntry(key_id=kid, key=key)
        self.assertEqual(entry.key_id, kid)
        self.assertEqual(len(entry.key.data), 64)


# ===================================================================
# 21f. Typed keychain containers
# ===================================================================


class TestTypedKeychains(unittest.TestCase):
    def test_public_key_chain(self):
        """PublicKeyChain can hold all three signed entry types."""
        ed_sk = sc.ed25519_keypair_from_seed(SEED_A)
        ed_pk = ed_sk.public_key
        kid1 = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x01")
        ed_entry = sc.build_ed25519_signed_public_key_entry(
            kid1, kid1, ed_pk, kid1, ed_sk
        )

        x_sk = sc.x25519_keypair_from_seed(SEED_B)
        kid2 = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x02")
        x_entry = sc.build_x25519_signed_public_key_entry(
            kid2, kid2, x_sk.public_key, kid1, ed_sk
        )

        p_sk = sc.p256_keypair_from_scalar(SEED_C)
        p_pk = sc.p256_public_key(p_sk)
        kid3 = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x03")
        p_entry = sc.build_p256_signed_public_key_entry(kid3, kid3, p_pk, kid3, p_sk)

        chain = [ed_entry, x_entry, p_entry]
        self.assertEqual(len(chain), 3)
        self.assertIsInstance(chain[0], sc.Ed25519SignedPublicKeyEntry)
        self.assertIsInstance(chain[1], sc.X25519SignedPublicKeyEntry)
        self.assertIsInstance(chain[2], sc.P256SignedPublicKeyEntry)

    def test_private_key_chain(self):
        """PrivateKeyChain can hold all three private entry types."""
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x10")
        chain = [
            sc.Ed25519PrivateKeyEntry(kid, sc.ed25519_keypair_from_seed(SEED_A)),
            sc.X25519PrivateKeyEntry(kid, sc.x25519_keypair_from_seed(SEED_B)),
            sc.P256PrivateKeyEntry(kid, sc.p256_keypair_from_scalar(SEED_C)),
        ]
        self.assertEqual(len(chain), 3)
        self.assertIsInstance(chain[0], sc.Ed25519PrivateKeyEntry)
        self.assertIsInstance(chain[1], sc.X25519PrivateKeyEntry)
        self.assertIsInstance(chain[2], sc.P256PrivateKeyEntry)

    def test_transport_key_chain(self):
        """SessionKeyChain can hold all four symmetric entry types."""
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x20")
        chain = [
            sc.Aes128KeyEntry(kid, sc.Aes128Key(data=b"\x00" * 16)),
            sc.Aes256KeyEntry(kid, sc.Aes256Key(data=b"\x00" * 32)),
            sc.Aes128SivKeyEntry(kid, sc.Aes128SivKey(data=b"\x00" * 32)),
            sc.Aes256SivKeyEntry(kid, sc.Aes256SivKey(data=b"\x00" * 64)),
        ]
        self.assertEqual(len(chain), 4)
        self.assertIsInstance(chain[0], sc.Aes128KeyEntry)
        self.assertIsInstance(chain[1], sc.Aes256KeyEntry)
        self.assertIsInstance(chain[2], sc.Aes128SivKeyEntry)
        self.assertIsInstance(chain[3], sc.Aes256SivKeyEntry)


# ===================================================================
# 21b. Keychain entry accessors (get_key_entry_key_id, find_key_entry)
# ===================================================================


class TestKeychainLookup(unittest.TestCase):
    def test_get_key_entry_key_id_public(self):
        """get_key_entry_key_id extracts key_id from a public key entry."""
        sk = sc.ed25519_keypair_from_seed(SEED_A)
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x01")
        entry = sc.build_ed25519_signed_public_key_entry(
            kid, kid, sc.ed25519_public_key(sk), kid, sk
        )
        self.assertEqual(sc.get_key_entry_key_id(entry).data, kid.data)

    def test_get_key_entry_key_id_private(self):
        """get_key_entry_key_id extracts key_id from a private key entry."""
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x02")
        entry = sc.Ed25519PrivateKeyEntry(kid, sc.ed25519_keypair_from_seed(SEED_A))
        self.assertEqual(sc.get_key_entry_key_id(entry).data, kid.data)

    def test_get_key_entry_key_id_session(self):
        """get_key_entry_key_id extracts key_id from a session key entry."""
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x03")
        entry = sc.Aes128KeyEntry(kid, sc.Aes128Key(data=b"\x00" * 16))
        self.assertEqual(sc.get_key_entry_key_id(entry).data, kid.data)

    def test_find_key_entry_hit(self):
        """find_key_entry returns the matching entry."""
        kid1 = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x10")
        kid2 = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x11")
        chain = [
            sc.Aes128KeyEntry(kid1, sc.Aes128Key(data=b"\x00" * 16)),
            sc.Aes256KeyEntry(kid2, sc.Aes256Key(data=b"\x00" * 32)),
        ]
        found = sc.find_key_entry(chain, kid2)
        self.assertIsNotNone(found)
        self.assertIsInstance(found, sc.Aes256KeyEntry)
        self.assertEqual(found.key_id.data, kid2.data)

    def test_find_key_entry_miss(self):
        """find_key_entry returns None for missing KeyId."""
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x10")
        missing = sc.KeyId(data=b"\xff\xff\xff\xff\xff\xff\xff\xff")
        chain = [sc.Aes128KeyEntry(kid, sc.Aes128Key(data=b"\x00" * 16))]
        self.assertIsNone(sc.find_key_entry(chain, missing))

    def test_find_key_entry_empty(self):
        """find_key_entry returns None for empty chain."""
        kid = sc.KeyId(data=b"\x91\xe0\xf0\x00\x00\x00\x00\x10")
        self.assertIsNone(sc.find_key_entry([], kid))


# ===================================================================
# 22. Ed25519 key exchange PDU
# ===================================================================


class TestEd25519KeyExchangePdu(unittest.TestCase):
    def setUp(self):
        self.identity = sc.ed25519_keypair_from_seed(SEED_A)
        eph = sc.x25519_keypair_from_seed(SEED_B)
        self.eph_pk = eph.public_key

    def test_build_offer(self):
        pdu = sc.build_ed25519_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        self.assertEqual(pdu.message_type, sc.key_exchange_offer)
        self.assertEqual(pdu.sender_identity.data, self.identity.public_key.data)

    def test_build_and_verify(self):
        pdu = sc.build_ed25519_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        result = sc.verify_ed25519_key_exchange(pdu, self.identity.public_key)
        self.assertIsNotNone(result)
        self.assertEqual(result.data, self.eph_pk.data)

    def test_verify_wrong_identity(self):
        pdu = sc.build_ed25519_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        wrong = sc.ed25519_keypair_from_seed(SEED_C)
        self.assertIsNone(sc.verify_ed25519_key_exchange(pdu, wrong.public_key))

    def test_verify_tampered_signature(self):
        pdu = sc.build_ed25519_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        bad_sig = bytearray(pdu.signature.data)
        bad_sig[0] ^= 0xFF
        tampered = sc.Ed25519KeyExchangePdu(
            message_type=pdu.message_type,
            sender_identity=pdu.sender_identity,
            ephemeral_pubkey=pdu.ephemeral_pubkey,
            signature=sc.Ed25519Signature(data=bytes(bad_sig)),
        )
        self.assertIsNone(
            sc.verify_ed25519_key_exchange(tampered, self.identity.public_key)
        )

    def test_serialize_size(self):
        pdu = sc.build_ed25519_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        wire = sc.serialize_ed25519_key_exchange(pdu)
        self.assertEqual(len(wire), sc.ed25519_key_exchange_pdu_wire_size)

    def test_serialize_deserialize_roundtrip(self):
        pdu = sc.build_ed25519_key_exchange(
            sc.key_exchange_accept, self.identity, self.eph_pk
        )
        wire = sc.serialize_ed25519_key_exchange(pdu)
        pdu2 = sc.deserialize_ed25519_key_exchange(wire)
        self.assertIsNotNone(pdu2)
        self.assertEqual(pdu2.message_type, pdu.message_type)
        self.assertEqual(pdu2.sender_identity.data, pdu.sender_identity.data)
        self.assertEqual(pdu2.ephemeral_pubkey.data, pdu.ephemeral_pubkey.data)
        self.assertEqual(pdu2.signature.data, pdu.signature.data)

    def test_deserialize_wrong_size(self):
        self.assertIsNone(sc.deserialize_ed25519_key_exchange(bytes(128)))


# ===================================================================
# 23. P-256 key exchange PDU
# ===================================================================


class TestP256KeyExchangePdu(unittest.TestCase):
    def setUp(self):
        self.identity = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        eph = sc.p256_ecdsa_keypair_from_seed(SEED_B)
        self.eph_pk = eph.public_key

    def test_build_offer(self):
        pdu = sc.build_p256_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        self.assertEqual(pdu.message_type, sc.key_exchange_offer)

    def test_build_and_verify(self):
        pdu = sc.build_p256_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        result = sc.verify_p256_key_exchange(pdu, self.identity.public_key)
        self.assertIsNotNone(result)
        self.assertEqual(result.data, self.eph_pk.data)

    def test_verify_wrong_identity(self):
        pdu = sc.build_p256_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        wrong = sc.p256_ecdsa_keypair_from_seed(SEED_C)
        self.assertIsNone(sc.verify_p256_key_exchange(pdu, wrong.public_key))

    def test_verify_tampered_signature(self):
        pdu = sc.build_p256_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        bad_sig = bytearray(pdu.signature.data)
        bad_sig[0] ^= 0xFF
        tampered = sc.P256KeyExchangePdu(
            message_type=pdu.message_type,
            sender_identity=pdu.sender_identity,
            ephemeral_pubkey=pdu.ephemeral_pubkey,
            signature=sc.P256EcdsaSignature(data=bytes(bad_sig)),
        )
        self.assertIsNone(
            sc.verify_p256_key_exchange(tampered, self.identity.public_key)
        )

    def test_serialize_size(self):
        pdu = sc.build_p256_key_exchange(
            sc.key_exchange_offer, self.identity, self.eph_pk
        )
        wire = sc.serialize_p256_key_exchange(pdu)
        self.assertEqual(len(wire), sc.p256_key_exchange_pdu_wire_size)

    def test_serialize_deserialize_roundtrip(self):
        pdu = sc.build_p256_key_exchange(
            sc.key_exchange_accept, self.identity, self.eph_pk
        )
        wire = sc.serialize_p256_key_exchange(pdu)
        pdu2 = sc.deserialize_p256_key_exchange(wire)
        self.assertIsNotNone(pdu2)
        self.assertEqual(pdu2.message_type, pdu.message_type)
        self.assertEqual(pdu2.sender_identity.data, pdu.sender_identity.data)
        self.assertEqual(pdu2.signature.data, pdu.signature.data)

    def test_deserialize_wrong_size(self):
        self.assertIsNone(sc.deserialize_p256_key_exchange(bytes(192)))


# ===================================================================
# 24. AUTH_GET_NONCE / AUTH_ADD_KEY_NONCE / Wrapped keys
# ===================================================================


class TestAuthGetNonceSerialization(unittest.TestCase):
    def test_roundtrip(self):
        payload = sc.AuthGetNoncePayload(
            controller_nonce=sc.Nonce(data=bytes(range(8)))
        )
        wire = sc.serialize_auth_get_nonce(payload)
        self.assertEqual(len(wire), sc.auth_get_nonce_payload_size)
        p2 = sc.deserialize_auth_get_nonce(wire)
        self.assertEqual(p2.controller_nonce.data, payload.controller_nonce.data)

    def test_response_roundtrip(self):
        payload = sc.AuthGetNonceResponsePayload(
            controller_nonce=sc.Nonce(data=bytes(range(8))),
            target_nonce=sc.Nonce(data=bytes(range(8, 16))),
        )
        wire = sc.serialize_auth_get_nonce_response(payload)
        self.assertEqual(len(wire), sc.auth_get_nonce_response_payload_size)
        p2 = sc.deserialize_auth_get_nonce_response(wire)
        self.assertEqual(p2.controller_nonce.data, payload.controller_nonce.data)
        self.assertEqual(p2.target_nonce.data, payload.target_nonce.data)


class TestAuthAddKeyNonceSerialization(unittest.TestCase):
    def test_header_roundtrip(self):
        header = sc.AuthAddKeyNonceHeader(
            controller_nonce=sc.Nonce(data=bytes(range(8))),
            target_nonce=sc.Nonce(data=bytes(range(8, 16))),
            key_id=sc.KeyId(data=KEY_ID_A),
            key_type=sc.KeyType.aes256_siv,
            key_length=64,
        )
        wire = sc.serialize_auth_add_key_nonce_header(header)
        self.assertEqual(len(wire), sc.auth_add_key_nonce_header_size)
        h2 = sc.deserialize_auth_add_key_nonce_header(wire)
        self.assertIsNotNone(h2)
        self.assertEqual(h2.controller_nonce.data, header.controller_nonce.data)
        self.assertEqual(h2.target_nonce.data, header.target_nonce.data)
        self.assertEqual(h2.key_id.data, header.key_id.data)
        self.assertEqual(h2.key_type, header.key_type)
        self.assertEqual(h2.key_length, header.key_length)

    def test_response_roundtrip(self):
        payload = sc.AuthAddKeyNonceResponsePayload(
            controller_nonce=sc.Nonce(data=bytes(range(8))),
            target_nonce=sc.Nonce(data=bytes(range(8, 16))),
            key_id=sc.KeyId(data=KEY_ID_A),
        )
        wire = sc.serialize_auth_add_key_nonce_response(payload)
        self.assertEqual(len(wire), sc.auth_add_key_nonce_response_payload_size)
        p2 = sc.deserialize_auth_add_key_nonce_response(wire)
        self.assertEqual(p2.controller_nonce.data, payload.controller_nonce.data)
        self.assertEqual(p2.target_nonce.data, payload.target_nonce.data)
        self.assertEqual(p2.key_id.data, payload.key_id.data)


class TestAes128KeyWrapUnwrap(unittest.TestCase):
    def setUp(self):
        self.transport_key = sc.Aes256SivKey(data=bytes(range(64)))
        self.cn = sc.Nonce(data=bytes(range(8)))
        self.tn = sc.Nonce(data=bytes(range(8, 16)))
        self.kid = sc.KeyId(data=KEY_ID_A)
        self.key = sc.Aes128Key(data=bytes(range(16)))

    def test_roundtrip(self):
        wrapped = sc.wrap_aes128_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        result = sc.unwrap_aes128_key(
            self.transport_key, self.cn, self.tn, self.kid, wrapped
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.data, self.key.data)

    def test_wrong_transport_key(self):
        wrapped = sc.wrap_aes128_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        wrong = sc.Aes256SivKey(data=bytes(64))
        self.assertIsNone(
            sc.unwrap_aes128_key(wrong, self.cn, self.tn, self.kid, wrapped)
        )

    def test_serialize_roundtrip(self):
        wrapped = sc.wrap_aes128_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        wire = sc.serialize_aes128_wrapped_key(wrapped)
        self.assertEqual(len(wire), sc.aes128_wrapped_key_size)
        w2 = sc.deserialize_aes128_wrapped_key(wire)
        self.assertEqual(w2.ciphertext, wrapped.ciphertext)
        self.assertEqual(w2.siv_tag, wrapped.siv_tag)


class TestAes256KeyWrapUnwrap(unittest.TestCase):
    def setUp(self):
        self.transport_key = sc.Aes256SivKey(data=bytes(range(64)))
        self.cn = sc.Nonce(data=bytes(range(8)))
        self.tn = sc.Nonce(data=bytes(range(8, 16)))
        self.kid = sc.KeyId(data=KEY_ID_A)
        self.key = sc.Aes256Key(data=bytes(range(32)))

    def test_roundtrip(self):
        wrapped = sc.wrap_aes256_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        result = sc.unwrap_aes256_key(
            self.transport_key, self.cn, self.tn, self.kid, wrapped
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.data, self.key.data)

    def test_tampered_ciphertext(self):
        wrapped = sc.wrap_aes256_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        bad_ct = bytearray(wrapped.ciphertext)
        bad_ct[0] ^= 0xFF
        tampered = sc.Aes256WrappedKey(
            ciphertext=bytes(bad_ct), siv_tag=wrapped.siv_tag
        )
        self.assertIsNone(
            sc.unwrap_aes256_key(
                self.transport_key, self.cn, self.tn, self.kid, tampered
            )
        )

    def test_tampered_siv_tag(self):
        wrapped = sc.wrap_aes256_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        bad_tag = bytearray(wrapped.siv_tag)
        bad_tag[0] ^= 0xFF
        tampered = sc.Aes256WrappedKey(
            ciphertext=wrapped.ciphertext, siv_tag=bytes(bad_tag)
        )
        self.assertIsNone(
            sc.unwrap_aes256_key(
                self.transport_key, self.cn, self.tn, self.kid, tampered
            )
        )

    def test_serialize_roundtrip(self):
        wrapped = sc.wrap_aes256_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        wire = sc.serialize_aes256_wrapped_key(wrapped)
        self.assertEqual(len(wire), sc.aes256_wrapped_key_size)
        w2 = sc.deserialize_aes256_wrapped_key(wire)
        self.assertEqual(w2.ciphertext, wrapped.ciphertext)
        self.assertEqual(w2.siv_tag, wrapped.siv_tag)


class TestAes128SivKeyWrapUnwrap(unittest.TestCase):
    def setUp(self):
        self.transport_key = sc.Aes256SivKey(data=bytes(range(64)))
        self.cn = sc.Nonce(data=bytes(range(8)))
        self.tn = sc.Nonce(data=bytes(range(8, 16)))
        self.kid = sc.KeyId(data=KEY_ID_A)
        self.key = sc.Aes128SivKey(data=bytes(range(32)))

    def test_roundtrip(self):
        wrapped = sc.wrap_aes128_siv_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        result = sc.unwrap_aes128_siv_key(
            self.transport_key, self.cn, self.tn, self.kid, wrapped
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.data, self.key.data)

    def test_serialize_roundtrip(self):
        wrapped = sc.wrap_aes128_siv_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        wire = sc.serialize_aes128_siv_wrapped_key(wrapped)
        self.assertEqual(len(wire), sc.aes128_siv_wrapped_key_size)
        w2 = sc.deserialize_aes128_siv_wrapped_key(wire)
        self.assertEqual(w2.ciphertext, wrapped.ciphertext)
        self.assertEqual(w2.siv_tag, wrapped.siv_tag)


class TestAes256SivKeyWrapUnwrap(unittest.TestCase):
    def setUp(self):
        self.transport_key = sc.Aes256SivKey(data=bytes(range(64)))
        self.cn = sc.Nonce(data=bytes(range(8)))
        self.tn = sc.Nonce(data=bytes(range(8, 16)))
        self.kid = sc.KeyId(data=KEY_ID_A)
        self.key = sc.Aes256SivKey(data=bytes(range(64)))

    def test_roundtrip(self):
        wrapped = sc.wrap_aes256_siv_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        result = sc.unwrap_aes256_siv_key(
            self.transport_key, self.cn, self.tn, self.kid, wrapped
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.data, self.key.data)

    def test_nonce_binding(self):
        """Changing a nonce in unwrap causes authentication failure."""
        wrapped = sc.wrap_aes256_siv_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        wrong_cn = sc.Nonce(data=bytes(8))
        self.assertIsNone(
            sc.unwrap_aes256_siv_key(
                self.transport_key, wrong_cn, self.tn, self.kid, wrapped
            )
        )
        wrong_tn = sc.Nonce(data=bytes(8))
        self.assertIsNone(
            sc.unwrap_aes256_siv_key(
                self.transport_key, self.cn, wrong_tn, self.kid, wrapped
            )
        )

    def test_serialize_roundtrip(self):
        wrapped = sc.wrap_aes256_siv_key(
            self.transport_key, self.cn, self.tn, self.kid, self.key
        )
        wire = sc.serialize_aes256_siv_wrapped_key(wrapped)
        self.assertEqual(len(wire), sc.aes256_siv_wrapped_key_size)
        w2 = sc.deserialize_aes256_siv_wrapped_key(wire)
        self.assertEqual(w2.ciphertext, wrapped.ciphertext)
        self.assertEqual(w2.siv_tag, wrapped.siv_tag)


# ===================================================================
# 25. Transport key derivation
# ===================================================================


class TestTransportKeyDerivation(unittest.TestCase):
    def test_ed25519_info_format(self):
        a = sc.ed25519_keypair_from_seed(SEED_A)
        b = sc.ed25519_keypair_from_seed(SEED_B)
        info = sc.build_ed25519_transport_key_info(a.public_key, b.public_key)
        self.assertTrue(info.startswith(b"avtp-transport"))
        self.assertEqual(len(info), 14 + 32 + 32)  # "avtp-transport" + 2 * 32

    def test_ed25519_derive_deterministic(self):
        a = sc.ed25519_keypair_from_seed(SEED_A)
        b = sc.ed25519_keypair_from_seed(SEED_B)
        ss = bytes(range(32))
        k1 = sc.derive_ed25519_transport_key(ss, a.public_key, b.public_key)
        k2 = sc.derive_ed25519_transport_key(ss, a.public_key, b.public_key)
        self.assertEqual(k1.data, k2.data)
        self.assertEqual(len(k1.data), 64)

    def test_ed25519_derive_wrong_shared_secret_size(self):
        a = sc.ed25519_keypair_from_seed(SEED_A)
        b = sc.ed25519_keypair_from_seed(SEED_B)
        with self.assertRaises(ValueError):
            sc.derive_ed25519_transport_key(bytes(31), a.public_key, b.public_key)

    def test_p256_info_format(self):
        a = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        b = sc.p256_ecdsa_keypair_from_seed(SEED_B)
        info = sc.build_p256_transport_key_info(a.public_key, b.public_key)
        self.assertTrue(info.startswith(b"avtp-transport-p256"))
        self.assertEqual(len(info), 19 + 64 + 64)  # "avtp-transport-p256" + 2 * 64

    def test_p256_derive_deterministic(self):
        a = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        b = sc.p256_ecdsa_keypair_from_seed(SEED_B)
        ss = bytes(range(32))
        k1 = sc.derive_p256_transport_key(ss, a.public_key, b.public_key)
        k2 = sc.derive_p256_transport_key(ss, a.public_key, b.public_key)
        self.assertEqual(k1.data, k2.data)
        self.assertEqual(len(k1.data), 64)

    def test_p256_different_identities(self):
        a = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        b = sc.p256_ecdsa_keypair_from_seed(SEED_B)
        c = sc.p256_ecdsa_keypair_from_seed(SEED_C)
        ss = bytes(range(32))
        k1 = sc.derive_p256_transport_key(ss, a.public_key, b.public_key)
        k2 = sc.derive_p256_transport_key(ss, a.public_key, c.public_key)
        self.assertNotEqual(k1.data, k2.data)


# ===================================================================
# 26. ECC_PUBLIC_256 wire format
# ===================================================================


class TestEccPublic256Wire(unittest.TestCase):
    def setUp(self):
        self.signer = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        self.subject = sc.p256_ecdsa_keypair_from_seed(SEED_B)
        self.kid = sc.KeyId(data=KEY_ID_A)
        self.sig_kid = sc.KeyId(data=KEY_ID_B)

    def test_build_and_verify(self):
        wire = sc.build_ecc_public_256_wire(
            self.kid, self.subject.public_key, self.sig_kid, self.signer
        )
        self.assertTrue(sc.verify_ecc_public_256_wire(wire, self.signer.public_key))

    def test_verify_wrong_signer(self):
        wire = sc.build_ecc_public_256_wire(
            self.kid, self.subject.public_key, self.sig_kid, self.signer
        )
        wrong = sc.p256_ecdsa_keypair_from_seed(SEED_C)
        self.assertFalse(sc.verify_ecc_public_256_wire(wire, wrong.public_key))

    def test_extract_public_key(self):
        wire = sc.build_ecc_public_256_wire(
            self.kid, self.subject.public_key, self.sig_kid, self.signer
        )
        pk = sc.extract_p256_public_key(wire)
        self.assertIsNotNone(pk)
        self.assertEqual(pk.data, self.subject.public_key.data)

    def test_extract_wrong_curve_params(self):
        wire = sc.build_ecc_public_256_wire(
            self.kid, self.subject.public_key, self.sig_kid, self.signer
        )
        wire.field_size = bytes(32)  # wrong q
        self.assertIsNone(sc.extract_p256_public_key(wire))

    def test_serialize_size(self):
        wire = sc.build_ecc_public_256_wire(
            self.kid, self.subject.public_key, self.sig_kid, self.signer
        )
        data = sc.serialize_ecc_public_256_wire(wire)
        self.assertEqual(len(data), sc.ecc_public_256_wire_size)

    def test_serialize_deserialize_roundtrip(self):
        wire = sc.build_ecc_public_256_wire(
            self.kid, self.subject.public_key, self.sig_kid, self.signer
        )
        data = sc.serialize_ecc_public_256_wire(wire)
        wire2 = sc.deserialize_ecc_public_256_wire(data)
        self.assertEqual(wire2.related_key_id.data, wire.related_key_id.data)
        self.assertEqual(wire2.public_x, wire.public_x)
        self.assertEqual(wire2.ecdsa_signature_c, wire.ecdsa_signature_c)

    def test_deserialize_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.deserialize_ecc_public_256_wire(bytes(335))


# ===================================================================
# 27. ECC_PRIVATE_256 wire format
# ===================================================================


class TestEccPrivate256Wire(unittest.TestCase):
    def setUp(self):
        self.sk = sc.p256_ecdsa_keypair_from_seed(SEED_A)
        self.kid = sc.KeyId(data=KEY_ID_A)

    def test_build(self):
        wire = sc.build_ecc_private_256_wire(self.kid, self.sk)
        self.assertEqual(wire.private_scalar, self.sk.data)
        self.assertEqual(wire.related_key_id.data, self.kid.data)

    def test_extract_private_key(self):
        wire = sc.build_ecc_private_256_wire(self.kid, self.sk)
        sk2 = sc.extract_p256_private_key(wire)
        self.assertIsNotNone(sk2)
        self.assertEqual(sk2.data, self.sk.data)
        self.assertEqual(sk2.public_key.data, self.sk.public_key.data)

    def test_extract_wrong_curve_params(self):
        wire = sc.build_ecc_private_256_wire(self.kid, self.sk)
        wire.field_size = bytes(32)
        self.assertIsNone(sc.extract_p256_private_key(wire))

    def test_serialize_size(self):
        wire = sc.build_ecc_private_256_wire(self.kid, self.sk)
        data = sc.serialize_ecc_private_256_wire(wire)
        self.assertEqual(len(data), sc.ecc_private_256_wire_size)

    def test_serialize_deserialize_roundtrip(self):
        wire = sc.build_ecc_private_256_wire(self.kid, self.sk)
        data = sc.serialize_ecc_private_256_wire(wire)
        wire2 = sc.deserialize_ecc_private_256_wire(data)
        self.assertEqual(wire2.private_scalar, wire.private_scalar)
        self.assertEqual(wire2.related_key_id.data, wire.related_key_id.data)

    def test_deserialize_wrong_size(self):
        with self.assertRaises(ValueError):
            sc.deserialize_ecc_private_256_wire(bytes(231))


# ===================================================================

if __name__ == "__main__":
    unittest.main()
