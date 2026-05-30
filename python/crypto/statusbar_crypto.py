# Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>


"""
Python statusbar_crypto library — mirrors the C++ statusbar_crypto API.

Provides the same type names, function names, and size constants as the C++
statusbar_crypto headers, delegating to the ``cryptography`` and ``pycryptodome``
packages for all cryptographic computation.

Dependencies: cryptography >= 43.0, pycryptodome >= 3.20
"""

from __future__ import annotations

import enum
import hashlib
import hmac as _hmac_module
from dataclasses import dataclass, field
from typing import Callable, Optional, Union

#
# Size constants (mirror C++ constexpr values)
#

aes128_key_size = 16
aes256_key_size = 32
aes128_block_size = 16
aes256_block_size = 16
aes128_siv_key_size = 32
aes256_siv_key_size = 64
aes_gcm_siv_nonce_size = 12
aes_gcm_siv_tag_size = 16
ed25519_public_key_size = 32
ed25519_private_key_size = 64
ed25519_seed_size = 32
ed25519_signature_size = 64
x25519_public_key_size = 32
x25519_private_key_size = 32
x25519_shared_secret_size = 32
sha256_block_size = 64
sha256_digest_size = 32
sha512_block_size = 128
sha512_digest_size = 64
hkdf_sha256_prk_size = 32
hkdf_sha256_max_info_size = 256
aes_block_size = 16
polyval_block_size = 16
p256_field_element_size = 32
p256_scalar_size = 32
p256_compressed_point_size = 33
p256_uncompressed_point_size = 64
key_id_size = 8

# P-256 curve parameters as integers (NIST FIPS 186-4)
_P256_PRIME = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A_INT = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_P256_B_INT = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


#
# Key types (mirror C++ structs from avtp_keychain.hpp)
#


def _check_size(name: str, data: bytes, expected: int) -> None:
    if len(data) != expected:
        raise ValueError(f"{name} data must be {expected} bytes, got {len(data)}")


@dataclass(frozen=True)
class Aes128Key:
    """AES-128 symmetric key (16 bytes)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("Aes128Key", self.data, aes128_key_size)


@dataclass(frozen=True)
class Aes256Key:
    """AES-256 symmetric key (32 bytes)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("Aes256Key", self.data, aes256_key_size)


@dataclass(frozen=True)
class Aes128SivKey:
    """AES-128-SIV combined key (32 bytes: K1 for CMAC, K2 for CTR)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("Aes128SivKey", self.data, aes128_siv_key_size)


@dataclass(frozen=True)
class Aes256SivKey:
    """AES-256-SIV combined key (64 bytes: K1 for CMAC, K2 for CTR)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("Aes256SivKey", self.data, aes256_siv_key_size)


@dataclass(frozen=True)
class Ed25519PublicKey:
    """Ed25519 public key (32-byte compressed Edwards point)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("Ed25519PublicKey", self.data, ed25519_public_key_size)


@dataclass(frozen=True)
class Ed25519PrivateKey:
    """Ed25519 private key (expanded form).

    ``data`` is the 64-byte SHA-512(seed) with clamping (matching C++ layout).
    ``public_key`` is the precomputed public key.
    ``_seed`` is the original 32-byte seed, needed to reconstruct the
    ``cryptography`` library's key object for signing.
    """

    data: bytes
    public_key: Ed25519PublicKey
    _seed: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _check_size("Ed25519PrivateKey", self.data, ed25519_private_key_size)
        _check_size("Ed25519PrivateKey._seed", self._seed, ed25519_seed_size)


@dataclass(frozen=True)
class X25519PublicKey:
    """X25519 public key (32-byte Montgomery u-coordinate)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("X25519PublicKey", self.data, x25519_public_key_size)


@dataclass(frozen=True)
class X25519PrivateKey:
    """X25519 private key (32-byte scalar) with precomputed public key."""

    data: bytes
    public_key: X25519PublicKey

    def __post_init__(self) -> None:
        _check_size("X25519PrivateKey", self.data, x25519_private_key_size)


@dataclass(frozen=True)
class Ed25519Signature:
    """Ed25519 signature: R (32 bytes) || S (32 bytes)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("Ed25519Signature", self.data, ed25519_signature_size)


# Note: Typed keychain type aliases (PublicKeyEntry, PrivateKeyEntry,
# SessionKeyEntry, PublicKeyChain, PrivateKeyChain, SessionKeyChain)
# are defined after all key/entry types are declared — see "Typed keychain
# variants and containers" section near the end of the key management block.


#
# SHA-256 (FIPS 180-4)
#


def sha256(message: bytes) -> bytes:
    """Compute SHA-256 digest. Returns 32 bytes."""
    return hashlib.sha256(message).digest()


def sha256_hex(message: bytes) -> str:
    """Compute SHA-256 digest, returned as a hex string."""
    return hashlib.sha256(message).hexdigest()


#
# SHA-512 (FIPS 180-4)
#


def sha512(message: bytes) -> bytes:
    """Compute SHA-512 digest. Returns 64 bytes."""
    return hashlib.sha512(message).digest()


def sha512_hex(message: bytes) -> str:
    """Compute SHA-512 digest, returned as a hex string."""
    return hashlib.sha512(message).hexdigest()


#
# HMAC-SHA-256 (RFC 2104)
#


def sha256_hmac(key: bytes, message: bytes, message2: bytes = b"") -> bytes:
    """Compute HMAC-SHA-256. Returns 32 bytes.

    Supports optional two-part messages: HMAC(key, message1 || message2).
    """
    h = _hmac_module.new(key, message, hashlib.sha256)
    if message2:
        h.update(message2)
    return h.digest()


#
# Incremental SHA-512 (FIPS 180-4)
#


class Sha512Context:
    """Incremental SHA-512 hashing context for multi-part message processing."""

    def __init__(self) -> None:
        self._ctx = hashlib.sha512()

    def update(self, data: bytes) -> None:
        self._ctx.update(data)

    def digest(self) -> bytes:
        return self._ctx.copy().digest()


def sha512_init() -> Sha512Context:
    """Initialize a SHA-512 context."""
    return Sha512Context()


def sha512_update(ctx: Sha512Context, data: bytes) -> None:
    """Feed data into an initialized SHA-512 context."""
    ctx.update(data)


def sha512_final(ctx: Sha512Context) -> bytes:
    """Finalize the SHA-512 hash and produce the 64-byte digest."""
    return ctx.digest()


#
# AES block cipher (FIPS 197)
#


def aes128_block_encrypt(key: Aes128Key, plaintext: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-128 (ECB). Returns 16 bytes."""
    from Crypto.Cipher import AES

    if len(plaintext) != 16:
        raise ValueError(f"plaintext must be 16 bytes, got {len(plaintext)}")
    cipher = AES.new(key.data, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def aes128_block_decrypt(key: Aes128Key, ciphertext: bytes) -> bytes:
    """Decrypt a single 16-byte block with AES-128 (ECB). Returns 16 bytes."""
    from Crypto.Cipher import AES

    if len(ciphertext) != 16:
        raise ValueError(f"ciphertext must be 16 bytes, got {len(ciphertext)}")
    cipher = AES.new(key.data, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def aes256_block_encrypt(key: Aes256Key, plaintext: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-256 (ECB). Returns 16 bytes."""
    from Crypto.Cipher import AES

    if len(plaintext) != 16:
        raise ValueError(f"plaintext must be 16 bytes, got {len(plaintext)}")
    cipher = AES.new(key.data, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def aes256_block_decrypt(key: Aes256Key, ciphertext: bytes) -> bytes:
    """Decrypt a single 16-byte block with AES-256 (ECB). Returns 16 bytes."""
    from Crypto.Cipher import AES

    if len(ciphertext) != 16:
        raise ValueError(f"ciphertext must be 16 bytes, got {len(ciphertext)}")
    cipher = AES.new(key.data, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


#
# AES-CBC with null IV (IEEE 1363a-2004 / ECIES)
#


def aes256_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC with null IV and PKCS#7 padding. Returns ciphertext."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
    return cipher.encrypt(pad(plaintext, 16))


def aes256_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CBC with null IV and PKCS#7 unpadding. Returns plaintext."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
    return unpad(cipher.decrypt(ciphertext), 16)


#
# AES-CMAC (RFC 4493 / NIST SP 800-38B)
#


def aes128_cmac(key: Aes128Key, message: bytes) -> bytes:
    """Compute AES-128-CMAC. Returns 16 bytes."""
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES

    c = CMAC.new(key.data, ciphermod=AES)
    c.update(message)
    return c.digest()


def aes256_cmac(key: Aes256Key, message: bytes) -> bytes:
    """Compute AES-256-CMAC. Returns 16 bytes."""
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES

    c = CMAC.new(key.data, ciphermod=AES)
    c.update(message)
    return c.digest()


def aes128_cmac_xorend(key: Aes128Key, message: bytes, xor_end: bytes) -> bytes:
    """AES-128-CMAC with xorend (RFC 5297 Section 2.4 helper). Returns 16 bytes.

    Computes CMAC over message with last 16 bytes XORed with xor_end.
    """
    if len(message) < 16:
        return bytes(16)
    if len(xor_end) != 16:
        raise ValueError(f"xor_end must be 16 bytes, got {len(xor_end)}")
    modified = bytearray(message)
    offset = len(message) - 16
    for i in range(16):
        modified[offset + i] ^= xor_end[i]
    return aes128_cmac(key, bytes(modified))


def aes256_cmac_xorend(key: Aes256Key, message: bytes, xor_end: bytes) -> bytes:
    """AES-256-CMAC with xorend (RFC 5297 Section 2.4 helper). Returns 16 bytes.

    Computes CMAC over message with last 16 bytes XORed with xor_end.
    """
    if len(message) < 16:
        return bytes(16)
    if len(xor_end) != 16:
        raise ValueError(f"xor_end must be 16 bytes, got {len(xor_end)}")
    modified = bytearray(message)
    offset = len(message) - 16
    for i in range(16):
        modified[offset + i] ^= xor_end[i]
    return aes256_cmac(key, bytes(modified))


def aes128_cmac_verify(key: Aes128Key, message: bytes, expected_tag: bytes) -> bool:
    """Verify an AES-128-CMAC tag. Returns True if valid."""
    if len(expected_tag) != 16:
        return False
    computed = aes128_cmac(key, message)
    return _hmac_module.compare_digest(computed, expected_tag)


def aes256_cmac_verify(key: Aes256Key, message: bytes, expected_tag: bytes) -> bool:
    """Verify an AES-256-CMAC tag. Returns True if valid."""
    if len(expected_tag) != 16:
        return False
    computed = aes256_cmac(key, message)
    return _hmac_module.compare_digest(computed, expected_tag)


#
# HKDF-SHA-256 (RFC 5869)
#


def hkdf_sha256_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-SHA-256 Extract (RFC 5869 Section 2.2). Returns 32-byte PRK."""
    if not salt:
        salt = bytes(sha256_digest_size)
    return sha256_hmac(salt, ikm)


def hkdf_sha256_expand(prk: bytes, info: bytes, okm_length: int) -> bytes:
    """HKDF-SHA-256 Expand (RFC 5869 Section 2.3). Returns okm_length bytes."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    from cryptography.hazmat.primitives import hashes

    h = HKDFExpand(algorithm=hashes.SHA256(), length=okm_length, info=info)
    return h.derive(prk)


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, okm_length: int) -> bytes:
    """HKDF-SHA-256 one-shot Extract-then-Expand (RFC 5869). Returns okm_length bytes."""
    prk = hkdf_sha256_extract(salt, ikm)
    return hkdf_sha256_expand(prk, info, okm_length)


#
# AES-128-SIV (RFC 5297)
#


def aes128_siv_encrypt(
    key: Aes128SivKey, plaintext: bytes, aad: bytes
) -> tuple[bytes, bytes]:
    """AES-128-SIV encrypt (RFC 5297).

    Returns (siv, ciphertext) where siv is 16 bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    cipher = AESSIV(key.data)
    ct = cipher.encrypt(plaintext, [aad])
    return (ct[:16], ct[16:])


def aes128_siv_decrypt(
    key: Aes128SivKey, ciphertext: bytes, siv: bytes, aad: bytes
) -> tuple[bool, bytes]:
    """AES-128-SIV decrypt (RFC 5297).

    Returns (ok, plaintext). On auth failure returns (False, zero-filled bytes).
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    try:
        cipher = AESSIV(key.data)
        plaintext = cipher.decrypt(siv + ciphertext, [aad])
        return (True, plaintext)
    except (InvalidTag, ValueError):
        return (False, bytes(len(ciphertext)))


#
# AES-256-SIV (RFC 5297)
#


def aes256_siv_encrypt(
    key: Aes256SivKey, plaintext: bytes, aad: bytes
) -> tuple[bytes, bytes]:
    """AES-256-SIV encrypt (RFC 5297).

    Returns (siv, ciphertext) where siv is 16 bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    cipher = AESSIV(key.data)
    ct = cipher.encrypt(plaintext, [aad])
    return (ct[:16], ct[16:])


def aes256_siv_decrypt(
    key: Aes256SivKey, ciphertext: bytes, siv: bytes, aad: bytes
) -> tuple[bool, bytes]:
    """AES-256-SIV decrypt (RFC 5297).

    Returns (ok, plaintext). On auth failure returns (False, zero-filled bytes).
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    try:
        cipher = AESSIV(key.data)
        plaintext = cipher.decrypt(siv + ciphertext, [aad])
        return (True, plaintext)
    except (InvalidTag, ValueError):
        return (False, bytes(len(ciphertext)))


#
# AES-128-GCM-SIV (RFC 8452)
#


def aes128_gcm_siv_encrypt(
    key: Aes128Key,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> tuple[bytes, bytes]:
    """AES-128-GCM-SIV encrypt (RFC 8452).

    Returns (tag, ciphertext) where tag is 16 bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

    cipher = AESGCMSIV(key.data)
    ct = cipher.encrypt(nonce, plaintext, aad)
    return (ct[-16:], ct[:-16])


def aes128_gcm_siv_decrypt(
    key: Aes128Key,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes,
) -> tuple[bool, bytes]:
    """AES-128-GCM-SIV decrypt (RFC 8452).

    Returns (ok, plaintext). On auth failure returns (False, zero-filled bytes).
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

    try:
        cipher = AESGCMSIV(key.data)
        plaintext = cipher.decrypt(nonce, ciphertext + tag, aad)
        return (True, plaintext)
    except (InvalidTag, ValueError):
        return (False, bytes(len(ciphertext)))


#
# AES-256-GCM-SIV (RFC 8452)
#


def aes256_gcm_siv_encrypt(
    key: Aes256Key,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> tuple[bytes, bytes]:
    """AES-256-GCM-SIV encrypt (RFC 8452).

    Returns (tag, ciphertext) where tag is 16 bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

    cipher = AESGCMSIV(key.data)
    ct = cipher.encrypt(nonce, plaintext, aad)
    return (ct[-16:], ct[:-16])


def aes256_gcm_siv_decrypt(
    key: Aes256Key,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes,
) -> tuple[bool, bytes]:
    """AES-256-GCM-SIV decrypt (RFC 8452).

    Returns (ok, plaintext). On auth failure returns (False, zero-filled bytes).
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

    try:
        cipher = AESGCMSIV(key.data)
        plaintext = cipher.decrypt(nonce, ciphertext + tag, aad)
        return (True, plaintext)
    except (InvalidTag, ValueError):
        return (False, bytes(len(ciphertext)))


#
# Ed25519 (RFC 8032)
#


def ed25519_keypair_from_seed(seed: bytes) -> Ed25519PrivateKey:
    """Generate Ed25519 keypair from 32-byte seed (RFC 8032 Section 5.1.5).

    Returns an Ed25519PrivateKey containing the expanded key, precomputed
    public key, and the original seed (needed internally for signing).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Ed25519SK,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if len(seed) != ed25519_seed_size:
        raise ValueError(f"seed must be {ed25519_seed_size} bytes, got {len(seed)}")

    # Compute expanded key matching C++ layout: SHA-512(seed) with clamping
    expanded = bytearray(hashlib.sha512(seed).digest())
    expanded[0] &= 248
    expanded[31] &= 127
    expanded[31] |= 64
    data = bytes(expanded)

    # Get public key from the cryptography library
    sk_obj = _Ed25519SK.from_private_bytes(seed)
    pk_bytes = sk_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    pk = Ed25519PublicKey(data=pk_bytes)
    return Ed25519PrivateKey(data=data, public_key=pk, _seed=seed)


def ed25519_public_key(sk: Ed25519PrivateKey) -> Ed25519PublicKey:
    """Extract the embedded public key from a private key (no computation)."""
    return sk.public_key


def ed25519_sign(sk: Ed25519PrivateKey, message: bytes) -> Ed25519Signature:
    """PureEdDSA signature (RFC 8032 Section 5.1.6). Returns 64-byte signature."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Ed25519SK,
    )

    sk_obj = _Ed25519SK.from_private_bytes(sk._seed)
    sig = sk_obj.sign(message)
    return Ed25519Signature(data=sig)


def ed25519_verify(
    pk: Ed25519PublicKey,
    message: bytes,
    signature: Ed25519Signature,
) -> bool:
    """PureEdDSA verification (RFC 8032 Section 5.1.7). Returns True if valid."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey as _Ed25519PK,
    )

    try:
        pk_obj = _Ed25519PK.from_public_bytes(pk.data)
        pk_obj.verify(signature.data, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def ed25519_pk_to_x25519_pk(ed_pk: Ed25519PublicKey) -> X25519PublicKey:
    """Convert Ed25519 public key to X25519 public key.

    Computes u = (1+y)/(1-y) mod p to map from twisted Edwards to Montgomery form.
    """
    p = (1 << 255) - 19
    # Decode y from Ed25519 public key (lower 255 bits, little-endian)
    y_bytes = bytearray(ed_pk.data)
    y_bytes[31] &= 0x7F  # clear sign bit
    y = int.from_bytes(y_bytes, "little")
    # u = (1 + y) * inverse(1 - y) mod p
    u = ((1 + y) * pow(1 - y, p - 2, p)) % p
    return X25519PublicKey(data=u.to_bytes(32, "little"))


def ed25519_sk_to_x25519_sk(ed_sk: Ed25519PrivateKey) -> X25519PrivateKey:
    """Convert Ed25519 private key to X25519 private key.

    The clamped scalar from SHA-512(seed) serves as the X25519 scalar.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey as _X25519SK,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # X25519 scalar = first 32 bytes of expanded Ed25519 key (already clamped)
    x_sk_bytes = ed_sk.data[:32]
    x_sk_obj = _X25519SK.from_private_bytes(x_sk_bytes)
    x_pk_bytes = x_sk_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return X25519PrivateKey(
        data=x_sk_bytes, public_key=X25519PublicKey(data=x_pk_bytes)
    )


#
# X25519 (RFC 7748)
#


def x25519_keypair_from_seed(seed: bytes) -> X25519PrivateKey:
    """Generate X25519 keypair from 32-byte seed (RFC 7748).

    Scalar clamping is applied internally by the cryptography library.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey as _X25519SK,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if len(seed) != x25519_private_key_size:
        raise ValueError(
            f"seed must be {x25519_private_key_size} bytes, got {len(seed)}"
        )

    sk_obj = _X25519SK.from_private_bytes(seed)
    pk_bytes = sk_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return X25519PrivateKey(data=seed, public_key=X25519PublicKey(data=pk_bytes))


def x25519(sk: X25519PrivateKey, pk: X25519PublicKey) -> bytes:
    """X25519 ECDH shared secret (RFC 7748). Returns 32 bytes.

    The result must be validated with x25519_shared_secret_is_valid().
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey as _X25519SK,
        X25519PublicKey as _X25519PK,
    )

    sk_obj = _X25519SK.from_private_bytes(sk.data)
    pk_obj = _X25519PK.from_public_bytes(pk.data)
    return sk_obj.exchange(pk_obj)


def x25519_shared_secret_is_valid(shared_secret: bytes) -> bool:
    """Check that shared secret is not all-zero (low-order point rejection)."""
    return any(b != 0 for b in shared_secret)


#
# P-256 types and sizes (mirrors C++ avtp_keychain.hpp)
#

p256_public_key_size = 64
p256_private_key_size = 32
p256_ecdsa_signature_size = 64


@dataclass(frozen=True)
class P256PublicKey:
    """NIST P-256 public key (64-byte uncompressed: x || y, big-endian)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("P256PublicKey", self.data, p256_public_key_size)


@dataclass(frozen=True)
class P256PrivateKey:
    """NIST P-256 private key (32-byte scalar d, big-endian) with precomputed public key."""

    data: bytes
    public_key: P256PublicKey

    def __post_init__(self) -> None:
        _check_size("P256PrivateKey", self.data, p256_private_key_size)


@dataclass(frozen=True)
class P256EcdsaSignature:
    """P-256 ECDSA signature (64-byte: r || s, big-endian)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("P256EcdsaSignature", self.data, p256_ecdsa_signature_size)


#
# P-256 key utilities
#


def p256_public_key(sk: P256PrivateKey) -> P256PublicKey:
    """Extract the embedded public key from a P-256 private key (no computation)."""
    return sk.public_key


def p256_keypair_from_scalar(scalar_bytes: bytes) -> Optional[P256PrivateKey]:
    """Construct a P256PrivateKey from a raw 32-byte scalar (big-endian).

    Unlike p256_ecdsa_keypair_from_seed, this takes the scalar d directly
    (no hashing). Computes the public key Q = d * G.
    Returns None if scalar is zero or >= n.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        derive_private_key,
    )

    if len(scalar_bytes) != 32:
        return None
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(scalar_bytes, "big")
    if d == 0 or d >= n:
        return None

    sk_obj = derive_private_key(d, SECP256R1())
    pub_numbers = sk_obj.public_key().public_numbers()
    x_bytes = pub_numbers.x.to_bytes(32, "big")
    y_bytes = pub_numbers.y.to_bytes(32, "big")

    return P256PrivateKey(
        data=scalar_bytes, public_key=P256PublicKey(data=x_bytes + y_bytes)
    )


#
# P-256 ECDSA (IEEE 1722-2016 clause 16)
#


def p256_ecdsa_keypair_from_seed(seed: bytes) -> P256PrivateKey:
    """Generate P-256 keypair from 32-byte seed.

    The seed is hashed with SHA-256 and reduced mod n to produce scalar d.
    Q = d * G is the public key.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        EllipticCurvePublicNumbers,
        generate_private_key,
    )
    from cryptography.hazmat.primitives import hashes

    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")

    # Hash seed with SHA-256, interpret as big-endian integer, reduce mod n
    h = hashlib.sha256(seed).digest()
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(h, "big") % n
    if d == 0:
        d = 1

    # Derive public key Q = d * G using cryptography library
    curve = SECP256R1()
    d_bytes = d.to_bytes(32, "big")

    from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key

    sk_obj = derive_private_key(d, curve)
    pub_obj = sk_obj.public_key()
    pub_numbers = pub_obj.public_numbers()

    x_bytes = pub_numbers.x.to_bytes(32, "big")
    y_bytes = pub_numbers.y.to_bytes(32, "big")

    pk = P256PublicKey(data=x_bytes + y_bytes)
    return P256PrivateKey(data=d_bytes, public_key=pk)


def p256_ecdsa_sign(sk: P256PrivateKey, message: bytes) -> P256EcdsaSignature:
    """ECDSA sign with SHA-256 and deterministic nonce (RFC 6979).

    Returns 64-byte signature (r || s), each 32 bytes big-endian.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        derive_private_key,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    d = int.from_bytes(sk.data, "big")
    sk_obj = derive_private_key(d, SECP256R1())

    # Sign with deterministic nonce (RFC 6979)
    der_sig = sk_obj.sign(message, ECDSA(hashes.SHA256(), deterministic_signing=True))

    # Convert DER-encoded (r, s) to fixed 64-byte format
    r, s = decode_dss_signature(der_sig)
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")

    return P256EcdsaSignature(data=r_bytes + s_bytes)


def p256_ecdsa_verify(
    pk: P256PublicKey, message: bytes, signature: P256EcdsaSignature
) -> bool:
    """ECDSA verify with SHA-256. Returns True if valid."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        EllipticCurvePublicNumbers,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    x = int.from_bytes(pk.data[:32], "big")
    y = int.from_bytes(pk.data[32:], "big")
    pub_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    pk_obj = pub_numbers.public_key()

    r = int.from_bytes(signature.data[:32], "big")
    s = int.from_bytes(signature.data[32:], "big")
    der_sig = encode_dss_signature(r, s)

    try:
        pk_obj.verify(der_sig, message, ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


#
# P-256 ECDH (IEEE 1722-2016 clause 17)
#


def p256_ecdh(sk: P256PrivateKey, peer_pk: P256PublicKey) -> bytes:
    """P-256 ECDH shared secret. Returns 32-byte x-coordinate of d * Q."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDH,
        SECP256R1,
        EllipticCurvePublicNumbers,
        derive_private_key,
    )

    d = int.from_bytes(sk.data, "big")
    sk_obj = derive_private_key(d, SECP256R1())

    x = int.from_bytes(peer_pk.data[:32], "big")
    y = int.from_bytes(peer_pk.data[32:], "big")
    peer_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    peer_obj = peer_numbers.public_key()

    shared = sk_obj.exchange(ECDH(), peer_obj)
    return shared


#
# DL/ECIES (IEEE 1363a-2004 / IEEE 1722-2016 clause 17)
#

ecies_ephemeral_key_size = 33
ecies_mac_tag_size = 32
ecies_fixed_overhead = ecies_ephemeral_key_size + ecies_mac_tag_size


def ecies_output_size(plaintext_len: int) -> int:
    """Compute total ECIES output size for a given plaintext size."""
    return ecies_fixed_overhead + ((plaintext_len // 16) + 1) * 16


def _kdf2_sha256(z: bytes, params: bytes, output_len: int) -> bytes:
    """KDF2 with SHA-256 (IEEE 1363a-2004 Section 13.2)."""
    result = b""
    counter = 1
    while len(result) < output_len:
        counter_bytes = counter.to_bytes(4, "big")
        result += hashlib.sha256(z + counter_bytes + params).digest()
        counter += 1
    return result[:output_len]


def _aes256_cbc_iv0_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC with null IV and PKCS#7 padding."""
    return aes256_cbc_encrypt(key, plaintext)


def _aes256_cbc_iv0_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CBC with null IV and PKCS#7 unpadding."""
    return aes256_cbc_decrypt(key, ciphertext)


def ecies_encrypt(
    recipient_pk: P256PublicKey, plaintext: bytes, entropy: bytes
) -> bytes:
    """DL/ECIES encrypt (IEEE 1363a-2004).

    Returns V || C || T where V is the ephemeral key (33 bytes EC2OSP-X),
    C is the ciphertext (AES-256-CBC-IV0), T is the MAC (HMAC-SHA-256).
    """
    import hmac as _hmac

    # Generate ephemeral keypair from entropy
    eph_sk = p256_ecdsa_keypair_from_seed(entropy)

    # EC2OSP-X encoding: 0x01 || x (33 bytes)
    V = b"\x01" + eph_sk.public_key.data[:32]

    # ECDH shared secret
    Z = p256_ecdh(eph_sk, recipient_pk)

    # DHAES mode: VZ = V || Z
    VZ = V + Z

    # KDF2: derive K2 (32, MAC key) + K1 (32, encryption key) = 64 bytes
    # Per IEEE 1363a-2004: MAC key is first, encryption key is second
    kdf_out = _kdf2_sha256(VZ, b"", 64)
    mac_key = kdf_out[:32]  # K2
    enc_key = kdf_out[32:]  # K1

    # AES-256-CBC-IV0 encrypt
    C = _aes256_cbc_iv0_encrypt(enc_key, plaintext)

    # HMAC-SHA-256 over C || I2OSP(0, 8) per IEEE 1363a-2004 (L2 = 8 zero bytes)
    T = _hmac.new(mac_key, C + b"\x00" * 8, hashlib.sha256).digest()

    return V + C + T


# Type alias for a pluggable ECDH function: takes peer public key bytes, returns shared secret.
EcdhFn = Callable[[bytes], bytes]


def ecies_decrypt_with_ecdh(ecdh_fn: EcdhFn, data: bytes) -> bytes:
    """DL/ECIES decrypt (IEEE 1363a-2004) using a pluggable P-256 ECDH function.

    ecdh_fn(peer_pk_64_bytes) -> shared_secret_32_bytes
    where peer_pk_64_bytes is the uncompressed x || y (without 04 prefix).

    Expects V || C || T. Returns plaintext or raises on failure.
    """
    import hmac as _hmac

    if len(data) < ecies_fixed_overhead + 16:
        raise ValueError("ECIES ciphertext too short")

    V = data[:33]
    T = data[-32:]
    C = data[33:-32]

    # Decode ephemeral public key from EC2OSP-X
    if V[0] != 0x01:
        raise ValueError("Invalid EC2OSP-X prefix")
    eph_x = V[1:]

    # Recover y from x (pick even y - doesn't matter for ECDH x-only)
    x_int = int.from_bytes(eph_x, "big")
    rhs = (pow(x_int, 3, _P256_PRIME) + _P256_A_INT * x_int + _P256_B_INT) % _P256_PRIME
    y_int = pow(rhs, (_P256_PRIME + 1) // 4, _P256_PRIME)
    if y_int % 2 != 0:
        y_int = _P256_PRIME - y_int

    eph_pk_data = eph_x + y_int.to_bytes(32, "big")

    # ECDH shared secret via pluggable function
    Z = ecdh_fn(eph_pk_data)

    # DHAES mode: VZ = V || Z
    VZ = V + Z

    # KDF2: K2 (MAC key) = K[0:32], K1 (encryption key) = K[32:64]
    kdf_out = _kdf2_sha256(VZ, b"", 64)
    mac_key = kdf_out[:32]  # K2
    enc_key = kdf_out[32:]  # K1

    # Verify MAC: HMAC(K2, C || I2OSP(0, 8))
    expected_T = _hmac.new(mac_key, C + b"\x00" * 8, hashlib.sha256).digest()
    if not _hmac.compare_digest(T, expected_T):
        raise ValueError("ECIES MAC verification failed")

    # Decrypt
    return _aes256_cbc_iv0_decrypt(enc_key, C)


def ecies_decrypt(sk: P256PrivateKey, data: bytes) -> bytes:
    """DL/ECIES decrypt (IEEE 1363a-2004). Software ECDH.

    Expects V || C || T. Returns plaintext or raises on failure.
    """

    def sw_ecdh(peer_pk_bytes: bytes) -> bytes:
        return p256_ecdh(sk, P256PublicKey(data=peer_pk_bytes))

    return ecies_decrypt_with_ecdh(sw_ecdh, data)


#
# X25519 ECIES (IEEE 1722-2016 Clause 17, enc=1)
#

x25519_ecies_ephemeral_key_size = 32
x25519_ecies_mac_tag_size = 32
x25519_ecies_fixed_overhead = (
    x25519_ecies_ephemeral_key_size + x25519_ecies_mac_tag_size
)


def x25519_ecies_output_size(plaintext_len: int) -> int:
    """Compute total X25519 ECIES output size for a given plaintext size."""
    return x25519_ecies_fixed_overhead + ((plaintext_len // 16) + 1) * 16


def x25519_ecies_encrypt(
    recipient_pk: X25519PublicKey, plaintext: bytes, entropy: bytes
) -> bytes:
    """X25519 ECIES encrypt (IEEE 1722-2016 Clause 17, enc=1).

    Returns V || C || T where V is the ephemeral X25519 public key (32 bytes),
    C is the ciphertext (AES-256-CBC-IV0), T is the MAC (HMAC-SHA-256).
    """
    import hmac as _hmac

    # Generate ephemeral keypair from entropy
    eph_sk = x25519_keypair_from_seed(entropy)

    # V = ephemeral public key (32 bytes, native Montgomery u-coordinate)
    V = eph_sk.public_key.data

    # X25519 shared secret
    Z = x25519(eph_sk, recipient_pk)
    if not x25519_shared_secret_is_valid(Z):
        raise ValueError("X25519 shared secret is all-zero (low-order point)")

    # HKDF-SHA-256: K = HKDF(salt="", ikm=Z, info="X25519-ECIES"||V, 64)
    info = b"X25519-ECIES" + V
    kdf_out = hkdf_sha256(b"", Z, info, 64)
    mac_key = kdf_out[:32]  # K2
    enc_key = kdf_out[32:]  # K1

    # AES-256-CBC-IV0 encrypt
    C = _aes256_cbc_iv0_encrypt(enc_key, plaintext)

    # HMAC-SHA-256 over C || I2OSP(0, 8)
    T = _hmac.new(mac_key, C + b"\x00" * 8, hashlib.sha256).digest()

    return V + C + T


def x25519_ecies_decrypt_with_ecdh(ecdh_fn: EcdhFn, data: bytes) -> bytes:
    """X25519 ECIES decrypt using a pluggable ECDH function.

    ecdh_fn(peer_pk_32_bytes) -> shared_secret_32_bytes

    Expects V || C || T. Returns plaintext or raises on failure.
    """
    import hmac as _hmac

    if len(data) < x25519_ecies_fixed_overhead + 16:
        raise ValueError("X25519 ECIES ciphertext too short")

    V = data[:32]
    T = data[-32:]
    C = data[32:-32]

    if len(C) % 16 != 0:
        raise ValueError("X25519 ECIES ciphertext not block-aligned")

    # X25519 shared secret via pluggable function
    Z = ecdh_fn(V)
    if not x25519_shared_secret_is_valid(Z):
        raise ValueError("X25519 shared secret is all-zero (low-order point)")

    # HKDF-SHA-256: K = HKDF(salt="", ikm=Z, info="X25519-ECIES"||V, 64)
    info = b"X25519-ECIES" + V
    kdf_out = hkdf_sha256(b"", Z, info, 64)
    mac_key = kdf_out[:32]  # K2
    enc_key = kdf_out[32:]  # K1

    # Verify MAC: HMAC(K2, C || I2OSP(0, 8))
    expected_T = _hmac.new(mac_key, C + b"\x00" * 8, hashlib.sha256).digest()
    if not _hmac.compare_digest(T, expected_T):
        raise ValueError("X25519 ECIES MAC verification failed")

    # Decrypt
    return _aes256_cbc_iv0_decrypt(enc_key, C)


def x25519_ecies_decrypt(sk: X25519PrivateKey, data: bytes) -> bytes:
    """X25519 ECIES decrypt (IEEE 1722-2016 Clause 17, enc=1). Software ECDH.

    Expects V || C || T. Returns plaintext or raises on failure.
    """

    def sw_ecdh(peer_pk_bytes: bytes) -> bytes:
        return x25519(sk, X25519PublicKey(data=peer_pk_bytes))

    return x25519_ecies_decrypt_with_ecdh(sw_ecdh, data)


#
# KDF2 (IEEE 1363a-2004 Section 13.2) — public API
#


def kdf2_sha256(shared_secret: bytes, params: bytes, output_len: int) -> bytes:
    """KDF2 key derivation with SHA-256 (IEEE 1363a-2004 Section 13.2).

    Derives key material: Hash_i = SHA-256(Z || I2OSP(counter, 4) || P).
    Returns output_len bytes.
    """
    return _kdf2_sha256(shared_secret, params, output_len)


#
# POLYVAL (RFC 8452 Section 3)
#


def _gf128_mul_polyval(x: int, y: int) -> int:
    """Multiply in GF(2^128) with POLYVAL reduction polynomial.

    POLYVAL uses x^128 + x^127 + x^126 + x^121 + 1 (reflected from GHASH).
    """
    # POLYVAL reduction: x^128 = x^127 + x^126 + x^121 + 1
    result = 0
    for i in range(128):
        if (y >> i) & 1:
            result ^= x
        # Reduce: if bit 127 is set, XOR with polynomial
        if (x >> 127) & 1:
            x = ((x << 1) ^ ((1 << 127) | (1 << 126) | (1 << 121) | 1)) & (
                (1 << 128) - 1
            )
        else:
            x = (x << 1) & ((1 << 128) - 1)
    return result


def _bytes_to_le128(b: bytes) -> int:
    """Convert 16 bytes to a 128-bit integer (little-endian)."""
    return int.from_bytes(b, "little")


def _le128_to_bytes(v: int) -> bytes:
    """Convert a 128-bit integer to 16 bytes (little-endian)."""
    return v.to_bytes(16, "little")


@dataclass(frozen=True)
class PolyvalKey:
    """POLYVAL hash key (128-bit)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("PolyvalKey", self.data, polyval_block_size)


def polyval(H: PolyvalKey, input_data: bytes) -> bytes:
    """Compute POLYVAL hash over input (RFC 8452 Section 3). Returns 16 bytes.

    Input must be a multiple of 16 bytes.
    """
    if len(input_data) % 16 != 0:
        raise ValueError(f"input must be a multiple of 16 bytes, got {len(input_data)}")
    h_val = _bytes_to_le128(H.data)
    acc = 0
    for i in range(0, len(input_data), 16):
        block = _bytes_to_le128(input_data[i : i + 16])
        acc = _gf128_mul_polyval(acc ^ block, h_val)
    return _le128_to_bytes(acc)


def polyval_update(H: PolyvalKey, input_data: bytes, accumulator: bytearray) -> None:
    """Incrementally update a POLYVAL accumulator with additional input blocks.

    Input must be a multiple of 16 bytes.
    Accumulator must be a 16-byte bytearray, modified in place.
    """
    if len(input_data) % 16 != 0:
        raise ValueError(f"input must be a multiple of 16 bytes, got {len(input_data)}")
    if len(accumulator) != 16:
        raise ValueError(f"accumulator must be 16 bytes, got {len(accumulator)}")
    h_val = _bytes_to_le128(H.data)
    acc = _bytes_to_le128(bytes(accumulator))
    for i in range(0, len(input_data), 16):
        block = _bytes_to_le128(input_data[i : i + 16])
        acc = _gf128_mul_polyval(acc ^ block, h_val)
    result = _le128_to_bytes(acc)
    accumulator[:] = result


#
# PKCS#8 and SPKI DER encoding (RFC 8410, RFC 5480, RFC 5958)
#

# Ed25519 DER constants (from pkcs8_ed25519_constants.hpp)
_SPKI_ED25519_PREFIX = bytes(
    [
        0x30,
        0x2A,  # SEQUENCE (42 bytes)
        0x30,
        0x05,  # SEQUENCE (5 bytes) AlgorithmIdentifier
        0x06,
        0x03,
        0x2B,
        0x65,
        0x70,  # OID 1.3.101.112 (Ed25519)
        0x03,
        0x21,  # BIT STRING (33 bytes)
        0x00,  # 0 unused bits
    ]
)

_PKCS8_ED25519_PREFIX = bytes(
    [
        0x30,
        0x2E,  # SEQUENCE (46 bytes)
        0x02,
        0x01,
        0x00,  # INTEGER version = 0
        0x30,
        0x05,  # SEQUENCE (5 bytes) AlgorithmIdentifier
        0x06,
        0x03,
        0x2B,
        0x65,
        0x70,  # OID 1.3.101.112 (Ed25519)
        0x04,
        0x22,  # OCTET STRING (34 bytes)
        0x04,
        0x20,  # OCTET STRING (32 bytes) CurvePrivateKey
    ]
)

# P-256 DER constants (from pkcs8_p256_constants.hpp)
_SPKI_P256_PREFIX = bytes(
    [
        0x30,
        0x59,  # SEQUENCE (89 bytes)
        0x30,
        0x13,  # SEQUENCE (19 bytes) AlgorithmIdentifier
        0x06,
        0x07,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x02,
        0x01,  # OID ecPublicKey
        0x06,
        0x08,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x03,
        0x01,
        0x07,  # OID prime256v1
        0x03,
        0x42,  # BIT STRING (66 bytes)
        0x00,  # 0 unused bits
        0x04,  # uncompressed point marker
    ]
)

_PKCS8_P256_PREFIX = bytes(
    [
        0x30,
        0x41,  # SEQUENCE (65 bytes)
        0x02,
        0x01,
        0x00,  # INTEGER version = 0
        0x30,
        0x13,  # SEQUENCE (19 bytes) AlgorithmIdentifier
        0x06,
        0x07,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x02,
        0x01,  # OID ecPublicKey
        0x06,
        0x08,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x03,
        0x01,
        0x07,  # OID prime256v1
        0x04,
        0x27,  # OCTET STRING (39 bytes)
        0x30,
        0x25,  # SEQUENCE (37 bytes) ECPrivateKey
        0x02,
        0x01,
        0x01,  # INTEGER version = 1
        0x04,
        0x20,  # OCTET STRING (32 bytes)
    ]
)

spki_ed25519_der_size = 44
pkcs8_ed25519_der_size = 48
spki_p256_der_size = 91
pkcs8_p256_der_size = 67


def spki_export_ed25519(pk: Ed25519PublicKey) -> bytes:
    """Export an Ed25519 public key as SubjectPublicKeyInfo DER. Returns 44 bytes."""
    return _SPKI_ED25519_PREFIX + pk.data


def spki_import_ed25519(der: bytes) -> Optional[Ed25519PublicKey]:
    """Import an Ed25519 public key from SubjectPublicKeyInfo DER.

    Returns the public key, or None on parse failure.
    """
    prefix_len = len(_SPKI_ED25519_PREFIX)
    if len(der) < prefix_len + 32:
        return None
    if der[:prefix_len] != _SPKI_ED25519_PREFIX:
        return None
    key_data = der[prefix_len : prefix_len + 32]
    return Ed25519PublicKey(data=key_data)


def pkcs8_export_ed25519(seed: bytes) -> bytes:
    """Export an Ed25519 seed as PKCS#8 PrivateKeyInfo DER. Returns 48 bytes.

    Takes the 32-byte seed (not the expanded key).
    """
    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
    return _PKCS8_ED25519_PREFIX + seed


def pkcs8_import_ed25519(der: bytes) -> Optional[Ed25519PrivateKey]:
    """Import an Ed25519 private key from PKCS#8 PrivateKeyInfo DER.

    Accepts both minimal (48-byte) and formats with [1] publicKey attribute.
    Returns the private key, or None on parse failure.
    """
    prefix_len = len(_PKCS8_ED25519_PREFIX)
    if len(der) < prefix_len + 32:
        return None
    if der[:prefix_len] != _PKCS8_ED25519_PREFIX:
        return None
    seed = der[prefix_len : prefix_len + 32]
    return ed25519_keypair_from_seed(seed)


def spki_export_p256(pk: P256PublicKey) -> bytes:
    """Export a P-256 public key as SubjectPublicKeyInfo DER. Returns 91 bytes."""
    return _SPKI_P256_PREFIX + pk.data


def spki_import_p256(der: bytes) -> Optional[P256PublicKey]:
    """Import a P-256 public key from SubjectPublicKeyInfo DER.

    Validates that the point is on the P-256 curve.
    Returns the public key, or None on parse failure or invalid point.
    """
    prefix_len = len(_SPKI_P256_PREFIX)
    if len(der) < prefix_len + 64:
        return None
    if der[:prefix_len] != _SPKI_P256_PREFIX:
        return None
    key_data = der[prefix_len : prefix_len + 64]
    # Validate point is on curve
    x = int.from_bytes(key_data[:32], "big")
    y = int.from_bytes(key_data[32:], "big")
    if (y * y - x * x * x - _P256_A_INT * x - _P256_B_INT) % _P256_PRIME != 0:
        return None
    return P256PublicKey(data=key_data)


def pkcs8_export_p256(sk: P256PrivateKey) -> bytes:
    """Export a P-256 private key as PKCS#8 PrivateKeyInfo DER. Returns 67 bytes."""
    return _PKCS8_P256_PREFIX + sk.data


def pkcs8_import_p256(der: bytes) -> Optional[P256PrivateKey]:
    """Import a P-256 private key from PKCS#8 PrivateKeyInfo DER.

    Accepts both minimal (67-byte) and OpenSSL-style (with public key) formats.
    Returns the private key, or None on parse failure or invalid scalar.
    """
    prefix_len = len(_PKCS8_P256_PREFIX)
    if len(der) < prefix_len + 32:
        return None
    if der[:prefix_len] != _PKCS8_P256_PREFIX:
        return None
    scalar_bytes = der[prefix_len : prefix_len + 32]
    return p256_keypair_from_scalar(scalar_bytes)


#
# IEEE 1722.1 key management types (avtp_keychain.hpp)
#


@dataclass(frozen=True)
class KeyId:
    """EUI-64 key identifier per IEEE 1722.1."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("KeyId", self.data, key_id_size)

    def is_static(self) -> bool:
        """True if this is a statically assigned key."""
        return (self.data[0] & 0x01) == 0

    def is_dynamic(self) -> bool:
        """True if this is a dynamically assigned ephemeral key."""
        return (self.data[0] & 0x01) != 0


class KeyType(enum.IntEnum):
    """Key type classification (4-bit field, values 0-15)."""

    aes128 = 0
    aes256 = 1
    ecc_public_256 = 2
    ecc_private_256 = 3
    aes128_siv = 4
    aes256_siv = 5
    ed25519_public = 6
    ed25519_private = 7
    x25519_public = 8
    x25519_private = 9


def key_type_data_size(key_type: KeyType) -> int:
    """Return the key data size in bytes for a given key type."""
    sizes = {
        KeyType.aes128: 16,
        KeyType.aes256: 32,
        KeyType.ecc_public_256: 64,
        KeyType.ecc_private_256: 32,
        KeyType.aes128_siv: 32,
        KeyType.aes256_siv: 64,
        KeyType.ed25519_public: 32,
        KeyType.ed25519_private: 32,
        KeyType.x25519_public: 32,
        KeyType.x25519_private: 32,
    }
    return sizes.get(key_type, 0)


def is_valid_key_type(key_type: KeyType) -> bool:
    """Return True if the key type value is a defined type (0-9)."""
    return 0 <= int(key_type) <= 9


class KeyChainId(enum.IntEnum):
    """Keychain identifier values per IEEE 1722.1-2021 Table 7-184."""

    entity_public = 0x0000
    entity_private = 0x0001
    manufacturer_public = 0x0002
    controllers = 0x0003
    transport = 0x0004


#
# Ed25519 signed public key entry (avtp_keychain.hpp)
#

ed25519_signed_public_key_entry_wire_size = 120
ed25519_signed_public_key_entry_signed_data_size = 48


@dataclass
class Ed25519SignedPublicKeyEntry:
    """A public key entry signed by an authority's Ed25519 key."""

    key_id: KeyId
    related_key_id: KeyId
    public_key: Ed25519PublicKey
    signature_key_id: KeyId
    signature: Ed25519Signature


def build_ed25519_signed_public_key_entry(
    key_id: KeyId,
    related_key_id: KeyId,
    public_key: Ed25519PublicKey,
    signature_key_id: KeyId,
    signing_key: Ed25519PrivateKey,
) -> Ed25519SignedPublicKeyEntry:
    """Build an Ed25519 signed public key entry.

    Signature covers: key_id (8) || related_key_id (8) || public_key (32) = 48 bytes.
    """
    signed_data = key_id.data + related_key_id.data + public_key.data
    signature = ed25519_sign(signing_key, signed_data)
    return Ed25519SignedPublicKeyEntry(
        key_id=key_id,
        related_key_id=related_key_id,
        public_key=public_key,
        signature_key_id=signature_key_id,
        signature=signature,
    )


def verify_ed25519_signed_public_key_entry(
    entry: Ed25519SignedPublicKeyEntry,
    signer_public_key: Ed25519PublicKey,
) -> bool:
    """Verify the signature on an Ed25519 signed public key entry."""
    signed_data = entry.key_id.data + entry.related_key_id.data + entry.public_key.data
    return ed25519_verify(signer_public_key, signed_data, entry.signature)


def serialize_ed25519_signed_public_key_entry(
    entry: Ed25519SignedPublicKeyEntry,
) -> bytes:
    """Serialize an Ed25519SignedPublicKeyEntry to a 120-byte wire buffer."""
    return (
        entry.key_id.data
        + entry.related_key_id.data
        + entry.public_key.data
        + entry.signature_key_id.data
        + entry.signature.data
    )


def deserialize_ed25519_signed_public_key_entry(
    data: bytes,
) -> Ed25519SignedPublicKeyEntry:
    """Deserialize an Ed25519SignedPublicKeyEntry from a 120-byte wire buffer."""
    if len(data) != ed25519_signed_public_key_entry_wire_size:
        raise ValueError(
            f"expected {ed25519_signed_public_key_entry_wire_size} bytes, got {len(data)}"
        )
    return Ed25519SignedPublicKeyEntry(
        key_id=KeyId(data=data[0:8]),
        related_key_id=KeyId(data=data[8:16]),
        public_key=Ed25519PublicKey(data=data[16:48]),
        signature_key_id=KeyId(data=data[48:56]),
        signature=Ed25519Signature(data=data[56:120]),
    )


#
# X25519 signed public key entry (avtp_keychain.hpp)
#

x25519_signed_public_key_entry_wire_size = 120
x25519_signed_public_key_entry_signed_data_size = 48


@dataclass
class X25519SignedPublicKeyEntry:
    """An X25519 public key entry signed by an authority's Ed25519 key.

    X25519 is a DH-only key type, so the signature uses Ed25519 (same curve family).
    """

    key_id: KeyId
    related_key_id: KeyId
    public_key: X25519PublicKey
    signature_key_id: KeyId
    signature: Ed25519Signature


def build_x25519_signed_public_key_entry(
    key_id: KeyId,
    related_key_id: KeyId,
    public_key: X25519PublicKey,
    signature_key_id: KeyId,
    signing_key: Ed25519PrivateKey,
) -> X25519SignedPublicKeyEntry:
    """Build an X25519 signed public key entry.

    Signature covers: key_id (8) || related_key_id (8) || public_key (32) = 48 bytes.
    """
    signed_data = key_id.data + related_key_id.data + public_key.data
    signature = ed25519_sign(signing_key, signed_data)
    return X25519SignedPublicKeyEntry(
        key_id=key_id,
        related_key_id=related_key_id,
        public_key=public_key,
        signature_key_id=signature_key_id,
        signature=signature,
    )


def verify_x25519_signed_public_key_entry(
    entry: X25519SignedPublicKeyEntry,
    signer_public_key: Ed25519PublicKey,
) -> bool:
    """Verify the signature on an X25519 signed public key entry."""
    signed_data = entry.key_id.data + entry.related_key_id.data + entry.public_key.data
    return ed25519_verify(signer_public_key, signed_data, entry.signature)


def serialize_x25519_signed_public_key_entry(
    entry: X25519SignedPublicKeyEntry,
) -> bytes:
    """Serialize an X25519SignedPublicKeyEntry to a 120-byte wire buffer."""
    return (
        entry.key_id.data
        + entry.related_key_id.data
        + entry.public_key.data
        + entry.signature_key_id.data
        + entry.signature.data
    )


def deserialize_x25519_signed_public_key_entry(
    data: bytes,
) -> X25519SignedPublicKeyEntry:
    """Deserialize an X25519SignedPublicKeyEntry from a 120-byte wire buffer."""
    if len(data) != x25519_signed_public_key_entry_wire_size:
        raise ValueError(
            f"expected {x25519_signed_public_key_entry_wire_size} bytes, got {len(data)}"
        )
    return X25519SignedPublicKeyEntry(
        key_id=KeyId(data=data[0:8]),
        related_key_id=KeyId(data=data[8:16]),
        public_key=X25519PublicKey(data=data[16:48]),
        signature_key_id=KeyId(data=data[48:56]),
        signature=Ed25519Signature(data=data[56:120]),
    )


#
# P-256 signed public key entry (avtp_keychain.hpp)
#

p256_signed_public_key_entry_wire_size = 152
p256_signed_public_key_entry_signed_data_size = 80


@dataclass
class P256SignedPublicKeyEntry:
    """A P-256 public key entry signed by an authority's P-256 ECDSA key."""

    key_id: KeyId
    related_key_id: KeyId
    public_key: P256PublicKey
    signature_key_id: KeyId
    signature: P256EcdsaSignature


def build_p256_signed_public_key_entry(
    key_id: KeyId,
    related_key_id: KeyId,
    public_key: P256PublicKey,
    signature_key_id: KeyId,
    signing_key: P256PrivateKey,
) -> P256SignedPublicKeyEntry:
    """Build a P-256 signed public key entry.

    Signature covers: key_id (8) || related_key_id (8) || public_key (64) = 80 bytes.
    """
    signed_data = key_id.data + related_key_id.data + public_key.data
    signature = p256_ecdsa_sign(signing_key, signed_data)
    return P256SignedPublicKeyEntry(
        key_id=key_id,
        related_key_id=related_key_id,
        public_key=public_key,
        signature_key_id=signature_key_id,
        signature=signature,
    )


def verify_p256_signed_public_key_entry(
    entry: P256SignedPublicKeyEntry,
    signer_public_key: P256PublicKey,
) -> bool:
    """Verify the signature on a P-256 signed public key entry."""
    signed_data = entry.key_id.data + entry.related_key_id.data + entry.public_key.data
    return p256_ecdsa_verify(signer_public_key, signed_data, entry.signature)


def serialize_p256_signed_public_key_entry(entry: P256SignedPublicKeyEntry) -> bytes:
    """Serialize a P256SignedPublicKeyEntry to a 152-byte wire buffer."""
    return (
        entry.key_id.data
        + entry.related_key_id.data
        + entry.public_key.data
        + entry.signature_key_id.data
        + entry.signature.data
    )


def deserialize_p256_signed_public_key_entry(data: bytes) -> P256SignedPublicKeyEntry:
    """Deserialize a P256SignedPublicKeyEntry from a 152-byte wire buffer."""
    if len(data) != p256_signed_public_key_entry_wire_size:
        raise ValueError(
            f"expected {p256_signed_public_key_entry_wire_size} bytes, got {len(data)}"
        )
    return P256SignedPublicKeyEntry(
        key_id=KeyId(data=data[0:8]),
        related_key_id=KeyId(data=data[8:16]),
        public_key=P256PublicKey(data=data[16:80]),
        signature_key_id=KeyId(data=data[80:88]),
        signature=P256EcdsaSignature(data=data[88:152]),
    )


#
# P-256 signed X25519 public key entry (avtp_keychain.hpp)
#

p256_signed_x25519_public_key_entry_wire_size = 120
p256_signed_x25519_public_key_entry_signed_data_size = 48


@dataclass
class P256SignedX25519PublicKeyEntry:
    """An X25519 public key entry signed by an authority's P-256 ECDSA key."""

    key_id: KeyId
    related_key_id: KeyId
    public_key: X25519PublicKey
    signature_key_id: KeyId
    signature: P256EcdsaSignature


def build_p256_signed_x25519_public_key_entry(
    key_id: KeyId,
    related_key_id: KeyId,
    public_key: X25519PublicKey,
    signature_key_id: KeyId,
    signing_key: P256PrivateKey,
) -> P256SignedX25519PublicKeyEntry:
    """Build a P-256 signed X25519 public key entry.

    Signature covers: key_id (8) || related_key_id (8) || public_key (32) = 48 bytes.
    """
    signed_data = key_id.data + related_key_id.data + public_key.data
    signature = p256_ecdsa_sign(signing_key, signed_data)
    return P256SignedX25519PublicKeyEntry(
        key_id=key_id,
        related_key_id=related_key_id,
        public_key=public_key,
        signature_key_id=signature_key_id,
        signature=signature,
    )


def verify_p256_signed_x25519_public_key_entry(
    entry: P256SignedX25519PublicKeyEntry,
    signer_public_key: P256PublicKey,
) -> bool:
    """Verify the signature on a P-256 signed X25519 public key entry."""
    signed_data = entry.key_id.data + entry.related_key_id.data + entry.public_key.data
    return p256_ecdsa_verify(signer_public_key, signed_data, entry.signature)


def serialize_p256_signed_x25519_public_key_entry(
    entry: P256SignedX25519PublicKeyEntry,
) -> bytes:
    """Serialize a P256SignedX25519PublicKeyEntry to a 120-byte wire buffer."""
    return (
        entry.key_id.data
        + entry.related_key_id.data
        + entry.public_key.data
        + entry.signature_key_id.data
        + entry.signature.data
    )


def deserialize_p256_signed_x25519_public_key_entry(
    data: bytes,
) -> P256SignedX25519PublicKeyEntry:
    """Deserialize a P256SignedX25519PublicKeyEntry from a 120-byte wire buffer."""
    if len(data) != p256_signed_x25519_public_key_entry_wire_size:
        raise ValueError(
            f"expected {p256_signed_x25519_public_key_entry_wire_size} bytes, got {len(data)}"
        )
    return P256SignedX25519PublicKeyEntry(
        key_id=KeyId(data=data[0:8]),
        related_key_id=KeyId(data=data[8:16]),
        public_key=X25519PublicKey(data=data[16:48]),
        signature_key_id=KeyId(data=data[48:56]),
        signature=P256EcdsaSignature(data=data[56:120]),
    )


#
# Private key entries (avtp_keychain.hpp)
#


@dataclass
class Ed25519PrivateKeyEntry:
    """Ed25519 private key with its EUI-64 identifier."""

    key_id: KeyId
    private_key: Ed25519PrivateKey


@dataclass
class X25519PrivateKeyEntry:
    """X25519 private key with its EUI-64 identifier."""

    key_id: KeyId
    private_key: X25519PrivateKey


@dataclass
class P256PrivateKeyEntry:
    """P-256 private key with its EUI-64 identifier."""

    key_id: KeyId
    private_key: P256PrivateKey


#
# Transport key entries (avtp_keychain.hpp)
#


@dataclass
class Aes128KeyEntry:
    """AES-128 symmetric key with its EUI-64 identifier."""

    key_id: KeyId
    key: Aes128Key


@dataclass
class Aes256KeyEntry:
    """AES-256 symmetric key with its EUI-64 identifier."""

    key_id: KeyId
    key: Aes256Key


@dataclass
class Aes128SivKeyEntry:
    """AES-128-SIV combined key with its EUI-64 identifier."""

    key_id: KeyId
    key: Aes128SivKey


@dataclass
class Aes256SivKeyEntry:
    """AES-256-SIV combined key with its EUI-64 identifier."""

    key_id: KeyId
    key: Aes256SivKey


#
# Typed keychain variants and containers (avtp_keychain.hpp)
#

PublicKeyEntry = Union[
    Ed25519SignedPublicKeyEntry,
    X25519SignedPublicKeyEntry,
    P256SignedPublicKeyEntry,
    P256SignedX25519PublicKeyEntry,
]
PrivateKeyEntry = Union[
    Ed25519PrivateKeyEntry, X25519PrivateKeyEntry, P256PrivateKeyEntry
]
SessionKeyEntry = Union[
    Aes128KeyEntry, Aes256KeyEntry, Aes128SivKeyEntry, Aes256SivKeyEntry
]

PublicKeyChain = list  # list[PublicKeyEntry]
PrivateKeyChain = list  # list[PrivateKeyEntry]
SessionKeyChain = list  # list[SessionKeyEntry]


def get_key_entry_key_id(entry) -> KeyId:
    """Extract the key_id from any keychain entry (PublicKeyEntry, PrivateKeyEntry, or SessionKeyEntry)."""
    return entry.key_id


def find_key_entry(chain, key_id: KeyId):
    """Find an entry by KeyId in a keychain. Returns None if not found."""
    for entry in chain:
        if entry.key_id.data == key_id.data:
            return entry
    return None


@dataclass
class KeyChains:
    """Aggregates all keychains for an entity (mirrors C++ KeyChains struct)."""

    entity_public: list = field(default_factory=list)  # list[PublicKeyEntry]
    entity_private: list = field(default_factory=list)  # list[PrivateKeyEntry]
    manufacturer_public: list = field(default_factory=list)  # list[PublicKeyEntry]
    controllers: list = field(default_factory=list)  # list[PublicKeyEntry]
    transport: list = field(default_factory=list)  # list[SessionKeyEntry]

    def find_public_key_entry(self, key_id: KeyId) -> Optional[PublicKeyEntry]:
        """Search manufacturer_public, controllers, then entity_public for a key."""
        entry = find_key_entry(self.manufacturer_public, key_id)
        if entry is not None:
            return entry
        entry = find_key_entry(self.controllers, key_id)
        if entry is not None:
            return entry
        return find_key_entry(self.entity_public, key_id)

    def find_private_key_entry(self, key_id: KeyId) -> Optional[PrivateKeyEntry]:
        """Search entity_private for a key."""
        return find_key_entry(self.entity_private, key_id)

    def find_session_key_entry(self, key_id: KeyId) -> Optional[SessionKeyEntry]:
        """Search transport for a key."""
        return find_key_entry(self.transport, key_id)


#
# AVTP Crypto PDU types and operations (avtp_crypto_pdu.hpp)
#


# Key exchange message type constants (replaces PduMessageType enum)
key_exchange_offer: int = 0x01
key_exchange_accept: int = 0x02

# Nonce size for AUTH_GET_NONCE / AUTH_ADD_KEY_NONCE (IEEE 1722.1-2021 §7.4.103)
nonce_size = 8

# Wire sizes
ed25519_key_exchange_pdu_wire_size = 129  # 1 + 32 + 32 + 64
p256_key_exchange_pdu_wire_size = 193  # 1 + 64 + 64 + 64
auth_get_nonce_payload_size = 8
auth_get_nonce_response_payload_size = 16
auth_add_key_nonce_header_size = 28
auth_add_key_nonce_response_payload_size = 24
aes128_wrapped_key_size = 32  # 16 + 16
aes256_wrapped_key_size = 48  # 32 + 16
aes128_siv_wrapped_key_size = 48  # 32 + 16
aes256_siv_wrapped_key_size = 80  # 64 + 16


@dataclass(frozen=True)
class Nonce:
    """64-bit nonce for AUTH_GET_NONCE challenge-response (8 bytes)."""

    data: bytes

    def __post_init__(self) -> None:
        _check_size("Nonce", self.data, nonce_size)


@dataclass
class Ed25519KeyExchangePdu:
    """Ed25519 signed key exchange PDU (129 bytes on wire)."""

    message_type: int
    sender_identity: Ed25519PublicKey
    ephemeral_pubkey: X25519PublicKey
    signature: Ed25519Signature


@dataclass
class P256KeyExchangePdu:
    """P-256 signed key exchange PDU (193 bytes on wire)."""

    message_type: int
    sender_identity: P256PublicKey
    ephemeral_pubkey: P256PublicKey
    signature: P256EcdsaSignature


@dataclass
class AuthGetNoncePayload:
    """AUTH_GET_NONCE command payload (IEEE 1722.1-2021 §7.4.103)."""

    controller_nonce: Nonce


@dataclass
class AuthGetNonceResponsePayload:
    """AUTH_GET_NONCE response payload."""

    controller_nonce: Nonce
    target_nonce: Nonce


@dataclass
class AuthAddKeyNonceHeader:
    """AUTH_ADD_KEY_NONCE command payload header (IEEE 1722.1-2021 §7.4.104)."""

    controller_nonce: Nonce
    target_nonce: Nonce
    key_id: KeyId
    key_type: KeyType
    key_length: int


@dataclass
class AuthAddKeyNonceResponsePayload:
    """AUTH_ADD_KEY_NONCE response payload."""

    controller_nonce: Nonce
    target_nonce: Nonce
    key_id: KeyId


@dataclass(frozen=True)
class Aes128WrappedKey:
    """AES-128 key wrapped with AES-256-SIV (16 + 16 = 32 bytes)."""

    ciphertext: bytes  # 16 bytes
    siv_tag: bytes  # 16 bytes

    def __post_init__(self) -> None:
        _check_size("Aes128WrappedKey.ciphertext", self.ciphertext, aes128_key_size)
        _check_size("Aes128WrappedKey.siv_tag", self.siv_tag, aes_block_size)


@dataclass(frozen=True)
class Aes256WrappedKey:
    """AES-256 key wrapped with AES-256-SIV (32 + 16 = 48 bytes)."""

    ciphertext: bytes  # 32 bytes
    siv_tag: bytes  # 16 bytes

    def __post_init__(self) -> None:
        _check_size("Aes256WrappedKey.ciphertext", self.ciphertext, aes256_key_size)
        _check_size("Aes256WrappedKey.siv_tag", self.siv_tag, aes_block_size)


@dataclass(frozen=True)
class Aes128SivWrappedKey:
    """AES-128-SIV key wrapped with AES-256-SIV (32 + 16 = 48 bytes)."""

    ciphertext: bytes  # 32 bytes
    siv_tag: bytes  # 16 bytes

    def __post_init__(self) -> None:
        _check_size(
            "Aes128SivWrappedKey.ciphertext", self.ciphertext, aes128_siv_key_size
        )
        _check_size("Aes128SivWrappedKey.siv_tag", self.siv_tag, aes_block_size)


@dataclass(frozen=True)
class Aes256SivWrappedKey:
    """AES-256-SIV key wrapped with AES-256-SIV (64 + 16 = 80 bytes)."""

    ciphertext: bytes  # 64 bytes
    siv_tag: bytes  # 16 bytes

    def __post_init__(self) -> None:
        _check_size(
            "Aes256SivWrappedKey.ciphertext", self.ciphertext, aes256_siv_key_size
        )
        _check_size("Aes256SivWrappedKey.siv_tag", self.siv_tag, aes_block_size)


# Ed25519 key exchange: build and verify


def build_ed25519_key_exchange(
    msg_type: int,
    identity_key: Ed25519PrivateKey,
    ephemeral_pk: X25519PublicKey,
) -> Ed25519KeyExchangePdu:
    """Build a signed Ed25519 key exchange PDU (offer or accept).

    Signature covers: message_type (1) || sender_identity (32) || ephemeral_pubkey (32) = 65 bytes.
    """
    sender_identity = ed25519_public_key(identity_key)
    signed_data = bytes([msg_type]) + sender_identity.data + ephemeral_pk.data
    signature = ed25519_sign(identity_key, signed_data)
    return Ed25519KeyExchangePdu(
        message_type=msg_type,
        sender_identity=sender_identity,
        ephemeral_pubkey=ephemeral_pk,
        signature=signature,
    )


def verify_ed25519_key_exchange(
    pdu: Ed25519KeyExchangePdu,
    expected_identity: Ed25519PublicKey,
) -> Optional[X25519PublicKey]:
    """Verify an Ed25519 key exchange PDU signature.

    Returns the peer's ephemeral X25519 public key on success, or None on failure.
    """
    if pdu.sender_identity.data != expected_identity.data:
        return None
    signed_data = (
        bytes([pdu.message_type]) + pdu.sender_identity.data + pdu.ephemeral_pubkey.data
    )
    if not ed25519_verify(expected_identity, signed_data, pdu.signature):
        return None
    return pdu.ephemeral_pubkey


# P-256 key exchange: build and verify


def build_p256_key_exchange(
    msg_type: int,
    identity_key: P256PrivateKey,
    ephemeral_pk: P256PublicKey,
) -> P256KeyExchangePdu:
    """Build a signed P-256 key exchange PDU (offer or accept).

    Signature covers: message_type (1) || sender_identity (64) || ephemeral_pubkey (64) = 129 bytes.
    """
    sender_identity = p256_public_key(identity_key)
    signed_data = bytes([msg_type]) + sender_identity.data + ephemeral_pk.data
    signature = p256_ecdsa_sign(identity_key, signed_data)
    return P256KeyExchangePdu(
        message_type=msg_type,
        sender_identity=sender_identity,
        ephemeral_pubkey=ephemeral_pk,
        signature=signature,
    )


def verify_p256_key_exchange(
    pdu: P256KeyExchangePdu,
    expected_identity: P256PublicKey,
) -> Optional[P256PublicKey]:
    """Verify a P-256 key exchange PDU signature.

    Returns the peer's ephemeral P-256 public key on success, or None on failure.
    """
    if pdu.sender_identity.data != expected_identity.data:
        return None
    signed_data = (
        bytes([pdu.message_type]) + pdu.sender_identity.data + pdu.ephemeral_pubkey.data
    )
    if not p256_ecdsa_verify(expected_identity, signed_data, pdu.signature):
        return None
    return pdu.ephemeral_pubkey


# Ed25519 transport key derivation


def build_ed25519_transport_key_info(
    initiator_identity: Ed25519PublicKey,
    responder_identity: Ed25519PublicKey,
) -> bytes:
    """Build HKDF info for Ed25519 AVTP transport key derivation.

    Returns: "avtp-transport" (15 bytes) || initiator_pk (32) || responder_pk (32) = 79 bytes.
    """
    return b"avtp-transport" + initiator_identity.data + responder_identity.data


def derive_ed25519_transport_key(
    shared_secret: bytes,
    initiator_identity: Ed25519PublicKey,
    responder_identity: Ed25519PublicKey,
) -> Aes256SivKey:
    """Derive a 64-byte AES-256-SIV transport key from X25519 shared secret.

    Uses HKDF-SHA-256 with salt="avtp-crypto-v1" and structured info.
    """
    if len(shared_secret) != 32:
        raise ValueError(f"shared_secret must be 32 bytes, got {len(shared_secret)}")
    info = build_ed25519_transport_key_info(initiator_identity, responder_identity)
    key_material = hkdf_sha256(b"avtp-crypto-v1", shared_secret, info, 64)
    return Aes256SivKey(data=key_material)


# P-256 transport key derivation


def build_p256_transport_key_info(
    initiator_identity: P256PublicKey,
    responder_identity: P256PublicKey,
) -> bytes:
    """Build HKDF info for P-256 AVTP transport key derivation.

    Returns: "avtp-transport-p256" (19 bytes) || initiator_pk (64) || responder_pk (64) = 147 bytes.
    """
    return b"avtp-transport-p256" + initiator_identity.data + responder_identity.data


def derive_p256_transport_key(
    shared_secret: bytes,
    initiator_identity: P256PublicKey,
    responder_identity: P256PublicKey,
) -> Aes256SivKey:
    """Derive a 64-byte AES-256-SIV transport key from P-256 ECDH shared secret.

    Uses HKDF-SHA-256 with salt="avtp-crypto-p256-v1" and structured info.
    """
    if len(shared_secret) != 32:
        raise ValueError(f"shared_secret must be 32 bytes, got {len(shared_secret)}")
    info = build_p256_transport_key_info(initiator_identity, responder_identity)
    key_material = hkdf_sha256(b"avtp-crypto-p256-v1", shared_secret, info, 64)
    return Aes256SivKey(data=key_material)


# Per-key-type key wrapping / unwrapping
#
# AAD = controller_nonce(8) || target_nonce(8) || key_id(8) || key_type(1) = 25 bytes


def _build_wrap_aad(
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    key_type: KeyType,
) -> bytes:
    """Build the AAD for AES-256-SIV key wrapping."""
    return (
        controller_nonce.data + target_nonce.data + key_id.data + bytes([int(key_type)])
    )


def wrap_aes128_key(
    transport_key: Aes256SivKey,
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    key: Aes128Key,
) -> Aes128WrappedKey:
    """Wrap an AES-128 session key for AUTH_ADD_KEY_NONCE distribution."""
    aad = _build_wrap_aad(controller_nonce, target_nonce, key_id, KeyType.aes128)
    siv, ciphertext = aes256_siv_encrypt(transport_key, key.data, aad)
    return Aes128WrappedKey(ciphertext=ciphertext, siv_tag=siv)


def unwrap_aes128_key(
    transport_key: Aes256SivKey,
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    wrapped: Aes128WrappedKey,
) -> Optional[Aes128Key]:
    """Unwrap a received AES-128 session key."""
    aad = _build_wrap_aad(controller_nonce, target_nonce, key_id, KeyType.aes128)
    ok, plaintext = aes256_siv_decrypt(
        transport_key, wrapped.ciphertext, wrapped.siv_tag, aad
    )
    if not ok:
        return None
    return Aes128Key(data=plaintext)


def wrap_aes256_key(
    transport_key: Aes256SivKey,
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    key: Aes256Key,
) -> Aes256WrappedKey:
    """Wrap an AES-256 session key for AUTH_ADD_KEY_NONCE distribution."""
    aad = _build_wrap_aad(controller_nonce, target_nonce, key_id, KeyType.aes256)
    siv, ciphertext = aes256_siv_encrypt(transport_key, key.data, aad)
    return Aes256WrappedKey(ciphertext=ciphertext, siv_tag=siv)


def unwrap_aes256_key(
    transport_key: Aes256SivKey,
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    wrapped: Aes256WrappedKey,
) -> Optional[Aes256Key]:
    """Unwrap a received AES-256 session key."""
    aad = _build_wrap_aad(controller_nonce, target_nonce, key_id, KeyType.aes256)
    ok, plaintext = aes256_siv_decrypt(
        transport_key, wrapped.ciphertext, wrapped.siv_tag, aad
    )
    if not ok:
        return None
    return Aes256Key(data=plaintext)


def wrap_aes128_siv_key(
    transport_key: Aes256SivKey,
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    key: Aes128SivKey,
) -> Aes128SivWrappedKey:
    """Wrap an AES-128-SIV session key for AUTH_ADD_KEY_NONCE distribution."""
    aad = _build_wrap_aad(controller_nonce, target_nonce, key_id, KeyType.aes128_siv)
    siv, ciphertext = aes256_siv_encrypt(transport_key, key.data, aad)
    return Aes128SivWrappedKey(ciphertext=ciphertext, siv_tag=siv)


def unwrap_aes128_siv_key(
    transport_key: Aes256SivKey,
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    wrapped: Aes128SivWrappedKey,
) -> Optional[Aes128SivKey]:
    """Unwrap a received AES-128-SIV session key."""
    aad = _build_wrap_aad(controller_nonce, target_nonce, key_id, KeyType.aes128_siv)
    ok, plaintext = aes256_siv_decrypt(
        transport_key, wrapped.ciphertext, wrapped.siv_tag, aad
    )
    if not ok:
        return None
    return Aes128SivKey(data=plaintext)


def wrap_aes256_siv_key(
    transport_key: Aes256SivKey,
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    key: Aes256SivKey,
) -> Aes256SivWrappedKey:
    """Wrap an AES-256-SIV session key for AUTH_ADD_KEY_NONCE distribution."""
    aad = _build_wrap_aad(controller_nonce, target_nonce, key_id, KeyType.aes256_siv)
    siv, ciphertext = aes256_siv_encrypt(transport_key, key.data, aad)
    return Aes256SivWrappedKey(ciphertext=ciphertext, siv_tag=siv)


def unwrap_aes256_siv_key(
    transport_key: Aes256SivKey,
    controller_nonce: Nonce,
    target_nonce: Nonce,
    key_id: KeyId,
    wrapped: Aes256SivWrappedKey,
) -> Optional[Aes256SivKey]:
    """Unwrap a received AES-256-SIV session key."""
    aad = _build_wrap_aad(controller_nonce, target_nonce, key_id, KeyType.aes256_siv)
    ok, plaintext = aes256_siv_decrypt(
        transport_key, wrapped.ciphertext, wrapped.siv_tag, aad
    )
    if not ok:
        return None
    return Aes256SivKey(data=plaintext)


# Ed25519 wire-format serialization


def serialize_ed25519_key_exchange(pdu: Ed25519KeyExchangePdu) -> bytes:
    """Serialize an Ed25519KeyExchangePdu to a 129-byte wire buffer."""
    return (
        bytes([pdu.message_type])
        + pdu.sender_identity.data
        + pdu.ephemeral_pubkey.data
        + pdu.signature.data
    )


def deserialize_ed25519_key_exchange(data: bytes) -> Optional[Ed25519KeyExchangePdu]:
    """Deserialize an Ed25519KeyExchangePdu from a 129-byte wire buffer."""
    if len(data) != ed25519_key_exchange_pdu_wire_size:
        return None
    raw_type = data[0]
    if raw_type < key_exchange_offer or raw_type > key_exchange_accept:
        return None
    return Ed25519KeyExchangePdu(
        message_type=raw_type,
        sender_identity=Ed25519PublicKey(data=data[1:33]),
        ephemeral_pubkey=X25519PublicKey(data=data[33:65]),
        signature=Ed25519Signature(data=data[65:129]),
    )


# P-256 wire-format serialization


def serialize_p256_key_exchange(pdu: P256KeyExchangePdu) -> bytes:
    """Serialize a P256KeyExchangePdu to a 193-byte wire buffer."""
    return (
        bytes([pdu.message_type])
        + pdu.sender_identity.data
        + pdu.ephemeral_pubkey.data
        + pdu.signature.data
    )


def deserialize_p256_key_exchange(data: bytes) -> Optional[P256KeyExchangePdu]:
    """Deserialize a P256KeyExchangePdu from a 193-byte wire buffer."""
    if len(data) != p256_key_exchange_pdu_wire_size:
        return None
    raw_type = data[0]
    if raw_type < key_exchange_offer or raw_type > key_exchange_accept:
        return None
    return P256KeyExchangePdu(
        message_type=raw_type,
        sender_identity=P256PublicKey(data=data[1:65]),
        ephemeral_pubkey=P256PublicKey(data=data[65:129]),
        signature=P256EcdsaSignature(data=data[129:193]),
    )


# AUTH_GET_NONCE wire-format serialization


def serialize_auth_get_nonce(payload: AuthGetNoncePayload) -> bytes:
    """Serialize an AuthGetNoncePayload to an 8-byte wire buffer."""
    return payload.controller_nonce.data


def deserialize_auth_get_nonce(data: bytes) -> AuthGetNoncePayload:
    """Deserialize an AuthGetNoncePayload from an 8-byte wire buffer."""
    if len(data) != auth_get_nonce_payload_size:
        raise ValueError(
            f"expected {auth_get_nonce_payload_size} bytes, got {len(data)}"
        )
    return AuthGetNoncePayload(controller_nonce=Nonce(data=data[0:8]))


def serialize_auth_get_nonce_response(payload: AuthGetNonceResponsePayload) -> bytes:
    """Serialize an AuthGetNonceResponsePayload to a 16-byte wire buffer."""
    return payload.controller_nonce.data + payload.target_nonce.data


def deserialize_auth_get_nonce_response(data: bytes) -> AuthGetNonceResponsePayload:
    """Deserialize an AuthGetNonceResponsePayload from a 16-byte wire buffer."""
    if len(data) != auth_get_nonce_response_payload_size:
        raise ValueError(
            f"expected {auth_get_nonce_response_payload_size} bytes, got {len(data)}"
        )
    return AuthGetNonceResponsePayload(
        controller_nonce=Nonce(data=data[0:8]),
        target_nonce=Nonce(data=data[8:16]),
    )


# AUTH_ADD_KEY_NONCE wire-format serialization


def serialize_auth_add_key_nonce_header(header: AuthAddKeyNonceHeader) -> bytes:
    """Serialize an AuthAddKeyNonceHeader to a 28-byte wire buffer."""
    type_length_byte = (int(header.key_type) << 4) | ((header.key_length >> 8) & 0x0F)
    length_low = header.key_length & 0xFF
    return (
        header.controller_nonce.data
        + header.target_nonce.data
        + header.key_id.data
        + bytes([type_length_byte, length_low, 0x00, 0x00])
    )


def deserialize_auth_add_key_nonce_header(
    data: bytes,
) -> Optional[AuthAddKeyNonceHeader]:
    """Deserialize an AuthAddKeyNonceHeader from a 28-byte wire buffer."""
    if len(data) != auth_add_key_nonce_header_size:
        return None
    key_type = KeyType((data[24] >> 4) & 0x0F)
    key_length = ((data[24] & 0x0F) << 8) | data[25]
    return AuthAddKeyNonceHeader(
        controller_nonce=Nonce(data=data[0:8]),
        target_nonce=Nonce(data=data[8:16]),
        key_id=KeyId(data=data[16:24]),
        key_type=key_type,
        key_length=key_length,
    )


def serialize_auth_add_key_nonce_response(
    payload: AuthAddKeyNonceResponsePayload,
) -> bytes:
    """Serialize an AuthAddKeyNonceResponsePayload to a 24-byte wire buffer."""
    return (
        payload.controller_nonce.data + payload.target_nonce.data + payload.key_id.data
    )


def deserialize_auth_add_key_nonce_response(
    data: bytes,
) -> AuthAddKeyNonceResponsePayload:
    """Deserialize an AuthAddKeyNonceResponsePayload from a 24-byte wire buffer."""
    if len(data) != auth_add_key_nonce_response_payload_size:
        raise ValueError(
            f"expected {auth_add_key_nonce_response_payload_size} bytes, got {len(data)}"
        )
    return AuthAddKeyNonceResponsePayload(
        controller_nonce=Nonce(data=data[0:8]),
        target_nonce=Nonce(data=data[8:16]),
        key_id=KeyId(data=data[16:24]),
    )


# Wrapped key wire-format serialization


def serialize_aes128_wrapped_key(wk: Aes128WrappedKey) -> bytes:
    """Serialize an Aes128WrappedKey to a 32-byte wire buffer."""
    return wk.ciphertext + wk.siv_tag


def deserialize_aes128_wrapped_key(data: bytes) -> Aes128WrappedKey:
    """Deserialize an Aes128WrappedKey from a 32-byte wire buffer."""
    if len(data) != aes128_wrapped_key_size:
        raise ValueError(f"expected {aes128_wrapped_key_size} bytes, got {len(data)}")
    return Aes128WrappedKey(ciphertext=data[0:16], siv_tag=data[16:32])


def serialize_aes256_wrapped_key(wk: Aes256WrappedKey) -> bytes:
    """Serialize an Aes256WrappedKey to a 48-byte wire buffer."""
    return wk.ciphertext + wk.siv_tag


def deserialize_aes256_wrapped_key(data: bytes) -> Aes256WrappedKey:
    """Deserialize an Aes256WrappedKey from a 48-byte wire buffer."""
    if len(data) != aes256_wrapped_key_size:
        raise ValueError(f"expected {aes256_wrapped_key_size} bytes, got {len(data)}")
    return Aes256WrappedKey(ciphertext=data[0:32], siv_tag=data[32:48])


def serialize_aes128_siv_wrapped_key(wk: Aes128SivWrappedKey) -> bytes:
    """Serialize an Aes128SivWrappedKey to a 48-byte wire buffer."""
    return wk.ciphertext + wk.siv_tag


def deserialize_aes128_siv_wrapped_key(data: bytes) -> Aes128SivWrappedKey:
    """Deserialize an Aes128SivWrappedKey from a 48-byte wire buffer."""
    if len(data) != aes128_siv_wrapped_key_size:
        raise ValueError(
            f"expected {aes128_siv_wrapped_key_size} bytes, got {len(data)}"
        )
    return Aes128SivWrappedKey(ciphertext=data[0:32], siv_tag=data[32:48])


def serialize_aes256_siv_wrapped_key(wk: Aes256SivWrappedKey) -> bytes:
    """Serialize an Aes256SivWrappedKey to an 80-byte wire buffer."""
    return wk.ciphertext + wk.siv_tag


def deserialize_aes256_siv_wrapped_key(data: bytes) -> Aes256SivWrappedKey:
    """Deserialize an Aes256SivWrappedKey from an 80-byte wire buffer."""
    if len(data) != aes256_siv_wrapped_key_size:
        raise ValueError(
            f"expected {aes256_siv_wrapped_key_size} bytes, got {len(data)}"
        )
    return Aes256SivWrappedKey(ciphertext=data[0:64], siv_tag=data[64:80])


#
# IEEE 1722.1 P-256 wire formats (p256_wire.hpp)
#

ecc_public_256_wire_size = 336
ecc_public_256_signed_data_size = 272
ecc_private_256_wire_size = 232

# Canonical P-256 curve domain parameters (big-endian, 32 bytes each)
_P256_Q = bytes.fromhex(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
)
_P256_A = bytes.fromhex(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
)
_P256_B = bytes.fromhex(
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
)
_P256_R = bytes.fromhex(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
)
_P256_GX = bytes.fromhex(
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
)
_P256_GY = bytes.fromhex(
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
)


@dataclass
class EccPublic256Wire:
    """IEEE 1722.1 ECC_PUBLIC_256 wire format (336 bytes)."""

    related_key_id: KeyId
    field_size: bytes  # q (32 bytes)
    semimajor: bytes  # a (32 bytes)
    semiminor: bytes  # b (32 bytes)
    prime_divisor: bytes  # r (32 bytes)
    generator_x: bytes  # G.x (32 bytes)
    generator_y: bytes  # G.y (32 bytes)
    public_x: bytes  # W.x (32 bytes)
    public_y: bytes  # W.y (32 bytes)
    signature_key_id: KeyId
    ecdsa_signature_c: bytes  # r (32 bytes)
    ecdsa_signature_d: bytes  # s (32 bytes)


@dataclass
class EccPrivate256Wire:
    """IEEE 1722.1 ECC_PRIVATE_256 wire format (232 bytes)."""

    related_key_id: KeyId
    field_size: bytes  # q (32 bytes)
    semimajor: bytes  # a (32 bytes)
    semiminor: bytes  # b (32 bytes)
    prime_divisor: bytes  # r (32 bytes)
    generator_x: bytes  # G.x (32 bytes)
    generator_y: bytes  # G.y (32 bytes)
    private_scalar: bytes  # s (32 bytes)


def build_ecc_public_256_wire(
    related_key_id: KeyId,
    public_key: P256PublicKey,
    signature_key_id: KeyId,
    signing_key: P256PrivateKey,
) -> EccPublic256Wire:
    """Build an ECC_PUBLIC_256 wire struct with ECDSA signature."""
    wire = EccPublic256Wire(
        related_key_id=related_key_id,
        field_size=_P256_Q,
        semimajor=_P256_A,
        semiminor=_P256_B,
        prime_divisor=_P256_R,
        generator_x=_P256_GX,
        generator_y=_P256_GY,
        public_x=public_key.data[:32],
        public_y=public_key.data[32:],
        signature_key_id=signature_key_id,
        ecdsa_signature_c=bytes(32),
        ecdsa_signature_d=bytes(32),
    )
    # Sign bytes [0..271] (signed_data = first 272 bytes of wire format)
    wire_bytes = serialize_ecc_public_256_wire(wire)
    signed_data = wire_bytes[:ecc_public_256_signed_data_size]
    sig = p256_ecdsa_sign(signing_key, signed_data)
    wire.ecdsa_signature_c = sig.data[:32]
    wire.ecdsa_signature_d = sig.data[32:]
    return wire


def verify_ecc_public_256_wire(
    wire: EccPublic256Wire,
    signer_public_key: P256PublicKey,
) -> bool:
    """Verify the ECDSA signature on an ECC_PUBLIC_256 wire struct."""
    wire_bytes = serialize_ecc_public_256_wire(wire)
    signed_data = wire_bytes[:ecc_public_256_signed_data_size]
    sig = P256EcdsaSignature(data=wire.ecdsa_signature_c + wire.ecdsa_signature_d)
    return p256_ecdsa_verify(signer_public_key, signed_data, sig)


def extract_p256_public_key(wire: EccPublic256Wire) -> Optional[P256PublicKey]:
    """Extract a P256PublicKey from an ECC_PUBLIC_256 wire struct.

    Validates curve domain parameters match canonical P-256 values.
    """
    if (
        wire.field_size != _P256_Q
        or wire.semimajor != _P256_A
        or wire.semiminor != _P256_B
        or wire.prime_divisor != _P256_R
        or wire.generator_x != _P256_GX
        or wire.generator_y != _P256_GY
    ):
        return None
    return P256PublicKey(data=wire.public_x + wire.public_y)


def serialize_ecc_public_256_wire(wire: EccPublic256Wire) -> bytes:
    """Serialize an EccPublic256Wire to a 336-byte buffer."""
    return (
        wire.related_key_id.data
        + wire.field_size
        + wire.semimajor
        + wire.semiminor
        + wire.prime_divisor
        + wire.generator_x
        + wire.generator_y
        + wire.public_x
        + wire.public_y
        + wire.signature_key_id.data
        + wire.ecdsa_signature_c
        + wire.ecdsa_signature_d
    )


def deserialize_ecc_public_256_wire(data: bytes) -> EccPublic256Wire:
    """Deserialize an EccPublic256Wire from a 336-byte buffer."""
    if len(data) != ecc_public_256_wire_size:
        raise ValueError(f"expected {ecc_public_256_wire_size} bytes, got {len(data)}")
    o = 0

    def take(n: int) -> bytes:
        nonlocal o
        r = data[o : o + n]
        o += n
        return r

    return EccPublic256Wire(
        related_key_id=KeyId(data=take(8)),
        field_size=take(32),
        semimajor=take(32),
        semiminor=take(32),
        prime_divisor=take(32),
        generator_x=take(32),
        generator_y=take(32),
        public_x=take(32),
        public_y=take(32),
        signature_key_id=KeyId(data=take(8)),
        ecdsa_signature_c=take(32),
        ecdsa_signature_d=take(32),
    )


def build_ecc_private_256_wire(
    related_key_id: KeyId,
    private_key: P256PrivateKey,
) -> EccPrivate256Wire:
    """Build an ECC_PRIVATE_256 wire struct with P-256 curve params."""
    return EccPrivate256Wire(
        related_key_id=related_key_id,
        field_size=_P256_Q,
        semimajor=_P256_A,
        semiminor=_P256_B,
        prime_divisor=_P256_R,
        generator_x=_P256_GX,
        generator_y=_P256_GY,
        private_scalar=private_key.data,
    )


def extract_p256_private_key(wire: EccPrivate256Wire) -> Optional[P256PrivateKey]:
    """Extract a P256PrivateKey from an ECC_PRIVATE_256 wire struct.

    Validates curve domain parameters and scalar range.
    """
    if (
        wire.field_size != _P256_Q
        or wire.semimajor != _P256_A
        or wire.semiminor != _P256_B
        or wire.prime_divisor != _P256_R
        or wire.generator_x != _P256_GX
        or wire.generator_y != _P256_GY
    ):
        return None
    return p256_keypair_from_scalar(wire.private_scalar)


def serialize_ecc_private_256_wire(wire: EccPrivate256Wire) -> bytes:
    """Serialize an EccPrivate256Wire to a 232-byte buffer."""
    return (
        wire.related_key_id.data
        + wire.field_size
        + wire.semimajor
        + wire.semiminor
        + wire.prime_divisor
        + wire.generator_x
        + wire.generator_y
        + wire.private_scalar
    )


def deserialize_ecc_private_256_wire(data: bytes) -> EccPrivate256Wire:
    """Deserialize an EccPrivate256Wire from a 232-byte buffer."""
    if len(data) != ecc_private_256_wire_size:
        raise ValueError(f"expected {ecc_private_256_wire_size} bytes, got {len(data)}")
    o = 0

    def take(n: int) -> bytes:
        nonlocal o
        r = data[o : o + n]
        o += n
        return r

    return EccPrivate256Wire(
        related_key_id=KeyId(data=take(8)),
        field_size=take(32),
        semimajor=take(32),
        semiminor=take(32),
        prime_divisor=take(32),
        generator_x=take(32),
        generator_y=take(32),
        private_scalar=take(32),
    )
