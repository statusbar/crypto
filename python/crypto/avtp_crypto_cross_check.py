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
Cross-validation tool for statusbar_crypto C++ implementations.

Generates Python test vectors using cryptography/pycryptodome, feeds them
to the C++ CLI tool (avtp_crypto_tool), and compares results.

Usage:
    uv run avtp_crypto_cross_check.py
    uv run avtp_crypto_cross_check.py --build-dir build-Release
    uv run avtp_crypto_cross_check.py --verbose
"""

import argparse
import subprocess
import sys
from pathlib import Path


CLI_TIMEOUT = 30  # seconds; override with --timeout


def run_cli(cli_path: Path, *args: str) -> str:
    """Run avtp_crypto_tool and return stdout, or raise on failure."""
    result = subprocess.run(
        [str(cli_path)] + list(args),
        capture_output=True,
        text=True,
        timeout=CLI_TIMEOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"CLI failed: {' '.join(args)}\n  stderr: {result.stderr.strip()}"
        )
    return result.stdout.strip()


#
# Cross-validation: Python vectors vs C++ CLI
#


def cross_validate_aes_block(
    cli: Path, vectors: dict, cmd_prefix: str, encrypt_cmd: str = ""
) -> list[tuple[str, bool, str]]:
    """Cross-validate AES block encrypt for 128 or 256."""
    if not encrypt_cmd:
        encrypt_cmd = f"{cmd_prefix}_encrypt"
    results = []
    for v in vectors["vectors"]:
        name = f"{vectors['algorithm']}/{v['name']}"
        try:
            cpp_ct = run_cli(cli, encrypt_cmd, v["key"], v["plaintext"])
            if cpp_ct == v["ciphertext"]:
                results.append((name, True, ""))
            else:
                results.append(
                    (name, False, f"expected {v['ciphertext']}, got {cpp_ct}")
                )
        except Exception as e:
            results.append((name, False, str(e)))
    return results


def cross_validate_cmac(
    cli: Path, vectors: dict, cmd: str
) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        name = f"{vectors['algorithm']}/{v['name']}"
        try:
            cpp_tag = run_cli(cli, cmd, v["key"], v["message"])
            if cpp_tag == v["tag"]:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"expected {v['tag']}, got {cpp_tag}"))
        except Exception as e:
            results.append((name, False, str(e)))
    return results


def cross_validate_siv(
    cli: Path, vectors: dict, cmd_prefix: str
) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        name = f"{vectors['algorithm']}/{v['name']}/encrypt"
        try:
            output = run_cli(
                cli, f"{cmd_prefix}_encrypt", v["key"], v["aad"], v["plaintext"]
            )
            parts = output.split(" ", 1)
            cpp_siv = parts[0]
            cpp_ct = parts[1] if len(parts) > 1 else ""
            expected_ct = v["ciphertext"]

            if cpp_siv == v["siv"] and cpp_ct == expected_ct:
                results.append((name, True, ""))
            else:
                msg = ""
                if cpp_siv != v["siv"]:
                    msg += f"siv: expected {v['siv']}, got {cpp_siv}. "
                if cpp_ct != expected_ct:
                    msg += f"ct: expected {expected_ct}, got {cpp_ct}."
                results.append((name, False, msg))
        except Exception as e:
            results.append((name, False, str(e)))

        # Decrypt roundtrip
        name_dec = f"{vectors['algorithm']}/{v['name']}/decrypt"
        try:
            output = run_cli(
                cli,
                f"{cmd_prefix}_decrypt",
                v["key"],
                v["siv"],
                v["aad"],
                v["ciphertext"],
            )
            parts = output.split(" ", 1)
            status = parts[0]
            cpp_pt = parts[1] if len(parts) > 1 else ""
            expected_pt = v["plaintext"]

            if status == "ok" and cpp_pt == expected_pt:
                results.append((name_dec, True, ""))
            else:
                results.append(
                    (
                        name_dec,
                        False,
                        f"status={status}, pt: expected {expected_pt}, got {cpp_pt}",
                    )
                )
        except Exception as e:
            results.append((name_dec, False, str(e)))

    return results


def cross_validate_gcm_siv(
    cli: Path, vectors: dict, cmd_prefix: str
) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        name = f"{vectors['algorithm']}/{v['name']}/encrypt"
        try:
            output = run_cli(
                cli,
                f"{cmd_prefix}_encrypt",
                v["key"],
                v["nonce"],
                v["aad"],
                v["plaintext"],
            )
            parts = output.split(" ", 1)
            cpp_tag = parts[0]
            cpp_ct = parts[1] if len(parts) > 1 else ""
            expected_ct = v["ciphertext"]

            if cpp_tag == v["tag"] and cpp_ct == expected_ct:
                results.append((name, True, ""))
            else:
                msg = ""
                if cpp_tag != v["tag"]:
                    msg += f"tag: expected {v['tag']}, got {cpp_tag}. "
                if cpp_ct != expected_ct:
                    msg += f"ct: expected {expected_ct}, got {cpp_ct}."
                results.append((name, False, msg))
        except Exception as e:
            results.append((name, False, str(e)))

        # Decrypt roundtrip
        name_dec = f"{vectors['algorithm']}/{v['name']}/decrypt"
        try:
            output = run_cli(
                cli,
                f"{cmd_prefix}_decrypt",
                v["key"],
                v["nonce"],
                v["tag"],
                v["aad"],
                v["ciphertext"],
            )
            parts = output.split(" ", 1)
            status = parts[0]
            cpp_pt = parts[1] if len(parts) > 1 else ""
            expected_pt = v["plaintext"]

            if status == "ok" and cpp_pt == expected_pt:
                results.append((name_dec, True, ""))
            else:
                results.append(
                    (
                        name_dec,
                        False,
                        f"status={status}, pt: expected {expected_pt}, got {cpp_pt}",
                    )
                )
        except Exception as e:
            results.append((name_dec, False, str(e)))

    return results


def cross_validate_sha(
    cli: Path, vectors: dict, cmd: str
) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        name = f"{vectors['algorithm']}/{v['name']}"
        try:
            cpp_digest = run_cli(cli, cmd, v["message"])
            if cpp_digest == v["digest"]:
                results.append((name, True, ""))
            else:
                results.append(
                    (name, False, f"expected {v['digest']}, got {cpp_digest}")
                )
        except Exception as e:
            results.append((name, False, str(e)))
    return results


def cross_validate_hmac(
    cli: Path, vectors: dict, cmd: str = "sha256_hmac"
) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        name = f"{vectors['algorithm']}/{v['name']}"
        try:
            cpp_mac = run_cli(cli, cmd, v["key"], v["message"])
            if cpp_mac == v["mac"]:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"expected {v['mac']}, got {cpp_mac}"))
        except Exception as e:
            results.append((name, False, str(e)))
    return results


def cross_validate_hkdf(cli: Path, vectors: dict) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        # Extract
        name_ext = f"{vectors['algorithm']}/{v['name']}/extract"
        try:
            cpp_prk = run_cli(cli, "hkdf_extract", v["salt"], v["ikm"])
            if cpp_prk == v["prk"]:
                results.append((name_ext, True, ""))
            else:
                results.append((name_ext, False, f"expected {v['prk']}, got {cpp_prk}"))
        except Exception as e:
            results.append((name_ext, False, str(e)))

        # Expand
        name_exp = f"{vectors['algorithm']}/{v['name']}/expand"
        try:
            cpp_okm = run_cli(
                cli, "hkdf_expand", v["prk"], v["info"], str(v["okm_length"])
            )
            if cpp_okm == v["okm"]:
                results.append((name_exp, True, ""))
            else:
                results.append((name_exp, False, f"expected {v['okm']}, got {cpp_okm}"))
        except Exception as e:
            results.append((name_exp, False, str(e)))

    return results


def cross_validate_ed25519(cli: Path, vectors: dict) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        # Public key derivation
        name_pk = f"{vectors['algorithm']}/{v['name']}/pubkey"
        try:
            cpp_pk = run_cli(cli, "ed25519_pubkey", v["seed"])
            if cpp_pk == v["public_key"]:
                results.append((name_pk, True, ""))
            else:
                results.append(
                    (name_pk, False, f"expected {v['public_key']}, got {cpp_pk}")
                )
        except Exception as e:
            results.append((name_pk, False, str(e)))

        # Sign
        name_sig = f"{vectors['algorithm']}/{v['name']}/sign"
        try:
            cpp_sig = run_cli(cli, "ed25519_sign", v["seed"], v["message"])
            if cpp_sig == v["signature"]:
                results.append((name_sig, True, ""))
            else:
                results.append(
                    (name_sig, False, f"expected {v['signature']}, got {cpp_sig}")
                )
        except Exception as e:
            results.append((name_sig, False, str(e)))

        # Verify
        name_ver = f"{vectors['algorithm']}/{v['name']}/verify"
        try:
            cpp_result = run_cli(
                cli, "ed25519_verify", v["public_key"], v["message"], v["signature"]
            )
            if cpp_result == "ok":
                results.append((name_ver, True, ""))
            else:
                results.append((name_ver, False, f"expected ok, got {cpp_result}"))
        except Exception as e:
            results.append((name_ver, False, str(e)))

    return results


def cross_validate_p256_ecdsa(cli: Path, vectors: dict) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        # Public key derivation
        name_pk = f"{vectors['algorithm']}/{v['name']}/pubkey"
        try:
            cpp_pk = run_cli(cli, "p256_ecdsa_pubkey", v["seed"])
            if cpp_pk == v["public_key"]:
                results.append((name_pk, True, ""))
            else:
                results.append(
                    (name_pk, False, f"expected {v['public_key']}, got {cpp_pk}")
                )
        except Exception as e:
            results.append((name_pk, False, str(e)))

        # Sign
        name_sig = f"{vectors['algorithm']}/{v['name']}/sign"
        try:
            cpp_sig = run_cli(cli, "p256_ecdsa_sign", v["seed"], v["message"])
            if cpp_sig == v["signature"]:
                results.append((name_sig, True, ""))
            else:
                results.append(
                    (name_sig, False, f"expected {v['signature']}, got {cpp_sig}")
                )
        except Exception as e:
            results.append((name_sig, False, str(e)))

        # Verify
        name_ver = f"{vectors['algorithm']}/{v['name']}/verify"
        try:
            cpp_result = run_cli(
                cli, "p256_ecdsa_verify", v["public_key"], v["message"], v["signature"]
            )
            if cpp_result == "ok":
                results.append((name_ver, True, ""))
            else:
                results.append((name_ver, False, f"expected ok, got {cpp_result}"))
        except Exception as e:
            results.append((name_ver, False, str(e)))

    return results


def cross_validate_p256_ecdh(cli: Path, vectors: dict) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        # Alice's pubkey
        name_apk = f"{vectors['algorithm']}/{v['name']}/alice_pubkey"
        try:
            cpp_pk = run_cli(cli, "p256_ecdsa_pubkey", v["alice_seed"])
            if cpp_pk == v["alice_public_key"]:
                results.append((name_apk, True, ""))
            else:
                results.append(
                    (name_apk, False, f"expected {v['alice_public_key']}, got {cpp_pk}")
                )
        except Exception as e:
            results.append((name_apk, False, str(e)))

        # Bob's pubkey
        name_bpk = f"{vectors['algorithm']}/{v['name']}/bob_pubkey"
        try:
            cpp_pk = run_cli(cli, "p256_ecdsa_pubkey", v["bob_seed"])
            if cpp_pk == v["bob_public_key"]:
                results.append((name_bpk, True, ""))
            else:
                results.append(
                    (name_bpk, False, f"expected {v['bob_public_key']}, got {cpp_pk}")
                )
        except Exception as e:
            results.append((name_bpk, False, str(e)))

        # Shared secret (Alice SK * Bob PK)
        name_ss = f"{vectors['algorithm']}/{v['name']}/shared_secret"
        try:
            cpp_ss = run_cli(cli, "p256_ecdh", v["alice_seed"], v["bob_public_key"])
            if cpp_ss == v["shared_secret"]:
                results.append((name_ss, True, ""))
            else:
                results.append(
                    (name_ss, False, f"expected {v['shared_secret']}, got {cpp_ss}")
                )
        except Exception as e:
            results.append((name_ss, False, str(e)))

    return results


def cross_validate_ecies(cli: Path, vectors: dict) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        # Encrypt
        name_enc = f"{vectors['algorithm']}/{v['name']}/encrypt"
        try:
            cpp_ct = run_cli(
                cli,
                "ecies_encrypt",
                v["recipient_public_key"],
                v["entropy"],
                v["plaintext"],
            )
            if cpp_ct == v["ciphertext"]:
                results.append((name_enc, True, ""))
            else:
                results.append(
                    (name_enc, False, f"expected {v['ciphertext']}, got {cpp_ct}")
                )
        except Exception as e:
            results.append((name_enc, False, str(e)))

        # Decrypt
        name_dec = f"{vectors['algorithm']}/{v['name']}/decrypt"
        try:
            output = run_cli(cli, "ecies_decrypt", v["recipient_seed"], v["ciphertext"])
            parts = output.split(" ", 1)
            status = parts[0]
            cpp_pt = parts[1] if len(parts) > 1 else ""
            if status == "ok" and cpp_pt == v["plaintext"]:
                results.append((name_dec, True, ""))
            else:
                results.append(
                    (
                        name_dec,
                        False,
                        f"status={status}, pt: expected {v['plaintext']}, got {cpp_pt}",
                    )
                )
        except Exception as e:
            results.append((name_dec, False, str(e)))

    return results


def cross_validate_x25519_ecies(
    cli: Path, vectors: dict
) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        # Encrypt
        name_enc = f"{vectors['algorithm']}/{v['name']}/encrypt"
        try:
            cpp_ct = run_cli(
                cli,
                "x25519_ecies_encrypt",
                v["recipient_public_key"],
                v["entropy"],
                v["plaintext"],
            )
            if cpp_ct == v["ciphertext"]:
                results.append((name_enc, True, ""))
            else:
                results.append(
                    (name_enc, False, f"expected {v['ciphertext']}, got {cpp_ct}")
                )
        except Exception as e:
            results.append((name_enc, False, str(e)))

        # Decrypt
        name_dec = f"{vectors['algorithm']}/{v['name']}/decrypt"
        try:
            output = run_cli(
                cli, "x25519_ecies_decrypt", v["recipient_seed"], v["ciphertext"]
            )
            parts = output.split(" ", 1)
            status = parts[0]
            cpp_pt = parts[1] if len(parts) > 1 else ""
            if status == "ok" and cpp_pt == v["plaintext"]:
                results.append((name_dec, True, ""))
            else:
                results.append(
                    (
                        name_dec,
                        False,
                        f"status={status}, pt: expected {v['plaintext']}, got {cpp_pt}",
                    )
                )
        except Exception as e:
            results.append((name_dec, False, str(e)))

    return results


def cross_validate_x25519(cli: Path, vectors: dict) -> list[tuple[str, bool, str]]:
    results = []
    for v in vectors["vectors"]:
        # Alice public key
        name_apk = f"{vectors['algorithm']}/{v['name']}/alice_pubkey"
        try:
            cpp_pk = run_cli(cli, "x25519_pubkey", v["alice_private_key"])
            if cpp_pk == v["alice_public_key"]:
                results.append((name_apk, True, ""))
            else:
                results.append(
                    (name_apk, False, f"expected {v['alice_public_key']}, got {cpp_pk}")
                )
        except Exception as e:
            results.append((name_apk, False, str(e)))

        # Bob public key
        name_bpk = f"{vectors['algorithm']}/{v['name']}/bob_pubkey"
        try:
            cpp_pk = run_cli(cli, "x25519_pubkey", v["bob_private_key"])
            if cpp_pk == v["bob_public_key"]:
                results.append((name_bpk, True, ""))
            else:
                results.append(
                    (name_bpk, False, f"expected {v['bob_public_key']}, got {cpp_pk}")
                )
        except Exception as e:
            results.append((name_bpk, False, str(e)))

        # Shared secret (Alice SK * Bob PK)
        name_ss = f"{vectors['algorithm']}/{v['name']}/shared_secret"
        try:
            cpp_ss = run_cli(cli, "x25519", v["alice_private_key"], v["bob_public_key"])
            if cpp_ss == v["shared_secret"]:
                results.append((name_ss, True, ""))
            else:
                results.append(
                    (name_ss, False, f"expected {v['shared_secret']}, got {cpp_ss}")
                )
        except Exception as e:
            results.append((name_ss, False, str(e)))

    return results


#
# Python library cross-validation against C++ CLI
#


def cross_validate_python_library(cli: Path, vecgen) -> list[tuple[str, bool, str]]:
    """Cross-validate the statusbar_crypto Python library against C++ CLI output."""
    import statusbar_crypto as ac

    results = []

    # --- SHA-256 ---
    for v in vecgen.gen_sha256()["vectors"]:
        name = f"pylib/sha256/{v['name']}"
        try:
            msg = bytes.fromhex(v["message"]) if v["message"] else b""
            py_digest = ac.sha256(msg).hex()
            cpp_digest = run_cli(cli, "sha256", v["message"])
            if py_digest == cpp_digest:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"py={py_digest}, cpp={cpp_digest}"))
        except Exception as e:
            results.append((name, False, str(e)))

    # --- SHA-512 ---
    for v in vecgen.gen_sha512()["vectors"]:
        name = f"pylib/sha512/{v['name']}"
        try:
            msg = bytes.fromhex(v["message"]) if v["message"] else b""
            py_digest = ac.sha512(msg).hex()
            cpp_digest = run_cli(cli, "sha512", v["message"])
            if py_digest == cpp_digest:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"py={py_digest}, cpp={cpp_digest}"))
        except Exception as e:
            results.append((name, False, str(e)))

    # --- HMAC-SHA-256 ---
    for v in vecgen.gen_sha256_hmac()["vectors"]:
        name = f"pylib/sha256_hmac/{v['name']}"
        try:
            key = bytes.fromhex(v["key"])
            msg = bytes.fromhex(v["message"]) if v["message"] else b""
            py_mac = ac.sha256_hmac(key, msg).hex()
            cpp_mac = run_cli(cli, "sha256_hmac", v["key"], v["message"])
            if py_mac == cpp_mac:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"py={py_mac}, cpp={cpp_mac}"))
        except Exception as e:
            results.append((name, False, str(e)))

    # --- AES-128 Block ---
    for v in vecgen.gen_aes128_block()["vectors"]:
        name = f"pylib/aes128_block/{v['name']}/encrypt"
        try:
            key = ac.Aes128Key(data=bytes.fromhex(v["key"]))
            pt = bytes.fromhex(v["plaintext"])
            py_ct = ac.aes128_block_encrypt(key, pt).hex()
            cpp_ct = run_cli(cli, "aes128_encrypt", v["key"], v["plaintext"])
            if py_ct == cpp_ct:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"py={py_ct}, cpp={cpp_ct}"))
        except Exception as e:
            results.append((name, False, str(e)))

        name_dec = f"pylib/aes128_block/{v['name']}/decrypt"
        try:
            ct = bytes.fromhex(v["ciphertext"])
            py_pt = ac.aes128_block_decrypt(key, ct).hex()
            if py_pt == v["plaintext"]:
                results.append((name_dec, True, ""))
            else:
                results.append(
                    (name_dec, False, f"py={py_pt}, expected={v['plaintext']}")
                )
        except Exception as e:
            results.append((name_dec, False, str(e)))

    # --- AES-256 Block ---
    for v in vecgen.gen_aes256_block()["vectors"]:
        name = f"pylib/aes256_block/{v['name']}/encrypt"
        try:
            key = ac.Aes256Key(data=bytes.fromhex(v["key"]))
            pt = bytes.fromhex(v["plaintext"])
            py_ct = ac.aes256_block_encrypt(key, pt).hex()
            cpp_ct = run_cli(cli, "aes256_encrypt", v["key"], v["plaintext"])
            if py_ct == cpp_ct:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"py={py_ct}, cpp={cpp_ct}"))
        except Exception as e:
            results.append((name, False, str(e)))

        name_dec = f"pylib/aes256_block/{v['name']}/decrypt"
        try:
            ct = bytes.fromhex(v["ciphertext"])
            py_pt = ac.aes256_block_decrypt(key, ct).hex()
            if py_pt == v["plaintext"]:
                results.append((name_dec, True, ""))
            else:
                results.append(
                    (name_dec, False, f"py={py_pt}, expected={v['plaintext']}")
                )
        except Exception as e:
            results.append((name_dec, False, str(e)))

    # --- AES-128-CMAC ---
    for v in vecgen.gen_aes128_cmac()["vectors"]:
        name = f"pylib/aes128_cmac/{v['name']}"
        try:
            key = ac.Aes128Key(data=bytes.fromhex(v["key"]))
            msg = bytes.fromhex(v["message"]) if v["message"] else b""
            py_tag = ac.aes128_cmac(key, msg).hex()
            cpp_tag = run_cli(cli, "aes128_cmac", v["key"], v["message"])
            if py_tag == cpp_tag:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"py={py_tag}, cpp={cpp_tag}"))
        except Exception as e:
            results.append((name, False, str(e)))

    # --- AES-256-CMAC ---
    for v in vecgen.gen_aes256_cmac()["vectors"]:
        name = f"pylib/aes256_cmac/{v['name']}"
        try:
            key = ac.Aes256Key(data=bytes.fromhex(v["key"]))
            msg = bytes.fromhex(v["message"]) if v["message"] else b""
            py_tag = ac.aes256_cmac(key, msg).hex()
            cpp_tag = run_cli(cli, "aes256_cmac", v["key"], v["message"])
            if py_tag == cpp_tag:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"py={py_tag}, cpp={cpp_tag}"))
        except Exception as e:
            results.append((name, False, str(e)))

    # --- HKDF-SHA-256 ---
    for v in vecgen.gen_hkdf()["vectors"]:
        name_ext = f"pylib/hkdf/{v['name']}/extract"
        try:
            salt = bytes.fromhex(v["salt"]) if v["salt"] else b""
            ikm = bytes.fromhex(v["ikm"])
            py_prk = ac.hkdf_sha256_extract(salt, ikm).hex()
            cpp_prk = run_cli(cli, "hkdf_extract", v["salt"], v["ikm"])
            if py_prk == cpp_prk:
                results.append((name_ext, True, ""))
            else:
                results.append((name_ext, False, f"py={py_prk}, cpp={cpp_prk}"))
        except Exception as e:
            results.append((name_ext, False, str(e)))

        name_exp = f"pylib/hkdf/{v['name']}/expand"
        try:
            prk = bytes.fromhex(v["prk"])
            info = bytes.fromhex(v["info"]) if v["info"] else b""
            py_okm = ac.hkdf_sha256_expand(prk, info, v["okm_length"]).hex()
            cpp_okm = run_cli(
                cli, "hkdf_expand", v["prk"], v["info"], str(v["okm_length"])
            )
            if py_okm == cpp_okm:
                results.append((name_exp, True, ""))
            else:
                results.append((name_exp, False, f"py={py_okm}, cpp={cpp_okm}"))
        except Exception as e:
            results.append((name_exp, False, str(e)))

    # --- AES-128-SIV ---
    for v in vecgen.gen_aes128_siv()["vectors"]:
        name = f"pylib/aes128_siv/{v['name']}/encrypt"
        try:
            key = ac.Aes128SivKey(data=bytes.fromhex(v["key"]))
            pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            aad = bytes.fromhex(v["aad"]) if v["aad"] else b""
            siv, ct = ac.aes128_siv_encrypt(key, pt, aad)
            py_siv = siv.hex()
            py_ct = ct.hex()
            if py_siv == v["siv"] and py_ct == v["ciphertext"]:
                results.append((name, True, ""))
            else:
                results.append(
                    (
                        name,
                        False,
                        f"siv: py={py_siv} exp={v['siv']}, ct: py={py_ct} exp={v['ciphertext']}",
                    )
                )
        except Exception as e:
            results.append((name, False, str(e)))

        name_dec = f"pylib/aes128_siv/{v['name']}/decrypt"
        try:
            siv_bytes = bytes.fromhex(v["siv"])
            ct_bytes = bytes.fromhex(v["ciphertext"]) if v["ciphertext"] else b""
            ok, pt = ac.aes128_siv_decrypt(key, ct_bytes, siv_bytes, aad)
            expected_pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            if ok and pt == expected_pt:
                results.append((name_dec, True, ""))
            else:
                results.append((name_dec, False, f"ok={ok}, pt={pt.hex()}"))
        except Exception as e:
            results.append((name_dec, False, str(e)))

    # --- AES-256-SIV ---
    for v in vecgen.gen_aes256_siv()["vectors"]:
        name = f"pylib/aes256_siv/{v['name']}/encrypt"
        try:
            key = ac.Aes256SivKey(data=bytes.fromhex(v["key"]))
            pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            aad = bytes.fromhex(v["aad"]) if v["aad"] else b""
            siv, ct = ac.aes256_siv_encrypt(key, pt, aad)
            if siv.hex() == v["siv"] and ct.hex() == v["ciphertext"]:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"siv: py={siv.hex()} exp={v['siv']}"))
        except Exception as e:
            results.append((name, False, str(e)))

        name_dec = f"pylib/aes256_siv/{v['name']}/decrypt"
        try:
            siv_bytes = bytes.fromhex(v["siv"])
            ct_bytes = bytes.fromhex(v["ciphertext"]) if v["ciphertext"] else b""
            ok, dec_pt = ac.aes256_siv_decrypt(key, ct_bytes, siv_bytes, aad)
            expected_pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            if ok and dec_pt == expected_pt:
                results.append((name_dec, True, ""))
            else:
                results.append((name_dec, False, f"ok={ok}, pt={dec_pt.hex()}"))
        except Exception as e:
            results.append((name_dec, False, str(e)))

    # --- AES-128-GCM-SIV ---
    for v in vecgen.gen_aes128_gcm_siv()["vectors"]:
        name = f"pylib/aes128_gcm_siv/{v['name']}/encrypt"
        try:
            key = ac.Aes128Key(data=bytes.fromhex(v["key"]))
            nonce = bytes.fromhex(v["nonce"])
            pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            aad = bytes.fromhex(v["aad"]) if v["aad"] else b""
            tag, ct = ac.aes128_gcm_siv_encrypt(key, nonce, pt, aad)
            if tag.hex() == v["tag"] and ct.hex() == v["ciphertext"]:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"tag: py={tag.hex()} exp={v['tag']}"))
        except Exception as e:
            results.append((name, False, str(e)))

        name_dec = f"pylib/aes128_gcm_siv/{v['name']}/decrypt"
        try:
            tag_bytes = bytes.fromhex(v["tag"])
            ct_bytes = bytes.fromhex(v["ciphertext"]) if v["ciphertext"] else b""
            ok, dec_pt = ac.aes128_gcm_siv_decrypt(key, nonce, ct_bytes, tag_bytes, aad)
            expected_pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            if ok and dec_pt == expected_pt:
                results.append((name_dec, True, ""))
            else:
                results.append((name_dec, False, f"ok={ok}, pt={dec_pt.hex()}"))
        except Exception as e:
            results.append((name_dec, False, str(e)))

    # --- AES-256-GCM-SIV ---
    for v in vecgen.gen_aes256_gcm_siv()["vectors"]:
        name = f"pylib/aes256_gcm_siv/{v['name']}/encrypt"
        try:
            key = ac.Aes256Key(data=bytes.fromhex(v["key"]))
            nonce = bytes.fromhex(v["nonce"])
            pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            aad = bytes.fromhex(v["aad"]) if v["aad"] else b""
            tag, ct = ac.aes256_gcm_siv_encrypt(key, nonce, pt, aad)
            if tag.hex() == v["tag"] and ct.hex() == v["ciphertext"]:
                results.append((name, True, ""))
            else:
                results.append((name, False, f"tag: py={tag.hex()} exp={v['tag']}"))
        except Exception as e:
            results.append((name, False, str(e)))

        name_dec = f"pylib/aes256_gcm_siv/{v['name']}/decrypt"
        try:
            tag_bytes = bytes.fromhex(v["tag"])
            ct_bytes = bytes.fromhex(v["ciphertext"]) if v["ciphertext"] else b""
            ok, dec_pt = ac.aes256_gcm_siv_decrypt(key, nonce, ct_bytes, tag_bytes, aad)
            expected_pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            if ok and dec_pt == expected_pt:
                results.append((name_dec, True, ""))
            else:
                results.append((name_dec, False, f"ok={ok}, pt={dec_pt.hex()}"))
        except Exception as e:
            results.append((name_dec, False, str(e)))

    # --- Ed25519 ---
    for v in vecgen.gen_ed25519()["vectors"]:
        seed = bytes.fromhex(v["seed"])
        msg = bytes.fromhex(v["message"]) if v["message"] else b""

        name_pk = f"pylib/ed25519/{v['name']}/pubkey"
        try:
            sk = ac.ed25519_keypair_from_seed(seed)
            pk = ac.ed25519_public_key(sk)
            cpp_pk = run_cli(cli, "ed25519_pubkey", v["seed"])
            if pk.data.hex() == cpp_pk:
                results.append((name_pk, True, ""))
            else:
                results.append((name_pk, False, f"py={pk.data.hex()}, cpp={cpp_pk}"))
        except Exception as e:
            results.append((name_pk, False, str(e)))

        name_sig = f"pylib/ed25519/{v['name']}/sign"
        try:
            sig = ac.ed25519_sign(sk, msg)
            cpp_sig = run_cli(cli, "ed25519_sign", v["seed"], v["message"])
            if sig.data.hex() == cpp_sig:
                results.append((name_sig, True, ""))
            else:
                results.append((name_sig, False, f"py={sig.data.hex()}, cpp={cpp_sig}"))
        except Exception as e:
            results.append((name_sig, False, str(e)))

        name_ver = f"pylib/ed25519/{v['name']}/verify"
        try:
            ok = ac.ed25519_verify(pk, msg, sig)
            if ok:
                results.append((name_ver, True, ""))
            else:
                results.append((name_ver, False, "verify returned False"))
        except Exception as e:
            results.append((name_ver, False, str(e)))

    # --- X25519 ---
    for v in vecgen.gen_x25519()["vectors"]:
        name_apk = f"pylib/x25519/{v['name']}/alice_pubkey"
        try:
            alice = ac.x25519_keypair_from_seed(bytes.fromhex(v["alice_private_key"]))
            cpp_pk = run_cli(cli, "x25519_pubkey", v["alice_private_key"])
            if alice.public_key.data.hex() == cpp_pk:
                results.append((name_apk, True, ""))
            else:
                results.append(
                    (name_apk, False, f"py={alice.public_key.data.hex()}, cpp={cpp_pk}")
                )
        except Exception as e:
            results.append((name_apk, False, str(e)))

        name_ss = f"pylib/x25519/{v['name']}/shared_secret"
        try:
            bob = ac.x25519_keypair_from_seed(bytes.fromhex(v["bob_private_key"]))
            shared = ac.x25519(alice, bob.public_key)
            cpp_ss = run_cli(cli, "x25519", v["alice_private_key"], v["bob_public_key"])
            if shared.hex() == cpp_ss:
                results.append((name_ss, True, ""))
            else:
                results.append((name_ss, False, f"py={shared.hex()}, cpp={cpp_ss}"))
        except Exception as e:
            results.append((name_ss, False, str(e)))

    # --- P-256 ECDSA ---
    for v in vecgen.gen_p256_ecdsa()["vectors"]:
        seed = bytes.fromhex(v["seed"])
        msg = bytes.fromhex(v["message"]) if v["message"] else b""

        name_pk = f"pylib/p256_ecdsa/{v['name']}/pubkey"
        try:
            sk = ac.p256_ecdsa_keypair_from_seed(seed)
            cpp_pk = run_cli(cli, "p256_ecdsa_pubkey", v["seed"])
            if sk.public_key.data.hex() == cpp_pk:
                results.append((name_pk, True, ""))
            else:
                results.append(
                    (name_pk, False, f"py={sk.public_key.data.hex()}, cpp={cpp_pk}")
                )
        except Exception as e:
            results.append((name_pk, False, str(e)))

        name_sig = f"pylib/p256_ecdsa/{v['name']}/sign"
        try:
            sig = ac.p256_ecdsa_sign(sk, msg)
            cpp_sig = run_cli(cli, "p256_ecdsa_sign", v["seed"], v["message"])
            if sig.data.hex() == cpp_sig:
                results.append((name_sig, True, ""))
            else:
                results.append((name_sig, False, f"py={sig.data.hex()}, cpp={cpp_sig}"))
        except Exception as e:
            results.append((name_sig, False, str(e)))

        name_ver = f"pylib/p256_ecdsa/{v['name']}/verify"
        try:
            ok = ac.p256_ecdsa_verify(sk.public_key, msg, sig)
            if ok:
                results.append((name_ver, True, ""))
            else:
                results.append((name_ver, False, "verify returned False"))
        except Exception as e:
            results.append((name_ver, False, str(e)))

    # --- P-256 ECDH ---
    for v in vecgen.gen_p256_ecdh()["vectors"]:
        name_ss = f"pylib/p256_ecdh/{v['name']}/shared_secret"
        try:
            alice_sk = ac.p256_ecdsa_keypair_from_seed(bytes.fromhex(v["alice_seed"]))
            bob_sk = ac.p256_ecdsa_keypair_from_seed(bytes.fromhex(v["bob_seed"]))
            shared = ac.p256_ecdh(alice_sk, bob_sk.public_key)
            cpp_ss = run_cli(cli, "p256_ecdh", v["alice_seed"], v["bob_public_key"])
            if shared.hex() == cpp_ss:
                results.append((name_ss, True, ""))
            else:
                results.append((name_ss, False, f"py={shared.hex()}, cpp={cpp_ss}"))
        except Exception as e:
            results.append((name_ss, False, str(e)))

    # --- ECIES ---
    for v in vecgen.gen_ecies()["vectors"]:
        # Encrypt with Python, compare with C++
        name_enc = f"pylib/ecies/{v['name']}/encrypt"
        try:
            recipient_seed = bytes.fromhex(v["recipient_seed"])
            entropy = bytes.fromhex(v["entropy"])
            plaintext = bytes.fromhex(v["plaintext"])
            recipient_sk = ac.p256_ecdsa_keypair_from_seed(recipient_seed)
            py_ct = ac.ecies_encrypt(recipient_sk.public_key, plaintext, entropy)
            cpp_ct = run_cli(
                cli,
                "ecies_encrypt",
                v["recipient_public_key"],
                v["entropy"],
                v["plaintext"],
            )
            if py_ct.hex() == cpp_ct:
                results.append((name_enc, True, ""))
            else:
                results.append((name_enc, False, f"py={py_ct.hex()}, cpp={cpp_ct}"))
        except Exception as e:
            results.append((name_enc, False, str(e)))

        # Decrypt C++ ciphertext with Python
        name_dec = f"pylib/ecies/{v['name']}/decrypt"
        try:
            cpp_ct_bytes = bytes.fromhex(cpp_ct)
            py_pt = ac.ecies_decrypt(recipient_sk, cpp_ct_bytes)
            if py_pt == plaintext:
                results.append((name_dec, True, ""))
            else:
                results.append(
                    (name_dec, False, f"py={py_pt.hex()}, expected={plaintext.hex()}")
                )
        except Exception as e:
            results.append((name_dec, False, str(e)))

    # --- X25519 ECIES ---
    for v in vecgen.gen_x25519_ecies()["vectors"]:
        # Encrypt with Python, compare with C++
        name_enc = f"pylib/x25519_ecies/{v['name']}/encrypt"
        try:
            recipient_seed = bytes.fromhex(v["recipient_seed"])
            entropy = bytes.fromhex(v["entropy"])
            plaintext = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            recipient_sk = ac.x25519_keypair_from_seed(recipient_seed)
            py_ct = ac.x25519_ecies_encrypt(recipient_sk.public_key, plaintext, entropy)
            cpp_ct = run_cli(
                cli,
                "x25519_ecies_encrypt",
                v["recipient_public_key"],
                v["entropy"],
                v["plaintext"],
            )
            if py_ct.hex() == cpp_ct:
                results.append((name_enc, True, ""))
            else:
                results.append((name_enc, False, f"py={py_ct.hex()}, cpp={cpp_ct}"))
        except Exception as e:
            results.append((name_enc, False, str(e)))

        # Decrypt C++ ciphertext with Python
        name_dec = f"pylib/x25519_ecies/{v['name']}/decrypt"
        try:
            cpp_ct_bytes = bytes.fromhex(cpp_ct)
            py_pt = ac.x25519_ecies_decrypt(recipient_sk, cpp_ct_bytes)
            expected_pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            if py_pt == expected_pt:
                results.append((name_dec, True, ""))
            else:
                results.append(
                    (name_dec, False, f"py={py_pt.hex()}, expected={expected_pt.hex()}")
                )
        except Exception as e:
            results.append((name_dec, False, str(e)))

    # --- Ed25519-to-X25519 conversion ---
    for v in vecgen.gen_ed25519()["vectors"]:
        seed = bytes.fromhex(v["seed"])
        ed_sk = ac.ed25519_keypair_from_seed(seed)

        name_conv_pk = f"pylib/ed25519_to_x25519/{v['name']}/pk"
        try:
            x_pk = ac.ed25519_pk_to_x25519_pk(ed_sk.public_key)
            cpp_x_pk = run_cli(cli, "ed25519_to_x25519_pk", v["public_key"])
            if x_pk.data.hex() == cpp_x_pk:
                results.append((name_conv_pk, True, ""))
            else:
                results.append(
                    (name_conv_pk, False, f"py={x_pk.data.hex()}, cpp={cpp_x_pk}")
                )
        except Exception as e:
            results.append((name_conv_pk, False, str(e)))

        name_conv_sk = f"pylib/ed25519_to_x25519/{v['name']}/sk"
        try:
            x_sk = ac.ed25519_sk_to_x25519_sk(ed_sk)
            cpp_output = run_cli(cli, "ed25519_to_x25519_sk", v["seed"])
            parts = cpp_output.split(" ")
            cpp_x_sk = parts[0]
            cpp_x_pk = parts[1] if len(parts) > 1 else ""
            if x_sk.data.hex() == cpp_x_sk and x_sk.public_key.data.hex() == cpp_x_pk:
                results.append((name_conv_sk, True, ""))
            else:
                msg = ""
                if x_sk.data.hex() != cpp_x_sk:
                    msg += f"sk: py={x_sk.data.hex()}, cpp={cpp_x_sk}. "
                if x_sk.public_key.data.hex() != cpp_x_pk:
                    msg += f"pk: py={x_sk.public_key.data.hex()}, cpp={cpp_x_pk}."
                results.append((name_conv_sk, False, msg))
        except Exception as e:
            results.append((name_conv_sk, False, str(e)))

    return results


#
# PKCS#8 / SPKI DER cross-validation (Python cryptography lib vs C++ CLI)
#


def cross_validate_pkcs8_spki(cli: Path) -> list[tuple[str, bool, str]]:
    """Cross-validate PKCS#8 and SPKI DER encoding between Python and C++."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        derive_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        PrivateFormat,
        NoEncryption,
    )

    results = []
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    # ------------------------------------------------------------------
    # P-256 SPKI: Python export → C++ import, and C++ export → byte match
    # ------------------------------------------------------------------
    p256_seeds = [
        ("seed_1_to_32", bytes(range(1, 33))),
        ("zero_seed", bytes(32)),
    ]

    for vec_name, seed in p256_seeds:
        import hashlib

        h = hashlib.sha256(seed).digest()
        d = int.from_bytes(h, "big") % n
        if d == 0:
            d = 1
        p256_sk = derive_private_key(d, SECP256R1())
        p256_pk = p256_sk.public_key()
        pub_nums = p256_pk.public_numbers()
        pk_xy = pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")

        # Python SPKI DER
        py_spki = p256_pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Test 1: Python SPKI → C++ import
        name = f"pkcs8_spki/p256_spki/{vec_name}/py_to_cpp"
        try:
            output = run_cli(cli, "spki_import_p256", py_spki.hex())
            parts = output.split(" ", 1)
            if parts[0] == "ok" and parts[1] == pk_xy.hex():
                results.append((name, True, ""))
            else:
                results.append(
                    (name, False, f"expected ok {pk_xy.hex()}, got {output}")
                )
        except Exception as e:
            results.append((name, False, str(e)))

        # Test 2: C++ SPKI export → byte-for-byte match with Python
        name = f"pkcs8_spki/p256_spki/{vec_name}/cpp_export_match"
        try:
            cpp_spki = run_cli(cli, "spki_export_p256", pk_xy.hex())
            if cpp_spki == py_spki.hex():
                results.append((name, True, ""))
            else:
                results.append(
                    (
                        name,
                        False,
                        f"DER mismatch: cpp={cpp_spki[:40]}... py={py_spki.hex()[:40]}...",
                    )
                )
        except Exception as e:
            results.append((name, False, str(e)))

    # ------------------------------------------------------------------
    # P-256 PKCS#8: Python export → C++ import
    # ------------------------------------------------------------------
    for vec_name, seed in p256_seeds:
        import hashlib

        h = hashlib.sha256(seed).digest()
        d = int.from_bytes(h, "big") % n
        if d == 0:
            d = 1
        p256_sk = derive_private_key(d, SECP256R1())
        pub_nums = p256_sk.public_key().public_numbers()
        pk_xy = pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
        scalar_bytes = d.to_bytes(32, "big")

        # Python PKCS#8 DER (OpenSSL-style, includes optional publicKey)
        py_pkcs8 = p256_sk.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

        # Test: Python PKCS#8 → C++ import
        name = f"pkcs8_spki/p256_pkcs8/{vec_name}/py_to_cpp"
        try:
            output = run_cli(cli, "pkcs8_import_p256", py_pkcs8.hex())
            parts = output.split(" ", 2)
            if (
                parts[0] == "ok"
                and parts[1] == scalar_bytes.hex()
                and parts[2] == pk_xy.hex()
            ):
                results.append((name, True, ""))
            else:
                results.append(
                    (
                        name,
                        False,
                        f"expected ok {scalar_bytes.hex()} {pk_xy.hex()}, got {output}",
                    )
                )
        except Exception as e:
            results.append((name, False, str(e)))

        # Test: C++ PKCS#8 export → Python import roundtrip
        name = f"pkcs8_spki/p256_pkcs8/{vec_name}/cpp_to_py"
        try:
            cpp_pkcs8 = run_cli(cli, "pkcs8_export_p256", scalar_bytes.hex())
            from cryptography.hazmat.primitives.serialization import (
                load_der_private_key,
            )

            recovered_sk = load_der_private_key(bytes.fromhex(cpp_pkcs8), password=None)
            recovered_d = recovered_sk.private_numbers().private_value
            if recovered_d == d:
                results.append((name, True, ""))
            else:
                results.append(
                    (name, False, f"scalar mismatch: expected {d}, got {recovered_d}")
                )
        except Exception as e:
            results.append((name, False, str(e)))

    # ------------------------------------------------------------------
    # Ed25519 SPKI: Python export → C++ import, and C++ export → byte match
    # ------------------------------------------------------------------
    ed25519_seeds = [
        (
            "rfc8032_vector1",
            bytes.fromhex(
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
            ),
        ),
        (
            "rfc8032_vector2",
            bytes.fromhex(
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
            ),
        ),
    ]

    for vec_name, seed in ed25519_seeds:
        ed_sk = Ed25519PrivateKey.from_private_bytes(seed)
        ed_pk = ed_sk.public_key()
        pk_bytes = ed_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Python SPKI DER
        py_spki = ed_pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Test 1: Python SPKI → C++ import
        name = f"pkcs8_spki/ed25519_spki/{vec_name}/py_to_cpp"
        try:
            output = run_cli(cli, "spki_import_ed25519", py_spki.hex())
            parts = output.split(" ", 1)
            if parts[0] == "ok" and parts[1] == pk_bytes.hex():
                results.append((name, True, ""))
            else:
                results.append(
                    (name, False, f"expected ok {pk_bytes.hex()}, got {output}")
                )
        except Exception as e:
            results.append((name, False, str(e)))

        # Test 2: C++ SPKI export → byte-for-byte match with Python
        name = f"pkcs8_spki/ed25519_spki/{vec_name}/cpp_export_match"
        try:
            cpp_spki = run_cli(cli, "spki_export_ed25519", pk_bytes.hex())
            if cpp_spki == py_spki.hex():
                results.append((name, True, ""))
            else:
                results.append(
                    (
                        name,
                        False,
                        f"DER mismatch: cpp={cpp_spki[:40]}... py={py_spki.hex()[:40]}...",
                    )
                )
        except Exception as e:
            results.append((name, False, str(e)))

    # ------------------------------------------------------------------
    # Ed25519 PKCS#8: Python export → C++ import
    # ------------------------------------------------------------------
    for vec_name, seed in ed25519_seeds:
        ed_sk = Ed25519PrivateKey.from_private_bytes(seed)
        ed_pk = ed_sk.public_key()
        pk_bytes = ed_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Python PKCS#8 DER (may include optional [1] publicKey)
        py_pkcs8 = ed_sk.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

        # Test: Python PKCS#8 → C++ import → verify pubkey matches
        name = f"pkcs8_spki/ed25519_pkcs8/{vec_name}/py_to_cpp"
        try:
            output = run_cli(cli, "pkcs8_import_ed25519", py_pkcs8.hex())
            parts = output.split(" ", 1)
            if parts[0] == "ok" and parts[1] == pk_bytes.hex():
                results.append((name, True, ""))
            else:
                results.append(
                    (name, False, f"expected ok {pk_bytes.hex()}, got {output}")
                )
        except Exception as e:
            results.append((name, False, str(e)))

        # Test: C++ PKCS#8 export → Python import roundtrip
        name = f"pkcs8_spki/ed25519_pkcs8/{vec_name}/cpp_to_py"
        try:
            cpp_pkcs8 = run_cli(cli, "pkcs8_export_ed25519", seed.hex())
            from cryptography.hazmat.primitives.serialization import (
                load_der_private_key,
            )

            recovered_sk = load_der_private_key(bytes.fromhex(cpp_pkcs8), password=None)
            recovered_pk = recovered_sk.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            if recovered_pk == pk_bytes:
                results.append((name, True, ""))
            else:
                results.append(
                    (
                        name,
                        False,
                        f"pk mismatch: expected {pk_bytes.hex()}, got {recovered_pk.hex()}",
                    )
                )
        except Exception as e:
            results.append((name, False, str(e)))

    return results


#
# Main
#


def main():
    parser = argparse.ArgumentParser(
        description="Cross-validate Python test vectors against statusbar_crypto C++ CLI"
    )
    parser.add_argument(
        "--build-dir",
        "-b",
        default="build-Debug",
        help="Build directory (default: build-Debug)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="CLI subprocess timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    global CLI_TIMEOUT
    CLI_TIMEOUT = args.timeout

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    build_dir = repo_root / args.build_dir

    if not build_dir.is_dir():
        print(f"ERROR: Build directory not found: {build_dir}", file=sys.stderr)
        print(f"  Try: make build", file=sys.stderr)
        sys.exit(1)

    # Search for the avtp_crypto CLI binary across the build layouts this
    # script may run under: a standalone / monolithic build, and the split
    # aggregate export build where avtp_crypto ships in the avb package.
    cli_candidates = [
        build_dir
        / "statusbar"
        / "avtp_crypto"
        / "statusbar-avtp-crypto-tool",  # new name
        build_dir / "statusbar" / "avtp_crypto" / "avtp_crypto_tool",  # legacy name
        build_dir
        / "statusbar-avb"
        / "statusbar"
        / "avtp_crypto"
        / "statusbar-avtp-crypto-tool",  # aggregate export build (avb package)
    ]
    # Fallback: any matching binary anywhere under the build tree, so a
    # future layout change does not silently rebreak this lookup.
    cli_candidates += sorted(build_dir.glob("**/statusbar-avtp-crypto-tool"))
    cli_path = next((p for p in cli_candidates if p.is_file()), None)
    if cli_path is None:
        # avtp_crypto ships in the avb package; a standalone crypto build
        # cannot produce this tool. Skip rather than fail — CTest treats
        # exit 77 as "skipped" via SKIP_RETURN_CODE on the test (see
        # crypto/CMakeLists.txt).
        print(
            "SKIP: avtp_crypto CLI tool not found (needs the avb package); "
            f"searched under {build_dir}",
            file=sys.stderr,
        )
        sys.exit(77)

    # Import vector generator and Python library
    sys.path.insert(0, str(script_dir))
    import avtp_crypto_vectors as vecgen

    print(f"CLI tool: {cli_path}")
    print()

    all_results: list[tuple[str, bool, str]] = []

    # Part 1: Python vectors vs C++ CLI (existing)
    print("Part 1: Python test vectors vs C++ CLI")

    dispatch = [
        (
            "aes128_block",
            vecgen.gen_aes128_block,
            lambda cli, v: cross_validate_aes_block(cli, v, "aes128"),
        ),
        (
            "aes256_block",
            vecgen.gen_aes256_block,
            lambda cli, v: cross_validate_aes_block(cli, v, "aes256"),
        ),
        (
            "aes128_cmac",
            vecgen.gen_aes128_cmac,
            lambda cli, v: cross_validate_cmac(cli, v, "aes128_cmac"),
        ),
        (
            "aes256_cmac",
            vecgen.gen_aes256_cmac,
            lambda cli, v: cross_validate_cmac(cli, v, "aes256_cmac"),
        ),
        (
            "aes128_siv",
            vecgen.gen_aes128_siv,
            lambda cli, v: cross_validate_siv(cli, v, "aes128_siv"),
        ),
        (
            "aes256_siv",
            vecgen.gen_aes256_siv,
            lambda cli, v: cross_validate_siv(cli, v, "aes256_siv"),
        ),
        (
            "aes128_gcm_siv",
            vecgen.gen_aes128_gcm_siv,
            lambda cli, v: cross_validate_gcm_siv(cli, v, "aes128_gcm_siv"),
        ),
        (
            "aes256_gcm_siv",
            vecgen.gen_aes256_gcm_siv,
            lambda cli, v: cross_validate_gcm_siv(cli, v, "aes256_gcm_siv"),
        ),
        (
            "sha256",
            vecgen.gen_sha256,
            lambda cli, v: cross_validate_sha(cli, v, "sha256"),
        ),
        (
            "sha512",
            vecgen.gen_sha512,
            lambda cli, v: cross_validate_sha(cli, v, "sha512"),
        ),
        (
            "sha256_hmac",
            vecgen.gen_sha256_hmac,
            lambda cli, v: cross_validate_hmac(cli, v),
        ),
        ("hkdf_sha256", vecgen.gen_hkdf, lambda cli, v: cross_validate_hkdf(cli, v)),
        ("ed25519", vecgen.gen_ed25519, lambda cli, v: cross_validate_ed25519(cli, v)),
        ("x25519", vecgen.gen_x25519, lambda cli, v: cross_validate_x25519(cli, v)),
        (
            "p256_ecdsa",
            vecgen.gen_p256_ecdsa,
            lambda cli, v: cross_validate_p256_ecdsa(cli, v),
        ),
        (
            "p256_ecdh",
            vecgen.gen_p256_ecdh,
            lambda cli, v: cross_validate_p256_ecdh(cli, v),
        ),
        ("ecies", vecgen.gen_ecies, lambda cli, v: cross_validate_ecies(cli, v)),
        (
            "x25519_ecies",
            vecgen.gen_x25519_ecies,
            lambda cli, v: cross_validate_x25519_ecies(cli, v),
        ),
        # Hardware-accelerated variants (same vectors, _hw CLI commands)
        (
            "aes128_block_hw",
            vecgen.gen_aes128_block,
            lambda cli, v: cross_validate_aes_block(
                cli, v, "aes128", "aes128_encrypt_hw"
            ),
        ),
        (
            "aes256_block_hw",
            vecgen.gen_aes256_block,
            lambda cli, v: cross_validate_aes_block(
                cli, v, "aes256", "aes256_encrypt_hw"
            ),
        ),
        (
            "aes128_cmac_hw",
            vecgen.gen_aes128_cmac,
            lambda cli, v: cross_validate_cmac(cli, v, "aes128_cmac_hw"),
        ),
        (
            "aes256_cmac_hw",
            vecgen.gen_aes256_cmac,
            lambda cli, v: cross_validate_cmac(cli, v, "aes256_cmac_hw"),
        ),
        (
            "sha256_hw",
            vecgen.gen_sha256,
            lambda cli, v: cross_validate_sha(cli, v, "sha256_hw"),
        ),
        (
            "sha512_hw",
            vecgen.gen_sha512,
            lambda cli, v: cross_validate_sha(cli, v, "sha512_hw"),
        ),
        (
            "sha256_hmac_hw",
            vecgen.gen_sha256_hmac,
            lambda cli, v: cross_validate_hmac(cli, v, "sha256_hmac_hw"),
        ),
    ]

    for algo_name, gen_func, validate_func in dispatch:
        vectors = gen_func()
        results = validate_func(cli_path, vectors)
        all_results.extend(results)

        algo_pass = all(r[1] for r in results)
        icon = "+" if algo_pass else "X"
        count = len(results)
        passed = sum(1 for r in results if r[1])
        print(f"  [{icon}] {algo_name}: {passed}/{count} vectors match")

        if args.verbose or not algo_pass:
            for name, ok, msg in results:
                if not ok:
                    print(f"      MISMATCH: {name}: {msg}")

    # Part 2: Python library vs C++ CLI
    print()
    print("Part 2: Python statusbar_crypto library vs C++ CLI")

    pylib_results = cross_validate_python_library(cli_path, vecgen)
    all_results.extend(pylib_results)

    # Group by algorithm prefix for display
    algo_groups: dict[str, list[tuple[str, bool, str]]] = {}
    for name, ok, msg in pylib_results:
        # Extract algo from "pylib/algo/..."
        parts = name.split("/")
        algo = parts[1] if len(parts) > 1 else name
        algo_groups.setdefault(algo, []).append((name, ok, msg))

    for algo, group_results in algo_groups.items():
        algo_pass = all(r[1] for r in group_results)
        icon = "+" if algo_pass else "X"
        count = len(group_results)
        passed = sum(1 for r in group_results if r[1])
        print(f"  [{icon}] {algo}: {passed}/{count} tests match")

        if args.verbose or not algo_pass:
            for name, ok, msg in group_results:
                if not ok:
                    print(f"      MISMATCH: {name}: {msg}")

    # Part 3: PKCS#8 / SPKI DER cross-validation
    print()
    print("Part 3: PKCS#8 / SPKI DER encoding (Python cryptography vs C++ CLI)")

    pkcs8_results = cross_validate_pkcs8_spki(cli_path)
    all_results.extend(pkcs8_results)

    # Group by algorithm prefix for display
    pkcs8_groups: dict[str, list[tuple[str, bool, str]]] = {}
    for name, ok, msg in pkcs8_results:
        # Extract algo from "pkcs8_spki/algo/..."
        parts = name.split("/")
        algo = parts[1] if len(parts) > 1 else name
        pkcs8_groups.setdefault(algo, []).append((name, ok, msg))

    for algo, group_results in pkcs8_groups.items():
        algo_pass = all(r[1] for r in group_results)
        icon = "+" if algo_pass else "X"
        count = len(group_results)
        passed = sum(1 for r in group_results if r[1])
        print(f"  [{icon}] {algo}: {passed}/{count} tests match")

        if args.verbose or not algo_pass:
            for name, ok, msg in group_results:
                if not ok:
                    print(f"      MISMATCH: {name}: {msg}")

    # Part 4: Rust CLI cross-validation (optional — skipped if binary not found)
    rust_candidates = [
        # Corrosion build (CMake integrates Rust via FetchContent)
        # Corrosion build (CMake integrates Rust via FetchContent)
        build_dir
        / "cargo"
        / "build"
        / "aarch64-unknown-linux-gnu"
        / "debug"
        / "statusbar-crypto-cli-rs",
        build_dir
        / "cargo"
        / "build"
        / "aarch64-unknown-linux-gnu"
        / "release"
        / "statusbar-crypto-cli-rs",
        build_dir
        / "cargo"
        / "build"
        / "x86_64-unknown-linux-gnu"
        / "debug"
        / "statusbar-crypto-cli-rs",
        build_dir
        / "cargo"
        / "build"
        / "x86_64-unknown-linux-gnu"
        / "release"
        / "statusbar-crypto-cli-rs",
        # Standalone Rust build (cargo build from rust/ directory)
        repo_root / "rust" / "target" / "debug" / "statusbar-crypto-cli-rs",
        repo_root / "rust" / "target" / "release" / "statusbar-crypto-cli-rs",
    ]
    rust_cli = next((p for p in rust_candidates if p.is_file()), None)

    if rust_cli is not None:
        print()
        print(f"Part 4: Python test vectors vs Rust CLI ({rust_cli.name})")

        # Same dispatch as Part 1, but skip _hw variants and x25519_ecies (not in Rust)
        rust_dispatch = [
            (
                "aes128_block",
                vecgen.gen_aes128_block,
                lambda cli, v: cross_validate_aes_block(cli, v, "aes128"),
            ),
            (
                "aes256_block",
                vecgen.gen_aes256_block,
                lambda cli, v: cross_validate_aes_block(cli, v, "aes256"),
            ),
            (
                "aes128_cmac",
                vecgen.gen_aes128_cmac,
                lambda cli, v: cross_validate_cmac(cli, v, "aes128_cmac"),
            ),
            (
                "aes256_cmac",
                vecgen.gen_aes256_cmac,
                lambda cli, v: cross_validate_cmac(cli, v, "aes256_cmac"),
            ),
            (
                "aes128_siv",
                vecgen.gen_aes128_siv,
                lambda cli, v: cross_validate_siv(cli, v, "aes128_siv"),
            ),
            (
                "aes256_siv",
                vecgen.gen_aes256_siv,
                lambda cli, v: cross_validate_siv(cli, v, "aes256_siv"),
            ),
            (
                "aes128_gcm_siv",
                vecgen.gen_aes128_gcm_siv,
                lambda cli, v: cross_validate_gcm_siv(cli, v, "aes128_gcm_siv"),
            ),
            (
                "aes256_gcm_siv",
                vecgen.gen_aes256_gcm_siv,
                lambda cli, v: cross_validate_gcm_siv(cli, v, "aes256_gcm_siv"),
            ),
            (
                "sha256",
                vecgen.gen_sha256,
                lambda cli, v: cross_validate_sha(cli, v, "sha256"),
            ),
            (
                "sha512",
                vecgen.gen_sha512,
                lambda cli, v: cross_validate_sha(cli, v, "sha512"),
            ),
            (
                "sha256_hmac",
                vecgen.gen_sha256_hmac,
                lambda cli, v: cross_validate_hmac(cli, v),
            ),
            (
                "hkdf_sha256",
                vecgen.gen_hkdf,
                lambda cli, v: cross_validate_hkdf(cli, v),
            ),
            (
                "ed25519",
                vecgen.gen_ed25519,
                lambda cli, v: cross_validate_ed25519(cli, v),
            ),
            ("x25519", vecgen.gen_x25519, lambda cli, v: cross_validate_x25519(cli, v)),
            (
                "p256_ecdsa",
                vecgen.gen_p256_ecdsa,
                lambda cli, v: cross_validate_p256_ecdsa(cli, v),
            ),
            (
                "p256_ecdh",
                vecgen.gen_p256_ecdh,
                lambda cli, v: cross_validate_p256_ecdh(cli, v),
            ),
            ("ecies", vecgen.gen_ecies, lambda cli, v: cross_validate_ecies(cli, v)),
        ]

        for algo_name, gen_func, validate_func in rust_dispatch:
            vectors = gen_func()
            results = validate_func(rust_cli, vectors)
            all_results.extend([(f"rust/{name}", ok, msg) for name, ok, msg in results])

            algo_pass = all(r[1] for r in results)
            icon = "+" if algo_pass else "X"
            count = len(results)
            passed_count = sum(1 for r in results if r[1])
            print(f"  [{icon}] {algo_name}: {passed_count}/{count} vectors match")

            if args.verbose or not algo_pass:
                for name, ok, msg in results:
                    if not ok:
                        print(f"      MISMATCH: {name}: {msg}")

        # Rust PKCS#8/SPKI
        print()
        print("Part 4b: PKCS#8 / SPKI DER (Python cryptography vs Rust CLI)")
        rust_pkcs8_results = cross_validate_pkcs8_spki(rust_cli)
        all_results.extend(
            [(f"rust/{name}", ok, msg) for name, ok, msg in rust_pkcs8_results]
        )

        rust_pkcs8_groups: dict[str, list[tuple[str, bool, str]]] = {}
        for name, ok, msg in rust_pkcs8_results:
            parts = name.split("/")
            algo = parts[1] if len(parts) > 1 else name
            rust_pkcs8_groups.setdefault(algo, []).append((name, ok, msg))

        for algo, group_results in rust_pkcs8_groups.items():
            algo_pass = all(r[1] for r in group_results)
            icon = "+" if algo_pass else "X"
            count = len(group_results)
            passed_count = sum(1 for r in group_results if r[1])
            print(f"  [{icon}] {algo}: {passed_count}/{count} tests match")

            if args.verbose or not algo_pass:
                for name, ok, msg in group_results:
                    if not ok:
                        print(f"      MISMATCH: {name}: {msg}")

    else:
        print()
        print(
            "Part 4: Rust CLI (skipped — binary not found, build with: cd rust && cargo build)"
        )

    # Summary — separate C++ (required) from Rust (informational)
    cpp_results = [(n, o, m) for n, o, m in all_results if not n.startswith("rust/")]
    rust_results = [(n, o, m) for n, o, m in all_results if n.startswith("rust/")]

    cpp_total = len(cpp_results)
    cpp_passed = sum(1 for r in cpp_results if r[1])
    cpp_failed = cpp_total - cpp_passed

    rust_total = len(rust_results)
    rust_passed = sum(1 for r in rust_results if r[1])
    rust_failed = rust_total - rust_passed

    print()
    print(
        f"C++ cross-validation: {cpp_passed} passed, {cpp_failed} failed, {cpp_total} total"
    )
    if rust_total > 0:
        print(
            f"Rust cross-validation: {rust_passed} passed, {rust_failed} failed, {rust_total} total"
        )

    if cpp_failed > 0:
        print()
        print("C++ mismatches (FATAL):")
        for name, ok, msg in cpp_results:
            if not ok:
                print(f"  {name}: {msg}")

    if rust_failed > 0:
        print()
        print("Rust mismatches (informational):")
        for name, ok, msg in rust_results:
            if not ok:
                print(f"  {name}: {msg}")

    # Only fail on C++ mismatches — Rust failures are informational
    if cpp_failed > 0:
        sys.exit(1)
    else:
        print()
        print("All required tests pass.")


if __name__ == "__main__":
    main()
