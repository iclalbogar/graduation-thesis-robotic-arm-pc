"""Crypto primitives for the secure channel.

No USB imports here. Everything is pure in-memory transforms:
- ECDH P-256 (raw 64-byte X||Y public keys)
- NIST SP800-56C one-step KDF with H=SHA-256, matching NXP ELS
  mcuxClEls_Hkdf_Sp80056c_Async. ELS forbids setting AES/CMAC usage bits
  directly on an ECDH output slot; HKDF-56c outputs 32 bytes to plain RAM,
  which the MCU then feeds to ELS AES/CMAC via extkey=ENABLE. The PC side
  reproduces the KDF in software so both sides arrive at byte-identical
  session keys.
- AES-256-CBC + AES-256-CMAC encrypt-then-MAC record format.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


CURVE = ec.SECP256R1()
PUBKEY_COORD_SIZE = 32
PUBKEY_RAW_SIZE = 64  # X || Y
SHARED_SECRET_SIZE = 32
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16
IV_SIZE = 16
CMAC_TAG_SIZE = 16

# FixedInfo for the HKDF calls. Kept at 12 bytes (legacy CKDF size) for parity
# with the MCU-side constants; HKDF-56c allows any length. Must match the
# MCU label arrays in source/secure_channel.c exactly.
HKDF_LABEL_SIZE  = 12
HKDF_LABEL_KCBC  = b"MCXN:KCBC:00"
HKDF_LABEL_KCMAC = b"MCXN:KMAC:00"
assert len(HKDF_LABEL_KCBC)  == HKDF_LABEL_SIZE
assert len(HKDF_LABEL_KCMAC) == HKDF_LABEL_SIZE

MSG_ENC_DATA = 0x10  # must match protocol.MSG_ENC_DATA; duplicated to avoid import cycle


class CryptoError(Exception):
    pass


def generate_ecdh_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Return (private_key, raw_64B_public_key)."""
    priv = ec.generate_private_key(CURVE)
    return priv, _serialize_public_raw(priv.public_key())


def _serialize_public_raw(pub: ec.EllipticCurvePublicKey) -> bytes:
    nums = pub.public_numbers()
    x = nums.x.to_bytes(PUBKEY_COORD_SIZE, "big")
    y = nums.y.to_bytes(PUBKEY_COORD_SIZE, "big")
    return x + y


def public_key_from_raw(raw: bytes) -> ec.EllipticCurvePublicKey:
    if len(raw) != PUBKEY_RAW_SIZE:
        raise CryptoError(f"raw pubkey must be {PUBKEY_RAW_SIZE}B, got {len(raw)}B")
    x = int.from_bytes(raw[:PUBKEY_COORD_SIZE], "big")
    y = int.from_bytes(raw[PUBKEY_COORD_SIZE:], "big")
    try:
        return ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key()
    except ValueError as e:
        raise CryptoError(f"invalid P-256 point: {e}") from e


def derive_shared_secret(
    private_key: ec.EllipticCurvePrivateKey, peer_pub_raw: bytes
) -> bytes:
    peer = public_key_from_raw(peer_pub_raw)
    z = private_key.exchange(ec.ECDH(), peer)
    if len(z) != SHARED_SECRET_SIZE:
        raise CryptoError(f"unexpected ECDH secret length: {len(z)}")
    return z


def _hkdf_sp80056c_sha256(z: bytes, fixed_info: bytes, n_bytes: int) -> bytes:
    """NIST SP800-56C one-step KDF with H = SHA-256.

    For each counter i = 1..reps:
        K(i) = SHA256([i]_4BE || z || fixed_info)
    Output = concat(K(1), K(2), ...) truncated to n_bytes.

    Matches mcuxClEls_Hkdf_Sp80056c_Async on the MCU (which emits one 32-byte
    block per call). Callers that need 32 bytes get exactly reps=1.
    """
    if len(z) != SHARED_SECRET_SIZE:
        raise CryptoError(f"Z must be {SHARED_SECRET_SIZE}B, got {len(z)}B")
    hash_len = 32
    reps = (n_bytes + hash_len - 1) // hash_len
    out = b""
    for i in range(1, reps + 1):
        h = hashlib.sha256()
        h.update(i.to_bytes(4, "big"))
        h.update(z)
        h.update(fixed_info)
        out += h.digest()
    return out[:n_bytes]


def derive_session_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    """Derive (K_CBC, K_CMAC) via HKDF-SP800-56C with Z as the derivation key.

    Mirrors the two HKDF-56c calls the MCU issues after ECDH; byte-equal
    output is what lets the two sides agree on the session keys.
    """
    if len(shared_secret) != AES_KEY_SIZE:
        raise CryptoError(f"shared secret must be {AES_KEY_SIZE}B, got {len(shared_secret)}B")
    k_cbc  = _hkdf_sp80056c_sha256(shared_secret, HKDF_LABEL_KCBC,  AES_KEY_SIZE)
    k_cmac = _hkdf_sp80056c_sha256(shared_secret, HKDF_LABEL_KCMAC, AES_KEY_SIZE)
    return k_cbc, k_cmac


def _cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def _cmac_verify(key: bytes, data: bytes, tag: bytes) -> None:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    try:
        c.verify(tag)
    except InvalidSignature as e:
        raise CryptoError("CMAC mismatch") from e


def encrypt(k_cbc: bytes, k_cmac: bytes, plaintext: bytes) -> bytes:
    """Return IV || CT || TAG. IV is fresh-random per message."""
    iv = os.urandom(IV_SIZE)
    pad = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded = pad.update(plaintext) + pad.finalize()

    enc = Cipher(algorithms.AES(k_cbc), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()

    tag = _cmac(k_cmac, bytes([MSG_ENC_DATA]) + iv + ct)
    return iv + ct + tag


def decrypt(k_cbc: bytes, k_cmac: bytes, record: bytes) -> bytes:
    """Verify the CMAC before decrypting; raise CryptoError on any failure."""
    if len(record) < IV_SIZE + AES_BLOCK_SIZE + CMAC_TAG_SIZE:
        raise CryptoError(f"record too short: {len(record)}B")

    iv = record[:IV_SIZE]
    tag = record[-CMAC_TAG_SIZE:]
    ct = record[IV_SIZE:-CMAC_TAG_SIZE]

    if len(ct) == 0 or len(ct) % AES_BLOCK_SIZE != 0:
        raise CryptoError(f"ciphertext length {len(ct)} is not a positive multiple of {AES_BLOCK_SIZE}")

    _cmac_verify(k_cmac, bytes([MSG_ENC_DATA]) + iv + ct, tag)

    dec = Cipher(algorithms.AES(k_cbc), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()

    unpad = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
    try:
        return unpad.update(padded) + unpad.finalize()
    except ValueError as e:
        raise CryptoError(f"PKCS#7 unpadding failed: {e}") from e
