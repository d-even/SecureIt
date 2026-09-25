"""
AES-256-GCM helpers.

This module handles the *document* encryption. A single random 256-bit
session key encrypts the file once; that same key is later wrapped
separately for each recipient using ML-KEM (see kem.py). AES-GCM gives us
both confidentiality and integrity (authenticated encryption) — any bit
flip in the ciphertext is detected on decrypt.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_BYTES = 32      # AES-256
NONCE_BYTES = 12        # 96-bit nonce, standard for GCM


def generate_session_key() -> bytes:
    """A fresh random 256-bit key. One per document distribution."""
    return os.urandom(AES_KEY_BYTES)


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns (nonce, ciphertext_with_tag).
    associated_data is authenticated but not encrypted (e.g. a document id) —
    useful to bind the ciphertext to a specific distribution without hiding it.
    """
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_BYTES} bytes, got {len(key)}")
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt AES-256-GCM ciphertext. Raises InvalidTag if the key is wrong
    or the ciphertext/associated_data was tampered with.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def encrypt_file(key: bytes, in_path: str, out_path: str, associated_data: bytes = b"") -> bytes:
    """Encrypt a file on disk. Returns the nonce used (store it in the manifest)."""
    with open(in_path, "rb") as f:
        plaintext = f.read()
    nonce, ciphertext = encrypt_bytes(key, plaintext, associated_data)
    with open(out_path, "wb") as f:
        f.write(ciphertext)
    return nonce


def decrypt_file(key: bytes, nonce: bytes, in_path: str, out_path: str, associated_data: bytes = b"") -> None:
    """Decrypt a file on disk given the key and nonce from the manifest."""
    with open(in_path, "rb") as f:
        ciphertext = f.read()
    plaintext = decrypt_bytes(key, nonce, ciphertext, associated_data)
    with open(out_path, "wb") as f:
        f.write(plaintext)
