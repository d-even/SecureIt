"""
ML-KEM-768 (FIPS 203, standardized CRYSTALS-Kyber) key encapsulation.

Design: KEM-then-DEM.
  - The AES session key made in aes.py is NOT sent directly.
  - For each recipient we run ML-KEM encapsulation against their public
    key. That produces a KEM ciphertext (safe to store/send) and a shared
    secret (never leaves this process in the clear).
  - The shared secret is used as a one-time key-encryption-key (KEK) to
    AES-GCM-wrap the actual session key.
  - The recipient reverses this: decapsulate with their private key to
    recover the same shared secret, then unwrap the session key.

This means every recipient gets their own independent wrap of the same
session key — nobody can unwrap another recipient's copy, and losing one
recipient's key never exposes anyone else's.
"""

import pqcrypto.kem.ml_kem_768 as _ml_kem_768
from . import aes

PUBLIC_KEY_BYTES = _ml_kem_768.PUBLIC_KEY_SIZE
SECRET_KEY_BYTES = _ml_kem_768.SECRET_KEY_SIZE
CIPHERTEXT_BYTES = _ml_kem_768.CIPHERTEXT_SIZE


def generate_recipient_keypair() -> tuple[bytes, bytes]:
    """
    Returns (public_key, secret_key) for one recipient.
    In production the secret key never leaves the recipient's device / HSM;
    the public key is what gets published or attached to their certificate
    by the offline CA (see keystore.py for a stand-in for that step).
    """
    return _ml_kem_768.keygen()


def wrap_session_key_for_recipient(session_key: bytes, recipient_public_key: bytes) -> dict:
    """
    Sender-side. Wraps `session_key` so only the holder of the matching
    ML-KEM secret key can recover it. Returns a small dict that goes into
    that recipient's entry in the distribution manifest.
    """
    kem_ciphertext, shared_secret = _ml_kem_768.encaps(recipient_public_key)
    # shared_secret from ML-KEM-768 is 32 bytes — exactly an AES-256 key.
    wrap_nonce, wrapped_key = aes.encrypt_bytes(shared_secret, session_key)
    return {
        "kem_ciphertext": kem_ciphertext,
        "wrap_nonce": wrap_nonce,
        "wrapped_key": wrapped_key,
    }


def unwrap_session_key(recipient_secret_key: bytes, wrap_entry: dict) -> bytes:
    """
    Recipient-side. Reverses wrap_session_key_for_recipient using this
    recipient's own secret key. Anyone else's secret key will produce a
    different shared_secret and the AES-GCM unwrap below will fail loudly
    (InvalidTag) rather than silently returning garbage.
    """
    shared_secret = _ml_kem_768.decaps(recipient_secret_key, wrap_entry["kem_ciphertext"])
    session_key = aes.decrypt_bytes(shared_secret, wrap_entry["wrap_nonce"], wrap_entry["wrapped_key"])
    return session_key
