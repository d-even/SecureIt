"""
ML-DSA-65 (FIPS 204, standardized CRYSTALS-Dilithium) digital signatures.

This is the non-repudiation layer: once a recipient decrypts a document,
they sign a *decryption record* (who, what document, when, which session)
with their own ML-DSA private key. Because only that recipient holds the
private key, they cannot later deny having produced that signature — and
nobody else can forge it in their name.

Separate from kem.py on purpose: ML-KEM keys are for key exchange (their
math doesn't support signing), ML-DSA keys are for signing. A recipient
holds one keypair of each type.
"""

import pqcrypto.sign.ml_dsa_65 as _ml_dsa_65
from pqcrypto import InvalidSignatureError

PUBLIC_KEY_BYTES = _ml_dsa_65.PUBLIC_KEY_SIZE     # 1952
SECRET_KEY_BYTES = _ml_dsa_65.SECRET_KEY_SIZE     # 4032
SIGNATURE_BYTES = _ml_dsa_65.SIGNATURE_SIZE       # 3309 (max; ML-DSA signatures are fixed-size)


def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Returns (public_key, secret_key). The secret key never leaves the
    recipient's device/HSM — same custody rule as the ML-KEM secret key."""
    return _ml_dsa_65.keygen()


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign arbitrary bytes (we'll feed it a canonical record encoding —
    see record.py) with this recipient's ML-DSA private key."""
    return _ml_dsa_65.sign(secret_key, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Returns True if `signature` is a valid ML-DSA signature over `message`
    by the holder of the secret key matching `public_key`. Returns False
    (rather than raising) on a bad signature, so callers can do simple
    `if not verify(...):` checks without a try/except.
    """
    try:
        _ml_dsa_65.verify(public_key, message, signature)
        return True
    except InvalidSignatureError:
        return False