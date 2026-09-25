"""
Minimal offline key storage.

This is a stand-in for what Phase 1's plan calls "a local offline CA
(OpenSSL-based) to issue recipient certificates binding identity to their
Kyber public key." For now we just persist raw keypairs to disk, one
folder per recipient, so the rest of the pipeline (and later phases) has
something real to read from. Swapping this for actual X.509-wrapped keys
later won't change any calling code — callers just ask for "the public
key bytes for recipient X."
"""

import os
from . import kem


def issue_recipient_keypair(keys_dir: str, recipient_id: str) -> None:
    """Generate and persist a keypair for one recipient. Idempotent-ish:
    refuses to overwrite an existing identity so you don't accidentally
    invalidate someone's already-distributed public key."""
    recipient_dir = os.path.join(keys_dir, recipient_id)
    if os.path.exists(recipient_dir):
        raise FileExistsError(f"Recipient '{recipient_id}' already has keys at {recipient_dir}")
    os.makedirs(recipient_dir)

    public_key, secret_key = kem.generate_recipient_keypair()

    with open(os.path.join(recipient_dir, "public.key"), "wb") as f:
        f.write(public_key)
    # In a real deployment this file lives on the recipient's device / HSM,
    # never on a shared server. Here it's just co-located for the demo.
    with open(os.path.join(recipient_dir, "secret.key"), "wb") as f:
        f.write(secret_key)


def load_public_key(keys_dir: str, recipient_id: str) -> bytes:
    path = os.path.join(keys_dir, recipient_id, "public.key")
    with open(path, "rb") as f:
        return f.read()


def load_secret_key(keys_dir: str, recipient_id: str) -> bytes:
    path = os.path.join(keys_dir, recipient_id, "secret.key")
    with open(path, "rb") as f:
        return f.read()


def list_recipients(keys_dir: str) -> list[str]:
    if not os.path.isdir(keys_dir):
        return []
    return sorted(
        name for name in os.listdir(keys_dir)
        if os.path.isdir(os.path.join(keys_dir, name))
    )
