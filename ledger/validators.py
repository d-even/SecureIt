"""
Validator identities — the "organizations" whose independent endorsement
is required before a record can be committed to the ledger.

This mirrors what Hyperledger Fabric calls an endorsement policy: a
transaction only gets committed once enough distinct organizations'
peers have independently simulated it and signed off. We use the same
ML-DSA-65 signing primitive from crypto/signing.py — a validator
endorsing a record is exactly the same cryptographic operation as a
recipient signing a decryption record, just done by a different party
for a different reason (confirming the record is well-formed) rather
than a different algorithm.

Why this matters for "no single admin can alter the ledger": tampering
with a committed record means also forging every validator org's
endorsement signature over the NEW content — which requires their
private keys. An admin with access to the ledger's storage does not,
by itself, have those keys.
"""

import os

from crypto import signing


def issue_validator(validators_dir: str, validator_id: str) -> None:
    """One ML-DSA-65 keypair per validator org. Same custody rule as
    everywhere else: the secret key belongs to that org, not to whoever
    hosts the ledger's storage."""
    org_dir = os.path.join(validators_dir, validator_id)
    if os.path.exists(org_dir):
        raise FileExistsError(f"Validator '{validator_id}' already exists at {org_dir}")
    os.makedirs(org_dir)

    public_key, secret_key = signing.generate_signing_keypair()
    with open(os.path.join(org_dir, "public.key"), "wb") as f:
        f.write(public_key)
    with open(os.path.join(org_dir, "secret.key"), "wb") as f:
        f.write(secret_key)


def load_validator_public_key(validators_dir: str, validator_id: str) -> bytes:
    with open(os.path.join(validators_dir, validator_id, "public.key"), "rb") as f:
        return f.read()


def load_validator_secret_key(validators_dir: str, validator_id: str) -> bytes:
    with open(os.path.join(validators_dir, validator_id, "secret.key"), "rb") as f:
        return f.read()


def list_validators(validators_dir: str) -> list[str]:
    if not os.path.isdir(validators_dir):
        return []
    return sorted(
        name for name in os.listdir(validators_dir)
        if os.path.isdir(os.path.join(validators_dir, name))
    )


def load_validator_registry(validators_dir: str) -> dict[str, bytes]:
    """validator_id -> public_key, for every validator that's been issued.
    This is what commit_record() checks endorsements against."""
    return {
        vid: load_validator_public_key(validators_dir, vid)
        for vid in list_validators(validators_dir)
    }
