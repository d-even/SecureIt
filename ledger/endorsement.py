"""
Endorsement: one validator org independently checking a decryption record
and putting their own signature on it.

An endorsement is a signature over (the record's canonical bytes + the
recipient's own signature bytes) — bundling both together means an
endorsement is tied to *this exact record with this exact recipient
signature*, not just the record content alone. If either changes, the
endorsement no longer verifies.

This is the "peer simulates and signs the transaction" step in Fabric's
endorsement flow, done here as a direct function call rather than a
network RPC — same cryptographic guarantee, simpler plumbing.
"""

from crypto import record as record_mod
from crypto import signing


def _endorsement_message(record: dict, record_signature: bytes) -> bytes:
    return record_mod.canonical_bytes(record) + record_signature


def endorse_record(validator_id: str, validator_secret_key: bytes,
                    record: dict, record_signature: bytes,
                    recipient_public_key: bytes) -> dict:
    """
    A validator's job before endorsing: verify the recipient's own
    signature is genuinely valid. An endorsement is worthless if the
    validator didn't actually check anything — this is exactly what
    "independently simulating the transaction" means in Fabric.

    Raises ValueError if the recipient's signature doesn't check out —
    a validator should refuse to endorse a bad record, not sign it anyway.
    """
    if not record_mod.verify_record(record, record_signature, recipient_public_key):
        raise ValueError(
            f"validator '{validator_id}' refuses to endorse: "
            f"the recipient's signature on this record does not verify"
        )

    endorsement_signature = signing.sign(validator_secret_key, _endorsement_message(record, record_signature))
    return {
        "validator_id": validator_id,
        "endorsement_signature": endorsement_signature,
    }


def verify_endorsement(endorsement: dict, record: dict, record_signature: bytes,
                        validator_public_key: bytes) -> bool:
    """Anyone (the ledger itself, an auditor) can re-check an endorsement
    without needing the validator's secret key — that's the point of a
    signature."""
    return signing.verify(
        validator_public_key,
        _endorsement_message(record, record_signature),
        endorsement["endorsement_signature"],
    )