"""
Server-side storage layout, and startup bootstrap.

IMPORTANT DESIGN NOTE — read this before treating this as production:
This single API process holds every recipient's secret keys, so it can
perform decrypt/sign/watermark on their behalf when they call
POST /documents/{id}/decrypt. That's a deliberate simplification for
Phase 5 (it lets the whole pipeline be driven by real HTTP calls instead
of hardcoded constants, which was the point of this phase) — NOT how a
real deployment should work. In a real deployment, a recipient's secret
key never leaves their own device: Phase 6's recipient client would hold
it locally and only call this server for the parts that genuinely are
server-side (fetching the encrypted file + manifest, submitting the
ALREADY-signed record for endorsement/commit). Flagging this clearly so
it isn't mistaken for the intended trust model.
"""

import os

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "server_data")

KEYS_DIR = os.path.join(DATA_DIR, "keys")
VALIDATORS_DIR = os.path.join(DATA_DIR, "validators")
LEDGER_PATH = os.path.join(DATA_DIR, "ledger.jsonl")
DOCUMENTS_DIR = os.path.join(DATA_DIR, "documents")          # ciphertext + manifest per document
WATERMARKED_DIR = os.path.join(DATA_DIR, "watermarked")      # per-recipient watermarked copies

VALIDATOR_ORGS = ["sender_org", "recipient_org", "audit_org"]
ENDORSEMENT_THRESHOLD = 2


def ensure_dirs() -> None:
    for d in (DATA_DIR, KEYS_DIR, VALIDATORS_DIR, DOCUMENTS_DIR, WATERMARKED_DIR):
        os.makedirs(d, exist_ok=True)


def bootstrap_validators() -> None:
    """Validator orgs represent fixed infrastructure (like Fabric
    organizations provisioned once when the network is set up) — they're
    issued automatically at startup if they don't already exist, not
    created ad hoc per request the way recipients are."""
    from ledger import validators
    for org in VALIDATOR_ORGS:
        if org not in validators.list_validators(VALIDATORS_DIR):
            validators.issue_validator(VALIDATORS_DIR, org)


def document_dir(document_id: str) -> str:
    return os.path.join(DOCUMENTS_DIR, document_id)