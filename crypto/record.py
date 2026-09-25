"""
Decryption record: the thing that actually gets signed and (in Phase 4)
committed to the ledger.

A record captures "recipient X decrypted document Y, in session Z, at
time T." It must be:
  - Canonically serializable (same dict -> same bytes, every time),
    otherwise sign/verify would be fragile to key ordering or whitespace.
  - Independent of any embedded public key, so a forged record can't just
    ship its own "trust me" key — verification always looks the signer's
    public key up from the keystore by recipient_id, not from the record.
"""

import base64
import json
import uuid
from datetime import datetime, timezone

from . import signing


def new_session_id() -> str:
    """One per decryption event. In Phase 3 this is the same id the
    invisible watermark encodes — it's the join key between a leaked file
    and its ledger record."""
    return uuid.uuid4().hex


def build_decryption_record(document_id: str, document_sha3_256: str, recipient_id: str,
                             session_id: str | None = None) -> dict:
    return {
        "record_version": 1,
        "session_id": session_id or new_session_id(),
        "document_id": document_id,
        "document_sha3_256": document_sha3_256,
        "recipient_id": recipient_id,
        "decrypted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def canonical_bytes(record: dict) -> bytes:
    """Deterministic encoding: sorted keys, no incidental whitespace.
    This is exactly what gets signed and what verification re-derives —
    never sign/verify the record dict directly."""
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_record(record: dict, recipient_secret_key: bytes) -> bytes:
    """Recipient-side. Signs the canonical bytes of the record with their
    own ML-DSA secret key."""
    return signing.sign(recipient_secret_key, canonical_bytes(record))


def verify_record(record: dict, signature: bytes, recipient_public_key: bytes) -> bool:
    """
    Verifier-side (the ledger, or anyone auditing later). `recipient_public_key`
    must come from the keystore/CA for `record["recipient_id"]` — NOT from
    anything attached to the record itself, or a forger could just attach
    their own key and "verify" their own forgery.
    """
    return signing.verify(recipient_public_key, canonical_bytes(record), signature)


def to_signed_json(record: dict, signature: bytes) -> dict:
    """Wire/storage format: the record plus its base64 signature."""
    return {"record": record, "signature": base64.b64encode(signature).decode("ascii")}


def from_signed_json(signed: dict) -> tuple[dict, bytes]:
    return signed["record"], base64.b64decode(signed["signature"].encode("ascii"))


def save_signed_record(record: dict, signature: bytes, path: str) -> None:
    with open(path, "w") as f:
        json.dump(to_signed_json(record, signature), f, indent=2)


def load_signed_record(path: str) -> tuple[dict, bytes]:
    with open(path, "r") as f:
        signed = json.load(f)
    return from_signed_json(signed) 