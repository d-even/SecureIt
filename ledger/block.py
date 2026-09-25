"""
A block: one committed, endorsed decryption record, chained to the
previous block by hash.

Fields:
  index          - position in the chain (0 = genesis)
  timestamp      - when this block was committed
  prev_hash      - the previous block's hash (this is the "chain" part)
  record         - the decryption record (from crypto/record.py)
  record_signature - the recipient's ML-DSA signature over it, base64
  recipient_public_key - base64, so the block is self-contained and
                          re-verifiable without a separate keystore lookup
  endorsements   - list of {validator_id, endorsement_signature (base64)}
  hash           - SHA3-256 over everything above (computed last)

The hash is computed over every other field, including prev_hash. That's
what makes the chain: change anything in block N — its record, its
endorsements, even its prev_hash — and block N's hash changes, which no
longer matches what block N+1 recorded as ITS prev_hash.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


GENESIS_PREV_HASH = "0" * 64


def _canonical_bytes(block_without_hash: dict) -> bytes:
    return json.dumps(block_without_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_hash(block_without_hash: dict) -> str:
    return hashlib.sha3_256(_canonical_bytes(block_without_hash)).hexdigest()


def make_genesis_block() -> dict:
    block = {
        "index": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "prev_hash": GENESIS_PREV_HASH,
        "record": None,
        "record_signature": None,
        "recipient_public_key": None,
        "endorsements": [],
    }
    block["hash"] = compute_hash(block)
    return block


def make_block(index: int, prev_hash: str, record: dict, record_signature: bytes,
               recipient_public_key: bytes, endorsements: list[dict]) -> dict:
    block = {
        "index": index,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "prev_hash": prev_hash,
        "record": record,
        "record_signature": _b64(record_signature),
        "recipient_public_key": _b64(recipient_public_key),
        "endorsements": [
            {"validator_id": e["validator_id"], "endorsement_signature": _b64(e["endorsement_signature"])}
            for e in endorsements
        ],
    }
    block["hash"] = compute_hash({k: v for k, v in block.items() if k != "hash"})
    return block


def block_without_hash(block: dict) -> dict:
    return {k: v for k, v in block.items() if k != "hash"}


def get_record_signature_bytes(block: dict) -> bytes:
    return _unb64(block["record_signature"])


def get_recipient_public_key_bytes(block: dict) -> bytes:
    return _unb64(block["recipient_public_key"])


def get_endorsement_signature_bytes(endorsement: dict) -> bytes:
    return _unb64(endorsement["endorsement_signature"])