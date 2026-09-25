"""
Distribution manifest.

One encryption event (one document, N recipients) produces one manifest:
  {
    "document_id": "...",
    "document_sha3_256": "...",       # hash of the ORIGINAL plaintext
    "recipients": {
      "<recipient_id>": {
        "kem_ciphertext": "<base64>",
        "wrap_nonce": "<base64>",
        "wrapped_key": "<base64>",
        "doc_nonce": "<base64>"       # AES-GCM nonce for the shared ciphertext file
      },
      ...
    }
  }

Everything in here is safe to store on a normal (even untrusted) file
server: without a recipient's ML-KEM secret key, their entry is useless.
"""

import base64
import hashlib
import json
import os


def sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def build_manifest(document_id: str, document_plaintext: bytes, doc_nonce: bytes) -> dict:
    return {
        "document_id": document_id,
        "document_sha3_256": sha3_256_hex(document_plaintext),
        "doc_nonce": _b64(doc_nonce),
        "recipients": {},
    }


def add_recipient_entry(manifest: dict, recipient_id: str, wrap_entry: dict) -> None:
    manifest["recipients"][recipient_id] = {
        "kem_ciphertext": _b64(wrap_entry["kem_ciphertext"]),
        "wrap_nonce": _b64(wrap_entry["wrap_nonce"]),
        "wrapped_key": _b64(wrap_entry["wrapped_key"]),
    }


def get_recipient_wrap_entry(manifest: dict, recipient_id: str) -> dict:
    entry = manifest["recipients"][recipient_id]
    return {
        "kem_ciphertext": _unb64(entry["kem_ciphertext"]),
        "wrap_nonce": _unb64(entry["wrap_nonce"]),
        "wrapped_key": _unb64(entry["wrapped_key"]),
    }


def get_doc_nonce(manifest: dict) -> bytes:
    return _unb64(manifest["doc_nonce"])


def save_manifest(manifest: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)


def load_manifest(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)
