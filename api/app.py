"""
Phase 5 — the API layer. Every operation here is triggered by an actual
HTTP request with real data (a real uploaded file, real recipient id
strings, a real query parameter) — nothing here is a hardcoded constant
baked into a script. This is what Phase 6's client apps (or `curl`, or
the automated tests below) actually call.

Run standalone with:  uvicorn api.app:app --reload
"""

import os
import uuid

from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse

from crypto import aes, kem, keystore, manifest as manifest_mod, record as record_mod
from watermark import text_watermark
from ledger import Ledger, endorsement as endorsement_mod, validators as validators_mod

from . import storage


@asynccontextmanager
async def _lifespan(app: FastAPI):
    storage.ensure_dirs()
    storage.bootstrap_validators()
    yield


app = FastAPI(title="Forensic Watermarking System — Phase 5 API", lifespan=_lifespan)

# Also run at import time (not just on startup) so it works whether the
# app is served by uvicorn (lifespan fires) or driven directly by
# TestClient without the `with` context (lifespan may not fire).
storage.ensure_dirs()
storage.bootstrap_validators()


def _get_ledger() -> Ledger:
    return Ledger(storage.LEDGER_PATH, storage.VALIDATORS_DIR, threshold=storage.ENDORSEMENT_THRESHOLD)


# ==================================================================
# Recipients — real identities, created by a real request, not a
# hardcoded RECIPIENTS list.
# ==================================================================

@app.post("/recipients/{recipient_id}")
def create_recipient(recipient_id: str):
    if recipient_id in keystore.list_recipients(storage.KEYS_DIR):
        raise HTTPException(409, f"recipient '{recipient_id}' already exists")
    keystore.issue_recipient_keypair(storage.KEYS_DIR, recipient_id)
    return {"recipient_id": recipient_id, "status": "issued"}


@app.get("/recipients")
def list_recipients():
    return {"recipients": keystore.list_recipients(storage.KEYS_DIR)}


# ==================================================================
# Documents — sender uploads a REAL file and picks REAL recipients.
# ==================================================================

@app.post("/documents")
async def distribute_document(file: UploadFile = File(...), recipient_ids: list[str] = Form(...)):
    known = set(keystore.list_recipients(storage.KEYS_DIR))
    unknown = [r for r in recipient_ids if r not in known]
    if unknown:
        raise HTTPException(400, f"unknown recipient(s): {unknown}. Create them first via POST /recipients/{{id}}")

    plaintext = await file.read()
    if not plaintext:
        raise HTTPException(400, "uploaded file is empty")

    document_id = uuid.uuid4().hex
    session_key = aes.generate_session_key()
    doc_nonce, ciphertext = aes.encrypt_bytes(session_key, plaintext)

    m = manifest_mod.build_manifest(document_id, plaintext, doc_nonce)
    for rid in recipient_ids:
        pk = keystore.load_public_key(storage.KEYS_DIR, rid)
        wrap_entry = kem.wrap_session_key_for_recipient(session_key, pk)
        manifest_mod.add_recipient_entry(m, rid, wrap_entry)

    d = storage.document_dir(document_id)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "ciphertext.bin"), "wb") as f:
        f.write(ciphertext)
    manifest_mod.save_manifest(m, os.path.join(d, "manifest.json"))
    with open(os.path.join(d, "original_filename.txt"), "w") as f:
        f.write(file.filename or "document")

    return {
        "document_id": document_id,
        "filename": file.filename,
        "document_sha3_256": m["document_sha3_256"],
        "recipients": recipient_ids,
    }


@app.get("/documents")
def list_documents():
    if not os.path.isdir(storage.DOCUMENTS_DIR):
        return {"documents": []}
    out = []
    for document_id in sorted(os.listdir(storage.DOCUMENTS_DIR)):
        try:
            m = manifest_mod.load_manifest(os.path.join(storage.document_dir(document_id), "manifest.json"))
            out.append({
                "document_id": document_id,
                "document_sha3_256": m["document_sha3_256"],
                "recipients": list(m["recipients"].keys()),
            })
        except FileNotFoundError:
            continue
    return {"documents": out}


# ==================================================================
# Decrypt — a specific recipient (real id, passed by the caller — this
# is where a real login/session would supply it) decrypts THEIR copy.
# This performs Phase 1 (decrypt) + Phase 2 (sign) + Phase 3 (watermark)
# + Phase 4 (endorse & commit), all in one real, auditable action.
# See the trust-model note in storage.py about where keys live here.
# ==================================================================

@app.post("/documents/{document_id}/decrypt")
def decrypt_document(document_id: str, recipient_id: str):
    d = storage.document_dir(document_id)
    manifest_path = os.path.join(d, "manifest.json")
    if not os.path.exists(manifest_path):
        raise HTTPException(404, f"document '{document_id}' not found")

    m = manifest_mod.load_manifest(manifest_path)
    if recipient_id not in m["recipients"]:
        raise HTTPException(403, f"'{recipient_id}' is not an authorized recipient of this document")
    if recipient_id not in keystore.list_recipients(storage.KEYS_DIR):
        raise HTTPException(404, f"recipient '{recipient_id}' has no issued keys")

    # Phase 1: decrypt
    with open(os.path.join(d, "ciphertext.bin"), "rb") as f:
        ciphertext = f.read()
    sk = keystore.load_secret_key(storage.KEYS_DIR, recipient_id)
    wrap_entry = manifest_mod.get_recipient_wrap_entry(m, recipient_id)
    session_key = kem.unwrap_session_key(sk, wrap_entry)
    doc_nonce = manifest_mod.get_doc_nonce(m)
    plaintext = aes.decrypt_bytes(session_key, doc_nonce, ciphertext)

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            415, "this Phase 5 endpoint currently watermarks text documents only "
                 "(image_watermark.py exists for image/screenshot leak paths — "
                 "wiring it into this endpoint for non-text files is a Phase 6 task)"
        )

    # Phase 2: sign the decryption record
    rec = record_mod.build_decryption_record(m["document_id"], m["document_sha3_256"], recipient_id)
    signing_sk = keystore.load_signing_secret_key(storage.KEYS_DIR, recipient_id)
    signing_pk = keystore.load_signing_public_key(storage.KEYS_DIR, recipient_id)
    signature = record_mod.sign_record(rec, signing_sk)

    # Phase 3: watermark this recipient's copy
    watermarked_text = text_watermark.embed(text, rec["session_id"], copies=4)

    out_path = os.path.join(storage.WATERMARKED_DIR, f"{document_id}__{recipient_id}.txt")
    # newline="" disables Python's platform-dependent newline translation
    # (on Windows, "w" mode silently turns \n into \r\n otherwise), so the
    # downloaded file is byte-for-byte what was embedded, not something
    # subtly altered by the OS the server happens to run on.
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write(watermarked_text)

    # Phase 4: independent validator orgs endorse, then commit
    endorsements = []
    for org in storage.VALIDATOR_ORGS[: storage.ENDORSEMENT_THRESHOLD]:
        v_sk = validators_mod.load_validator_secret_key(storage.VALIDATORS_DIR, org)
        endorsements.append(endorsement_mod.endorse_record(org, v_sk, rec, signature, signing_pk))

    ledger = _get_ledger()
    block = ledger.commit_record(rec, signature, signing_pk, endorsements)

    return {
        "session_id": rec["session_id"],
        "recipient_id": recipient_id,
        "ledger_block": block["index"],
        "ledger_hash": block["hash"],
        "endorsed_by": [e["validator_id"] for e in endorsements],
        "download_url": f"/documents/{document_id}/decrypt/{recipient_id}/download",
    }


@app.get("/documents/{document_id}/decrypt/{recipient_id}/download")
def download_watermarked_copy(document_id: str, recipient_id: str):
    path = os.path.join(storage.WATERMARKED_DIR, f"{document_id}__{recipient_id}.txt")
    if not os.path.exists(path):
        raise HTTPException(404, "no watermarked copy found — call POST .../decrypt first")
    return FileResponse(path, media_type="text/plain", filename=f"{document_id}.txt")


# ==================================================================
# Leak tracing — admin uploads a REAL leaked file. Nothing here is
# pre-selected; whatever bytes come in the request are what gets traced.
# ==================================================================

@app.post("/trace")
async def trace_leak(leaked_file: UploadFile = File(...)):
    raw = await leaked_file.read()
    # A leaked file may be truncated at an arbitrary byte offset (not a
    # clean character boundary) — e.g. a network cut, a partial copy.
    # errors="ignore" drops any malformed tail bytes instead of failing
    # the whole trace; the redundant watermark copies elsewhere in the
    # text (see text_watermark.py's module docstring) are what actually
    # make this recoverable, not lenient decoding.
    text = raw.decode("utf-8", errors="ignore")
    if not text:
        raise HTTPException(415, "could not read this file as text")

    session_id = text_watermark.extract(text)
    if session_id is None:
        return {"attributable": False, "reason": "no watermark could be extracted from this file"}

    ledger = _get_ledger()
    block = ledger.get_by_session_id(session_id)
    if block is None:
        return {"attributable": False, "reason": "watermark decoded but no matching ledger record", "session_id": session_id}

    valid, issues = ledger.verify_chain()
    rec = block["record"]
    return {
        "attributable": True,
        "recipient_id": rec["recipient_id"],
        "document_id": rec["document_id"],
        "decrypted_at": rec["decrypted_at"],
        "session_id": rec["session_id"],
        "endorsed_by": [e["validator_id"] for e in block["endorsements"]],
        "ledger_block": block["index"],
        "ledger_hash": block["hash"],
        "chain_integrity_valid": valid,
        "chain_issues": issues,
    }


# ==================================================================
# Ledger — direct inspection endpoints.
# ==================================================================

@app.get("/ledger/verify")
def verify_ledger():
    valid, issues = _get_ledger().verify_chain()
    return {"valid": valid, "issues": issues}


@app.get("/ledger/{session_id}")
def get_ledger_record(session_id: str):
    block = _get_ledger().get_by_session_id(session_id)
    if block is None:
        raise HTTPException(404, "no ledger record for that session_id")
    return block


# ==================================================================
# Serve the Phase 6 client app (web/) from this same process, so
# `uvicorn api.app:app` gives you both the API and a working UI at
# http://127.0.0.1:8000/. Mounted LAST so it never shadows an API route
# above — Starlette matches routes in registration order, and only
# requests that don't match any API path fall through to these files.
# ==================================================================

from fastapi.staticfiles import StaticFiles  # noqa: E402

_API_DIR = os.path.dirname(os.path.abspath(__file__))
_WEB_DIR = os.path.join(os.path.dirname(_API_DIR), "web")
app.mount("/", StaticFiles(directory=_WEB_DIR, html=True), name="web")