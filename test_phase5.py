"""
Automated tests for Phase 5: the real HTTP API.

Every test here drives the system the way Phase 6's client apps (or a
person using curl/Postman) would: real endpoints, real uploaded file
bytes, real recipient id strings in the URL/params. No hardcoded
RECIPIENTS list, no DOCUMENT_TEXT constant baked into the test itself
(each test builds its own document content inline, standing in for
"whatever a real user chose to upload").

Run: python3 -m pytest test_phase5.py -v
"""

import shutil

import pytest
from fastapi.testclient import TestClient

from api import storage


@pytest.fixture(autouse=True)
def clean_server_state():
    shutil.rmtree(storage.DATA_DIR, ignore_errors=True)
    storage.ensure_dirs()
    storage.bootstrap_validators()
    yield
    shutil.rmtree(storage.DATA_DIR, ignore_errors=True)


@pytest.fixture()
def client():
    # api.app is only imported (and its module-level bootstrap run) ONCE
    # per process, so clean_server_state re-runs the bootstrap explicitly
    # above rather than relying on re-import side effects.
    from api.app import app
    return TestClient(app)


def _distribute(client, filename, content_bytes, recipient_ids):
    files = {"file": (filename, content_bytes, "text/plain")}
    data = {"recipient_ids": recipient_ids}
    return client.post("/documents", files=files, data=data)


# ---------- recipients ----------

def test_create_and_list_recipients(client):
    r = client.post("/recipients/alice")
    assert r.status_code == 200
    assert r.json() == {"recipient_id": "alice", "status": "issued"}

    r = client.get("/recipients")
    assert r.json() == {"recipients": ["alice"]}


def test_duplicate_recipient_rejected(client):
    client.post("/recipients/alice")
    r = client.post("/recipients/alice")
    assert r.status_code == 409


# ---------- distribute ----------

def test_distribute_rejects_unknown_recipient(client):
    r = _distribute(client, "doc.txt", b"secret plans", ["nobody_issued_this_id"])
    assert r.status_code == 400


def test_distribute_rejects_empty_file(client):
    client.post("/recipients/alice")
    r = _distribute(client, "doc.txt", b"", ["alice"])
    assert r.status_code == 400


def test_distribute_succeeds_and_lists(client):
    client.post("/recipients/alice")
    client.post("/recipients/bob")
    content = b"Q4 strategy notes -- do not forward."
    r = _distribute(client, "strategy.txt", content, ["alice", "bob"])
    assert r.status_code == 200
    body = r.json()
    assert set(body["recipients"]) == {"alice", "bob"}
    assert len(body["document_sha3_256"]) == 64  # sha3-256 hex

    r = client.get("/documents")
    docs = r.json()["documents"]
    assert any(d["document_id"] == body["document_id"] for d in docs)


# ---------- decrypt ----------

def test_decrypt_rejects_unauthorized_recipient(client):
    client.post("/recipients/alice")
    client.post("/recipients/mallory")
    r = _distribute(client, "doc.txt", b"only for alice", ["alice"])
    doc_id = r.json()["document_id"]

    r = client.post(f"/documents/{doc_id}/decrypt", params={"recipient_id": "mallory"})
    assert r.status_code == 403


def test_decrypt_rejects_unknown_document(client):
    client.post("/recipients/alice")
    r = client.post("/documents/does-not-exist/decrypt", params={"recipient_id": "alice"})
    assert r.status_code == 404


def test_decrypt_produces_watermark_and_ledger_commit(client):
    client.post("/recipients/alice")
    r = _distribute(client, "doc.txt", b"Confidential quarterly figures.", ["alice"])
    doc_id = r.json()["document_id"]

    r = client.post(f"/documents/{doc_id}/decrypt", params={"recipient_id": "alice"})
    assert r.status_code == 200
    body = r.json()
    assert body["recipient_id"] == "alice"
    assert len(body["session_id"]) == 32
    assert body["ledger_block"] == 1
    assert len(body["endorsed_by"]) >= storage.ENDORSEMENT_THRESHOLD


def test_download_watermarked_copy_is_visually_identical(client):
    client.post("/recipients/alice")
    original = b"Confidential quarterly figures.\nRevenue is up 12 percent.\n"
    r = _distribute(client, "doc.txt", original, ["alice"])
    doc_id = r.json()["document_id"]
    decrypt_result = client.post(f"/documents/{doc_id}/decrypt", params={"recipient_id": "alice"}).json()

    r = client.get(decrypt_result["download_url"])
    assert r.status_code == 200
    from watermark import text_watermark
    assert text_watermark.strip(r.text) == original.decode("utf-8")


def test_download_without_decrypt_first_returns_404(client):
    client.post("/recipients/alice")
    r = _distribute(client, "doc.txt", b"content", ["alice"])
    doc_id = r.json()["document_id"]
    r = client.get(f"/documents/{doc_id}/decrypt/alice/download")
    assert r.status_code == 404


# ---------- trace (the full leak -> attribution loop) ----------

def test_trace_identifies_correct_recipient_from_partial_leak(client):
    client.post("/recipients/alice")
    client.post("/recipients/bob")
    original = b"Board briefing: M&A shortlist and headcount plan enclosed."
    r = _distribute(client, "briefing.txt", original, ["alice", "bob"])
    doc_id = r.json()["document_id"]

    # bob is the one who leaks it
    decrypt_result = client.post(f"/documents/{doc_id}/decrypt", params={"recipient_id": "bob"}).json()
    watermarked = client.get(decrypt_result["download_url"]).content

    leaked_fragment = watermarked[: int(len(watermarked) * 0.5)]
    r = client.post("/trace", files={"leaked_file": ("leaked.txt", leaked_fragment, "text/plain")})
    assert r.status_code == 200
    result = r.json()
    assert result["attributable"] is True
    assert result["recipient_id"] == "bob"
    assert result["chain_integrity_valid"] is True


def test_trace_does_not_misattribute_to_a_different_recipient(client):
    client.post("/recipients/alice")
    client.post("/recipients/bob")
    original = b"Shared document text identical for both recipients."
    r = _distribute(client, "doc.txt", original, ["alice", "bob"])
    doc_id = r.json()["document_id"]

    alice_result = client.post(f"/documents/{doc_id}/decrypt", params={"recipient_id": "alice"}).json()
    bob_result = client.post(f"/documents/{doc_id}/decrypt", params={"recipient_id": "bob"}).json()
    assert alice_result["session_id"] != bob_result["session_id"]  # different sessions despite identical text

    alice_copy = client.get(alice_result["download_url"]).content
    r = client.post("/trace", files={"leaked_file": ("leaked.txt", alice_copy, "text/plain")})
    assert r.json()["recipient_id"] == "alice"   # NOT bob, even though the visible text is identical


def test_trace_unwatermarked_file_is_not_attributable(client):
    r = client.post("/trace", files={"leaked_file": ("random.txt", b"just some random text", "text/plain")})
    assert r.status_code == 200
    assert r.json()["attributable"] is False


# ---------- ledger inspection ----------

def test_ledger_verify_clean_after_normal_use(client):
    client.post("/recipients/alice")
    r = _distribute(client, "doc.txt", b"content", ["alice"])
    doc_id = r.json()["document_id"]
    client.post(f"/documents/{doc_id}/decrypt", params={"recipient_id": "alice"})

    r = client.get("/ledger/verify")
    assert r.json() == {"valid": True, "issues": []}


def test_get_ledger_record_by_session_id(client):
    client.post("/recipients/alice")
    r = _distribute(client, "doc.txt", b"content", ["alice"])
    doc_id = r.json()["document_id"]
    decrypt_result = client.post(f"/documents/{doc_id}/decrypt", params={"recipient_id": "alice"}).json()

    r = client.get(f"/ledger/{decrypt_result['session_id']}")
    assert r.status_code == 200
    assert r.json()["record"]["recipient_id"] == "alice"


def test_get_ledger_record_unknown_session_id_404(client):
    r = client.get("/ledger/" + "0" * 32)
    assert r.status_code == 404