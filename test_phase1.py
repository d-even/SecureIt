"""
Automated tests for Phase 1: AES-256-GCM + ML-KEM-768 key wrapping.

Run: python3 -m pytest test_phase1.py -v
"""

import os
import shutil

import pytest
from cryptography.exceptions import InvalidTag

from crypto import aes, kem, keystore, manifest

TEST_KEYS_DIR = "/tmp/phase1_test_keys"
DOCUMENT = b"This is a confidential test document used for Phase 1 verification."


@pytest.fixture(autouse=True)
def clean_keys_dir():
    if os.path.exists(TEST_KEYS_DIR):
        shutil.rmtree(TEST_KEYS_DIR)
    os.makedirs(TEST_KEYS_DIR)
    yield
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


# ---------- AES-256-GCM ----------

def test_aes_round_trip():
    key = aes.generate_session_key()
    nonce, ct = aes.encrypt_bytes(key, DOCUMENT)
    pt = aes.decrypt_bytes(key, nonce, ct)
    assert pt == DOCUMENT


def test_aes_key_is_256_bit():
    key = aes.generate_session_key()
    assert len(key) == 32


def test_aes_tamper_detected():
    key = aes.generate_session_key()
    nonce, ct = aes.encrypt_bytes(key, DOCUMENT)
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF  # flip a bit
    with pytest.raises(InvalidTag):
        aes.decrypt_bytes(key, nonce, bytes(tampered))


def test_aes_wrong_key_rejected():
    key1 = aes.generate_session_key()
    key2 = aes.generate_session_key()
    nonce, ct = aes.encrypt_bytes(key1, DOCUMENT)
    with pytest.raises(InvalidTag):
        aes.decrypt_bytes(key2, nonce, ct)


# ---------- ML-KEM-768 ----------

def test_kem_key_sizes_match_nist_ml_kem_768():
    # FIPS 203 ML-KEM-768: public key 1184B, secret key 2400B, ciphertext 1088B.
    pk, sk = kem.generate_recipient_keypair()
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_kem_wrap_unwrap_round_trip():
    pk, sk = kem.generate_recipient_keypair()
    session_key = aes.generate_session_key()

    wrap_entry = kem.wrap_session_key_for_recipient(session_key, pk)
    recovered = kem.unwrap_session_key(sk, wrap_entry)

    assert recovered == session_key


def test_kem_wrong_recipient_rejected():
    pk_a, sk_a = kem.generate_recipient_keypair()
    pk_b, sk_b = kem.generate_recipient_keypair()
    session_key = aes.generate_session_key()

    wrap_entry = kem.wrap_session_key_for_recipient(session_key, pk_a)

    with pytest.raises(InvalidTag):
        kem.unwrap_session_key(sk_b, wrap_entry)


# ---------- Keystore ----------

def test_keystore_issue_and_load():
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
    pk = keystore.load_public_key(TEST_KEYS_DIR, "alice")
    sk = keystore.load_secret_key(TEST_KEYS_DIR, "alice")
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_keystore_refuses_duplicate_identity():
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
    with pytest.raises(FileExistsError):
        keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")


def test_keystore_list_recipients():
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "bob")
    assert keystore.list_recipients(TEST_KEYS_DIR) == ["alice", "bob"]


# ---------- Full pipeline: multiple recipients, one document ----------

def test_full_pipeline_multiple_recipients():
    recipients = ["alice", "bob", "carol"]
    for rid in recipients:
        keystore.issue_recipient_keypair(TEST_KEYS_DIR, rid)

    session_key = aes.generate_session_key()
    doc_nonce, ciphertext = aes.encrypt_bytes(session_key, DOCUMENT)

    m = manifest.build_manifest("doc1", DOCUMENT, doc_nonce)
    for rid in recipients:
        pk = keystore.load_public_key(TEST_KEYS_DIR, rid)
        wrap_entry = kem.wrap_session_key_for_recipient(session_key, pk)
        manifest.add_recipient_entry(m, rid, wrap_entry)

    # Every recipient independently recovers the exact same document.
    for rid in recipients:
        sk = keystore.load_secret_key(TEST_KEYS_DIR, rid)
        wrap_entry = manifest.get_recipient_wrap_entry(m, rid)
        recovered_key = kem.unwrap_session_key(sk, wrap_entry)
        recovered_doc = aes.decrypt_bytes(recovered_key, manifest.get_doc_nonce(m), ciphertext)
        assert recovered_doc == DOCUMENT

    # Manifest hash matches the original document.
    assert m["document_sha3_256"] == manifest.sha3_256_hex(DOCUMENT)


def test_manifest_save_and_load_round_trip():
    session_key = aes.generate_session_key()
    doc_nonce, _ = aes.encrypt_bytes(session_key, DOCUMENT)
    m = manifest.build_manifest("doc1", DOCUMENT, doc_nonce)

    pk, sk = kem.generate_recipient_keypair()
    wrap_entry = kem.wrap_session_key_for_recipient(session_key, pk)
    manifest.add_recipient_entry(m, "alice", wrap_entry)

    path = "/tmp/phase1_test_manifest.json"
    manifest.save_manifest(m, path)
    loaded = manifest.load_manifest(path)
    os.remove(path)

    assert loaded["document_sha3_256"] == m["document_sha3_256"]
    recovered = kem.unwrap_session_key(sk, manifest.get_recipient_wrap_entry(loaded, "alice"))
    assert recovered == session_key
