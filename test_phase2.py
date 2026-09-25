"""
Automated tests for Phase 2: ML-DSA-65 signing of decryption records.

Run: python3 -m pytest test_phase2.py -v
"""

import copy
import os
import shutil

import pytest

from crypto import keystore, record, signing

TEST_KEYS_DIR = "/tmp/phase2_test_keys"


@pytest.fixture(autouse=True)
def clean_keys_dir():
    if os.path.exists(TEST_KEYS_DIR):
        shutil.rmtree(TEST_KEYS_DIR)
    os.makedirs(TEST_KEYS_DIR)
    yield
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


# ---------- ML-DSA-65 primitives ----------

def test_signing_key_sizes_match_nist_ml_dsa_65():
    pk, sk = signing.generate_signing_keypair()
    assert len(pk) == 1952
    assert len(sk) == 4032


def test_sign_verify_round_trip():
    pk, sk = signing.generate_signing_keypair()
    msg = b"decryption record bytes"
    sig = signing.sign(sk, msg)
    assert signing.verify(pk, msg, sig) is True


def test_verify_rejects_tampered_message():
    pk, sk = signing.generate_signing_keypair()
    sig = signing.sign(sk, b"original message")
    assert signing.verify(pk, b"different message", sig) is False


def test_verify_rejects_wrong_public_key():
    pk_a, sk_a = signing.generate_signing_keypair()
    pk_b, _sk_b = signing.generate_signing_keypair()
    msg = b"decryption record bytes"
    sig = signing.sign(sk_a, msg)
    assert signing.verify(pk_b, msg, sig) is False


# ---------- keystore: signing keys issued alongside KEM keys ----------

def test_keystore_issues_both_key_types():
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
    assert len(keystore.load_public_key(TEST_KEYS_DIR, "alice")) == 1184
    assert len(keystore.load_secret_key(TEST_KEYS_DIR, "alice")) == 2400
    assert len(keystore.load_signing_public_key(TEST_KEYS_DIR, "alice")) == 1952
    assert len(keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")) == 4032


# ---------- record.py: canonical encoding + sign/verify ----------

def test_canonical_bytes_is_deterministic():
    r1 = {"b": 2, "a": 1}
    r2 = {"a": 1, "b": 2}
    assert record.canonical_bytes(r1) == record.canonical_bytes(r2)


def test_build_decryption_record_has_expected_fields():
    rec = record.build_decryption_record("doc1", "deadbeef", "alice")
    assert rec["document_id"] == "doc1"
    assert rec["document_sha3_256"] == "deadbeef"
    assert rec["recipient_id"] == "alice"
    assert "session_id" in rec and len(rec["session_id"]) == 32
    assert "decrypted_at" in rec


def test_record_sign_and_verify_round_trip():
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
    sk = keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")
    pk = keystore.load_signing_public_key(TEST_KEYS_DIR, "alice")

    rec = record.build_decryption_record("doc1", "deadbeef", "alice")
    sig = record.sign_record(rec, sk)

    assert record.verify_record(rec, sig, pk) is True


def test_record_tamper_after_signing_is_detected():
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
    sk = keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")
    pk = keystore.load_signing_public_key(TEST_KEYS_DIR, "alice")

    rec = record.build_decryption_record("doc1", "deadbeef", "alice")
    sig = record.sign_record(rec, sk)

    for field, new_value in [
        ("recipient_id", "mallory"),
        ("document_id", "doc2"),
        ("document_sha3_256", "0000"),
        ("session_id", "0" * 32),
    ]:
        tampered = copy.deepcopy(rec)
        tampered[field] = new_value
        assert record.verify_record(tampered, sig, pk) is False, f"tampering '{field}' was not detected"


def test_record_cannot_be_attributed_to_wrong_recipient():
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "bob")

    alice_sk = keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")
    bob_pk = keystore.load_signing_public_key(TEST_KEYS_DIR, "bob")

    rec = record.build_decryption_record("doc1", "deadbeef", "alice")
    sig = record.sign_record(rec, alice_sk)

    assert record.verify_record(rec, sig, bob_pk) is False


def test_signed_record_save_and_load_round_trip():
    keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
    sk = keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")
    pk = keystore.load_signing_public_key(TEST_KEYS_DIR, "alice")

    rec = record.build_decryption_record("doc1", "deadbeef", "alice")
    sig = record.sign_record(rec, sk)

    path = "/tmp/phase2_test_record.json"
    record.save_signed_record(rec, sig, path)
    loaded_rec, loaded_sig = record.load_signed_record(path)
    os.remove(path)

    assert loaded_rec == rec
    assert loaded_sig == sig
    assert record.verify_record(loaded_rec, loaded_sig, pk) is True