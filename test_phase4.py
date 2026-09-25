"""
Automated tests for Phase 4: endorsed, hash-chained ledger.

Run: python3 -m pytest test_phase4.py -v
"""

import json
import os
import shutil

import pytest

from crypto import keystore, record
from ledger import Ledger, block as block_mod, endorsement, validators

KEYS_DIR = "/tmp/phase4_test_keys"
VALIDATORS_DIR = "/tmp/phase4_test_validators"
LEDGER_PATH = "/tmp/phase4_test_ledger.jsonl"

VALIDATOR_ORGS = ["sender_org", "recipient_org", "audit_org"]


@pytest.fixture(autouse=True)
def clean_state():
    for p in (KEYS_DIR, VALIDATORS_DIR):
        shutil.rmtree(p, ignore_errors=True)
    if os.path.exists(LEDGER_PATH):
        os.remove(LEDGER_PATH)
    os.makedirs(KEYS_DIR)
    os.makedirs(VALIDATORS_DIR)
    for org in VALIDATOR_ORGS:
        validators.issue_validator(VALIDATORS_DIR, org)
    yield
    for p in (KEYS_DIR, VALIDATORS_DIR):
        shutil.rmtree(p, ignore_errors=True)
    if os.path.exists(LEDGER_PATH):
        os.remove(LEDGER_PATH)


def _make_signed_record(recipient_id="p_kapoor", document_id="doc1"):
    keystore.issue_recipient_keypair(KEYS_DIR, recipient_id)
    rec = record.build_decryption_record(document_id, "a" * 64, recipient_id)
    sk = keystore.load_signing_secret_key(KEYS_DIR, recipient_id)
    pk = keystore.load_signing_public_key(KEYS_DIR, recipient_id)
    sig = record.sign_record(rec, sk)
    return rec, sig, pk


def _endorse_with(orgs, rec, sig, pk):
    return [
        endorsement.endorse_record(org, validators.load_validator_secret_key(VALIDATORS_DIR, org), rec, sig, pk)
        for org in orgs
    ]


# ---------- validators.py ----------

def test_validator_issuance_and_registry():
    reg = validators.load_validator_registry(VALIDATORS_DIR)
    assert set(reg.keys()) == set(VALIDATOR_ORGS)
    for pk in reg.values():
        assert len(pk) == 1952  # ML-DSA-65 public key


def test_validator_refuses_duplicate_issuance():
    with pytest.raises(FileExistsError):
        validators.issue_validator(VALIDATORS_DIR, "sender_org")


# ---------- endorsement.py ----------

def test_endorsement_round_trip():
    rec, sig, pk = _make_signed_record()
    v_sk = validators.load_validator_secret_key(VALIDATORS_DIR, "sender_org")
    v_pk = validators.load_validator_public_key(VALIDATORS_DIR, "sender_org")

    e = endorsement.endorse_record("sender_org", v_sk, rec, sig, pk)
    assert endorsement.verify_endorsement(e, rec, sig, v_pk) is True


def test_endorsement_refuses_invalid_recipient_signature():
    rec, sig, pk = _make_signed_record()
    v_sk = validators.load_validator_secret_key(VALIDATORS_DIR, "sender_org")
    bad_sig = b"\x00" * len(sig)
    with pytest.raises(ValueError):
        endorsement.endorse_record("sender_org", v_sk, rec, bad_sig, pk)


def test_endorsement_invalid_after_record_tampered():
    import copy
    rec, sig, pk = _make_signed_record()
    v_sk = validators.load_validator_secret_key(VALIDATORS_DIR, "sender_org")
    v_pk = validators.load_validator_public_key(VALIDATORS_DIR, "sender_org")
    e = endorsement.endorse_record("sender_org", v_sk, rec, sig, pk)

    tampered = copy.deepcopy(rec)
    tampered["recipient_id"] = "mallory"
    assert endorsement.verify_endorsement(e, tampered, sig, v_pk) is False


# ---------- chain.py: commit ----------

def test_commit_succeeds_with_enough_endorsements():
    rec, sig, pk = _make_signed_record()
    endorsements = _endorse_with(["sender_org", "audit_org"], rec, sig, pk)
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    block = ledger.commit_record(rec, sig, pk, endorsements)
    assert block["index"] == 1
    assert block["record"]["recipient_id"] == "p_kapoor"


def test_commit_fails_with_too_few_endorsements():
    rec, sig, pk = _make_signed_record()
    endorsements = _endorse_with(["sender_org"], rec, sig, pk)  # only 1, threshold is 2
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    with pytest.raises(ValueError):
        ledger.commit_record(rec, sig, pk, endorsements)


def test_commit_fails_with_duplicate_endorser():
    rec, sig, pk = _make_signed_record()
    e = endorsement.endorse_record(
        "sender_org", validators.load_validator_secret_key(VALIDATORS_DIR, "sender_org"), rec, sig, pk
    )
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    with pytest.raises(ValueError):
        ledger.commit_record(rec, sig, pk, [e, e])  # same org twice != 2 distinct endorsers


def test_commit_fails_with_unknown_validator():
    rec, sig, pk = _make_signed_record()
    from crypto import signing
    rogue_pk, rogue_sk = signing.generate_signing_keypair()
    rogue_endorsement = {
        "validator_id": "rogue_org",
        "endorsement_signature": signing.sign(rogue_sk, record.canonical_bytes(rec) + sig),
    }
    real_endorsement = _endorse_with(["sender_org"], rec, sig, pk)[0]
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    with pytest.raises(ValueError):
        ledger.commit_record(rec, sig, pk, [rogue_endorsement, real_endorsement])


def test_commit_fails_with_bad_recipient_signature():
    rec, sig, pk = _make_signed_record()
    endorsements = _endorse_with(["sender_org", "audit_org"], rec, sig, pk)
    bad_sig = b"\x00" * len(sig)
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    with pytest.raises(ValueError):
        ledger.commit_record(rec, bad_sig, pk, endorsements)


# ---------- chain.py: lookup ----------

def test_get_by_session_id_finds_committed_record():
    rec, sig, pk = _make_signed_record()
    endorsements = _endorse_with(["sender_org", "audit_org"], rec, sig, pk)
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    ledger.commit_record(rec, sig, pk, endorsements)

    found = ledger.get_by_session_id(rec["session_id"])
    assert found is not None
    assert found["record"]["recipient_id"] == "p_kapoor"


def test_get_by_session_id_returns_none_for_unknown_id():
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    assert ledger.get_by_session_id("nonexistent" * 4) is None


# ---------- chain.py: integrity ----------

def test_verify_chain_passes_on_untouched_ledger():
    rec, sig, pk = _make_signed_record()
    endorsements = _endorse_with(["sender_org", "audit_org"], rec, sig, pk)
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    ledger.commit_record(rec, sig, pk, endorsements)

    valid, issues = ledger.verify_chain()
    assert valid is True
    assert issues == []


def test_verify_chain_catches_naive_tamper():
    """Admin edits a block's content but leaves the stored hash unchanged."""
    rec, sig, pk = _make_signed_record()
    endorsements = _endorse_with(["sender_org", "audit_org"], rec, sig, pk)
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    ledger.commit_record(rec, sig, pk, endorsements)

    lines = open(LEDGER_PATH).read().splitlines()
    tampered_block = json.loads(lines[1])
    tampered_block["record"]["recipient_id"] = "someone_else"
    lines[1] = json.dumps(tampered_block)
    open(LEDGER_PATH, "w").write("\n".join(lines) + "\n")

    valid, issues = ledger.verify_chain()
    assert valid is False
    assert any("hash does not match" in i for i in issues)


def test_verify_chain_catches_sophisticated_tamper_with_recomputed_hashes():
    """Admin edits a block AND recomputes that block's hash AND the next
    block's prev_hash, so the hash chain alone looks fine. Signatures
    (which the admin cannot forge) must still catch it."""
    rec, sig, pk = _make_signed_record()
    endorsements = _endorse_with(["sender_org", "audit_org"], rec, sig, pk)
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    ledger.commit_record(rec, sig, pk, endorsements)

    rec2, sig2, pk2 = _make_signed_record(recipient_id="s_mehta", document_id="doc2")
    endorsements2 = _endorse_with(["sender_org", "audit_org"], rec2, sig2, pk2)
    ledger.commit_record(rec2, sig2, pk2, endorsements2)

    lines = open(LEDGER_PATH).read().splitlines()
    blocks = [json.loads(l) for l in lines]

    blocks[1]["record"]["recipient_id"] = "someone_else"
    blocks[1]["hash"] = block_mod.compute_hash(block_mod.block_without_hash(blocks[1]))
    blocks[2]["prev_hash"] = blocks[1]["hash"]
    blocks[2]["hash"] = block_mod.compute_hash(block_mod.block_without_hash(blocks[2]))
    open(LEDGER_PATH, "w").write("\n".join(json.dumps(b) for b in blocks) + "\n")

    valid, issues = ledger.verify_chain()
    assert valid is False
    # The hash-chain-specific complaint should be GONE (attacker fixed that)...
    assert not any("hash does not match" in i or "chain broken" in i for i in issues)
    # ...but the signature/endorsement layers must still catch it.
    assert any("signature no longer verifies" in i for i in issues)
    assert any("endorsement" in i and "no longer verifies" in i for i in issues)


def test_multiple_recipients_multiple_blocks_all_findable():
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=2)
    session_ids = {}
    for rid in ["p_kapoor", "s_mehta", "a_rao"]:
        rec, sig, pk = _make_signed_record(recipient_id=rid, document_id="shared_doc")
        endorsements = _endorse_with(["sender_org", "audit_org"], rec, sig, pk)
        ledger.commit_record(rec, sig, pk, endorsements)
        session_ids[rid] = rec["session_id"]

    for rid, sid in session_ids.items():
        found = ledger.get_by_session_id(sid)
        assert found["record"]["recipient_id"] == rid

    valid, issues = ledger.verify_chain()
    assert valid is True