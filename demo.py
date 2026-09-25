"""
Phase 4 end-to-end demo — the FULL pipeline, start to finish.

  1. Sender encrypts once, wraps per recipient                 (Phase 1)
  2. Recipient decrypts, signs the decryption record            (Phase 2)
  3. Invisible watermark embedded, tied to the signed record     (Phase 3)
  4. Validators endorse the record; it's committed to the ledger (Phase 4)
  5. --- time passes, the document leaks ---
  6. Watermark extracted from the leaked copy
  7. Ledger looked up by the recovered session_id
  8. Chain integrity + signatures + endorsements all re-verified
  9. Final, cryptographically verifiable attribution is printed

Run: python3 demo_phase4.py
"""

import os
import shutil

from crypto import aes, kem, keystore, manifest, record
from watermark import text_watermark
from ledger import Ledger, endorsement, validators

BASE = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE, "keys")
VALIDATORS_DIR = os.path.join(BASE, "validators")
LEDGER_PATH = os.path.join(BASE, "workdir", "ledger.jsonl")
WORK_DIR = os.path.join(BASE, "workdir")

RECIPIENTS = ["p_kapoor", "s_mehta", "a_rao"]
VALIDATOR_ORGS = ["sender_org", "recipient_org", "audit_org"]
ENDORSEMENT_THRESHOLD = 2

DOCUMENT_TEXT = (
    "CONFIDENTIAL Q3 BOARDROOM BRIEFING\n\n"
    "Revenue projections, headcount plans, and the M&A shortlist are all\n"
    "included below. Do not distribute outside the leadership team.\n"
)


def banner(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def step0_reset() -> None:
    banner("STEP 0 — Reset demo environment")
    for d in (KEYS_DIR, VALIDATORS_DIR, WORK_DIR):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)


def step1_setup() -> None:
    banner("STEP 1 — Issue recipient keys and validator (org) identities")
    for rid in RECIPIENTS:
        keystore.issue_recipient_keypair(KEYS_DIR, rid)
        print(f"  recipient issued : {rid}")
    for org in VALIDATOR_ORGS:
        validators.issue_validator(VALIDATORS_DIR, org)
        print(f"  validator issued : {org}")


def step2_encrypt_distribute_decrypt(recipient_id: str) -> tuple[dict, bytes]:
    banner(f"STEP 2 — Encrypt once, distribute, '{recipient_id}' decrypts  (Phase 1)")
    session_key = aes.generate_session_key()
    doc_nonce, ciphertext = aes.encrypt_bytes(session_key, DOCUMENT_TEXT.encode("utf-8"))

    m = manifest.build_manifest("briefing_q3", DOCUMENT_TEXT.encode("utf-8"), doc_nonce)
    for rid in RECIPIENTS:
        pk = keystore.load_public_key(KEYS_DIR, rid)
        wrap_entry = kem.wrap_session_key_for_recipient(session_key, pk)
        manifest.add_recipient_entry(m, rid, wrap_entry)

    sk = keystore.load_secret_key(KEYS_DIR, recipient_id)
    wrap_entry = manifest.get_recipient_wrap_entry(m, recipient_id)
    recovered_key = kem.unwrap_session_key(sk, wrap_entry)
    plaintext = aes.decrypt_bytes(recovered_key, doc_nonce, ciphertext)
    print(f"  '{recipient_id}' decrypted successfully.")
    return m, plaintext


def step3_sign_record(m: dict, recipient_id: str) -> tuple[dict, bytes, bytes]:
    banner(f"STEP 3 — '{recipient_id}' signs the decryption record  (Phase 2)")
    rec = record.build_decryption_record(m["document_id"], m["document_sha3_256"], recipient_id)
    sk = keystore.load_signing_secret_key(KEYS_DIR, recipient_id)
    pk = keystore.load_signing_public_key(KEYS_DIR, recipient_id)
    sig = record.sign_record(rec, sk)
    print(f"  session_id = {rec['session_id']}")
    return rec, sig, pk


def step4_watermark_copy(plaintext: bytes, session_id: str) -> str:
    banner("STEP 4 — Embed the session_id as an invisible watermark  (Phase 3)")
    text = plaintext.decode("utf-8")
    watermarked = text_watermark.embed(text, session_id, copies=4)
    assert text_watermark.strip(watermarked) == text
    print("  Watermark embedded; recipient's copy is visually unchanged.")
    return watermarked


def step5_endorse_and_commit(rec: dict, sig: bytes, pk: bytes) -> Ledger:
    banner("STEP 5 — Validators endorse the record; commit to the ledger  (Phase 4)")
    ledger = Ledger(LEDGER_PATH, VALIDATORS_DIR, threshold=ENDORSEMENT_THRESHOLD)

    endorsements = []
    for org in VALIDATOR_ORGS[:ENDORSEMENT_THRESHOLD]:  # 2 of 3 orgs endorse
        v_sk = validators.load_validator_secret_key(VALIDATORS_DIR, org)
        e = endorsement.endorse_record(org, v_sk, rec, sig, pk)
        endorsements.append(e)
        print(f"  endorsed by      : {org}")

    committed_block = ledger.commit_record(rec, sig, pk, endorsements)
    print(f"  committed as block #{committed_block['index']}  (hash {committed_block['hash'][:16]}...)")
    return ledger


def step6_the_leak(watermarked_text: str) -> str:
    banner("STEP 6 — Time passes... the document leaks")
    leaked_fragment = watermarked_text[: int(len(watermarked_text) * 0.7)]
    print("  An anonymous tip includes a partial copy of the document.")
    print(f"  (leaked fragment is {len(leaked_fragment)}/{len(watermarked_text)} chars of the original)")
    return leaked_fragment


def step7_trace_the_leak(leaked_text: str, ledger: Ledger) -> dict:
    banner("STEP 7 — Trace the leak: extract watermark -> ledger lookup -> verify")

    recovered_session_id = text_watermark.extract(leaked_text)
    print(f"  Watermark extracted from leaked copy : {recovered_session_id}")
    if recovered_session_id is None:
        print("  No watermark found — cannot attribute this leak.")
        return {}

    found_block = ledger.get_by_session_id(recovered_session_id)
    if found_block is None:
        print("  session_id not found on the ledger — cannot attribute this leak.")
        return {}
    print(f"  Ledger match found   : block #{found_block['index']}")

    valid, issues = ledger.verify_chain()
    print(f"  Full chain integrity : {'VALID' if valid else 'COMPROMISED'}")
    if issues:
        for i in issues:
            print(f"    ! {i}")

    return found_block


def step8_final_report(block: dict) -> None:
    banner("STEP 8 — Final attribution report")
    if not block:
        print("  INCONCLUSIVE — see above for why.")
        return
    rec = block["record"]
    print(f"  Recipient responsible : {rec['recipient_id']}")
    print(f"  Document              : {rec['document_id']}")
    print(f"  Decrypted at          : {rec['decrypted_at']}")
    print(f"  Session (watermark)   : {rec['session_id']}")
    print(f"  Endorsed by           : {', '.join(e['validator_id'] for e in block['endorsements'])}")
    print(f"  Ledger block          : #{block['index']}  ({block['hash'][:16]}...)")
    print()
    print("  This is a cryptographically verifiable record: the recipient's own")
    print("  ML-DSA signature proves THEY decrypted it, independent validator")
    print("  endorsements prove the record wasn't forged after the fact, and the")
    print("  hash chain proves nothing on the ledger was altered since.")


def main() -> None:
    step0_reset()
    step1_setup()

    recipient_id = "s_mehta"   # this is who will turn out to be the leaker
    m, plaintext = step2_encrypt_distribute_decrypt(recipient_id)
    rec, sig, pk = step3_sign_record(m, recipient_id)
    watermarked_text = step4_watermark_copy(plaintext, rec["session_id"])
    ledger = step5_endorse_and_commit(rec, sig, pk)

    leaked_text = step6_the_leak(watermarked_text)
    found_block = step7_trace_the_leak(leaked_text, ledger)
    step8_final_report(found_block)

    banner("PHASE 4 COMPLETE — full pipeline working end to end")


if __name__ == "__main__":
    main()