"""
Phase 1 end-to-end demo.

Simulates:
  1. An offline CA issuing ML-KEM-768 keypairs for 3 recipients.
  2. A sender encrypting one document with AES-256-GCM, then wrapping the
     session key separately for each recipient with ML-KEM.
  3. One recipient decapsulating their wrap, unwrapping the session key,
     and decrypting the document — using ONLY their own secret key.
  4. Proof that: (a) the decrypted file is byte-identical to the original,
     and (b) a different recipient's secret key CANNOT unwrap this one's
     entry (tamper/identity check).

Run: python3 demo_phase1.py
"""

import os
import shutil

from crypto import aes, kem, keystore, manifest

BASE = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE, "keys")
WORK_DIR = os.path.join(BASE, "workdir")

RECIPIENTS = ["p_kapoor", "s_mehta", "a_rao"]


def banner(title: str) -> None:
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def step0_reset() -> None:
    banner("STEP 0 — Reset demo environment")
    if os.path.exists(KEYS_DIR):
        shutil.rmtree(KEYS_DIR)
    if os.path.exists(WORK_DIR):
        shutil.rmtree(WORK_DIR)
    os.makedirs(KEYS_DIR)
    os.makedirs(WORK_DIR)
    print(f"Keys dir : {KEYS_DIR}")
    print(f"Work dir : {WORK_DIR}")


def step1_issue_keys() -> None:
    banner("STEP 1 — Offline CA issues ML-KEM-768 keypairs per recipient")
    for rid in RECIPIENTS:
        keystore.issue_recipient_keypair(KEYS_DIR, rid)
        pk = keystore.load_public_key(KEYS_DIR, rid)
        print(f"  {rid:<10s}  public key issued  ({len(pk)} bytes, ML-KEM-768)")


def step2_prepare_document() -> str:
    banner("STEP 2 — Sender prepares the document")
    doc_path = os.path.join(WORK_DIR, "briefing.txt")
    content = (
        b"CONFIDENTIAL Q3 BOARDROOM BRIEFING\n"
        b"------------------------------------\n"
        b"This document is distributed under a broadcast-encrypt,\n"
        b"individually-decrypt model. Each recipient below has their own\n"
        b"ML-KEM-768 key wrap of the AES-256 session key that unlocks this\n"
        b"file. Decrypting it will (in later phases) generate a unique\n"
        b"invisible watermark and a signed, ledgered decryption record.\n"
    )
    with open(doc_path, "wb") as f:
        f.write(content)
    print(f"  Document       : {doc_path}")
    print(f"  Size            : {len(content)} bytes")
    print(f"  SHA3-256        : {manifest.sha3_256_hex(content)}")
    return doc_path


def step3_encrypt_and_distribute(doc_path: str) -> tuple[str, dict]:
    banner("STEP 3 — Sender encrypts once, wraps the key per recipient")

    with open(doc_path, "rb") as f:
        plaintext = f.read()

    session_key = aes.generate_session_key()
    print(f"  Session key      : {len(session_key)} bytes (AES-256), random per distribution")

    enc_path = os.path.join(WORK_DIR, "briefing.enc")
    doc_nonce, ciphertext = aes.encrypt_bytes(session_key, plaintext)
    with open(enc_path, "wb") as f:
        f.write(ciphertext)
    print(f"  Encrypted file   : {enc_path}  ({len(ciphertext)} bytes, AES-256-GCM)")

    m = manifest.build_manifest(document_id="briefing_q3", document_plaintext=plaintext, doc_nonce=doc_nonce)

    for rid in RECIPIENTS:
        pk = keystore.load_public_key(KEYS_DIR, rid)
        wrap_entry = kem.wrap_session_key_for_recipient(session_key, pk)
        manifest.add_recipient_entry(m, rid, wrap_entry)
        print(f"  Wrapped for      : {rid:<10s} "
              f"(kem_ct={len(wrap_entry['kem_ciphertext'])}B, wrapped_key={len(wrap_entry['wrapped_key'])}B)")

    manifest_path = os.path.join(WORK_DIR, "manifest.json")
    manifest.save_manifest(m, manifest_path)
    print(f"  Manifest saved   : {manifest_path}")

    return enc_path, m


def step4_recipient_decrypts(enc_path: str, m: dict, recipient_id: str) -> bytes:
    banner(f"STEP 4 — Recipient '{recipient_id}' decrypts using ONLY their own key")

    sk = keystore.load_secret_key(KEYS_DIR, recipient_id)
    wrap_entry = manifest.get_recipient_wrap_entry(m, recipient_id)

    session_key = kem.unwrap_session_key(sk, wrap_entry)
    print(f"  Session key recovered via ML-KEM-768 decapsulation: {len(session_key)} bytes")

    doc_nonce = manifest.get_doc_nonce(m)
    with open(enc_path, "rb") as f:
        ciphertext = f.read()
    plaintext = aes.decrypt_bytes(session_key, doc_nonce, ciphertext)

    out_path = os.path.join(WORK_DIR, f"decrypted_by_{recipient_id}.txt")
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"  Decrypted to     : {out_path}")
    print(f"  SHA3-256         : {manifest.sha3_256_hex(plaintext)}")
    return plaintext


def step5_verify_integrity(original_plaintext: bytes, recovered_plaintext: bytes, m: dict) -> None:
    banner("STEP 5 — Verify integrity")
    match = original_plaintext == recovered_plaintext
    hash_match = manifest.sha3_256_hex(recovered_plaintext) == m["document_sha3_256"]
    print(f"  Byte-for-byte match with original : {match}")
    print(f"  SHA3-256 matches manifest          : {hash_match}")
    assert match and hash_match, "Integrity check FAILED"
    print("  Result: PASS — recipient received an untampered copy.")


def step6_prove_isolation(enc_path: str, m: dict) -> None:
    banner("STEP 6 — Prove one recipient's key CANNOT unwrap another's entry")
    real_owner = "p_kapoor"
    wrong_key_owner = "s_mehta"

    wrong_sk = keystore.load_secret_key(KEYS_DIR, wrong_key_owner)
    wrap_entry = manifest.get_recipient_wrap_entry(m, real_owner)

    print(f"  Attempting: {wrong_key_owner}'s secret key on {real_owner}'s wrap entry...")
    try:
        kem.unwrap_session_key(wrong_sk, wrap_entry)
        print("  Result: FAIL — unwrap unexpectedly succeeded!")
    except Exception as e:
        print(f"  Result: PASS — rejected as expected ({type(e).__name__})")


def main() -> None:
    step0_reset()
    step1_issue_keys()
    doc_path = step2_prepare_document()
    with open(doc_path, "rb") as f:
        original_plaintext = f.read()

    enc_path, m = step3_encrypt_and_distribute(doc_path)
    recovered = step4_recipient_decrypts(enc_path, m, recipient_id="p_kapoor")
    step5_verify_integrity(original_plaintext, recovered, m)
    step6_prove_isolation(enc_path, m)

    banner("PHASE 1 COMPLETE")
    print("Encrypt-once / wrap-per-recipient / decrypt-with-own-key pipeline is working.")
    print("Next: Phase 2 will sign this decryption event with ML-DSA (Dilithium).")


if __name__ == "__main__":
    main()
