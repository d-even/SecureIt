# """
# Phase 2 end-to-end demo — builds on Phase 1.

# Simulates:
#   1. Everything from Phase 1 (encrypt once, wrap per recipient, one
#      recipient decrypts) — now each recipient ALSO gets an ML-DSA-65
#      signing keypair when their identity is issued.
#   2. The recipient who just decrypted builds a decryption record
#      (who / what document / which session / when) and signs it with
#      their own ML-DSA private key.
#   3. Anyone holding that recipient's PUBLIC signing key (e.g. the ledger,
#      in Phase 4) verifies the signature.
#   4. Proof that: (a) a valid signature verifies, (b) tampering with even
#      one field of the record breaks verification, (c) a different
#      recipient's signature does NOT verify against this recipient's
#      public key (no impersonation).

# Run: python3 demo_phase2.py
# """

# import copy
# import os
# import shutil

# from crypto import aes, kem, keystore, manifest, record

# BASE = os.path.dirname(os.path.abspath(__file__))
# KEYS_DIR = os.path.join(BASE, "keys")
# WORK_DIR = os.path.join(BASE, "workdir")

# RECIPIENTS = ["p_kapoor", "s_mehta", "a_rao"]


# def banner(title: str) -> None:
#     print("\n" + "=" * 60)
#     print(title)
#     print("=" * 60)


# def step0_reset() -> None:
#     banner("STEP 0 — Reset demo environment")
#     if os.path.exists(KEYS_DIR):
#         shutil.rmtree(KEYS_DIR)
#     if os.path.exists(WORK_DIR):
#         shutil.rmtree(WORK_DIR)
#     os.makedirs(KEYS_DIR)
#     os.makedirs(WORK_DIR)


# def step1_issue_keys() -> None:
#     banner("STEP 1 — Offline CA issues ML-KEM-768 + ML-DSA-65 keypairs per recipient")
#     for rid in RECIPIENTS:
#         keystore.issue_recipient_keypair(KEYS_DIR, rid)
#         pk_kem = keystore.load_public_key(KEYS_DIR, rid)
#         pk_sign = keystore.load_signing_public_key(KEYS_DIR, rid)
#         print(f"  {rid:<10s}  ML-KEM-768 pub: {len(pk_kem)}B   ML-DSA-65 pub: {len(pk_sign)}B")


# def step2_encrypt_and_distribute() -> tuple[str, dict, bytes]:
#     banner("STEP 2 — Sender encrypts once, wraps the key per recipient  (Phase 1)")
#     content = b"CONFIDENTIAL Q3 BOARDROOM BRIEFING - Phase 2 signing demo.\n"

#     session_key = aes.generate_session_key()
#     enc_path = os.path.join(WORK_DIR, "briefing.enc")
#     doc_nonce, ciphertext = aes.encrypt_bytes(session_key, content)
#     with open(enc_path, "wb") as f:
#         f.write(ciphertext)

#     m = manifest.build_manifest(document_id="briefing_q3", document_plaintext=content, doc_nonce=doc_nonce)
#     for rid in RECIPIENTS:
#         pk = keystore.load_public_key(KEYS_DIR, rid)
#         wrap_entry = kem.wrap_session_key_for_recipient(session_key, pk)
#         manifest.add_recipient_entry(m, rid, wrap_entry)

#     print(f"  Document encrypted and wrapped for {len(RECIPIENTS)} recipients.")
#     print(f"  document_sha3_256 = {m['document_sha3_256']}")
#     return enc_path, m, content


# def step3_recipient_decrypts(enc_path: str, m: dict, recipient_id: str) -> bytes:
#     banner(f"STEP 3 — '{recipient_id}' decrypts using their ML-KEM secret key  (Phase 1)")
#     sk = keystore.load_secret_key(KEYS_DIR, recipient_id)
#     wrap_entry = manifest.get_recipient_wrap_entry(m, recipient_id)
#     session_key = kem.unwrap_session_key(sk, wrap_entry)

#     doc_nonce = manifest.get_doc_nonce(m)
#     with open(enc_path, "rb") as f:
#         ciphertext = f.read()
#     plaintext = aes.decrypt_bytes(session_key, doc_nonce, ciphertext)
#     print(f"  Decrypted successfully. SHA3-256 = {manifest.sha3_256_hex(plaintext)}")
#     return plaintext


# def step4_sign_decryption_record(m: dict, recipient_id: str) -> tuple[dict, bytes]:
#     banner(f"STEP 4 — '{recipient_id}' signs the decryption record with ML-DSA-65  (Phase 2, NEW)")

#     rec = record.build_decryption_record(
#         document_id=m["document_id"],
#         document_sha3_256=m["document_sha3_256"],
#         recipient_id=recipient_id,
#     )
#     print("  Record to sign:")
#     for k, v in rec.items():
#         print(f"    {k:<20s}: {v}")

#     signing_sk = keystore.load_signing_secret_key(KEYS_DIR, recipient_id)
#     signature = record.sign_record(rec, signing_sk)
#     print(f"\n  Signature: {len(signature)} bytes (ML-DSA-65)")

#     out_path = os.path.join(WORK_DIR, f"decryption_record_{recipient_id}.json")
#     record.save_signed_record(rec, signature, out_path)
#     print(f"  Saved signed record -> {out_path}")
#     print("  (In Phase 4 this whole signed record is what gets committed to the ledger.)")

#     return rec, signature


# def step5_verify_signature(rec: dict, signature: bytes, recipient_id: str) -> None:
#     banner(f"STEP 5 — Verify the signature using '{recipient_id}'s PUBLIC signing key")
#     signing_pk = keystore.load_signing_public_key(KEYS_DIR, recipient_id)
#     ok = record.verify_record(rec, signature, signing_pk)
#     print(f"  Signature valid: {ok}")
#     assert ok, "Signature verification FAILED"
#     print("  Result: PASS — this is a genuine, non-repudiable record from this recipient.")


# def step6_prove_tamper_detected(rec: dict, signature: bytes, recipient_id: str) -> None:
#     banner("STEP 6 — Prove tampering with the record breaks verification")
#     signing_pk = keystore.load_signing_public_key(KEYS_DIR, recipient_id)

#     tampered = copy.deepcopy(rec)
#     tampered["recipient_id"] = "someone_else"  # attacker tries to reassign blame
#     ok = record.verify_record(tampered, signature, signing_pk)
#     print(f"  Verifying record with recipient_id swapped to 'someone_else': valid = {ok}")
#     assert not ok, "Tamper detection FAILED — this should NOT verify"
#     print("  Result: PASS — even a one-field change invalidates the signature.")


# def step7_prove_no_impersonation(rec: dict, signature: bytes) -> None:
#     banner("STEP 7 — Prove another recipient CANNOT be blamed using their public key")
#     other_recipient = "s_mehta" if rec["recipient_id"] != "s_mehta" else "a_rao"
#     other_pk = keystore.load_signing_public_key(KEYS_DIR, other_recipient)

#     ok = record.verify_record(rec, signature, other_pk)
#     print(f"  Verifying '{rec['recipient_id']}'s signed record against '{other_recipient}'s public key: valid = {ok}")
#     assert not ok, "Impersonation check FAILED"
#     print("  Result: PASS — a signature only verifies against its true signer's key.")


# def main() -> None:
#     step0_reset()
#     step1_issue_keys()
#     enc_path, m, _content = step2_encrypt_and_distribute()

#     recipient_id = "p_kapoor"
#     step3_recipient_decrypts(enc_path, m, recipient_id)
#     rec, signature = step4_sign_decryption_record(m, recipient_id)
#     step5_verify_signature(rec, signature, recipient_id)
#     step6_prove_tamper_detected(rec, signature, recipient_id)
#     step7_prove_no_impersonation(rec, signature)

#     banner("PHASE 2 COMPLETE")
#     print("Every decryption now produces a signed, non-repudiable, tamper-evident record.")
#     print("Next: Phase 3 embeds an invisible watermark carrying this record's session_id.")


# if __name__ == "__main__":
#     main()

"""
Phase 3 end-to-end demo — builds on Phase 1 + Phase 2.

Simulates the full "decrypt -> fingerprint -> sign" moment, then shows
BOTH watermarking paths tied to the SAME session_id from the signed
record:
  A) Text watermark — for a leak where someone copy-pastes the text out.
  B) Image watermark — for a leak where someone screenshots / photographs
     the rendered document, re-saved as a degraded JPEG.

Then simulates a leak of EACH kind and shows that extracting the
watermark recovers the exact session_id that was signed in Phase 2 —
this session_id is the join key Phase 4's ledger lookup will use.

Run: python3 demo_phase3.py
"""

import io
import os
import shutil

from PIL import Image, ImageDraw

from crypto import aes, kem, keystore, manifest, record
from watermark import text_watermark, image_watermark

BASE = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE, "keys")
WORK_DIR = os.path.join(BASE, "workdir")

RECIPIENTS = ["p_kapoor", "s_mehta", "a_rao"]
DOCUMENT_TEXT = (
    "CONFIDENTIAL Q3 BOARDROOM BRIEFING\n\n"
    "Revenue projections, headcount plans, and the M&A shortlist are all\n"
    "included below. Do not distribute outside the leadership team.\n\n"
    "Prepared for the recipient named in this copy.\n"
)


def banner(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


def render_as_image(text: str) -> Image.Image:
    """Stand-in for 'what a photo of this document on screen would look
    like' — a plain rendered page."""
    img = Image.new("L", (900, 700), color=255)
    draw = ImageDraw.Draw(img)
    draw.multiline_text((40, 40), text, fill=0)
    return img


def step0_reset() -> None:
    banner("STEP 0 — Reset demo environment")
    if os.path.exists(KEYS_DIR):
        shutil.rmtree(KEYS_DIR)
    if os.path.exists(WORK_DIR):
        shutil.rmtree(WORK_DIR)
    os.makedirs(KEYS_DIR)
    os.makedirs(WORK_DIR)


def step1_setup_and_decrypt(recipient_id: str) -> tuple[dict, bytes]:
    banner(f"STEP 1 — Issue keys, encrypt, distribute, '{recipient_id}' decrypts  (Phase 1)")
    for rid in RECIPIENTS:
        keystore.issue_recipient_keypair(KEYS_DIR, rid)

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
    plaintext = aes.decrypt_bytes(recovered_key, doc_nonce, ciphertext).decode("utf-8")
    print(f"  '{recipient_id}' decrypted the document successfully.")
    return m, plaintext.encode("utf-8")


def step2_sign_record(m: dict, recipient_id: str) -> dict:
    banner(f"STEP 2 — '{recipient_id}' signs the decryption record  (Phase 2)")
    rec = record.build_decryption_record(
        document_id=m["document_id"],
        document_sha3_256=m["document_sha3_256"],
        recipient_id=recipient_id,
    )
    signing_sk = keystore.load_signing_secret_key(KEYS_DIR, recipient_id)
    signature = record.sign_record(rec, signing_sk)
    record.save_signed_record(rec, signature, os.path.join(WORK_DIR, f"record_{recipient_id}.json"))
    print(f"  session_id (the watermark payload) = {rec['session_id']}")
    return rec


def step3_watermark_text_copy(plaintext_bytes: bytes, session_id: str) -> str:
    banner("STEP 3 — Embed the SAME session_id as an invisible TEXT watermark  (Phase 3a)")
    text = plaintext_bytes.decode("utf-8")
    watermarked_text = text_watermark.embed(text, session_id, copies=4)
    assert text_watermark.strip(watermarked_text) == text
    print("  Watermarked text is visually identical to the original.")
    with open(os.path.join(WORK_DIR, "recipient_copy.txt"), "w", encoding="utf-8") as f:
        f.write(watermarked_text)
    return watermarked_text


def step4_watermark_screenshot(plaintext_bytes: bytes, session_id: str) -> Image.Image:
    banner("STEP 4 — Embed the SAME session_id as an invisible IMAGE watermark  (Phase 3b)")
    text = plaintext_bytes.decode("utf-8")
    rendered = render_as_image(text)
    watermarked_img = image_watermark.embed(rendered, session_id)
    watermarked_img.save(os.path.join(WORK_DIR, "recipient_screen.png"))
    print("  Watermarked screen render saved (visually near-identical to the original).")
    return watermarked_img


def step5_simulate_text_leak_and_trace(watermarked_text: str, expected_session_id: str) -> None:
    banner("STEP 5 — LEAK #1: recipient copy-pastes half the text into an email")
    leaked_fragment = watermarked_text[: len(watermarked_text) // 2]
    recovered = text_watermark.extract(leaked_fragment)
    print(f"  Recovered session_id from the leaked fragment: {recovered}")
    print(f"  Matches the signed record's session_id       : {recovered == expected_session_id}")
    assert recovered == expected_session_id


def step6_simulate_screenshot_leak_and_trace(watermarked_img: Image.Image, expected_session_id: str) -> None:
    banner("STEP 6 — LEAK #2: recipient screenshots it, image gets re-saved as JPEG(q=75)")
    buf = io.BytesIO()
    watermarked_img.save(buf, format="JPEG", quality=75)
    buf.seek(0)
    leaked_image = Image.open(buf)

    recovered = image_watermark.extract(leaked_image)
    print(f"  Recovered session_id from the leaked JPEG : {recovered}")
    print(f"  Matches the signed record's session_id     : {recovered == expected_session_id}")
    assert recovered == expected_session_id


def main() -> None:
    step0_reset()
    recipient_id = "s_mehta"

    m, plaintext_bytes = step1_setup_and_decrypt(recipient_id)
    rec = step2_sign_record(m, recipient_id)
    session_id = rec["session_id"]

    watermarked_text = step3_watermark_text_copy(plaintext_bytes, session_id)
    watermarked_img = step4_watermark_screenshot(plaintext_bytes, session_id)

    step5_simulate_text_leak_and_trace(watermarked_text, session_id)
    step6_simulate_screenshot_leak_and_trace(watermarked_img, session_id)

    banner("PHASE 3 COMPLETE")
    print(f"Both leak paths trace back to the same session_id: {session_id}")
    print(f"...which is exactly what's signed in the record for recipient: {rec['recipient_id']}")
    print("Next: Phase 4 commits this signed record to the offline Hyperledger Fabric ledger,")
    print("      so a leaked file's watermark can be looked up and cryptographically verified.")


if __name__ == "__main__":
    main()