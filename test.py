# """
# Automated tests for Phase 2: ML-DSA-65 signing of decryption records.

# Run: python3 -m pytest test_phase2.py -v
# """

# import copy
# import os
# import shutil

# import pytest

# from crypto import keystore, record, signing

# TEST_KEYS_DIR = "/tmp/phase2_test_keys"


# @pytest.fixture(autouse=True)
# def clean_keys_dir():
#     if os.path.exists(TEST_KEYS_DIR):
#         shutil.rmtree(TEST_KEYS_DIR)
#     os.makedirs(TEST_KEYS_DIR)
#     yield
#     shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


# # ---------- ML-DSA-65 primitives ----------

# def test_signing_key_sizes_match_nist_ml_dsa_65():
#     pk, sk = signing.generate_signing_keypair()
#     assert len(pk) == 1952
#     assert len(sk) == 4032


# def test_sign_verify_round_trip():
#     pk, sk = signing.generate_signing_keypair()
#     msg = b"decryption record bytes"
#     sig = signing.sign(sk, msg)
#     assert signing.verify(pk, msg, sig) is True


# def test_verify_rejects_tampered_message():
#     pk, sk = signing.generate_signing_keypair()
#     sig = signing.sign(sk, b"original message")
#     assert signing.verify(pk, b"different message", sig) is False


# def test_verify_rejects_wrong_public_key():
#     pk_a, sk_a = signing.generate_signing_keypair()
#     pk_b, _sk_b = signing.generate_signing_keypair()
#     msg = b"decryption record bytes"
#     sig = signing.sign(sk_a, msg)
#     assert signing.verify(pk_b, msg, sig) is False


# # ---------- keystore: signing keys issued alongside KEM keys ----------

# def test_keystore_issues_both_key_types():
#     keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
#     assert len(keystore.load_public_key(TEST_KEYS_DIR, "alice")) == 1184
#     assert len(keystore.load_secret_key(TEST_KEYS_DIR, "alice")) == 2400
#     assert len(keystore.load_signing_public_key(TEST_KEYS_DIR, "alice")) == 1952
#     assert len(keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")) == 4032


# # ---------- record.py: canonical encoding + sign/verify ----------

# def test_canonical_bytes_is_deterministic():
#     r1 = {"b": 2, "a": 1}
#     r2 = {"a": 1, "b": 2}
#     assert record.canonical_bytes(r1) == record.canonical_bytes(r2)


# def test_build_decryption_record_has_expected_fields():
#     rec = record.build_decryption_record("doc1", "deadbeef", "alice")
#     assert rec["document_id"] == "doc1"
#     assert rec["document_sha3_256"] == "deadbeef"
#     assert rec["recipient_id"] == "alice"
#     assert "session_id" in rec and len(rec["session_id"]) == 32
#     assert "decrypted_at" in rec


# def test_record_sign_and_verify_round_trip():
#     keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
#     sk = keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")
#     pk = keystore.load_signing_public_key(TEST_KEYS_DIR, "alice")

#     rec = record.build_decryption_record("doc1", "deadbeef", "alice")
#     sig = record.sign_record(rec, sk)

#     assert record.verify_record(rec, sig, pk) is True


# def test_record_tamper_after_signing_is_detected():
#     keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
#     sk = keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")
#     pk = keystore.load_signing_public_key(TEST_KEYS_DIR, "alice")

#     rec = record.build_decryption_record("doc1", "deadbeef", "alice")
#     sig = record.sign_record(rec, sk)

#     for field, new_value in [
#         ("recipient_id", "mallory"),
#         ("document_id", "doc2"),
#         ("document_sha3_256", "0000"),
#         ("session_id", "0" * 32),
#     ]:
#         tampered = copy.deepcopy(rec)
#         tampered[field] = new_value
#         assert record.verify_record(tampered, sig, pk) is False, f"tampering '{field}' was not detected"


# def test_record_cannot_be_attributed_to_wrong_recipient():
#     keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
#     keystore.issue_recipient_keypair(TEST_KEYS_DIR, "bob")

#     alice_sk = keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")
#     bob_pk = keystore.load_signing_public_key(TEST_KEYS_DIR, "bob")

#     rec = record.build_decryption_record("doc1", "deadbeef", "alice")
#     sig = record.sign_record(rec, alice_sk)

#     assert record.verify_record(rec, sig, bob_pk) is False


# def test_signed_record_save_and_load_round_trip():
#     keystore.issue_recipient_keypair(TEST_KEYS_DIR, "alice")
#     sk = keystore.load_signing_secret_key(TEST_KEYS_DIR, "alice")
#     pk = keystore.load_signing_public_key(TEST_KEYS_DIR, "alice")

#     rec = record.build_decryption_record("doc1", "deadbeef", "alice")
#     sig = record.sign_record(rec, sk)

#     path = "/tmp/phase2_test_record.json"
#     record.save_signed_record(rec, sig, path)
#     loaded_rec, loaded_sig = record.load_signed_record(path)
#     os.remove(path)

#     assert loaded_rec == rec
#     assert loaded_sig == sig
#     assert record.verify_record(loaded_rec, loaded_sig, pk) is True


"""
Automated tests for Phase 3: invisible forensic watermarking.

Run: python3 -m pytest test_phase3.py -v
"""

import io
import uuid

import pytest
from PIL import Image, ImageDraw

from watermark import ecc, payload, text_watermark, image_watermark

SAMPLE_TEXT = (
    "CONFIDENTIAL Q3 BOARDROOM BRIEFING\n\n"
    "This document contains sensitive figures for the upcoming quarter.\n"
    "Revenue projections, headcount plans, and the M&A shortlist are all\n"
    "included below. Do not distribute outside the leadership team.\n\n"
    "Section 1: Revenue\nSection 2: Headcount\nSection 3: M&A targets\n"
)


def _sample_document_image(text: str = SAMPLE_TEXT, size=(900, 700)) -> Image.Image:
    img = Image.new("L", size, color=255)
    draw = ImageDraw.Draw(img)
    draw.multiline_text((40, 40), text, fill=0)
    return img


# ---------- ecc.py ----------

def test_ecc_round_trip():
    payload_bytes = bytes(range(16))
    encoded = ecc.encode_payload(payload_bytes)
    decoded = ecc.decode_payload(encoded, payload_len=16)
    assert decoded == payload_bytes


def test_ecc_corrects_a_few_byte_errors():
    payload_bytes = bytes(range(16))
    encoded = bytearray(ecc.encode_payload(payload_bytes))
    # Corrupt up to 5 bytes (PARITY_BYTES // 2) — should still recover.
    for i in (0, 3, 7, 12, 20):
        encoded[i] ^= 0xFF
    decoded = ecc.decode_payload(bytes(encoded), payload_len=16)
    assert decoded == payload_bytes


def test_ecc_gives_up_cleanly_on_severe_corruption():
    payload_bytes = bytes(range(16))
    encoded = bytearray(ecc.encode_payload(payload_bytes))
    for i in range(len(encoded)):
        encoded[i] ^= 0xFF   # corrupt everything
    decoded = ecc.decode_payload(bytes(encoded), payload_len=16)
    assert decoded is None   # must fail cleanly, not raise, not return garbage


# ---------- payload.py ----------

def test_session_id_bytes_round_trip():
    sid = uuid.uuid4().hex
    b = payload.session_id_to_bytes(sid)
    assert len(b) == 16
    assert payload.bytes_to_session_id(b) == sid


def test_session_id_ecc_bits_round_trip():
    sid = uuid.uuid4().hex
    bits = payload.session_id_to_ecc_bits(sid)
    assert len(bits) == payload.ecc_bit_length()
    recovered = payload.ecc_bits_to_session_id(bits)
    assert recovered == sid


# ---------- text_watermark.py ----------

def test_text_watermark_is_visually_invisible():
    sid = uuid.uuid4().hex
    wm = text_watermark.embed(SAMPLE_TEXT, sid)
    assert text_watermark.strip(wm) == SAMPLE_TEXT


def test_text_watermark_round_trip():
    sid = uuid.uuid4().hex
    wm = text_watermark.embed(SAMPLE_TEXT, sid)
    assert text_watermark.extract(wm) == sid


def test_text_watermark_survives_partial_document_leak():
    """Only half the document leaks (e.g. pasted into an email) — one of
    the redundant copies should still be intact."""
    sid = uuid.uuid4().hex
    wm = text_watermark.embed(SAMPLE_TEXT, sid, copies=4)
    half = wm[: len(wm) // 2]
    assert text_watermark.extract(half) == sid


def test_text_watermark_survives_middle_chunk_removed():
    sid = uuid.uuid4().hex
    wm = text_watermark.embed(SAMPLE_TEXT, sid, copies=4)
    tampered = wm[:200] + wm[400:]
    assert text_watermark.extract(tampered) == sid


def test_text_watermark_unwatermarked_document_returns_none():
    assert text_watermark.extract(SAMPLE_TEXT) is None


def test_text_watermark_fully_stripped_returns_none_not_garbage():
    sid = uuid.uuid4().hex
    wm = text_watermark.embed(SAMPLE_TEXT, sid)
    stripped = text_watermark.strip(wm)
    assert text_watermark.extract(stripped) is None


# ---------- image_watermark.py ----------

def test_image_watermark_round_trip_no_degradation():
    sid = uuid.uuid4().hex
    img = _sample_document_image()
    wm = image_watermark.embed(img, sid)
    assert image_watermark.extract(wm) == sid


def test_image_watermark_visually_close_to_original():
    import numpy as np
    img = _sample_document_image()
    sid = uuid.uuid4().hex
    wm = image_watermark.embed(img, sid)
    orig = np.asarray(img, dtype=np.float64)
    wmed = np.asarray(wm, dtype=np.float64)
    mse = float(np.mean((orig - wmed) ** 2))
    # Simple sanity bound: mean squared pixel error should be tiny (PSNR ~50dB+).
    assert mse < 25, f"watermark changed the image too much (MSE={mse:.2f})"


@pytest.mark.parametrize("quality", [95, 85, 75, 65])
def test_image_watermark_survives_jpeg_recompression(quality):
    sid = uuid.uuid4().hex
    img = _sample_document_image()
    wm = image_watermark.embed(img, sid)

    buf = io.BytesIO()
    wm.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    reloaded = Image.open(buf)

    assert image_watermark.extract(reloaded) == sid


def test_image_watermark_capacity_check_raises_on_too_small_image():
    sid = uuid.uuid4().hex
    tiny = Image.new("L", (32, 32), color=255)   # far too small for the payload
    with pytest.raises(ValueError):
        image_watermark.embed(tiny, sid)


def test_image_watermark_unwatermarked_image_does_not_crash():
    # Extracting from a plain, never-watermarked image should either
    # return None or (rarely, on tiny images) raise nothing — never crash.
    img = _sample_document_image()
    result = image_watermark.extract(img)
    assert result is None or isinstance(result, str)