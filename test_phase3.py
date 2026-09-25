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