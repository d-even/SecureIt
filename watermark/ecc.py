"""
Forward error correction for watermark payloads.

A watermark payload (the session_id) has to survive being physically
re-photographed, re-compressed as JPEG, or partially stripped during a
copy-paste — all of which flip individual bits/bytes without warning.
Reed-Solomon lets extraction correct a bounded number of corrupted bytes
instead of failing outright, which is exactly the "very high bit error
rate" tolerance real screen-watermarking research relies on.
"""

from reedsolo import RSCodec, ReedSolomonError

# 10 parity bytes -> can correct up to 5 corrupted bytes anywhere in the
# payload (Reed-Solomon corrects floor(parity/2) byte errors).
PARITY_BYTES = 10


def encode_payload(payload: bytes) -> bytes:
    """payload + parity bytes, ready to be turned into bits and embedded."""
    rs = RSCodec(PARITY_BYTES)
    return bytes(rs.encode(payload))


def decode_payload(data: bytes, payload_len: int) -> bytes | None:
    """
    Reverses encode_payload. Returns the original payload bytes if it could
    be recovered (possibly after correcting errors), or None if corruption
    was too severe to recover from — callers should treat None as
    "no watermark found here", not crash.
    """
    rs = RSCodec(PARITY_BYTES)
    try:
        decoded, _decoded_with_ecc, _errata_pos = rs.decode(bytes(data))
        decoded = bytes(decoded)
        if len(decoded) != payload_len:
            return None
        return decoded
    except ReedSolomonError:
        return None


def encoded_length(payload_len: int) -> int:
    return payload_len + PARITY_BYTES