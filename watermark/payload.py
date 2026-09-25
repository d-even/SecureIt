"""
Shared helpers: turning a session_id (the uuid4-hex string from
crypto/record.py) into bytes and bits, and back.
"""

from . import ecc

SESSION_ID_BYTES = 16   # uuid4 hex string (32 hex chars) == 16 raw bytes


def session_id_to_bytes(session_id_hex: str) -> bytes:
    if len(session_id_hex) != 32:
        raise ValueError(f"expected a 32-char uuid4 hex session_id, got {len(session_id_hex)} chars")
    return bytes.fromhex(session_id_hex)


def bytes_to_session_id(data: bytes) -> str:
    if len(data) != SESSION_ID_BYTES:
        raise ValueError(f"expected {SESSION_ID_BYTES} bytes, got {len(data)}")
    return data.hex()


def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit count must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | (1 if b else 0)
        out.append(byte)
    return bytes(out)


def session_id_to_ecc_bits(session_id_hex: str) -> list[int]:
    """session_id -> RS-encoded bytes -> bits. This is what actually gets
    embedded (by either watermark method)."""
    payload = session_id_to_bytes(session_id_hex)
    encoded = ecc.encode_payload(payload)
    return bytes_to_bits(encoded)


def ecc_bits_to_session_id(bits: list[int]) -> str | None:
    """Reverse of session_id_to_ecc_bits. Returns None if the bits were too
    corrupted to recover (rather than raising) — callers treat that as
    "no valid watermark found"."""
    try:
        data = bits_to_bytes(bits)
    except ValueError:
        return None
    decoded = ecc.decode_payload(data, payload_len=SESSION_ID_BYTES)
    if decoded is None:
        return None
    return bytes_to_session_id(decoded)


def ecc_bit_length() -> int:
    return ecc.encoded_length(SESSION_ID_BYTES) * 8