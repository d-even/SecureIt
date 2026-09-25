"""
Invisible text watermark — zero-width Unicode steganography.

Zero-width characters render as nothing (no glyph, no spacing change) in
essentially every font and viewer, but survive copy-paste and most
plain-text/rich-text re-saving. This is the right tool for a leak where
someone copies the *text* out of the document (pastes it into an email,
a chat, a different file) rather than photographing the screen — for
that second case see image_watermark.py.

Robustness design:
  - We encode 2 bits per character using a 4-symbol zero-width alphabet.
  - The RS-encoded payload is embedded as SEVERAL independent copies,
    spread across different whitespace positions in the document.
  - Extraction gathers every zero-width char in the document (in order)
    into one bit stream, then tries every possible starting offset for
    a "needed bit length" window and RS-decodes each. A deletion inside
    one copy corrupts only that copy's internal framing; it does NOT
    prevent another, still-intact copy from being found, because the
    offset search re-aligns to wherever a valid copy actually starts.
  - What this does NOT survive: every zero-width char being stripped
    (some chat apps and text normalizers do this on purpose) — that
    removes the watermark entirely, by design of the technique, and
    extract() simply returns None rather than guessing.
"""

from . import payload as payload_mod

# Four visually-nothing codepoints -> 2 bits each.
_SYMBOLS = ["\u200b", "\u200c", "\u200d", "\u2060"]   # ZWSP, ZWNJ, ZWJ, WORD JOINER
_SYMBOL_TO_BITS = {sym: idx for idx, sym in enumerate(_SYMBOLS)}
_ZERO_WIDTH_SET = set(_SYMBOLS)

DEFAULT_COPIES = 4


def _bits_to_symbols(bits: list[int]) -> str:
    padded = bits if len(bits) % 2 == 0 else bits + [0]
    out = []
    for i in range(0, len(padded), 2):
        val = (padded[i] << 1) | padded[i + 1]
        out.append(_SYMBOLS[val])
    return "".join(out)


def _symbols_to_bits(text: str) -> list[int]:
    bits = []
    for ch in text:
        if ch in _SYMBOL_TO_BITS:
            val = _SYMBOL_TO_BITS[ch]
            bits.append((val >> 1) & 1)
            bits.append(val & 1)
    return bits


def _whitespace_positions(text: str) -> list[int]:
    return [i for i, ch in enumerate(text) if ch.isspace()]


def embed(document_text: str, session_id_hex: str, copies: int = DEFAULT_COPIES) -> str:
    """
    Returns a new string, visually identical to document_text when
    rendered, with `copies` independent invisible embeddings of the
    session_id spread across the document's whitespace.
    """
    bits = payload_mod.session_id_to_ecc_bits(session_id_hex)
    marker = _bits_to_symbols(bits)

    ws_positions = _whitespace_positions(document_text)
    if not ws_positions:
        # No whitespace at all: fall back to a single copy appended at the end.
        return document_text + marker

    copies = max(1, min(copies, len(ws_positions)))
    # Spread copy insertion points evenly through the document.
    step = max(1, len(ws_positions) // copies)
    chosen = [ws_positions[i * step] for i in range(copies)]

    # Insert from the end backwards so earlier insertions don't shift
    # later indices.
    out = document_text
    for pos in sorted(chosen, reverse=True):
        out = out[:pos + 1] + marker + out[pos + 1:]
    return out


def extract(document_text: str) -> str | None:
    """
    Recovers the session_id if ANY of the embedded copies is still intact
    (see module docstring for what "intact" tolerates). Returns None if
    no valid watermark could be found.
    """
    found = [ch for ch in document_text if ch in _ZERO_WIDTH_SET]
    if not found:
        return None

    bits = _symbols_to_bits("".join(found))
    needed = payload_mod.ecc_bit_length()
    if len(bits) < needed:
        return None

    for offset in range(0, len(bits) - needed + 1):
        window = bits[offset:offset + needed]
        result = payload_mod.ecc_bits_to_session_id(window)
        if result is not None:
            return result
    return None


def strip(document_text: str) -> str:
    """Utility for testing/tampering: remove every zero-width watermark
    character, simulating a pipeline that normalizes/strips them."""
    return "".join(ch for ch in document_text if ch not in _ZERO_WIDTH_SET)