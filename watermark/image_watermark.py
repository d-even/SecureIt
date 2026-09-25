"""
Invisible image watermark — DCT-domain Quantization Index Modulation (QIM).

This is the counterpart to text_watermark.py for the leak path research
identifies as hardest to log: someone photographs or screenshots the
document instead of copying its text (see the Gugelmann et al. "Screen
watermarking" reference in the project's research list). Because a photo
or a re-saved JPEG re-encodes every pixel, the watermark has to live in
something that survives lossy compression — mid-frequency DCT
coefficients, the same domain JPEG itself uses, are the standard choice.

How it works:
  - The image (or its luminance channel) is split into 8x8 blocks, same
    grid JPEG uses internally.
  - One fixed, moderate-frequency coefficient per block is nudged up or
    down (QIM) so that round(coefficient / delta) is even (bit 0) or odd
    (bit 1). This is a small, spread-out change — invisible to the eye —
    but the *parity* of that rounded value tends to survive moderate
    JPEG re-compression, because JPEG's own quantization at typical
    quality levels doesn't move a mid-frequency coefficient by more than
    delta/2 in most blocks.
  - Each payload bit is written into several blocks (`repeat`); extraction
    majority-votes across those blocks before RS error-correcting the
    result, so a few flipped blocks don't sink the whole payload.
"""

import numpy as np
from PIL import Image
from scipy.fftpack import dct, idct

from . import payload as payload_mod

BLOCK = 8
COEFF_POS = (2, 1)        # a low/mid-frequency coefficient — empirically most JPEG-robust of those tested
DEFAULT_DELTA = 24.0
DEFAULT_REPEAT = 7


def _dct2(block: np.ndarray) -> np.ndarray:
    return dct(dct(block, axis=0, norm="ortho"), axis=1, norm="ortho")


def _idct2(block: np.ndarray) -> np.ndarray:
    return idct(idct(block, axis=1, norm="ortho"), axis=0, norm="ortho")


def _block_grid(height: int, width: int) -> list[tuple[int, int]]:
    """Top-left (row, col) pixel coordinate of every full BLOCK x BLOCK
    block, in raster order."""
    coords = []
    for by in range(0, height - BLOCK + 1, BLOCK):
        for bx in range(0, width - BLOCK + 1, BLOCK):
            coords.append((by, bx))
    return coords


def capacity(height: int, width: int, repeat: int = DEFAULT_REPEAT) -> int:
    """How many payload bits this image size can carry at the given
    redundancy. Compare against payload.ecc_bit_length() before embedding."""
    return len(_block_grid(height, width)) // repeat


def embed(image: Image.Image, session_id_hex: str,
          delta: float = DEFAULT_DELTA, repeat: int = DEFAULT_REPEAT) -> Image.Image:
    """
    Returns a new grayscale ('L') image, visually indistinguishable from
    the input, with the session_id embedded across its DCT coefficients.
    Raises ValueError if the image is too small to hold the payload at
    this redundancy.
    """
    gray = image.convert("L")
    arr = np.asarray(gray, dtype=np.float64).copy()
    height, width = arr.shape

    bits = payload_mod.session_id_to_ecc_bits(session_id_hex)
    blocks = _block_grid(height, width)
    needed_blocks = len(bits) * repeat
    if len(blocks) < needed_blocks:
        raise ValueError(
            f"image too small: have {len(blocks)} usable {BLOCK}x{BLOCK} blocks, "
            f"need {needed_blocks} ({len(bits)} bits x {repeat} repeats)"
        )

    block_i = 0
    for bit in bits:
        for _ in range(repeat):
            by, bx = blocks[block_i]
            block_i += 1
            block = arr[by:by + BLOCK, bx:bx + BLOCK]
            d = _dct2(block)

            c = d[COEFF_POS]
            q = round(c / delta)
            if (q % 2) != bit:
                q += 1 if c >= q * delta else -1
            d[COEFF_POS] = q * delta

            arr[by:by + BLOCK, bx:bx + BLOCK] = _idct2(d)

    arr = np.clip(arr, 0, 255)
    return Image.fromarray(arr.astype(np.uint8), mode="L")


def extract(image: Image.Image, delta: float = DEFAULT_DELTA, repeat: int = DEFAULT_REPEAT) -> str | None:
    """
    Recovers the session_id from a (possibly re-compressed, cropped, or
    otherwise degraded) image. Returns None if no valid watermark could
    be recovered.
    """
    gray = image.convert("L")
    arr = np.asarray(gray, dtype=np.float64)
    height, width = arr.shape

    needed_bits = payload_mod.ecc_bit_length()
    blocks = _block_grid(height, width)
    needed_blocks = needed_bits * repeat
    if len(blocks) < needed_blocks:
        return None

    bits = []
    block_i = 0
    for _ in range(needed_bits):
        votes = []
        for _ in range(repeat):
            by, bx = blocks[block_i]
            block_i += 1
            block = arr[by:by + BLOCK, bx:bx + BLOCK]
            d = _dct2(block)
            q = round(d[COEFF_POS] / delta)
            votes.append(q % 2)
        # majority vote across the redundant copies of this bit
        bits.append(1 if sum(votes) * 2 > len(votes) else 0)

    return payload_mod.ecc_bits_to_session_id(bits)