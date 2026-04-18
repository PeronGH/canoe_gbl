"""Skip the orange-state warning screen and the 5-second countdown.

1vivy fork Patch 7: rewrite the CBZ that guards the unlock-warning block as an
unconditional B, so the block is always skipped regardless of lock state.
"""

from __future__ import annotations

from .core import INSN_SIZE, InsnPattern, read_u32, write_u32

# Primary anchor: the unique CSEL that immediately precedes the CBZ.
# Fallback anchor: the countdown loop (mov w#,#0x30 / cbz / sub) inside the
# warning block — its CBZ sits 4 bytes before the mov.
CSEL_ANCHOR = InsnPattern("csel w22, w9, w8, cc", 0xFFFFFFFF, 0x1A883136)
CBZ_UPPER = InsnPattern("cbz wT, #+imm", 0xFFFFFF00, 0x34000400)

_MOV_W_30 = (None, 0x06, 0x80, 0x52)
_CBZ_WILD = (None, 0x00, 0x00, None)
_SUB_W_1 = (None, 0x05, None, None)
FALLBACK_PATTERN: tuple[int | None, ...] = _MOV_W_30 + _CBZ_WILD + _SUB_W_1


def _bytes_match(buf: bytearray, off: int, pattern: tuple[int | None, ...]) -> bool:
    return all(b is None or buf[off + i] == b for i, b in enumerate(pattern))


def _cbz_to_b(buf: bytearray, off: int) -> None:
    """Rewrite a 32-bit CBZ at off as an unconditional B targeting the same offset."""
    raw = read_u32(buf, off)
    imm19 = (raw >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= 1 << 19
    write_u32(buf, off, 0x14000000 | (imm19 & 0x03FFFFFF))


def patch_orange_warning(buf: bytearray) -> int:
    """Locate the orange-state guard CBZ and rewrite it as B. Return hits."""
    patched = 0
    for off in range(0, len(buf) - 2 * INSN_SIZE + 1, INSN_SIZE):
        if CSEL_ANCHOR.matches(read_u32(buf, off)) and CBZ_UPPER.matches(
            read_u32(buf, off + INSN_SIZE)
        ):
            _cbz_to_b(buf, off + INSN_SIZE)
            patched += 1

    if patched:
        return patched

    # Fallback: scan for the countdown loop, rewrite CBZ at 4 bytes before it.
    max_off = len(buf) - len(FALLBACK_PATTERN)
    for off in range(INSN_SIZE, max_off + 1):
        if _bytes_match(buf, off, FALLBACK_PATTERN):
            _cbz_to_b(buf, off - INSN_SIZE)
            return 1

    return 0
