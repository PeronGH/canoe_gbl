"""Bypass the OPlus fastboot_unlock_verify restriction.

The CBZ immediately before the verification error string skips the reboot
path. Make that branch unconditional while preserving its target.
"""

from __future__ import annotations

from .core import INSN_SIZE, read_u32, write_u32
from .device_state import decode_adrp_add_pair, str_at

VERIFY_ERROR = b"fastboot_unlock_verify error and reboot."

# Match both CBZ Wt and CBZ Xt, but not CBNZ.
CBZ_MASK = 0x7F000000
CBZ_VALUE = 0x34000000


def cbz_to_b(raw: int) -> int:
    """Convert CBZ to an unconditional B with the same target."""
    imm19 = (raw >> 5) & 0x7FFFF
    if imm19 & 0x40000:
        imm19 -= 0x80000
    return 0x14000000 | (imm19 & 0x03FFFFFF)


def patch_fastboot(buf: bytearray) -> int:
    """Bypass the verification guard and return the patched branch offset."""
    for off in range(0, len(buf) - 3 * INSN_SIZE + 1, INSN_SIZE):
        raw = read_u32(buf, off)
        if raw & CBZ_MASK != CBZ_VALUE:
            continue
        pair = decode_adrp_add_pair(buf, off + INSN_SIZE)
        if pair and str_at(buf, pair.target, VERIFY_ERROR):
            write_u32(buf, off, cbz_to_b(raw))
            return off

    raise ValueError("Fastboot verify-failure guard CBZ not found")
