"""Bypass the OPlus fastboot_unlock_verify restriction.

The CBZ immediately before the verification error string skips the reboot
path. Make that branch unconditional while preserving its target.
"""

from __future__ import annotations

import capstone.arm64_const as _ac

from .core import INSN_SIZE, disasm, write_u32
from .device_state import decode_adrp_add_pair, str_at

VERIFY_ERROR = b"fastboot_unlock_verify error and reboot."


def patch_fastboot(buf: bytearray) -> int:
    """Bypass the verification guard and return the patched branch offset."""
    for off in range(0, len(buf) - 3 * INSN_SIZE + 1, INSN_SIZE):
        insn = disasm(buf, off)
        if not insn or insn.id != _ac.ARM64_INS_CBZ:
            continue
        pair = decode_adrp_add_pair(buf, off + INSN_SIZE)
        if pair and str_at(buf, pair.target, VERIFY_ERROR):
            displacement = (insn.operands[1].imm - off) // INSN_SIZE
            write_u32(buf, off, 0x14000000 | (displacement & 0x03FFFFFF))
            return off

    raise ValueError("Fastboot verify-failure guard CBZ not found")
