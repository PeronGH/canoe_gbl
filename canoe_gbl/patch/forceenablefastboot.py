"""Force fastboot to stay enabled by always taking its verify-failure branch.

A `CBZ {Wt,Xt}, <skip>` guards the "fastboot_unlock_verify error and reboot."
path. Rewriting it to an unconditional `B` (keeping the branch target) makes the
loader always skip the reboot, leaving fastboot available.

This mirrors the C patcher's testing-only patch (gated behind
ENABLE_TESTING_PATCHS) and is therefore opt-in here too.
"""

from __future__ import annotations

from .core import INSN_SIZE, read_u32, write_u32
from .device_state import decode_adrp_add_pair, str_at

VERIFY_ERROR = b"fastboot_unlock_verify error and reboot."

# CBZ Wt / CBZ Xt: bits [30:24] fixed (op=0 -> CBZ), sf (bit 31) free.
CBZ_MASK = 0x7F000000
CBZ_VALUE = 0x34000000


def cbz_to_b(raw: int) -> int:
    """Convert a CBZ/CBNZ into an unconditional B with the same target."""
    imm19 = (raw >> 5) & 0x7FFFF
    if imm19 & 0x40000:  # sign-extend the 19-bit offset
        imm19 |= -0x80000
    return 0x14000000 | (imm19 & 0x03FFFFFF)


def patch_fastboot(buf: bytearray) -> int:
    """Force the fastboot verify-failure guard to always branch. Returns the
    patched CBZ offset."""
    for off in range(0, len(buf) - INSN_SIZE, INSN_SIZE):
        raw = read_u32(buf, off)
        if raw & CBZ_MASK != CBZ_VALUE:
            continue
        pair = decode_adrp_add_pair(buf, off + INSN_SIZE)
        if pair and str_at(buf, pair.target, VERIFY_ERROR):
            write_u32(buf, off, cbz_to_b(raw))
            return off

    raise ValueError("Fastboot verify-failure guard CBZ not found")
