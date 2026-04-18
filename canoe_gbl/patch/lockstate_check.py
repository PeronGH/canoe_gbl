"""NOP out jumps that report the `... is not allowed in Lock State` errors.

Upstream OnePlus patch (post-72619fe): allows `fastboot flash` / `erase` while
the bootloader still reports itself as locked, by killing the branch that
routes control to the error-string printer. For every direct branch whose
target starts with an ADRP+ADD to a string containing the keyword, replace the
branch itself with a NOP.

Upstream's `get_JUMP_target` treats only B, BL, CBZ, CBNZ as direct branches —
conditional B.cond, TBZ, TBNZ are deliberately excluded.
"""

from __future__ import annotations

import capstone.arm64_const as _ac

from .core import INSN_SIZE, NOP, decode_adrp_add_pair, disasm, write_u32

KEYWORD = b"is not allowed in Lock State"

_DIRECT_JUMP_IDS = frozenset(
    {
        _ac.ARM64_INS_B,
        _ac.ARM64_INS_BL,
        _ac.ARM64_INS_CBZ,
        _ac.ARM64_INS_CBNZ,
    }
)


def _direct_jump_target(insn) -> int | None:
    """Return the absolute target of a direct branch, or None if insn isn't one."""
    if insn is None or insn.id not in _DIRECT_JUMP_IDS:
        return None
    # Capstone reports B.cond with id=ARM64_INS_B too; skip the conditional form.
    if insn.id == _ac.ARM64_INS_B and insn.cc not in (
        _ac.ARM64_CC_INVALID,
        _ac.ARM64_CC_AL,
    ):
        return None
    imm = insn.operands[-1]
    return imm.imm if imm.type == _ac.ARM64_OP_IMM else None


def patch_lockstate_check(buf: bytearray) -> int:
    patched = 0
    size = len(buf)
    for off in range(0, size - INSN_SIZE, INSN_SIZE):
        target = _direct_jump_target(disasm(buf, off))
        if target is None or target < 0 or target + 2 * INSN_SIZE > size:
            continue
        pair = decode_adrp_add_pair(buf, target)
        if pair is None or not 0 <= pair.target < size:
            continue
        end = buf.find(b"\0", pair.target)
        end = size if end == -1 else end
        if KEYWORD in bytes(buf[pair.target : end]):
            write_u32(buf, off, NOP)
            patched += 1
    return patched
