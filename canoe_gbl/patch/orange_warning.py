"""Skip the orange-state warning screen and the 5-second countdown.

1vivy fork Patch 7: rewrite the CBZ that guards the unlock-warning block as an
unconditional B, so the block is always skipped regardless of lock state.
"""

from __future__ import annotations

import capstone.arm64_const as _ac

from .core import (
    INSN_SIZE,
    cbz_imm19,
    disasm,
    encode_b,
    read_u32,
    reg_num,
    write_u32,
)


def _csel_anchor(insn) -> bool:
    """Match `csel w22, w9, w8, cc` — the unique CSEL before the orange CBZ."""
    if insn.id != _ac.ARM64_INS_CSEL or len(insn.operands) != 3:
        return False
    rd, rn, rm = (reg_num(op.reg) for op in insn.operands)
    return (rd, rn, rm) == (22, 9, 8) and insn.cc == _ac.ARM64_CC_LO


def _is_fallback_countdown(buf: bytearray, off: int) -> bool:
    """Match the `mov w#,#0x30 / cbz / sub w#,w#,#1` countdown loop."""
    mov_insn = disasm(buf, off)
    cbz_insn = disasm(buf, off + INSN_SIZE)
    sub_insn = disasm(buf, off + 2 * INSN_SIZE)
    if not (mov_insn and cbz_insn and sub_insn):
        return False
    if mov_insn.id != _ac.ARM64_INS_MOV or len(mov_insn.operands) < 2:
        return False
    imm_op = mov_insn.operands[1]
    if imm_op.type != _ac.ARM64_OP_IMM or imm_op.imm != 0x30:
        return False
    if cbz_insn.id not in (_ac.ARM64_INS_CBZ, _ac.ARM64_INS_CBNZ):
        return False
    if sub_insn.id != _ac.ARM64_INS_SUB or len(sub_insn.operands) < 3:
        return False
    tail = sub_insn.operands[2]
    return tail.type == _ac.ARM64_OP_IMM and tail.imm == 1


def _cbz_to_b(buf: bytearray, off: int) -> None:
    write_u32(buf, off, encode_b(cbz_imm19(read_u32(buf, off))))


def patch_orange_warning(buf: bytearray) -> int:
    patched = 0
    for off in range(0, len(buf) - 2 * INSN_SIZE + 1, INSN_SIZE):
        anchor = disasm(buf, off)
        cbz = disasm(buf, off + INSN_SIZE)
        if not (anchor and cbz) or not _csel_anchor(anchor):
            continue
        if cbz.id not in (_ac.ARM64_INS_CBZ, _ac.ARM64_INS_CBNZ):
            continue
        _cbz_to_b(buf, off + INSN_SIZE)
        patched += 1

    if patched:
        return patched

    for off in range(INSN_SIZE, len(buf) - 3 * INSN_SIZE + 1, INSN_SIZE):
        if _is_fallback_countdown(buf, off):
            _cbz_to_b(buf, off - INSN_SIZE)
            return 1

    return 0
