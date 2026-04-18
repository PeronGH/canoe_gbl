"""Force the `androidboot.verifiedbootstate=` cmdline value to `orange`.

1vivy fork Patch 8: the cmdline-building helper reads `state->boot_state` from
`[x20, #0x438]` and uses it to index the color-string table. Replacing the
initial LDRSW with `mov x8, #1` makes the helper always pick index 1 (orange),
while leaving the underlying `boot_state` field — which the TEE handoff path
also consults — untouched.

Helper site signature (6 instructions, observed on Infiniti and Myron ABLs):
    ldrsw x8, [x20, #0x438]
    adrp  x9, <verifiedbootstate table>
    add   x9, x9, #<table lo12>
    mov   x0, x20
    add   x8, x9, x8, lsl #4
    ldr   x1, [x8, #8]
"""

from __future__ import annotations

import capstone.arm64_const as _ac

from .core import (
    INSN_SIZE,
    decode_adrp_add_pair,
    disasm,
    mov_x_imm,
    reg_num,
    rt_num,
    write_u32,
)

HELPER_INSN_COUNT = 6


def _reg(op) -> int:
    return reg_num(op.reg) if op.type == _ac.ARM64_OP_REG else -1


def _is_helper_site(buf: bytearray, off: int) -> bool:
    ldrsw = disasm(buf, off)
    if (
        not ldrsw
        or ldrsw.id != _ac.ARM64_INS_LDRSW
        or rt_num(ldrsw) != 8
        or reg_num(ldrsw.operands[1].mem.base) != 20
        or ldrsw.operands[1].mem.disp != 0x438
    ):
        return False

    adrp_pair = decode_adrp_add_pair(buf, off + INSN_SIZE)
    if adrp_pair is None or adrp_pair.reg != 9:
        return False

    mov_reg = disasm(buf, off + 3 * INSN_SIZE)
    if (
        not mov_reg
        or mov_reg.id != _ac.ARM64_INS_MOV
        or rt_num(mov_reg) != 0
        or _reg(mov_reg.operands[1]) != 20
    ):
        return False

    add_shifted = disasm(buf, off + 4 * INSN_SIZE)
    if (
        not add_shifted
        or add_shifted.id != _ac.ARM64_INS_ADD
        or rt_num(add_shifted) != 8
        or _reg(add_shifted.operands[1]) != 9
        or _reg(add_shifted.operands[2]) != 8
        or add_shifted.operands[2].shift.value != 4
    ):
        return False

    ldr = disasm(buf, off + 5 * INSN_SIZE)
    return (
        ldr is not None
        and ldr.id == _ac.ARM64_INS_LDR
        and rt_num(ldr) == 1
        and reg_num(ldr.operands[1].mem.base) == 8
        and ldr.operands[1].mem.disp == 8
    )


def patch_verifiedbootstate(buf: bytearray) -> int:
    patched = 0
    step = INSN_SIZE
    last = len(buf) - HELPER_INSN_COUNT * INSN_SIZE
    for off in range(0, last + 1, step):
        if _is_helper_site(buf, off):
            write_u32(buf, off, mov_x_imm(8, 1))
            patched += 1
    return patched
