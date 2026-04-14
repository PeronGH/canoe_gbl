"""Patch `androidboot.vbmeta.device_state` to always report locked."""

from __future__ import annotations

from dataclasses import dataclass

import capstone.arm64_const as _ac

from .core import INSN_SIZE, disasm, read_u32, reg_num, set_rd, set_rd_rn, write_u32

UNLOCKED = b"unlocked"
LOCKED = b"locked"
DEVICE_STATE_PROP = b"androidboot.vbmeta.device_state"


@dataclass(frozen=True)
class AdrlPair:
    reg: int
    target: int


@dataclass(frozen=True)
class AdrlTripleMatch:
    offset: int
    regs: tuple[int, int, int]


def add_imm_value(insn) -> int | None:
    """Return ADD-immediate value including optional LSL #12, else None."""
    imm = insn.operands[2]
    if imm.type != _ac.ARM64_OP_IMM:
        return None

    shift = imm.shift
    if shift.type == _ac.ARM64_SFT_INVALID:
        return imm.imm
    if shift.type != _ac.ARM64_SFT_LSL or shift.value not in (0, 12):
        return None
    return imm.imm << shift.value


def decode_adrp_add_pair(buf: bytearray, off: int) -> AdrlPair | None:
    """Decode ADRP + ADD (immediate) into (register, file_offset)."""
    i0 = disasm(buf, off)
    i1 = disasm(buf, off + INSN_SIZE)
    if not i0 or not i1:
        return None
    if i0.id != _ac.ARM64_INS_ADRP or i1.id != _ac.ARM64_INS_ADD:
        return None
    if len(i0.operands) != 2 or len(i1.operands) != 3:
        return None
    if (
        i0.operands[0].type != _ac.ARM64_OP_REG
        or i0.operands[1].type != _ac.ARM64_OP_IMM
    ):
        return None
    if (
        i1.operands[0].type != _ac.ARM64_OP_REG
        or i1.operands[1].type != _ac.ARM64_OP_REG
    ):
        return None

    rd = reg_num(i0.operands[0].reg)
    if rd < 0 or reg_num(i1.operands[0].reg) != rd or reg_num(i1.operands[1].reg) != rd:
        return None

    add_imm = add_imm_value(i1)
    if add_imm is None:
        return None

    return AdrlPair(rd, i0.operands[1].imm + add_imm)


def str_at(buf: bytearray, off: int, needle: bytes) -> bool:
    return 0 <= off <= len(buf) - len(needle) and buf[off : off + len(needle)] == needle


def scan_adrl_triples(
    buf: bytearray, strings: tuple[bytes, bytes, bytes]
) -> list[AdrlTripleMatch]:
    """Find ADRP+ADD triples where each pair resolves to the given strings."""
    matches: list[AdrlTripleMatch] = []
    triple_size = 6 * INSN_SIZE
    i = 0

    while i <= len(buf) - triple_size:
        pair0 = decode_adrp_add_pair(buf, i)
        pair1 = decode_adrp_add_pair(buf, i + 2 * INSN_SIZE)
        pair2 = decode_adrp_add_pair(buf, i + 4 * INSN_SIZE)
        if not (pair0 and pair1 and pair2):
            i += INSN_SIZE
            continue

        regs = (pair0.reg, pair1.reg, pair2.reg)
        if len(set(regs)) != 3:
            i += INSN_SIZE
            continue

        if all(
            str_at(buf, pair.target, needle)
            for pair, needle in zip((pair0, pair1, pair2), strings, strict=True)
        ):
            matches.append(AdrlTripleMatch(i, regs))
            i += triple_size
        else:
            i += INSN_SIZE

    return matches


def copy_adrl_pair(buf: bytearray, dst_off: int, src_off: int, dst_reg: int) -> None:
    """Copy an ADRP+ADD pair, replacing both destination registers with dst_reg."""
    write_u32(buf, dst_off, set_rd(read_u32(buf, src_off), dst_reg))
    write_u32(
        buf,
        dst_off + INSN_SIZE,
        set_rd_rn(read_u32(buf, src_off + INSN_SIZE), dst_reg),
    )


def patch_device_state(buf: bytearray) -> None:
    matches = scan_adrl_triples(buf, (UNLOCKED, LOCKED, DEVICE_STATE_PROP))
    if not matches:
        raise ValueError("ADRL triple (unlocked/locked/device_state) not found")

    for match in matches:
        copy_adrl_pair(buf, match.offset, match.offset + 2 * INSN_SIZE, match.regs[0])

    verified = scan_adrl_triples(buf, (LOCKED, LOCKED, DEVICE_STATE_PROP))
    if not verified:
        raise ValueError("ADRL verification failed")
