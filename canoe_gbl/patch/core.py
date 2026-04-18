"""Shared ARM64 helpers for patching LinuxLoader.efi."""

from __future__ import annotations

import struct
from dataclasses import dataclass

import capstone.arm64_const as _ac
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ADRP_PAGE_MASK = ~0xFFF & ((1 << 64) - 1)
ADRP_LO12_MASK = 0xFFF

_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = True

INSN_SIZE = 4
PACIASP = 0xD503233F

_REG_NUM: dict[int, int] = {
    _ac.ARM64_REG_SP: 31,
    _ac.ARM64_REG_XZR: 31,
    _ac.ARM64_REG_WZR: 31,
}
for _i in range(31):
    _REG_NUM[getattr(_ac, f"ARM64_REG_X{_i}")] = _i
    _REG_NUM[getattr(_ac, f"ARM64_REG_W{_i}")] = _i

_W_REGS = {getattr(_ac, f"ARM64_REG_W{_i}") for _i in range(31)} | {_ac.ARM64_REG_WZR}


@dataclass(frozen=True)
class InsnPattern:
    asm: str
    mask: int
    value: int

    def matches(self, raw: int) -> bool:
        return raw & self.mask == self.value


@dataclass(frozen=True)
class InsnPatch:
    asm: str
    value: int

    def apply(self, buf: bytearray, off: int) -> None:
        write_u32(buf, off, self.value)


def reg_num(cs_reg: int) -> int:
    """Map Capstone register constant to 0-31, or -1 for non-GPR."""
    return _REG_NUM.get(cs_reg, -1)


def read_u32(buf: bytearray, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def write_u32(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", buf, off, val)


def mov_w_imm(rd: int, imm16: int) -> int:
    """Encode `mov w<rd>, #<imm16>` as its MOVZ alias."""
    if not 0 <= rd <= 30:
        raise ValueError(f"Invalid W register: {rd}")
    if not 0 <= imm16 <= 0xFFFF:
        raise ValueError(f"Immediate out of range: {imm16}")
    return 0x52800000 | (imm16 << 5) | rd


def disasm(buf: bytearray, off: int):
    """Decode a single instruction at offset."""
    return next(_md.disasm(bytes(buf[off : off + INSN_SIZE]), off), None)


def set_rd(raw: int, new_rd: int) -> int:
    """Replace Rd/Rt field (bits [4:0])."""
    return (raw & ~0x1F) | (new_rd & 0x1F)


def set_rd_rn(raw: int, new_reg: int) -> int:
    """Replace both Rd (bits [4:0]) and Rn (bits [9:5])."""
    raw = (raw & ~0x1F) | (new_reg & 0x1F)
    raw = (raw & ~(0x1F << 5)) | ((new_reg & 0x1F) << 5)
    return raw


def is_sp_based(insn) -> bool:
    return insn.operands[1].mem.base == _ac.ARM64_REG_SP


def is_reg_to_reg_mov(insn) -> bool:
    return (
        insn.id == _ac.ARM64_INS_MOV
        and len(insn.operands) >= 2
        and insn.operands[1].type == _ac.ARM64_OP_REG
    )


def disp(insn) -> int:
    return insn.operands[1].mem.disp


def rt_num(insn) -> int:
    if not insn.operands or insn.operands[0].type != _ac.ARM64_OP_REG:
        return -1
    return reg_num(insn.operands[0].reg)


def is_x_sized(insn) -> bool:
    return insn.operands[0].reg not in _W_REGS


def iter_backward_insns(buf: bytearray, start_off: int):
    for off in range(start_off, -1, -INSN_SIZE):
        if read_u32(buf, off) == PACIASP:
            break
        insn = disasm(buf, off)
        if insn:
            yield off, insn


def iter_forward_insns(buf: bytearray, start_off: int):
    for off in range(start_off, len(buf) - INSN_SIZE, INSN_SIZE):
        if read_u32(buf, off) == PACIASP:
            break
        insn = disasm(buf, off)
        if insn:
            yield off, insn


@dataclass(frozen=True)
class AdrlPair:
    reg: int
    target: int


def _add_imm_value(insn) -> int | None:
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
    """Decode ADRP + ADD (immediate) into (register, target_offset).

    Target is a file offset when `disasm` was called with the file offset as PC.
    """
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
        or i1.operands[0].type != _ac.ARM64_OP_REG
        or i1.operands[1].type != _ac.ARM64_OP_REG
    ):
        return None

    rd = reg_num(i0.operands[0].reg)
    if rd < 0 or reg_num(i1.operands[0].reg) != rd or reg_num(i1.operands[1].reg) != rd:
        return None

    add_imm = _add_imm_value(i1)
    if add_imm is None:
        return None

    return AdrlPair(rd, i0.operands[1].imm + add_imm)


def encode_adrp_add_pair(pc: int, target: int, rd: int) -> tuple[int, int]:
    """Encode `adrp xRd, <page of target>` and `add xRd, xRd, #<lo12>`."""
    if not 0 <= rd <= 30:
        raise ValueError(f"Invalid register: x{rd}")
    page_delta = (target & ADRP_PAGE_MASK) - (pc & ADRP_PAGE_MASK)
    if page_delta % 0x1000:
        raise ValueError(f"ADRP page delta not page-aligned: 0x{page_delta:X}")
    imm21 = page_delta >> 12
    if not -(1 << 20) <= imm21 < (1 << 20):
        raise ValueError(f"ADRP page delta out of range: 0x{page_delta:X}")
    imm21 &= 0x1FFFFF
    immlo = imm21 & 0x3
    immhi = (imm21 >> 2) & 0x7FFFF
    adrp = 0x90000000 | (immlo << 29) | (immhi << 5) | rd
    lo12 = target & ADRP_LO12_MASK
    add = 0x91000000 | (lo12 << 10) | (rd << 5) | rd
    return adrp, add
