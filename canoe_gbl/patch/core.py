"""Shared ARM64 helpers for patching LinuxLoader.efi."""

from __future__ import annotations

import struct
from dataclasses import dataclass

import capstone.arm64_const as _ac
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

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
