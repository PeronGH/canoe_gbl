"""Patch `androidboot.vbmeta.device_state` to always report locked."""

from __future__ import annotations

from dataclasses import dataclass

import capstone.arm64_const as _ac

from .core import INSN_SIZE, disasm, read_u32, reg_num, set_rd, set_rd_rn, write_u32

UNLOCKED = b"unlocked"
LOCKED = b"locked"
DEVICE_STATE_PROP = b"androidboot.vbmeta.device_state"

# The device_state ADRP+ADD may trail the unlocked/locked pairs rather than sit
# immediately after them. Offsets are measured from the start of the unlocked
# pair and mirror the C patcher's i+16..i+40 byte scan.
DEVICE_STATE_WINDOW = range(4 * INSN_SIZE, 10 * INSN_SIZE + 1, INSN_SIZE)


@dataclass(frozen=True)
class AdrlPair:
    reg: int
    target: int


@dataclass(frozen=True)
class DeviceStateMatch:
    """An `unlocked`/`locked` ADRP+ADD pair confirmed by a nearby
    `androidboot.vbmeta.device_state` ADRL."""

    offset: int  # start of the "unlocked" pair
    unlocked_reg: int
    locked_off: int  # start of the "locked" pair


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


def has_device_state_adrl(buf: bytearray, base_off: int) -> bool:
    """True if a device_state ADRP+ADD pair sits within the trailing window."""
    for delta in DEVICE_STATE_WINDOW:
        pair = decode_adrp_add_pair(buf, base_off + delta)
        if pair and str_at(buf, pair.target, DEVICE_STATE_PROP):
            return True
    return False


def scan_device_state_matches(buf: bytearray) -> list[DeviceStateMatch]:
    """Find consecutive `unlocked`/`locked` ADRP+ADD pairs (distinct registers)
    confirmed by a nearby device_state ADRL."""
    matches: list[DeviceStateMatch] = []
    span = DEVICE_STATE_WINDOW.stop + 2 * INSN_SIZE
    i = 0

    while i <= len(buf) - span:
        unlocked = decode_adrp_add_pair(buf, i)
        locked = decode_adrp_add_pair(buf, i + 2 * INSN_SIZE)
        if (
            unlocked
            and locked
            and unlocked.reg != locked.reg
            and str_at(buf, unlocked.target, UNLOCKED)
            and str_at(buf, locked.target, LOCKED)
            and has_device_state_adrl(buf, i)
        ):
            matches.append(DeviceStateMatch(i, unlocked.reg, i + 2 * INSN_SIZE))
            i += span
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
    matches = scan_device_state_matches(buf)
    if not matches:
        raise ValueError("ADRL triple (unlocked/locked/device_state) not found")
    if len(matches) > 1:
        raise ValueError(
            f"Ambiguous device_state ADRL: {len(matches)} triples matched; "
            "refusing to patch"
        )

    match = matches[0]
    copy_adrl_pair(buf, match.offset, match.locked_off, match.unlocked_reg)

    patched = decode_adrp_add_pair(buf, match.offset)
    if not (patched and str_at(buf, patched.target, LOCKED)):
        raise ValueError("ADRL verification failed: unlocked pair does not read locked")
