"""Patch LinuxLoader.efi to report locked boot state.

Applies 5 patches:
  1. Replace UTF-16 "efisp" with "nulls" (disable EFI system partition)
  2. Rewrite ADRL triple so device_state always reports "locked"
  3. Patch boot state check pattern
  4. Replace source LDRB with MOV Wn, #1 (hardcode locked)
  5. Replace sink STRB Rt with WZR (zero out lock state write)
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import capstone.arm64_const as _ac
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

_md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_md.detail = True
_ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

# Register number lookup: Capstone register constant -> 0-31
_REG_NUM: dict[int, int] = {_ac.ARM64_REG_SP: 31, _ac.ARM64_REG_XZR: 31, _ac.ARM64_REG_WZR: 31}
for _i in range(31):
    _REG_NUM[getattr(_ac, f"ARM64_REG_X{_i}")] = _i
    _REG_NUM[getattr(_ac, f"ARM64_REG_W{_i}")] = _i

# W-register set for distinguishing 32-bit from 64-bit operands
_W_REGS = {getattr(_ac, f"ARM64_REG_W{_i}") for _i in range(31)} | {_ac.ARM64_REG_WZR}

# Taint location types
REG = "reg"
STK64 = "stk64"
STK8 = "stk8"


def _reg(cs_reg: int) -> int:
    """Capstone register constant -> register number (0-30, 31 for SP/ZR, -1 for non-GPR)."""
    return _REG_NUM.get(cs_reg, -1)


def _r32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _w32(buf, off, val):
    struct.pack_into("<I", buf, off, val)


def _asm(s: str) -> int:
    """Assemble a single ARM64 instruction, return as 32-bit int."""
    enc, _ = _ks.asm(s)
    return struct.unpack("<I", bytes(enc))[0]


def _disasm(buf, off):
    """Decode single instruction at offset."""
    for insn in _md.disasm(bytes(buf[off : off + 4]), off):
        return insn
    return None


def _set_rd(raw, new_rd):
    """Replace Rd/Rt field (bits [4:0])."""
    return (raw & ~0x1F) | (new_rd & 0x1F)


def _set_rd_rn(raw, new_reg):
    """Replace both Rd (bits [4:0]) and Rn (bits [9:5])."""
    raw = (raw & ~0x1F) | (new_reg & 0x1F)
    raw = (raw & ~(0x1F << 5)) | ((new_reg & 0x1F) << 5)
    return raw


PACIASP = 0xD503233F


# =====================================================================
# Patch 1: Replace UTF-16LE "efisp" with "nulls"
# =====================================================================

def patch_gbl(buf: bytearray) -> None:
    target = "efisp".encode("utf-16-le")
    replacement = "nulls".encode("utf-16-le")
    idx = buf.find(target)
    if idx == -1:
        raise ValueError("'efisp' (UTF-16LE) not found")
    buf[idx : idx + len(replacement)] = replacement


# =====================================================================
# Patch 2: Rewrite ADRL triple (unlocked -> locked)
# =====================================================================

def _is_adrp_add_pair(buf, off):
    """Check if off, off+4 form an ADRP+ADD pair with matching Rd."""
    i0 = _disasm(buf, off)
    i1 = _disasm(buf, off + 4)
    if not i0 or not i1:
        return False
    if i0.id != _ac.ARM64_INS_ADRP or i1.id != _ac.ARM64_INS_ADD:
        return False
    rd = _reg(i0.operands[0].reg)
    return _reg(i1.operands[0].reg) == rd and _reg(i1.operands[1].reg) == rd


def _adrl_target(buf, off):
    """Compute file offset from ADRP+ADD pair."""
    i0 = _disasm(buf, off)
    i1 = _disasm(buf, off + 4)
    return i0.operands[1].imm + i1.operands[2].imm


def _str_at(buf, off, needle):
    return 0 <= off <= len(buf) - len(needle) and buf[off : off + len(needle)] == needle


def _scan_adrl_triples(buf, str0, str1, str2):
    """Find ADRP+ADD triples where pairs point to the given strings. Returns count."""
    size = len(buf)
    count = 0
    i = 0
    while i <= size - 24:
        if not (
            _is_adrp_add_pair(buf, i)
            and _is_adrp_add_pair(buf, i + 8)
            and _is_adrp_add_pair(buf, i + 16)
        ):
            i += 4
            continue

        i0 = _disasm(buf, i)
        i8 = _disasm(buf, i + 8)
        i16 = _disasm(buf, i + 16)
        ra = _reg(i0.operands[0].reg)
        rb = _reg(i8.operands[0].reg)
        rc = _reg(i16.operands[0].reg)
        if ra == rb or rb == rc or ra == rc:
            i += 4
            continue

        off0 = _adrl_target(buf, i)
        off1 = _adrl_target(buf, i + 8)
        off2 = _adrl_target(buf, i + 16)

        if _str_at(buf, off0, str0) and _str_at(buf, off1, str1) and _str_at(buf, off2, str2):
            count += 1
            yield i, ra, rb, rc
            i += 24
        else:
            i += 4


def patch_device_state(buf: bytearray) -> None:
    patched = 0
    for off, ra, rb, rc in _scan_adrl_triples(buf, b"unlocked", b"locked", b"androidboot.vbmeta.device_state"):
        # Copy pair-1's ADRP+ADD encoding but with pair-0's register
        _w32(buf, off, _set_rd(_r32(buf, off + 8), ra))
        _w32(buf, off + 4, _set_rd_rn(_r32(buf, off + 12), ra))
        patched += 1

    if patched == 0:
        raise ValueError("ADRL triple (unlocked/locked/device_state) not found")

    # Verify: both pair-0 and pair-1 now point to "locked"
    verified = sum(1 for _ in _scan_adrl_triples(buf, b"locked", b"locked", b"androidboot.vbmeta.device_state"))
    if verified == 0:
        raise ValueError("ADRL verification failed")


# =====================================================================
# Patches 3/4/5: Boot state pattern + data-flow patching
# =====================================================================

BOOT_PATTERN = [
    -1, 0x00, 0x00, 0x34, 0x28, 0x00, 0x80, 0x52,
    0x06, 0x00, 0x00, 0x14, 0xE8, -1, 0x40, 0xF9,
    0x08, 0x01, 0x40, 0x39, 0x1F, 0x01, 0x00, 0x71,
    0xE8, 0x07, 0x9F, 0x1A, 0x08, 0x79, 0x1F, 0x53,
]

BOOT_PATCH = [
    -1, -1, -1, -1, 0x08, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
]


def _find_and_patch_boot_pattern(buf: bytearray) -> tuple[int, int]:
    """Find boot state pattern, apply patch 3, return (anchor_offset, lock_register)."""
    plen = len(BOOT_PATTERN)
    anchor = -1
    lock_reg = -1

    i = 0
    while i <= len(buf) - plen:
        if all(p == -1 or buf[i + j] == p for j, p in enumerate(BOOT_PATTERN)):
            lock_reg = buf[i] & 0x1F
            anchor = i
            for j, p in enumerate(BOOT_PATCH):
                if p != -1:
                    buf[i + j] = p
            i += plen
        else:
            i += 1

    if anchor == -1:
        raise ValueError("Boot state pattern not found")
    return anchor, lock_reg


def _is_sp_based(insn):
    return insn.operands[1].mem.base == _ac.ARM64_REG_SP


def _disp(insn):
    return insn.operands[1].mem.disp


def _rt_num(insn):
    if not insn.operands or insn.operands[0].type != _ac.ARM64_OP_REG:
        return -1
    return _reg(insn.operands[0].reg)


def _is_x_sized(insn):
    return insn.operands[0].reg not in _W_REGS


def _trace_backward(buf: bytearray, anchor_off: int, target_reg: int) -> tuple[int, int]:
    """Trace backward from anchor to find source LDRB. Patch it to MOV Wn, #1."""
    current = target_reg
    off = anchor_off - 4
    bounces = 0

    while off >= 0:
        if _r32(buf, off) == PACIASP:
            break

        insn = _disasm(buf, off)
        if not insn:
            off -= 4
            continue

        # 64-bit stack reload bounce: LDR Xt, [SP, #imm]
        if (
            insn.id == _ac.ARM64_INS_LDR
            and _is_x_sized(insn)
            and _is_sp_based(insn)
            and _rt_num(insn) == current
        ):
            spill_disp = _disp(insn)
            search = off - 4
            found = False
            while search >= 0:
                if _r32(buf, search) == PACIASP:
                    break
                si = _disasm(buf, search)
                if (
                    si
                    and si.id == _ac.ARM64_INS_STR
                    and _is_x_sized(si)
                    and _is_sp_based(si)
                    and _disp(si) == spill_disp
                ):
                    current = _rt_num(si)
                    off = search - 4
                    found = True
                    bounces += 1
                    break
                search -= 4
            if not found:
                raise ValueError(f"No matching STR for LDR bounce at 0x{off:X}")
            if bounces > 8:
                raise ValueError("Too many bounces")
            continue

        # Byte stack reload bounce: LDRB Wt, [SP, #imm]
        if insn.id == _ac.ARM64_INS_LDRB and _is_sp_based(insn) and _rt_num(insn) == current:
            byte_disp = _disp(insn)
            search = off - 4
            found = False
            while search >= 0:
                if _r32(buf, search) == PACIASP:
                    break
                si = _disasm(buf, search)
                if (
                    si
                    and si.id == _ac.ARM64_INS_STRB
                    and _is_sp_based(si)
                    and _disp(si) == byte_disp
                ):
                    current = _rt_num(si)
                    off = search - 4
                    found = True
                    bounces += 1
                    break
                search -= 4
            if not found:
                raise ValueError(f"No matching STRB for LDRB bounce at 0x{off:X}")
            if bounces > 8:
                raise ValueError("Too many bounces")
            continue

        # Source: LDRB Wt, [Xn!=SP, #imm]
        if insn.id == _ac.ARM64_INS_LDRB and _rt_num(insn) == current and not _is_sp_based(insn):
            _w32(buf, off, _asm(f"MOV W{current}, #1"))
            return off, current

        off -= 4

    raise ValueError(f"Source LDRB not found for W{target_reg}")


def _trace_forward_patch_strb(
    buf: bytearray, ldrb_off: int, src_reg: int, anchor_off: int,
) -> None:
    """Trace forward from patched LDRB to find sink STRB after anchor. Patch Rt to WZR."""
    size = len(buf)
    taint: set[tuple[str, int]] = {(REG, src_reg)}

    for off in range(ldrb_off + 4, size - 4, 4):
        if _r32(buf, off) == PACIASP:
            break

        insn = _disasm(buf, off)
        if not insn:
            continue

        rt = _rt_num(insn)

        # STR to stack — spill
        if insn.id == _ac.ARM64_INS_STR and _is_sp_based(insn):
            d = _disp(insn)
            if (REG, rt) in taint:
                taint.add((STK64, d))
            elif (STK64, d) in taint:
                taint.discard((STK64, d))
            continue

        # LDR from stack — reload
        if insn.id == _ac.ARM64_INS_LDR and _is_sp_based(insn):
            d = _disp(insn)
            if (STK64, d) in taint:
                taint.add((REG, rt))
            elif (REG, rt) in taint:
                taint.discard((REG, rt))
            continue

        # LDRB — external overwrite kills taint
        if insn.id == _ac.ARM64_INS_LDRB:
            taint.discard((REG, rt))
            continue

        # MOV reg-to-reg — propagate or kill taint
        if (
            insn.id == _ac.ARM64_INS_MOV
            and len(insn.operands) >= 2
            and insn.operands[1].type == _ac.ARM64_OP_REG
        ):
            rm = _reg(insn.operands[1].reg)
            if (REG, rm) in taint and rt != 31:
                taint.add((REG, rt))
            elif (REG, rt) in taint:
                taint.discard((REG, rt))
            continue

        # STRB — potential sink
        if insn.id == _ac.ARM64_INS_STRB:
            sp_based = _is_sp_based(insn)
            d = _disp(insn)

            if (REG, rt) in taint or (not taint and off > anchor_off):
                if off > anchor_off:
                    # SINK: replace Rt with WZR
                    _w32(buf, off, _set_rd(_r32(buf, off), 31))
                    return
                if sp_based:
                    taint.add((STK8, d))
            elif sp_based and (STK8, d) in taint:
                taint.discard((STK8, d))

    raise ValueError(f"Sink STRB not found after anchor 0x{anchor_off:X}")


def patch_bootstate(buf: bytearray) -> None:
    anchor, lock_reg = _find_and_patch_boot_pattern(buf)
    ldrb_off, src_reg = _trace_backward(buf, anchor, lock_reg)
    _trace_forward_patch_strb(buf, ldrb_off, src_reg, anchor)


# =====================================================================
# Orchestrator
# =====================================================================

def patch_efi(buf: bytearray) -> bytearray:
    patch_gbl(buf)
    patch_device_state(buf)
    patch_bootstate(buf)
    return buf


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Patch LinuxLoader.efi")
    parser.add_argument("input", type=Path, help="Input EFI file")
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: {args.input} not found", file=sys.stderr)
        sys.exit(1)

    buf = bytearray(args.input.read_bytes())
    patch_efi(buf)
    args.output.write_bytes(buf)
    print(f"Patched {len(buf)} bytes to {args.output}")
