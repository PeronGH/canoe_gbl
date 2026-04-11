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

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64_const import (
    ARM64_INS_ADD,
    ARM64_INS_ADRP,
    ARM64_INS_LDR,
    ARM64_INS_LDRB,
    ARM64_INS_MOV,
    ARM64_INS_PACIASP,
    ARM64_INS_STR,
    ARM64_INS_STRB,
    ARM64_OP_REG,
    ARM64_REG_SP,
)

_md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_md.detail = True

# Taint location types for data-flow tracking
REG = "reg"
STK64 = "stk64"
STK8 = "stk8"


# --- Raw instruction helpers ---

def _r32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _w32(buf, off, val):
    struct.pack_into("<I", buf, off, val)


def _rt(raw):
    return raw & 0x1F


def _rn(raw):
    return (raw >> 5) & 0x1F


def _rm(raw):
    return (raw >> 16) & 0x1F


def _disasm(buf, off):
    """Decode single instruction at offset. Returns CsInsn or None."""
    for insn in _md.disasm(bytes(buf[off : off + 4]), off):
        return insn
    return None


def _is_64bit_ldst(raw):
    """Check if a LDR/STR is 64-bit (X register) via bit 30."""
    return bool(raw & 0x40000000)


def _mem_disp(insn):
    """Extract memory displacement from a load/store instruction."""
    return insn.operands[1].mem.disp


def _mem_base_is_sp(insn):
    """Check if memory base register is SP."""
    return insn.operands[1].mem.base == ARM64_REG_SP


def _strb_raw_imm(raw):
    """Extract STRB/LDRB byte immediate from raw encoding (any form)."""
    if (raw & 0xFFC00000) in (0x39000000, 0x39400000):  # unsigned offset
        return (raw >> 10) & 0xFFF
    # pre/post index: 9-bit field used as slot identifier
    return (raw >> 12) & 0x1FF


# --- Encoding helpers ---

def _encode_movz_w(rd, imm16):
    """Encode MOVZ Wd, #imm16."""
    return 0x52800000 | (imm16 << 5) | (rd & 0x1F)


def _set_rt(raw, new_rt):
    """Replace Rt field (bits [4:0])."""
    return (raw & ~0x1F) | (new_rt & 0x1F)


def _set_rd_rn(raw, new_reg):
    """Replace both Rd (bits [4:0]) and Rn (bits [9:5])."""
    raw = (raw & ~0x1F) | (new_reg & 0x1F)
    raw = (raw & ~(0x1F << 5)) | ((new_reg & 0x1F) << 5)
    return raw


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
    if i0.id != ARM64_INS_ADRP or i1.id != ARM64_INS_ADD:
        return False
    rd = _rt(_r32(buf, off))
    r1 = _r32(buf, off + 4)
    return _rt(r1) == rd and _rn(r1) == rd


def _adrl_target(buf, off):
    """Compute file offset from ADRP+ADD pair using Capstone's resolved address."""
    i0 = _disasm(buf, off)
    i1 = _disasm(buf, off + 4)
    return i0.operands[1].imm + i1.operands[2].imm


def _str_at(buf, off, needle):
    return 0 <= off <= len(buf) - len(needle) and buf[off : off + len(needle)] == needle


def patch_device_state(buf: bytearray) -> None:
    size = len(buf)
    patched = 0
    i = 0
    while i <= size - 24:
        if not (
            _is_adrp_add_pair(buf, i)
            and _is_adrp_add_pair(buf, i + 8)
            and _is_adrp_add_pair(buf, i + 16)
        ):
            i += 4
            continue

        xa = _rt(_r32(buf, i))
        xb = _rt(_r32(buf, i + 8))
        xc = _rt(_r32(buf, i + 16))
        if xa == xb or xb == xc or xa == xc:
            i += 4
            continue

        off0 = _adrl_target(buf, i)
        off1 = _adrl_target(buf, i + 8)
        off2 = _adrl_target(buf, i + 16)

        if not (
            _str_at(buf, off0, b"unlocked")
            and _str_at(buf, off1, b"locked")
            and _str_at(buf, off2, b"androidboot.vbmeta.device_state")
        ):
            i += 4
            continue

        # Patch pair-0: copy pair-1's ADRP+ADD but with pair-0's register
        _w32(buf, i, _set_rt(_r32(buf, i + 8), xa))
        _w32(buf, i + 4, _set_rd_rn(_r32(buf, i + 12), xa))
        patched += 1
        i += 24

    if patched == 0:
        raise ValueError("ADRL triple (unlocked/locked/device_state) not found")

    # Verify: re-scan to confirm both pair-0 and pair-1 now point to "locked"
    i = 0
    verified = 0
    while i <= size - 24:
        if not (
            _is_adrp_add_pair(buf, i)
            and _is_adrp_add_pair(buf, i + 8)
            and _is_adrp_add_pair(buf, i + 16)
        ):
            i += 4
            continue

        xa = _rt(_r32(buf, i))
        xb = _rt(_r32(buf, i + 8))
        xc = _rt(_r32(buf, i + 16))
        if xa == xb or xb == xc or xa == xc:
            i += 4
            continue

        off0 = _adrl_target(buf, i)
        off1 = _adrl_target(buf, i + 8)
        off2 = _adrl_target(buf, i + 16)

        if (
            _str_at(buf, off0, b"locked")
            and _str_at(buf, off1, b"locked")
            and _str_at(buf, off2, b"androidboot.vbmeta.device_state")
        ):
            verified += 1
            i += 24
        else:
            i += 4

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
    found = 0
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
            found += 1
            i += plen
        else:
            i += 1

    if found == 0:
        raise ValueError("Boot state pattern not found")
    return anchor, lock_reg


def _trace_backward(buf: bytearray, anchor_off: int, target_reg: int) -> tuple[int, int]:
    """Trace backward from anchor to find source LDRB. Patch it to MOV Wn, #1.

    Returns (ldrb_offset, source_register).
    """
    current = target_reg
    off = anchor_off - 4
    bounces = 0

    while off >= 0:
        raw = _r32(buf, off)

        if raw == 0xD503233F:  # PACIASP — function boundary
            break

        insn = _disasm(buf, off)
        if not insn:
            off -= 4
            continue

        # 64-bit stack reload bounce: LDR Xt, [SP, #imm]
        if (
            insn.id == ARM64_INS_LDR
            and _is_64bit_ldst(raw)
            and _mem_base_is_sp(insn)
            and _rt(raw) == current
        ):
            spill_disp = _mem_disp(insn)
            search = off - 4
            while search >= 0:
                s_raw = _r32(buf, search)
                if s_raw == 0xD503233F:
                    break
                s_insn = _disasm(buf, search)
                if (
                    s_insn
                    and s_insn.id == ARM64_INS_STR
                    and _is_64bit_ldst(s_raw)
                    and _mem_base_is_sp(s_insn)
                    and _mem_disp(s_insn) == spill_disp
                ):
                    current = _rt(s_raw)
                    off = search - 4
                    bounces += 1
                    break
                search -= 4
            else:
                raise ValueError(f"No matching STR for LDR bounce at 0x{off:X}")
            if search >= 0 and _r32(buf, search) == 0xD503233F:
                raise ValueError(f"No matching STR for LDR bounce at 0x{off:X}")
            if bounces > 8:
                raise ValueError("Too many bounces in backward trace")
            continue

        # Byte stack reload bounce: LDRB Wt, [SP, #imm]
        if (
            insn.id == ARM64_INS_LDRB
            and _mem_base_is_sp(insn)
            and _rt(raw) == current
        ):
            byte_disp = _mem_disp(insn)
            search = off - 4
            while search >= 0:
                s_raw = _r32(buf, search)
                if s_raw == 0xD503233F:
                    break
                s_insn = _disasm(buf, search)
                if (
                    s_insn
                    and s_insn.id == ARM64_INS_STRB
                    and _mem_base_is_sp(s_insn)
                    and _mem_disp(s_insn) == byte_disp
                ):
                    current = _rt(s_raw)
                    off = search - 4
                    bounces += 1
                    break
                search -= 4
            else:
                raise ValueError(f"No matching STRB for LDRB bounce at 0x{off:X}")
            if search >= 0 and _r32(buf, search) == 0xD503233F:
                raise ValueError(f"No matching STRB for LDRB bounce at 0x{off:X}")
            if bounces > 8:
                raise ValueError("Too many bounces in backward trace")
            continue

        # Source: LDRB Wt, [Xn!=SP, #imm]
        if (
            insn.id == ARM64_INS_LDRB
            and _rt(raw) == current
            and not _mem_base_is_sp(insn)
        ):
            _w32(buf, off, _encode_movz_w(current, 1))
            return off, current

        off -= 4

    raise ValueError(f"Source LDRB not found for W{target_reg}")


def _trace_forward_patch_strb(
    buf: bytearray, ldrb_off: int, src_reg: int, anchor_off: int
) -> None:
    """Trace forward from patched LDRB to find sink STRB after anchor. Patch Rt to WZR."""
    size = len(buf)
    taint: set[tuple[str, int]] = {(REG, src_reg)}

    for off in range(ldrb_off + 4, size - 4, 4):
        raw = _r32(buf, off)

        if raw == 0xD503233F:  # PACIASP
            break

        insn = _disasm(buf, off)
        if not insn:
            continue

        rt = _rt(raw)

        # STR Xt/Wt, [SP, #imm] — stack spill
        if insn.id == ARM64_INS_STR and _mem_base_is_sp(insn):
            disp = _mem_disp(insn)
            if (REG, rt) in taint:
                taint.add((STK64, disp))
            elif (STK64, disp) in taint:
                taint.discard((STK64, disp))
            continue

        # LDR Xt/Wt, [SP, #imm] — stack reload
        if insn.id == ARM64_INS_LDR and _mem_base_is_sp(insn):
            disp = _mem_disp(insn)
            if (STK64, disp) in taint:
                taint.add((REG, rt))
            elif (REG, rt) in taint:
                taint.discard((REG, rt))
            continue

        # LDRB Wt, [Xn, #imm] — external memory overwrite
        if insn.id == ARM64_INS_LDRB:
            taint.discard((REG, rt))
            continue

        # MOV Xd, Xm / MOV Wd, Wm (register-to-register only)
        if (
            insn.id == ARM64_INS_MOV
            and len(insn.operands) >= 2
            and insn.operands[1].type == ARM64_OP_REG
        ):
            rm = _rm(raw)
            if (REG, rm) in taint and rt != 31:
                taint.add((REG, rt))
            elif (REG, rt) in taint:
                taint.discard((REG, rt))
            continue

        # STRB — potential sink
        if insn.id == ARM64_INS_STRB:
            si_rt = _rt(raw)
            si_rn = _rn(raw)
            si_imm = _strb_raw_imm(raw)

            if (REG, si_rt) in taint or (not taint and off > anchor_off):
                if off > anchor_off:
                    # SINK: patch Rt to WZR
                    _w32(buf, off, _set_rt(raw, 31))
                    return
                # Before anchor: track as byte stack spill
                if si_rn == 31:
                    taint.add((STK8, si_imm))
            elif si_rn == 31 and (STK8, si_imm) in taint:
                taint.discard((STK8, si_imm))

    raise ValueError(f"Sink STRB not found after anchor 0x{anchor_off:X}")


def patch_bootstate(buf: bytearray) -> None:
    """Apply patches 3, 4, and 5."""
    anchor, lock_reg = _find_and_patch_boot_pattern(buf)
    ldrb_off, src_reg = _trace_backward(buf, anchor, lock_reg)
    _trace_forward_patch_strb(buf, ldrb_off, src_reg, anchor)


# =====================================================================
# Orchestrator
# =====================================================================

def patch_efi(buf: bytearray) -> bytearray:
    """Apply all patches to a LinuxLoader.efi buffer."""
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
