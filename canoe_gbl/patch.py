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
from dataclasses import dataclass
from pathlib import Path

import capstone.arm64_const as _ac
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = True

# Register number lookup: Capstone register constant -> 0-31
_REG_NUM: dict[int, int] = {
    _ac.ARM64_REG_SP: 31,
    _ac.ARM64_REG_XZR: 31,
    _ac.ARM64_REG_WZR: 31,
}
for _i in range(31):
    _REG_NUM[getattr(_ac, f"ARM64_REG_X{_i}")] = _i
    _REG_NUM[getattr(_ac, f"ARM64_REG_W{_i}")] = _i

# W-register set for distinguishing 32-bit from 64-bit operands
_W_REGS = {getattr(_ac, f"ARM64_REG_W{_i}") for _i in range(31)} | {_ac.ARM64_REG_WZR}


def _reg(cs_reg: int) -> int:
    """Map Capstone register constant to 0-31, or -1 for non-GPR."""
    return _REG_NUM.get(cs_reg, -1)


def _r32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _w32(buf, off, val):
    struct.pack_into("<I", buf, off, val)


def _mov_w_imm(rd: int, imm16: int) -> int:
    """Encode `mov w<rd>, #<imm16>` as its MOVZ alias."""
    if not 0 <= rd <= 30:
        raise ValueError(f"Invalid W register: {rd}")
    if not 0 <= imm16 <= 0xFFFF:
        raise ValueError(f"Immediate out of range: {imm16}")
    return 0x52800000 | (imm16 << 5) | rd


def _disasm(buf, off):
    """Decode single instruction at offset."""
    return next(_md.disasm(bytes(buf[off : off + 4]), off), None)


def _set_rd(raw, new_rd):
    """Replace Rd/Rt field (bits [4:0])."""
    return (raw & ~0x1F) | (new_rd & 0x1F)


def _set_rd_rn(raw, new_reg):
    """Replace both Rd (bits [4:0]) and Rn (bits [9:5])."""
    raw = (raw & ~0x1F) | (new_reg & 0x1F)
    raw = (raw & ~(0x1F << 5)) | ((new_reg & 0x1F) << 5)
    return raw


INSN_SIZE = 4
PACIASP = 0xD503233F
MAX_TRACE_BOUNCES = 8

UNLOCKED = b"unlocked"
LOCKED = b"locked"
DEVICE_STATE_PROP = b"androidboot.vbmeta.device_state"


@dataclass(frozen=True)
class _InsnPattern:
    asm: str
    mask: int
    value: int

    def matches(self, raw: int) -> bool:
        return raw & self.mask == self.value


@dataclass(frozen=True)
class _InsnPatch:
    asm: str
    value: int

    def apply(self, buf: bytearray, off: int) -> None:
        _w32(buf, off, self.value)


@dataclass(frozen=True)
class _AdrlPair:
    reg: int
    target: int


@dataclass(frozen=True)
class _AdrlTripleMatch:
    offset: int
    regs: tuple[int, int, int]


@dataclass(frozen=True)
class _StackBounce:
    reload_id: int
    spill_id: int
    spill_name: str
    requires_x_sized: bool


@dataclass(frozen=True)
class _Taint:
    kind: str
    value: int


@dataclass
class _TaintTracker:
    entries: set[_Taint]

    @classmethod
    def from_reg(cls, reg: int) -> "_TaintTracker":
        return cls({_Taint("reg", reg)})

    def _has(self, kind: str, value: int) -> bool:
        return _Taint(kind, value) in self.entries

    def _add(self, kind: str, value: int) -> None:
        self.entries.add(_Taint(kind, value))

    def _discard(self, kind: str, value: int) -> None:
        self.entries.discard(_Taint(kind, value))

    def _transfer(self, src: _Taint, dst: _Taint) -> None:
        if src in self.entries:
            self.entries.add(dst)
        elif dst in self.entries:
            self.entries.discard(dst)

    def spill64(self, reg: int, disp: int) -> None:
        self._transfer(_Taint("reg", reg), _Taint("stk64", disp))

    def reload64(self, reg: int, disp: int) -> None:
        self._transfer(_Taint("stk64", disp), _Taint("reg", reg))

    def overwrite_reg_with_byte_load(self, reg: int) -> None:
        self._discard("reg", reg)

    def move_reg(self, src: int, dst: int) -> None:
        if self._has("reg", src) and dst != 31:
            self._add("reg", dst)
        elif self._has("reg", dst):
            self._discard("reg", dst)

    def note_byte_store(
        self,
        reg: int,
        disp: int,
        *,
        sp_based: bool,
        past_anchor: bool,
    ) -> bool:
        if self._has("reg", reg) or (past_anchor and not self.entries):
            if past_anchor:
                return True
            if sp_based:
                self._add("stk8", disp)
        elif sp_based and self._has("stk8", disp):
            self._discard("stk8", disp)
        return False


STACK_RELOAD_BOUNCES = (
    _StackBounce(_ac.ARM64_INS_LDR, _ac.ARM64_INS_STR, "STR", True),
    _StackBounce(_ac.ARM64_INS_LDRB, _ac.ARM64_INS_STRB, "STRB", False),
)


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


def _add_imm_value(insn) -> int | None:
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


def _decode_adrp_add_pair(buf, off) -> _AdrlPair | None:
    """Decode ADRP + ADD (immediate) into (register, file_offset)."""
    i0 = _disasm(buf, off)
    i1 = _disasm(buf, off + INSN_SIZE)
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
    rd = _reg(i0.operands[0].reg)
    if rd < 0 or _reg(i1.operands[0].reg) != rd or _reg(i1.operands[1].reg) != rd:
        return None

    add_imm = _add_imm_value(i1)
    if add_imm is None:
        return None

    return _AdrlPair(rd, i0.operands[1].imm + add_imm)


def _is_adrp_add_pair(buf, off):
    """Check if off, off+4 form a valid ADRP+ADD (immediate) pair."""
    return _decode_adrp_add_pair(buf, off) is not None


def _adrl_target(buf, off):
    """Compute file offset from ADRP+ADD pair."""
    pair = _decode_adrp_add_pair(buf, off)
    if pair is None:
        raise ValueError(f"Invalid ADRP+ADD(immediate) pair at 0x{off:X}")
    return pair.target


def _str_at(buf, off, needle):
    return 0 <= off <= len(buf) - len(needle) and buf[off : off + len(needle)] == needle


def _scan_adrl_triples(
    buf: bytearray, strings: tuple[bytes, bytes, bytes]
) -> list[_AdrlTripleMatch]:
    """Find ADRP+ADD triples where each pair resolves to the given strings."""
    size = len(buf)
    matches: list[_AdrlTripleMatch] = []
    i = 0
    triple_size = 6 * INSN_SIZE

    while i <= size - triple_size:
        pair0 = _decode_adrp_add_pair(buf, i)
        pair1 = _decode_adrp_add_pair(buf, i + 2 * INSN_SIZE)
        pair2 = _decode_adrp_add_pair(buf, i + 4 * INSN_SIZE)
        if not (pair0 and pair1 and pair2):
            i += INSN_SIZE
            continue

        regs = (pair0.reg, pair1.reg, pair2.reg)
        if len(set(regs)) != 3:
            i += INSN_SIZE
            continue

        if all(
            _str_at(buf, pair.target, needle)
            for pair, needle in zip((pair0, pair1, pair2), strings, strict=True)
        ):
            matches.append(_AdrlTripleMatch(i, regs))
            i += triple_size
        else:
            i += INSN_SIZE

    return matches


def _copy_adrl_pair(buf: bytearray, dst_off: int, src_off: int, dst_reg: int) -> None:
    """Copy an ADRP+ADD pair, replacing both destination registers with dst_reg."""
    _w32(buf, dst_off, _set_rd(_r32(buf, src_off), dst_reg))
    _w32(
        buf,
        dst_off + INSN_SIZE,
        _set_rd_rn(_r32(buf, src_off + INSN_SIZE), dst_reg),
    )


def patch_device_state(buf: bytearray) -> None:
    matches = _scan_adrl_triples(buf, (UNLOCKED, LOCKED, DEVICE_STATE_PROP))
    if not matches:
        raise ValueError("ADRL triple (unlocked/locked/device_state) not found")

    for match in matches:
        # Copy pair-1's ADRP+ADD encoding but with pair-0's register.
        _copy_adrl_pair(
            buf,
            match.offset,
            match.offset + 2 * INSN_SIZE,
            match.regs[0],
        )

    verified = _scan_adrl_triples(buf, (LOCKED, LOCKED, DEVICE_STATE_PROP))
    if not verified:
        raise ValueError("ADRL verification failed")


# =====================================================================
# Patches 3/4/5: Boot state pattern + data-flow patching
# =====================================================================

BOOT_PATTERN: list[_InsnPattern] = [
    _InsnPattern("cbz w<lock_reg>, <skip>", 0xFFFFFF00, 0x34000000),
    _InsnPattern("mov w8, #1", 0xFFFFFFFF, _mov_w_imm(8, 1)),
    _InsnPattern("b <after_load>", 0xFFFFFFFF, 0x14000006),
    _InsnPattern("ldr x8, [x?, #?]", 0xFFFF00FF, 0xF94000E8),
    _InsnPattern("ldrb w8, [x8]", 0xFFFFFFFF, 0x39400108),
    _InsnPattern("cmp w8, #0", 0xFFFFFFFF, 0x7100011F),
    _InsnPattern("cset w8, ne", 0xFFFFFFFF, 0x1A9F07E8),
    _InsnPattern("lsl w8, w8, #1", 0xFFFFFFFF, 0x531F7908),
]

BOOT_PATCH: list[_InsnPatch | None] = [
    None,
    _InsnPatch("mov w8, #0", _mov_w_imm(8, 0)),
    None,
    None,
    None,
    None,
    None,
    None,
]


def _find_and_patch_boot_pattern(buf: bytearray) -> tuple[int, int]:
    """Find boot state pattern, apply patch 3, return (anchor_offset, lock_register)."""
    plen = len(BOOT_PATTERN) * INSN_SIZE
    anchor = -1
    lock_reg = -1

    i = 0
    while i <= len(buf) - plen:
        if all(
            pattern.matches(_r32(buf, i + j * INSN_SIZE))
            for j, pattern in enumerate(BOOT_PATTERN)
        ):
            lock_reg = _r32(buf, i) & 0x1F
            anchor = i
            for j, patch in enumerate(BOOT_PATCH):
                if patch is not None:
                    patch.apply(buf, i + j * INSN_SIZE)
            i += plen
        else:
            i += 1

    if anchor == -1:
        raise ValueError("Boot state pattern not found")
    return anchor, lock_reg


def _is_sp_based(insn):
    return insn.operands[1].mem.base == _ac.ARM64_REG_SP


def _is_reg_to_reg_mov(insn) -> bool:
    return (
        insn.id == _ac.ARM64_INS_MOV
        and len(insn.operands) >= 2
        and insn.operands[1].type == _ac.ARM64_OP_REG
    )


def _disp(insn):
    return insn.operands[1].mem.disp


def _rt_num(insn):
    if not insn.operands or insn.operands[0].type != _ac.ARM64_OP_REG:
        return -1
    return _reg(insn.operands[0].reg)


def _is_x_sized(insn):
    return insn.operands[0].reg not in _W_REGS


def _iter_backward_insns(buf: bytearray, start_off: int):
    for off in range(start_off, -1, -INSN_SIZE):
        if _r32(buf, off) == PACIASP:
            break
        insn = _disasm(buf, off)
        if insn:
            yield off, insn


def _iter_forward_insns(buf: bytearray, start_off: int):
    for off in range(start_off, len(buf) - INSN_SIZE, INSN_SIZE):
        if _r32(buf, off) == PACIASP:
            break
        insn = _disasm(buf, off)
        if insn:
            yield off, insn


def _match_stack_reload(insn, target_reg: int) -> tuple[_StackBounce, int] | None:
    for bounce in STACK_RELOAD_BOUNCES:
        if insn.id != bounce.reload_id:
            continue
        if not _is_sp_based(insn) or _rt_num(insn) != target_reg:
            continue
        if bounce.requires_x_sized and not _is_x_sized(insn):
            continue
        return bounce, _disp(insn)
    return None


def _find_prior_stack_spill(
    buf: bytearray, start_off: int, bounce: _StackBounce, disp: int
) -> tuple[int, int] | None:
    for off, insn in _iter_backward_insns(buf, start_off):
        if insn.id != bounce.spill_id or not _is_sp_based(insn) or _disp(insn) != disp:
            continue
        if bounce.requires_x_sized and not _is_x_sized(insn):
            continue
        return off, _rt_num(insn)
    return None


def _is_bootstate_source_ldrb(insn, reg: int) -> bool:
    return (
        insn.id == _ac.ARM64_INS_LDRB
        and _rt_num(insn) == reg
        and not _is_sp_based(insn)
    )


def _patch_strb_rt_to_wzr(buf: bytearray, off: int) -> None:
    _w32(buf, off, _set_rd(_r32(buf, off), 31))


def _patch_bootstate_source(
    buf: bytearray, anchor_off: int, target_reg: int
) -> tuple[int, int]:
    """Trace backward from anchor to find source LDRB. Patch it to MOV Wn, #1."""
    current = target_reg
    search_off = anchor_off - INSN_SIZE
    bounces = 0

    while search_off >= 0:
        for off, insn in _iter_backward_insns(buf, search_off):
            bounce_match = _match_stack_reload(insn, current)
            if bounce_match is not None:
                bounce, disp = bounce_match
                spill = _find_prior_stack_spill(buf, off - INSN_SIZE, bounce, disp)
                if spill is None:
                    raise ValueError(
                        "No matching "
                        f"{bounce.spill_name} for reload bounce at 0x{off:X}"
                    )
                spill_off, current = spill
                search_off = spill_off - INSN_SIZE
                bounces += 1
                if bounces > MAX_TRACE_BOUNCES:
                    raise ValueError("Too many bounces")
                break

            if _is_bootstate_source_ldrb(insn, current):
                _w32(buf, off, _mov_w_imm(current, 1))
                return off, current
        else:
            break

    raise ValueError(f"Source LDRB not found for W{target_reg}")


def _patch_bootstate_sink(
    buf: bytearray,
    ldrb_off: int,
    src_reg: int,
    anchor_off: int,
) -> None:
    """Trace forward from patched LDRB to find and patch the sink STRB."""
    taint = _TaintTracker.from_reg(src_reg)

    for off, insn in _iter_forward_insns(buf, ldrb_off + INSN_SIZE):
        rt = _rt_num(insn)

        if insn.id == _ac.ARM64_INS_STR and _is_sp_based(insn):
            taint.spill64(rt, _disp(insn))
            continue

        if insn.id == _ac.ARM64_INS_LDR and _is_sp_based(insn):
            taint.reload64(rt, _disp(insn))
            continue

        if insn.id == _ac.ARM64_INS_LDRB:
            taint.overwrite_reg_with_byte_load(rt)
            continue

        if _is_reg_to_reg_mov(insn):
            taint.move_reg(_reg(insn.operands[1].reg), rt)
            continue

        if insn.id == _ac.ARM64_INS_STRB:
            if taint.note_byte_store(
                rt,
                _disp(insn),
                sp_based=_is_sp_based(insn),
                past_anchor=off > anchor_off,
            ):
                _patch_strb_rt_to_wzr(buf, off)
                return

    raise ValueError(f"Sink STRB not found after anchor 0x{anchor_off:X}")


def patch_bootstate(buf: bytearray) -> None:
    anchor, lock_reg = _find_and_patch_boot_pattern(buf)
    ldrb_off, src_reg = _patch_bootstate_source(buf, anchor, lock_reg)
    _patch_bootstate_sink(buf, ldrb_off, src_reg, anchor)


# =====================================================================
# Orchestrator
# =====================================================================


def patch_efi(buf: bytearray) -> bytearray:
    patch_gbl(buf)
    patch_device_state(buf)
    patch_bootstate(buf)
    return buf


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Patch LinuxLoader.efi")
    parser.add_argument("input", type=Path, help="Input EFI file")
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"Error: {args.input} not found", file=sys.stderr)
        return 1

    buf = bytearray(args.input.read_bytes())
    patch_efi(buf)
    args.output.write_bytes(buf)
    print(f"Patched {len(buf)} bytes to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
