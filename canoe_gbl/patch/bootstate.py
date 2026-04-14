"""Patch boot-state checks and data flow to force locked state."""

from __future__ import annotations

from dataclasses import dataclass

import capstone.arm64_const as _ac

from .core import (
    INSN_SIZE,
    InsnPatch,
    InsnPattern,
    disp,
    is_reg_to_reg_mov,
    is_sp_based,
    is_x_sized,
    iter_backward_insns,
    iter_forward_insns,
    mov_w_imm,
    read_u32,
    reg_num,
    rt_num,
    set_rd,
    write_u32,
)

MAX_TRACE_BOUNCES = 8


@dataclass(frozen=True)
class StackBounce:
    reload_id: int
    spill_id: int
    spill_name: str
    requires_x_sized: bool


@dataclass(frozen=True)
class Taint:
    kind: str
    value: int


@dataclass
class TaintTracker:
    entries: set[Taint]

    @classmethod
    def from_reg(cls, reg: int) -> "TaintTracker":
        return cls({Taint("reg", reg)})

    def has(self, kind: str, value: int) -> bool:
        return Taint(kind, value) in self.entries

    def add(self, kind: str, value: int) -> None:
        self.entries.add(Taint(kind, value))

    def discard(self, kind: str, value: int) -> None:
        self.entries.discard(Taint(kind, value))

    def transfer(self, src: Taint, dst: Taint) -> None:
        if src in self.entries:
            self.entries.add(dst)
        elif dst in self.entries:
            self.entries.discard(dst)

    def spill64(self, reg: int, stack_disp: int) -> None:
        self.transfer(Taint("reg", reg), Taint("stk64", stack_disp))

    def reload64(self, reg: int, stack_disp: int) -> None:
        self.transfer(Taint("stk64", stack_disp), Taint("reg", reg))

    def overwrite_reg_with_byte_load(self, reg: int) -> None:
        self.discard("reg", reg)

    def move_reg(self, src: int, dst: int) -> None:
        if self.has("reg", src) and dst != 31:
            self.add("reg", dst)
        elif self.has("reg", dst):
            self.discard("reg", dst)

    def note_byte_store(
        self,
        reg: int,
        stack_disp: int,
        *,
        sp_based: bool,
        past_anchor: bool,
    ) -> bool:
        if self.has("reg", reg) or (past_anchor and not self.entries):
            if past_anchor:
                return True
            if sp_based:
                self.add("stk8", stack_disp)
        elif sp_based and self.has("stk8", stack_disp):
            self.discard("stk8", stack_disp)
        return False


STACK_RELOAD_BOUNCES = (
    StackBounce(_ac.ARM64_INS_LDR, _ac.ARM64_INS_STR, "STR", True),
    StackBounce(_ac.ARM64_INS_LDRB, _ac.ARM64_INS_STRB, "STRB", False),
)

BOOT_PATTERN: list[InsnPattern] = [
    InsnPattern("cbz w<lock_reg>, <skip>", 0xFFFFFF00, 0x34000000),
    InsnPattern("mov w8, #1", 0xFFFFFFFF, mov_w_imm(8, 1)),
    InsnPattern("b <after_load>", 0xFFFFFFFF, 0x14000006),
    InsnPattern("ldr x8, [x?, #?]", 0xFFFF00FF, 0xF94000E8),
    InsnPattern("ldrb w8, [x8]", 0xFFFFFFFF, 0x39400108),
    InsnPattern("cmp w8, #0", 0xFFFFFFFF, 0x7100011F),
    InsnPattern("cset w8, ne", 0xFFFFFFFF, 0x1A9F07E8),
    InsnPattern("lsl w8, w8, #1", 0xFFFFFFFF, 0x531F7908),
]

BOOT_PATCH: list[InsnPatch | None] = [
    None,
    InsnPatch("mov w8, #0", mov_w_imm(8, 0)),
    None,
    None,
    None,
    None,
    None,
    None,
]


def find_and_patch_boot_pattern(buf: bytearray) -> tuple[int, int]:
    """Find boot state pattern, apply patch 3, return (anchor_offset, lock_register)."""
    pattern_size = len(BOOT_PATTERN) * INSN_SIZE
    anchor = -1
    lock_reg = -1

    i = 0
    while i <= len(buf) - pattern_size:
        if all(
            pattern.matches(read_u32(buf, i + j * INSN_SIZE))
            for j, pattern in enumerate(BOOT_PATTERN)
        ):
            lock_reg = read_u32(buf, i) & 0x1F
            anchor = i
            for j, patch in enumerate(BOOT_PATCH):
                if patch is not None:
                    patch.apply(buf, i + j * INSN_SIZE)
            i += pattern_size
        else:
            i += 1

    if anchor == -1:
        raise ValueError("Boot state pattern not found")
    return anchor, lock_reg


def match_stack_reload(insn, target_reg: int) -> tuple[StackBounce, int] | None:
    for bounce in STACK_RELOAD_BOUNCES:
        if insn.id != bounce.reload_id:
            continue
        if not is_sp_based(insn) or rt_num(insn) != target_reg:
            continue
        if bounce.requires_x_sized and not is_x_sized(insn):
            continue
        return bounce, disp(insn)
    return None


def find_prior_stack_spill(
    buf: bytearray, start_off: int, bounce: StackBounce, stack_disp: int
) -> tuple[int, int] | None:
    for off, insn in iter_backward_insns(buf, start_off):
        if (
            insn.id != bounce.spill_id
            or not is_sp_based(insn)
            or disp(insn) != stack_disp
        ):
            continue
        if bounce.requires_x_sized and not is_x_sized(insn):
            continue
        return off, rt_num(insn)
    return None


def is_bootstate_source_ldrb(insn, reg: int) -> bool:
    return (
        insn.id == _ac.ARM64_INS_LDRB and rt_num(insn) == reg and not is_sp_based(insn)
    )


def patch_strb_rt_to_wzr(buf: bytearray, off: int) -> None:
    write_u32(buf, off, set_rd(read_u32(buf, off), 31))


def patch_bootstate_source(
    buf: bytearray, anchor_off: int, target_reg: int
) -> tuple[int, int]:
    """Trace backward from anchor to find source LDRB. Patch it to MOV Wn, #1."""
    current = target_reg
    search_off = anchor_off - INSN_SIZE
    bounces = 0

    while search_off >= 0:
        for off, insn in iter_backward_insns(buf, search_off):
            bounce_match = match_stack_reload(insn, current)
            if bounce_match is not None:
                bounce, stack_disp = bounce_match
                spill = find_prior_stack_spill(buf, off - INSN_SIZE, bounce, stack_disp)
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

            if is_bootstate_source_ldrb(insn, current):
                write_u32(buf, off, mov_w_imm(current, 1))
                return off, current
        else:
            break

    raise ValueError(f"Source LDRB not found for W{target_reg}")


def patch_bootstate_sink(
    buf: bytearray,
    ldrb_off: int,
    src_reg: int,
    anchor_off: int,
) -> None:
    """Trace forward from patched LDRB to find and patch the sink STRB."""
    taint = TaintTracker.from_reg(src_reg)

    for off, insn in iter_forward_insns(buf, ldrb_off + INSN_SIZE):
        rt = rt_num(insn)

        if insn.id == _ac.ARM64_INS_STR and is_sp_based(insn):
            taint.spill64(rt, disp(insn))
            continue

        if insn.id == _ac.ARM64_INS_LDR and is_sp_based(insn):
            taint.reload64(rt, disp(insn))
            continue

        if insn.id == _ac.ARM64_INS_LDRB:
            taint.overwrite_reg_with_byte_load(rt)
            continue

        if is_reg_to_reg_mov(insn):
            taint.move_reg(reg_num(insn.operands[1].reg), rt)
            continue

        if insn.id == _ac.ARM64_INS_STRB and taint.note_byte_store(
            rt,
            disp(insn),
            sp_based=is_sp_based(insn),
            past_anchor=off > anchor_off,
        ):
            patch_strb_rt_to_wzr(buf, off)
            return

    raise ValueError(f"Sink STRB not found after anchor 0x{anchor_off:X}")


def patch_bootstate(buf: bytearray) -> None:
    anchor, lock_reg = find_and_patch_boot_pattern(buf)
    ldrb_off, src_reg = patch_bootstate_source(buf, anchor, lock_reg)
    patch_bootstate_sink(buf, ldrb_off, src_reg, anchor)
