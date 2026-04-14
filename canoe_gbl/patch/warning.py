"""Hide the unlock warning/countdown path."""

from __future__ import annotations

from .core import INSN_SIZE, InsnPattern, read_u32, set_rd, write_u32

UNLOCK_WARNING_PATTERN: list[InsnPattern] = [
    InsnPattern("mov w<counter>, #0x3?", 0xFFFFFF00, 0x52800600),
    InsnPattern("cbz x<counter>, <show_warning>", 0x00FFFF00, 0x00000000),
    InsnPattern("sub x<counter>, x<counter>, #1", 0x0000FF00, 0x00000500),
]


def patch_unlock_warning(buf: bytearray) -> int:
    """Force the warning guard branch to skip the unlock countdown path."""
    pattern_size = len(UNLOCK_WARNING_PATTERN) * INSN_SIZE

    for off in range(len(buf) - pattern_size + 1):
        if not all(
            pattern.matches(read_u32(buf, off + idx * INSN_SIZE))
            for idx, pattern in enumerate(UNLOCK_WARNING_PATTERN)
        ):
            continue

        branch_off = off - INSN_SIZE
        if branch_off < 0:
            raise ValueError("Unlock warning guard would start before file offset 0")

        branch_raw = read_u32(buf, branch_off)
        if branch_raw & 0x7F000000 != 0x34000000:
            raise ValueError(
                f"Unlock warning guard at 0x{branch_off:X} is not a 32-bit CBZ"
            )

        write_u32(buf, branch_off, set_rd(branch_raw, 31))
        return branch_off

    raise ValueError("Unlock warning pattern not found")
