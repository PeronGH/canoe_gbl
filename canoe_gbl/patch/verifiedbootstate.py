"""Force the `androidboot.verifiedbootstate=` cmdline value to `orange`.

1vivy fork Patch 8: the cmdline-building helper reads `state->boot_state` from
`[x20, #0x438]` and uses it to index the color-string table. Replacing the
initial LDRSW with `mov x8, #1` makes the helper always pick index 1 (orange),
while leaving the underlying `boot_state` field — which the TEE handoff path
also consults — untouched.
"""

from __future__ import annotations

from .core import INSN_SIZE, InsnPattern, read_u32, write_u32

MOV_X8_1 = 0xD2800028

HELPER_PATTERN: list[InsnPattern] = [
    InsnPattern("ldrsw x8, [x20, #0x438]", 0xFFFFFFFF, 0xB9843A88),
    InsnPattern("adrp x9, <table>", 0x9F00001F, 0x90000009),
    InsnPattern("add x9, x9, #<table_lo12>", 0xFFC003FF, 0x91000129),
    InsnPattern("mov x0, x20", 0xFFFFFFFF, 0xAA1403E0),
    InsnPattern("add x8, x9, x8, lsl #4", 0xFFFFFFFF, 0x8B081128),
    InsnPattern("ldr x1, [x8, #0x8]", 0xFFFFFFFF, 0xF9400501),
]


def patch_verifiedbootstate(buf: bytearray) -> int:
    pattern_size = len(HELPER_PATTERN) * INSN_SIZE
    patched = 0
    for off in range(0, len(buf) - pattern_size + 1, INSN_SIZE):
        if all(
            p.matches(read_u32(buf, off + i * INSN_SIZE))
            for i, p in enumerate(HELPER_PATTERN)
        ):
            write_u32(buf, off, MOV_X8_1)
            patched += 1
    return patched
