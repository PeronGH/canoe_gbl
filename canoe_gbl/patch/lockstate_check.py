"""NOP out jumps that report the `... is not allowed in Lock State` errors.

Upstream OnePlus patch (post-72619fe): allows `fastboot flash` / `erase` while
the bootloader still reports itself as locked, by killing the branch that
routes control to the error-string printer. We find every direct branch whose
target starts with an ADRP+ADD to a string containing the keyword, and replace
the branch itself with a NOP.
"""

from __future__ import annotations

from .core import INSN_SIZE, decode_adrp_add_pair, read_u32, write_u32

KEYWORD = b"is not allowed in Lock State"
NOP = 0xD503201F

# Raw encodings for the jump classes upstream's get_JUMP_target recognises:
#   B   (unconditional)            : bits 31-26 = 0b000101
#   BL                              : bits 31-26 = 0b100101
#   CBZ / CBNZ (W or X variant)    : bits 30-24 = 0b0110100 / 0b0110101
_JUMP_MATCHERS: tuple[tuple[int, int, int, int], ...] = (
    # (mask, value, imm_shift, imm_bits) — imm_bits = sign bit's value
    (0xFC000000, 0x14000000, 26, 0x02000000),  # B
    (0xFC000000, 0x94000000, 26, 0x02000000),  # BL
    (0x7E000000, 0x34000000, 19, 0x00040000),  # CBZ (W/X)
    (0x7E000000, 0x35000000, 19, 0x00040000),  # CBNZ (W/X)
)


def _jump_target(raw: int, pc: int) -> int | None:
    for mask, value, imm_shift, sign_bit in _JUMP_MATCHERS:
        if raw & mask != value:
            continue
        if imm_shift == 26:
            imm = raw & 0x03FFFFFF
        else:
            imm = (raw >> 5) & 0x7FFFF
        if imm & sign_bit:
            imm -= sign_bit << 1
        return pc + imm * INSN_SIZE
    return None


def patch_lockstate_check(buf: bytearray) -> int:
    patched = 0
    size = len(buf)
    for off in range(0, size - INSN_SIZE, INSN_SIZE):
        target = _jump_target(read_u32(buf, off), off)
        if target is None or target < 0 or target + 2 * INSN_SIZE > size:
            continue
        pair = decode_adrp_add_pair(buf, target)
        if pair is None or not 0 <= pair.target < size:
            continue
        end = buf.find(b"\0", pair.target)
        end = size if end == -1 else end
        if KEYWORD in bytes(buf[pair.target : end]):
            write_u32(buf, off, NOP)
            patched += 1
    return patched
