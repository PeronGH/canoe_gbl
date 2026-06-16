"""Hide the unlock-state warning by neutering its guard branch.

The warning screen is gated by a `CBZ Wt, <skip>` that reads the lock-state
global variable. We locate the warning message strings, walk backward to that
guard, confirm its register traces back to the same variable the boot-state
patch hardcoded, and rewrite it to `CBZ WZR` so the branch is always taken.
"""

from __future__ import annotations

from .bootstate import trace_to_source_ldrb
from .core import INSN_SIZE, PACIASP, read_u32, set_rd, write_u32
from .device_state import decode_adrp_add_pair, str_at

ORANGE_STATE = b"Orange State\n"
UNTRUSTED = b"Your device has been unlocked and can't be trusted\n"

# CBZ Wt: full top byte fixed (sf=0 -> 32-bit, op=0 -> CBZ).
CBZ_W_MASK = 0xFF000000
CBZ_W_VALUE = 0x34000000

# How far back from the message ADRL the guard branch may sit.
WARNING_SEARCH_BYTES = 64


def find_warning_adrl(buf: bytearray) -> int:
    """Offset of the ADRP+ADD pair loading the Orange State warning string,
    immediately followed by the 'unlocked and can't be trusted' pair."""
    for off in range(0, len(buf) - 4 * INSN_SIZE + 1, INSN_SIZE):
        first = decode_adrp_add_pair(buf, off)
        second = decode_adrp_add_pair(buf, off + 2 * INSN_SIZE)
        if (
            first
            and second
            and str_at(buf, first.target, ORANGE_STATE)
            and str_at(buf, second.target, UNTRUSTED)
        ):
            return off
    return -1


def patch_unlock_warning(buf: bytearray, lock_var_disp: int) -> int:
    """Neuter the warning guard CBZ that reads the lock-state variable at
    `lock_var_disp`. Returns the patched branch offset."""
    warn_off = find_warning_adrl(buf)
    if warn_off == -1:
        raise ValueError("Unlock warning string ADRL not found")

    search_floor = max(warn_off - WARNING_SEARCH_BYTES, 0)
    for off in range(warn_off - INSN_SIZE, search_floor - INSN_SIZE, -INSN_SIZE):
        raw = read_u32(buf, off)
        if raw == PACIASP:
            raise ValueError(
                f"Reached function start at 0x{off:X} before warning guard CBZ"
            )
        if raw & CBZ_W_MASK != CBZ_W_VALUE:
            continue

        source = trace_to_source_ldrb(buf, off, raw & 0x1F)
        if source is None or source.disp != lock_var_disp:
            continue

        write_u32(buf, off, set_rd(raw, 31))
        return off

    raise ValueError("Unlock warning guard CBZ not found")
