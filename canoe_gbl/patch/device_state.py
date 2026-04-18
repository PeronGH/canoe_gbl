"""Patch `androidboot.vbmeta.device_state` to always report locked."""

from __future__ import annotations

from dataclasses import dataclass

from .core import (
    INSN_SIZE,
    decode_adrp_add_pair,
    read_u32,
    set_rd,
    set_rd_rn,
    write_u32,
)

UNLOCKED = b"unlocked"
LOCKED = b"locked"
DEVICE_STATE_PROP = b"androidboot.vbmeta.device_state"


@dataclass(frozen=True)
class AdrlTripleMatch:
    offset: int
    regs: tuple[int, int, int]


def str_at(buf: bytearray, off: int, needle: bytes) -> bool:
    return 0 <= off <= len(buf) - len(needle) and buf[off : off + len(needle)] == needle


def scan_adrl_triples(
    buf: bytearray, strings: tuple[bytes, bytes, bytes]
) -> list[AdrlTripleMatch]:
    """Find ADRP+ADD triples where each pair resolves to the given strings."""
    matches: list[AdrlTripleMatch] = []
    triple_size = 6 * INSN_SIZE
    i = 0

    while i <= len(buf) - triple_size:
        pair0 = decode_adrp_add_pair(buf, i)
        pair1 = decode_adrp_add_pair(buf, i + 2 * INSN_SIZE)
        pair2 = decode_adrp_add_pair(buf, i + 4 * INSN_SIZE)
        if not (pair0 and pair1 and pair2):
            i += INSN_SIZE
            continue

        regs = (pair0.reg, pair1.reg, pair2.reg)
        if len(set(regs)) != 3:
            i += INSN_SIZE
            continue

        if all(
            str_at(buf, pair.target, needle)
            for pair, needle in zip((pair0, pair1, pair2), strings, strict=True)
        ):
            matches.append(AdrlTripleMatch(i, regs))
            i += triple_size
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
    matches = scan_adrl_triples(buf, (UNLOCKED, LOCKED, DEVICE_STATE_PROP))
    if not matches:
        raise ValueError("ADRL triple (unlocked/locked/device_state) not found")

    for match in matches:
        copy_adrl_pair(buf, match.offset, match.offset + 2 * INSN_SIZE, match.regs[0])

    verified = scan_adrl_triples(buf, (LOCKED, LOCKED, DEVICE_STATE_PROP))
    if not verified:
        raise ValueError("ADRL verification failed")
