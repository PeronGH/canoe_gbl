"""Force `androidboot.veritymode=logging` by retargeting string loads.

1vivy fork Patch 6 — two paths pick a veritymode string:
  * Cmdline build: ADRP+ADD loads "enforcing" (CSEL chooses between "eio" and
    "enforcing"). Rewrite the "enforcing" load to point at "logging" so the
    chosen value is "logging" for the default (unmanaged) case. Scoped to
    ADRP+ADD pairs within 512 bytes of an ADRP+ADD pointing at the
    "androidboot.veritymode" key string.
  * Verity setup: reads from a pointer table indexed by DeviceInfo.verity_mode,
    where entry 0 is &"logging" and entry 1 is &"enforcing". Overwrite the
    &"enforcing" entry with &"logging" so both indices return "logging".
"""

from __future__ import annotations

from .core import INSN_SIZE, decode_adrp_add_pair, encode_adrp_add_pair, write_u32

KEY = b"androidboot.veritymode"
ENFORCING = b"enforcing"
LOGGING = b"logging"
KEY_PROXIMITY = 512


def _find_null_prefixed(buf: bytearray, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        idx = buf.find(needle, start)
        if idx == -1:
            return out
        if idx == 0 or buf[idx - 1] == 0:
            out.append(idx)
        start = idx + 1


def _str_at(buf: bytearray, off: int, needle: bytes) -> bool:
    return 0 <= off <= len(buf) - len(needle) and buf[off : off + len(needle)] == needle


def patch_veritymode(buf: bytearray) -> int:
    log_hits = _find_null_prefixed(buf, LOGGING)
    if not log_hits:
        return 0
    log_first = log_hits[0]

    key_sites: list[int] = []
    for off in range(0, len(buf) - 2 * INSN_SIZE + 1, INSN_SIZE):
        pair = decode_adrp_add_pair(buf, off)
        if pair and _str_at(buf, pair.target, KEY):
            key_sites.append(off)

    patched = 0
    for off in range(0, len(buf) - 2 * INSN_SIZE + 1, INSN_SIZE):
        pair = decode_adrp_add_pair(buf, off)
        if pair is None or not _str_at(buf, pair.target, ENFORCING):
            continue
        if not any(abs(off - k) <= KEY_PROXIMITY for k in key_sites):
            continue
        new_adrp, new_add = encode_adrp_add_pair(off, log_first, pair.reg)
        write_u32(buf, off, new_adrp)
        write_u32(buf, off + INSN_SIZE, new_add)
        patched += 1

    # Pointer-table entry: [&"logging", _, &"enforcing"] -> rewrite 2nd pointer.
    # C picks the LAST null-prefix occurrence of each string, so mirror that.
    enf_hits = _find_null_prefixed(buf, ENFORCING)
    if enf_hits:
        log_last = log_hits[-1]
        enf_last = enf_hits[-1]
        log_qw = log_last.to_bytes(8, "little")
        enf_qw = enf_last.to_bytes(8, "little")
        for off in range(0, len(buf) - 32, 8):
            if buf[off : off + 8] == log_qw and buf[off + 16 : off + 24] == enf_qw:
                buf[off + 16 : off + 24] = log_qw
                patched += 1
                break

    return patched
