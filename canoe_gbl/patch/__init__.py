"""Patch LinuxLoader.efi for the custom-kernel variant.

Ports upstream + 1vivy fork patches to Python, producing bit-for-bit output
matching `tools/patch_abl` built from 1vivy-fork/main.

Patches applied:
  1. Replace UTF-16 "efisp" with "nulls" (disable EFI system partition)
  2. Rewrite ADRL triple so `vbmeta.device_state` always reports "locked"
  3. NOP jumps to "… is not allowed in Lock State" error messages
  4. Patch boot-state check pattern (CBZ target branch constant)
  5. Hardcode source LDRB to `mov Wn, #1` via backward data-flow tracing
  6. Zero the sink STRB via forward taint tracking
  7. Override the `verifiedbootstate=` cmdline helper to report `orange`
  8. Retarget veritymode string loads + pointer table to `logging`
  9. Rewrite the orange-warning CBZ as an unconditional B
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .bootstate import BOOT_PATCH, BOOT_PATTERN, patch_bootstate
from .device_state import patch_device_state
from .lockstate_check import patch_lockstate_check
from .orange_warning import patch_orange_warning
from .verifiedbootstate import patch_verifiedbootstate
from .veritymode import patch_veritymode


def patch_gbl(buf: bytearray) -> None:
    target = "efisp".encode("utf-16-le")
    replacement = "nulls".encode("utf-16-le")
    idx = buf.find(target)
    if idx == -1:
        raise ValueError("'efisp' (UTF-16LE) not found")
    buf[idx : idx + len(replacement)] = replacement


def patch_efi(buf: bytearray) -> bytearray:
    patch_gbl(buf)
    patch_device_state(buf)
    patch_lockstate_check(buf)
    patch_bootstate(buf)
    patch_verifiedbootstate(buf)
    patch_veritymode(buf)
    patch_orange_warning(buf)
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


__all__ = [
    "BOOT_PATCH",
    "BOOT_PATTERN",
    "main",
    "patch_bootstate",
    "patch_device_state",
    "patch_efi",
    "patch_gbl",
    "patch_lockstate_check",
    "patch_orange_warning",
    "patch_verifiedbootstate",
    "patch_veritymode",
]
