"""Patch LinuxLoader.efi to report locked boot state.

Applies 6 patches:
  1. Replace UTF-16 "efisp" with "nulls" (disable EFI system partition)
  2. Rewrite ADRL triple so device_state always reports "locked"
  3. Hide the unlock warning/countdown
  4. Patch boot state check pattern
  5. Replace source LDRB with MOV Wn, #1 (hardcode locked)
  6. Replace sink STRB Rt with WZR (zero out lock state write)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .bootstate import BOOT_PATCH, BOOT_PATTERN, patch_bootstate
from .device_state import patch_device_state
from .warning import UNLOCK_WARNING_PATTERN, patch_unlock_warning


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
    patch_unlock_warning(buf)
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


__all__ = [
    "BOOT_PATCH",
    "BOOT_PATTERN",
    "UNLOCK_WARNING_PATTERN",
    "main",
    "patch_bootstate",
    "patch_device_state",
    "patch_efi",
    "patch_gbl",
    "patch_unlock_warning",
]
