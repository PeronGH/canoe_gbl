"""Extract LinuxLoader.efi from Qualcomm ABL partition images.

ABL image structure:
  ELF 32-bit ARM container
    -> EFI Firmware Volume (FV), found via _FVH signature
      -> LZMA compressed blob inside FV
        -> PE/COFF ARM64 EFI application (LinuxLoader.efi)
"""

from __future__ import annotations

import argparse
import lzma
import struct
import sys
from pathlib import Path

import lief

EFI_FV_SIGNATURE = b"_FVH"
PE_MZ_SIGNATURE = b"MZ"
PE_SIGNATURE = b"PE"


def extract_fv(data: bytes) -> bytes:
    """Find the first EFI Firmware Volume in raw data and return its bytes."""
    off = data.find(EFI_FV_SIGNATURE)
    if off == -1:
        raise ValueError("EFI Firmware Volume signature (_FVH) not found")

    fv_start = off - 0x28
    if fv_start < 0:
        raise ValueError(f"FV header would start at negative offset {fv_start}")

    fv_len = struct.unpack_from("<Q", data, fv_start + 0x20)[0]
    if fv_len < 0x48 or fv_start + fv_len > len(data):
        raise ValueError(f"Invalid FV length: 0x{fv_len:X}")

    return data[fv_start : fv_start + fv_len]


def decompress_fv(fv: bytes) -> bytes:
    """Find and decompress the LZMA section inside a Firmware Volume."""
    off = fv.find(b"\x5d\x00\x00")
    if off == -1:
        raise ValueError("No LZMA compressed section found in FV")

    return lzma.decompress(fv[off:])


def _pe_real_size(pe: lief.PE.Binary) -> int:
    """Calculate the real on-disk size of a PE from its section table."""
    size = pe.optional_header.sizeof_headers
    for section in pe.sections:
        end = section.pointerto_raw_data + section.sizeof_raw_data
        if end > size:
            size = end
    return size


def extract_pe(data: bytes) -> bytes:
    """Find the largest PE in a data blob and return it trimmed to real size."""
    candidates: list[tuple[int, int]] = []
    off = 0
    while True:
        off = data.find(PE_MZ_SIGNATURE, off)
        if off == -1:
            break
        if off + 0x40 < len(data):
            pe_ptr = struct.unpack_from("<H", data, off + 0x3C)[0]
            if (
                off + pe_ptr + 4 <= len(data)
                and data[off + pe_ptr : off + pe_ptr + 2] == PE_SIGNATURE
            ):
                candidates.append((off, len(data) - off))
        off += 2

    if not candidates:
        raise ValueError("No PE binary found in decompressed data")

    # Pick the largest candidate
    candidates.sort(key=lambda c: c[1], reverse=True)
    pe_off, _ = candidates[0]
    pe_data = data[pe_off:]

    pe = lief.PE.parse(list(pe_data))
    if pe is None:
        raise ValueError(f"LIEF failed to parse PE at offset 0x{pe_off:X}")

    real_size = _pe_real_size(pe)
    return pe_data[:real_size]


def extract_efi(abl_path: Path) -> bytes:
    """Extract LinuxLoader.efi from an ABL partition image."""
    raw = abl_path.read_bytes()
    fv = extract_fv(raw)
    decompressed = decompress_fv(fv)
    return extract_pe(decompressed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract EFI from ABL image")
    parser.add_argument("input", type=Path, help="Path to ABL image")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("LinuxLoader.efi"),
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: {args.input} not found", file=sys.stderr)
        sys.exit(1)

    efi = extract_efi(args.input)
    args.output.write_bytes(efi)
    print(f"Extracted {len(efi)} bytes to {args.output}")
