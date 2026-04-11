import argparse
import sys
from pathlib import Path

from canoe_gbl.extract import extract_efi


def main() -> None:
    parser = argparse.ArgumentParser(description="canoe_gbl")
    sub = parser.add_subparsers(dest="command")

    ext = sub.add_parser("extract", help="Extract EFI from ABL image")
    ext.add_argument("input", type=Path, help="Path to ABL image")
    ext.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("LinuxLoader.efi"),
        help="Output path (default: LinuxLoader.efi)",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "extract":
        if not args.input.exists():
            print(f"Error: {args.input} not found", file=sys.stderr)
            sys.exit(1)
        efi = extract_efi(args.input)
        args.output.write_bytes(efi)
        print(f"Extracted {len(efi)} bytes to {args.output}")


if __name__ == "__main__":
    main()
