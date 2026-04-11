# canoe_gbl

Qualcomm ABL loads `efisp` early in boot without signature verification. This tool patches ABL and flashes it to `efisp` as GBL, taking over the boot with locked state checks bypassed.

Affects any Snapdragon 8 Elite Gen 5 phone without Qualcomm's March 2026 ABL patch, excluding Samsung. Developed and tested on OnePlus 15 (`canoe`).

**For security research only. Use at your own risk.**

## Prerequisites

- An unlocked bootloader
- Stock `abl.img` from your device

## Usage

```bash
uv run python -m canoe_gbl.extract abl.img -o LinuxLoader.efi
uv run python -m canoe_gbl.patch LinuxLoader.efi -o LinuxLoader_patched.efi
fastboot flash efisp LinuxLoader_patched.efi
```

## What the patcher does

1. Replaces the `efisp` reference with `nulls` so the patched GBL doesn't recursively load itself
2. Rewrites `androidboot.vbmeta.device_state` to always report `locked`
3. Patches the boot state check sequence
4. Hardcodes the lock state read to 1 via backward data-flow tracing
5. Zeros out the lock state write via forward taint tracking

The TEE derives its boot state from ABL. Since the patched GBL reports locked state, the hardware key attestation passes, which gives STRONG Play Integrity and Widevine L1.

## License

[GPLv3](LICENSE)
