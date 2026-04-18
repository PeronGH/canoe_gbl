# canoe_gbl

Qualcomm ABL loads `efisp` early in boot without signature verification ([details](docs/abl-efisp-load.md)). This tool patches ABL and flashes it to `efisp` as GBL, taking over the boot and spoofing locked state.

Affects any Snapdragon 8 Elite Gen 5 (`canoe`) phone without Qualcomm's March 2026 ABL patch, excluding Samsung. Developed and tested on OnePlus 15.

**For security research only. Use at your own risk.**

## Prerequisites

- An unlocked bootloader
- Stock `abl.img` from your device

## Usage

I tested this on all stock firmware. The only other change was a patched `init_boot` (with KernelSU Next). I suspect other partition modifications may prevent boot or break Play Integrity.

1. Extract and patch GBL:
   ```bash
   uv run python -m canoe_gbl.extract abl.img -o LinuxLoader.efi
   uv run python -m canoe_gbl.patch LinuxLoader.efi -o LinuxLoader_patched.efi
   ```
2. Flash to `efisp`:
   ```bash
   fastboot flash efisp LinuxLoader_patched.efi
   ```
3. Reboot into recovery and wipe data.

Other approaches (skip the data wipe, modify other partitions, etc.) might work too but I haven't tested them. If something goes wrong, revert with `fastboot erase efisp`. If you get something else working, open an issue and I'll update this.

## What the patcher does

1. Replaces the `efisp` reference with `nulls` so the patched GBL doesn't recursively load itself
2. Rewrites `androidboot.vbmeta.device_state` to always report `locked`
3. Skips the unlock warning/countdown path
4. Patches the boot state check sequence
5. Hardcodes the lock state read to 1 via backward data-flow tracing
6. Zeros out the lock state write via forward taint tracking

The TEE derives its boot state from ABL. Since the patched GBL reports locked state, the hardware key attestation passes, which gives STRONG Play Integrity and Widevine L1.

## Variants

- [`variant/custom-kernel`](https://github.com/PeronGH/canoe_gbl/tree/variant/custom-kernel) — reports `verifiedbootstate=orange` and `veritymode=logging` to the kernel instead of spoofing locked/enforcing. Third-party recoveries can decrypt data and you can modify `system`/`vendor`/`product`. Requires a custom kernel that spoofs those two cmdline strings back to `green`/`enforcing` for Play Integrity (trivial with a Susfs-capable kernel).

## Credits

- [Qualcomm GBL Exploit PoC](https://github.com/kasnria001/qualcomm_gbl_exploit_poc)
- [Original C implementation](https://github.com/superturtlee/gbl_root_canoe)
- [Fork of original implementation](https://github.com/fggdc/gbl_root_canoe_abl_701)

## License

[GPLv3](LICENSE)
