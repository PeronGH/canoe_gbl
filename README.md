# canoe_gbl — custom-kernel variant

Parallel variant of [`next`](https://github.com/PeronGH/canoe_gbl/tree/next). **Only use this if you run a custom kernel that can spoof the verified-boot cmdline back to locked/green/enforcing** (trivial with e.g. a KernelSU/SukiSU kernel and Susfs).

This branch is a faithful Python port of [1vivy-fork/main](https://github.com/1vivy/gbl_root_canoe) — running `uv run python -m canoe_gbl.patch` on an extracted `LinuxLoader.efi` produces bit-for-bit identical output to their C `tools/patch_abl` binary.

## What's different from `next`

`next` spoofs the full lock-state chain so Android sees a locked+verified device even when the bootloader is unlocked. This variant keeps all of that and adds three further patches:

- `androidboot.verifiedbootstate` is forced to `orange` via an override at the cmdline helper site (Patch 7). Third-party recoveries (TWRP, OrangeFox) can then decrypt data and boot cleanly instead of bailing on the state-vs-signing mismatch that `next`'s `green` produces.
- `androidboot.veritymode` is rewritten to `logging` instead of `enforcing`. dm-verity errors on modified `system`/`vendor`/`product` partitions become non-fatal, so you can actually modify those partitions.
- `fastboot flash` / `erase` is allowed even while the bootloader reports itself as locked (upstream's "… is not allowed in Lock State" jump NOPs).

TEE attestation is unaffected. TEE sees the spoofed locked state through `next`'s bootstate source/sink patches, which pin the internal lock booleans that the ABL→TEE handoff reads — a path entirely separate from the kernel cmdline this variant modifies. STRONG Play Integrity and Widevine L1 are preserved **provided your kernel rewrites `androidboot.verifiedbootstate=green` and `androidboot.veritymode=enforcing` back before init consumes them**. That kernel-side spoof is standard fare for any Susfs-capable kernel.

If you don't have a kernel that does this, stay on `next` — it reports green/enforcing directly from ABL and works without kernel cooperation.

## Prerequisites

- An unlocked bootloader
- Stock `abl.img` from your device
- A kernel that spoofs `androidboot.verifiedbootstate=green` and `androidboot.veritymode=enforcing` in its cmdline rewrite pass

## Usage

Same as `next`:

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

If something goes wrong, revert with `fastboot erase efisp`.

## What the patcher does

1. Replaces the `efisp` reference with `nulls` so the patched GBL doesn't recursively load itself
2. Rewrites `androidboot.vbmeta.device_state` to always report `locked`
3. NOPs direct jumps to the "… is not allowed in Lock State" error strings, so `fastboot flash` / `erase` works without unlock
4. Patches the boot-state check sequence
5. Hardcodes the lock-state read to 1 via backward data-flow tracing
6. Zeros out the lock-state write via forward taint tracking
7. Overrides the `verifiedbootstate=` cmdline helper to always index `orange` (leaves internal `boot_state` untouched, so TEE still sees locked)
8. Retargets `androidboot.veritymode` loads (both the cmdline ADRP+ADD and the verity-setup pointer table) to `logging`
9. Rewrites the orange-warning guard CBZ as an unconditional B, skipping the screen + 5-second countdown

## Credits

- [Qualcomm GBL Exploit PoC](https://github.com/kasnria001/qualcomm_gbl_exploit_poc)
- [Original C implementation](https://github.com/superturtlee/gbl_root_canoe)
- [1vivy's fork](https://github.com/1vivy/gbl_root_canoe) — source of the orange/logging patches
- [fggdc's fork](https://github.com/fggdc/gbl_root_canoe_abl_701)

## License

[GPLv3](LICENSE)
