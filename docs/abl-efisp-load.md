# When ABL loads `efisp`

Notes from reverse-engineering OnePlus `LinuxLoader.efi` extracted from a OnePlus 15 ABL build `16.0.5.700`. File offsets below are into the extracted PE; base is 0. `16.0.3.503` has the same code layout.

## TL;DR

`LinuxLoaderEntry` looks for a GPT partition named `efisp`, reads its entire contents into a pool allocation, and calls `LoadImage`/`StartImage` on the buffer **without any signature or hash check**. Since Qualcomm's GPT on these devices ships an `efisp` partition and Android never writes to it during normal use, anyone with `fastboot flash efisp <blob>` can hand ABL an arbitrary EFI binary to run with full ABL privileges, extremely early in boot.

## Call sequence

All inside the single function `LinuxLoaderEntry` at **0x4E50** (identified by the log string "LinuxLoaderEntry Address: 0x%llx" it prints during init).

1. **Early init (0x4E50 – ~0x5094)**
   - "Loader Build Info: Feb 12 2026 …"
   - Thread stack setup, PRNG / stack canary
   - Locate a handful of EFI protocols
   - Filesystem and partition-table init

2. **Find the `efisp` partition (0x5600 – 0x5688)**
   ```
   0x5600: adrp x0, L"efisp"             ; UTF-16 string at 0x6F248
   0x560C: bl   StrLen
   0x5644: bl   StrnCpyS                 ; copies "efisp" into sp+0x5e8
   0x5688: bl   0x17B88                  ; wraps BootServices->LocateHandleBuffer
                                         ; (ByProtocol, BlockIoGuid, ..., &Count, &Handles)
                                         ; filtered by partition name — expects Count == 1
   ```

3. **Read the raw partition bytes (0x56A0 – 0x56D0)**
   ```
   0x56A4: bl 0x21558                    ; get partition size
   0x56B8: bl 0x3BA4                     ; AllocatePool(size)
   0x56CC: bl 0x18298                    ; ReadBlocks(handle, buf, size)
   ```
   Failure at any step falls through to normal boot after logging one of:
   - `EFISP: GetBlkIOHandles failed loading GBL: %r`
   - `EFISP: GBL partition buffer allocation failure`
   - `EFISP: GBL partition buffer loading failed`

4. **`LoadImage` on the raw buffer (0x5AA8 – 0x5B00)** — the actual exploit:
   ```
   ldr x9, [BootServices + 0xC8]         ; &LoadImage
   blr x9                                ; LoadImage(BootPolicy=FALSE, ParentImage,
                                         ;           DevicePath=NULL,
                                         ;           SourceBuffer=efisp_buf,
                                         ;           SourceSize=size,
                                         ;           &ImageHandle)
   ```
   `BootPolicy=FALSE` and `DevicePath=NULL` mean the EFI DXE does a plain PE parse on the supplied buffer and builds an image handle — **no `AuthenticatedImage` check, no AVB, no hash**.

5. **`StartImage` (0x6538 – 0x6564)**
   ```
   Print "Starting GBL app\n"
   ldr x8, [BootServices + 0xD0]         ; &StartImage
   blr x8                                ; StartImage(ImageHandle, NULL, NULL)
   ```
   Control transfers into whatever was in `efisp`. If `StartImage` ever returns, ABL branches to 0x57D4 and continues normal boot.

## Position in the overall boot flow

`efisp` is loaded **before**:
- Any AVB work (`LoadImageAndAuthVB2` is called later, from the child's own `LinuxLoaderEntry`)
- The BCB / boot-mode decision (recovery / normal / fastbootd)
- Kernel image load
- All the cmdline-building logic the patcher targets

and **after**:
- Basic EFI init (protocols located, filesystem ready, partition table parsed)

So once our patched image is running via `StartImage`, it is inside ABL's environment, with full access to ABL's data, but everything interesting from a boot-mode / AVB / cmdline perspective is still to come — in its own copy of `LinuxLoaderEntry`.

## Why `efisp` → `nulls`

The patched image we flash to `efisp` is a patched copy of `LinuxLoader.efi`. When it runs via `StartImage`, its own `LinuxLoaderEntry` would otherwise repeat step 2 above, `LocateHandleBuffer` would succeed again on the same partition, and we'd `LoadImage`/`StartImage` ourselves recursively.

To break the loop, the patcher rewrites the UTF-16 constant `L"efisp"` (at 0x6F248 in the PE) to `L"nulls"`. The child's `LocateHandleBuffer` call looks for a partition named `nulls`, finds nothing, takes the error branch, and continues into the normal boot flow below 0x55E8.
