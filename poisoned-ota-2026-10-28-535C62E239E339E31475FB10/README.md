# Poisoned OTA Payload Archive (`2026-10-28` · Module `535C62E239E339E31475FB10`)

## Summary

On `2026-10-28`, querying the official WeChat Mini Program backend (`https://www.iffrc.com/ffkj/user/ble.php`) for module `535C62E239E339E31475FB10` revealed that the server is serving a **67-page UTF-8 Chinese text copy of the WCH CH32V208 datasheet** (`" CH32V208 数据手册 V2.6..."`) disguised as a valid OTA firmware package for both `isapp=1` (runtime) and `isapp=0` (bootloader).

Because every 1,026-byte transport page has a valid 2-byte big-endian page index (`0x0000..0x0042`) and a matching 16-bit checksum in `CheckCode`, the official WeChat Mini Program passes all download checks and flashes the datasheet text into the module's runtime flash slot (`0x08008000`).

When the bootloader (`TSL-BOOT`, `boot.payload.bin`) finishes the update (`0x45`) and attempts to boot `0x08008000`:
- At `0x00263c..0x00264c`, the bootloader checks `*(uint8_t*)0x08077B04 != 2` and verifies that the first byte at `0x08008000` is `0x6F` (the RISC-V `j` / `jal` opcode).
- Because byte 0 of the flashed datasheet payload is `0x20` (ASCII space `' '`), the bootloader refuses to jump to runtime and remains stuck advertising as `TSL-BOOT`.

## Forensic Evidence of Intentional Server-Side Poisoning

1. **Spoofed `fw_ver_new: 16640` (`0x4100` / `V4.1.00`) in `fun=getinfo`**:
   - `getinfo.json` returns:
     ```json
     {
       "hw_ver": 6,
       "name": "TSL6代模块",
       "bt_ver": 0,
       "bt_ver_new": 4096,
       "fw_ver": 16640,
       "fw_ver_new": 16640,
       "auth_time": "2025-03-25 14:40:33",
       "state": 1,
       "msgId": 0,
       "msg": ""
     }
     ```
   - Whereas the genuine TSL6 runtime version is `5376` (`0x1500` / `V1.5.00`), the server reports `fw_ver_new = 16640` (`0x4100` / `V4.1.00`), forcing the WeChat Mini Program to prompt the user to upgrade whenever a real `V1.5.00` (or `V0.0.00` bootloader) module connects.
2. **Identical Payload for Both `isapp=1` (Runtime) and `isapp=0` (Bootloader)**:
   - Both `fun=update&isapp=1` and `fun=update&isapp=0` return the exact same 67-page (`68,742`-byte) transport stream (`SHA-256: e5946fe50422653e2bc70efdf2592e2e5e6f71b94fb65a315ca9c92bdc28df83`).
3. **Packaged Specifically With the Vendor's OTA Framing Tool**:
   - The payload is not random corruption or an HTTP error page; it is the plain-text extraction of the **WCH CH32V208 datasheet (`V2.6`)**—the exact RISC-V MCU used inside the TSL6 module—padded with `0xFF` on the final page (`page 66`) to 1,024 bytes, prefixed with 2-byte big-endian page numbers `0x0000..0x0042`, and accompanied by precomputed 16-bit `CheckCode` page sums.
   - Unregistered module IDs (e.g. `...FB11`) receive `{"success": false, "data": "", "msg": "固件下载失败\r\n\r\n设备未授权"}`, confirming that this decoy/poisoned package is specifically served to authorized/flagged module records.

## Archived Artifacts

- `archive.manifest.json` — Top-level metadata and SHA-256 digests.
- `getinfo.json` — Raw `fun=getinfo` response for `535C62E239E339E31475FB10`.
- `runtime-isapp1/`
  - `raw_chunks.json` — Exact JSON response from `fun=update&isapp=1`.
  - `runtime-isapp1.transport.bin` — Reassembled 67-page transport binary (`68,742` bytes, `1,026` bytes/page; SHA-256 `e5946fe50422653e2bc70efdf2592e2e5e6f71b94fb65a315ca9c92bdc28df83`).
  - `runtime-isapp1.payload.bin` — Stripped flash payload (`68,608` bytes, `1,024` bytes/page with trailing `0xFF` padding; SHA-256 `bc13a7bfb46d62328c8047d8393f9a2da23943cf84705af0464157d8569f41ed`).
  - `runtime-isapp1.payload.txt` — UTF-8 text of the CH32V208 datasheet extracted from the payload.
  - `manifest.json` — Package metadata and hashes.
- `boot-isapp0/`
  - `raw_chunks.json` — Exact JSON response from `fun=update&isapp=0`.
  - `boot-isapp0.transport.bin` — Reassembled 67-page transport binary (`68,742` bytes).
  - `boot-isapp0.payload.bin` — Stripped flash payload (`68,608` bytes).
  - `boot-isapp0.payload.txt` — UTF-8 text of the CH32V208 datasheet.
  - `manifest.json` — Package metadata and hashes.
