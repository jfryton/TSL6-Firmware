# TSL6 Community Firmware Modifications & Binary Patcher

This document specifies the verified binary modifications for the archived **TSL6** runtime firmware (`WCH CH32V208`, RISC-V `RV32IMAC`) and documents the modular patching toolkit (`tools/firmware_patcher.py` and `analysis/patch_catalog.json`).

---

## 1. Image Geometry & Address Mapping

| Property | Value |
|---|---|
| Transport image (`latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin`) | `73,872` bytes (`72` pages × `1,026` bytes) |
| Transport SHA-256 (stock) | `b1b2a3aa5e71d88336719bccb5da822faffc05acf50b5b482e570f1981dabbd5` |
| Stripped payload (`work/runtime.payload.bin`) | `73,728` bytes (`72` pages × `1,024` bytes, `0x00000..0x11FFF`) |
| Payload SHA-256 (stock) | `7adcb4622f017714a4896060522ce0076e8f0ff94511845d1b9d15b49dd677fd` |
| Linked code base | `0x00008000` (`linked_addr = 0x00008000 + payload_offset`) |
| Flash alias base | `0x08008000` (`flash_addr = 0x08008000 + payload_offset`) |
| Transport offset formula | `page = payload_offset // 1024`<br>`intra = payload_offset % 1024`<br>`transport_offset = page * 1026 + 2 + intra` |
| Per-page checksum (`checksum16`) | `sum(transport_page_bytes[0..1025]) & 0xFFFF` |

---

## 2. Mandatory Boot & Runtime Safety Invariants

`tools/firmware_patcher.py` enforces the following invariants before and after applying any patch:

1. **Reset Vector Jump (`0x0000`)**:
   - Payload offset `0x0000` must remain `6f f0 b0 09` (`j 0xf89a`).
   - `TSL-BOOT` (`boot.payload.bin` @ `0x002642`) checks `*(uint8_t*)0x08008000 == 0x6F` before jumping into the runtime slot.
2. **Startup Boot-Flag Clear Sequence (`0x001E6A..0x001E78`)**:
   - Payload offset `0x001E6A` must remain `c1 47 a3 04 f1 00 28 00 23 06 01 00 31 3f` (`c.li a5, 0x10; sb a5, 9(sp); c.addi4spn a0, sp, 8; sb zero, 0xc(sp); c.jal 0x1d92`).
   - During startup (`0x001E48`), this sequence clears the boot/upgrade request flag at `0x08077B04` (`0xc(sp)`). Preserving it guarantees the module exits `TSL-BOOT` cleanly after flashing.
3. **2-Byte Big-Endian Page Headers (`0..71`)**:
   - Every 1,026-byte transport page starts with `struct.pack(">H", page_index)`. All patches are applied to the unwrapped 73,728-byte payload and re-wrapped into 72 transport pages with freshly computed 16-bit page checksums.

---

## 3. Verified Binary Modifications

### Mod 1A: `ignore_server_deauth_0xae` — Ignore Remote Deauthorization (`0xAE`)

- **Context**:
  In `work/runtime.payload.bin`, the `0xA0` sub-command dispatcher at `0x00BCC8..0x00BDCA` handles `0xAD` (`0x00BD54`), `0xAE` (`0x00BD8A`), and `0xA8` (`0x00BDC0`), while `0xAF` is dispatched at `0x00BE16 -> 0x00C7F8`.
  When the legacy WeChat Mini Program receives `state: 1` from `iffrc.com`, it sends `0xAE` with the 14-byte UID.
- **Disassembly (`0x00BD8A..0x00BDC0`)**:
  ```text
  0x00bd8a: 93f5f60f andi     a1, a3, 0xff
  0x00bd8e: 3285     c.mv     a0, a2
  0x00bd90: ef504fd4 jal      -0xaabc   ; -> 0x0012d4 (validate 14-byte UID)
  0x00bd94: 1df1     c.bnez   a0, -0xda ; -> 0x00bcba (exit on UID mismatch)
  0x00bd96: 17050000 auipc    a0, 0
  0x00bd9a: 130525e1 addi     a0, a0, -0x1ee
  0x00bd9e: ef508faf jal      -0xad08   ; -> 0x001096
  0x00bda2: ef404fc0 jal      -0xbbfc   ; -> 0x0001a6 (load 0xd3(gp) auth flag)
  0x00bda6: 11c5     c.beqz   a0, 0xc   ; -> 0x00bdb2  <-- PATCH SITE
  0x00bda8: 0145     c.li     a0, 0
  0x00bdaa: ef60cf87 jal      -0x9f84   ; -> 0x001e26 (writes 0x0000 to flash 0x08077B02!)
  0x00bdae: efa08f94 jal      -0x5eb8   ; -> 0x005ef6 (arms 1000 ms deauth timer)
  0x00bdb2: 0546     c.li     a2, 1
  0x00bdb4: 9305e00a addi     a1, zero, 0xae
  0x00bdb8: 4a85     c.mv     a0, s2
  0x00bdba: eff0dfdc jal      -0x234    ; -> 0x00bb86 (send 0xAE [0x01] ACK)
  0x00bdbe: f5bd     c.j      -0x104    ; -> 0x00bcba
  ```
- **Patch Specification**:
  - **Payload offset**: `0x00BDA6` (linked `0x00013DA6`, flash `0x08013DA6`, page `47`, intra-page `0x1A6`, transport offset `0xBE06`)
  - **Before**: `11 c5` (`c.beqz a0, 0xc ; -> 0x00bdb2`)
  - **After**: `31 a0` (`c.j 0xc ; -> 0x00bdb2`)
  - **Effect**: Unconditionally branches to `0x00BDB2`, skipping `0x1E26(0)` (flash token wipe) and `0x5EF6` (lockout timer) while still returning the `0xAE [0x01]` ACK frame.

### Mod 1B: `bypass_auth_check_0x1380` — Always Set Local Authorization Flag (`0xd3(gp) = 1`)

- **Context**:
  `gp+0xd3` has a single write site (`0x001384: sb a0, 0xd3(gp)` inside `0x001360`) and a single read site (`0x0001A6: lbu a0, 0xd3(gp)`). At boot (`0x001E78`), `0x001360` reads the 16-bit token at `0x08077B02` via `0x001DBA`, compares it with the CRC-16 token from `0x001316` (seed `0x5AA5`, polynomial `0x1021`), and executes `seqz a0, a0` at `0x001380`.
- **Disassembly (`0x001360..0x00138A`)**:
  ```text
  0x001360: 4111     c.addi   sp, -0x10
  0x001362: 22c4     c.swsp   s0, 8(sp)
  0x001364: 06c6     c.swsp   ra, 0xc(sp)
  0x001366: ef0045a5 jal      0xa54     ; -> 0x001dba
  0x00136a: 02c0     c.swsp   a0, 0(sp)
  0x00136c: 03542100 lhu      s0, 2(sp) ; stored 16-bit token from 0x08077B02
  0x001370: 293f     c.jal    -0x5a     ; -> 0x001316 (compute expected token)
  0x001372: 198c     c.sub    s0, a0
  0x001374: 0204     c.slli   s0, 0x10
  0x001376: 2285     c.mv     a0, s0
  0x001378: b240     c.lwsp   ra, 0xc(sp)
  0x00137a: 2244     c.lwsp   s0, 8(sp)
  0x00137c: 4101     c.addi   sp, 0x10
  0x00137e: 4181     c.srli   a0, 0x10
  0x001380: 13351500 seqz     a0, a0    <-- PATCH SITE
  0x001384: a389a10c sb       a0, 0xd3(gp)
  0x001388: 8280     c.jr     ra
  ```
- **Patch Specification**:
  - **Payload offset**: `0x001380` (linked `0x00009380`, flash `0x08009380`, page `4`, intra-page `0x380`, transport offset `0x138A`)
  - **Before**: `13 35 15 00` (`seqz a0, a0`)
  - **After**: `13 05 10 00` (`addi a0, zero, 1`)
  - **Effect**: Forces `0xd3(gp) = 1` on boot without writing to flash, even if `0x08077B02` was previously wiped by `0xAE`.

---

### Mod 2A: `enable_0xa6_disable_cmd` — Make `0xA6 00` Cleanly Disable Both AP Auto-Restore & Media Scheduler

- **Context**:
  When `0xA6` (`0x00BFB4`) receives payload byte `0x00`, `0x00BFB8` branches to `0x00C522`. In stock firmware, `0x00C522` calls `0x0025F6` (which clears the `0x2000BEF1` AP/FSD auto-restore flag) and then at `0x00C526` jumps to `0x00BCBA`, leaving the `0x00E4E4` autonomous media pulse scheduler (`0x18c(gp)`) active.
  Immediately preceding `0x00C522` is the `0xA1` handler at `0x00C510`, which reads `0(s0)`, sets `a1 = 1`, and calls `0x00E4E4(a0, 1)`. Because `s0` is callee-saved and untouched by `0x0025F6`, `0(s0)` is still `0` when `0x0025F6` returns to `0x00C526`.
- **Disassembly (`0x00BFB4..0x00BFC0` and `0x00C510..0x00C528`)**:
  ```text
  0x00bfb4: 83470400 lbu      a5, 0(s0)
  0x00bfb8: 63850756 beqz     a5, 0x56a   ; -> 0x00c522
  0x00bfbc: ef604fdf jal      -0x9a0c     ; -> 0x0025b0
  0x00bfc0: edb9     c.j      -0x306      ; -> 0x00bcba
  ...
  0x00c510: 03450400 lbu      a0, 0(s0)
  0x00c514: 8545     c.li     a1, 1
  0x00c516: 3335a000 snez     a0, a0
  0x00c51a: ef10b07c jal      0x1fca      ; -> 0x00e4e4
  0x00c51e: 6ff0cff9 j        -0x864      ; -> 0x00bcba
  0x00c522: ef604f8d jal      -0x9f2c     ; -> 0x0025f6
  0x00c526: 6ff04ff9 j        -0x86c      ; -> 0x00bcba  <-- PATCH SITE
  ```
- **Patch Specification**:
  - **Payload offset**: `0x00C526` (linked `0x00014526`, flash `0x08014526`, page `49`, intra-page `0x126`, transport offset `0xC58A`)
  - **Before**: `6f f0 4f f9` (`j -0x86c ; -> 0x00bcba`)
  - **After**: `6f f0 bf fe` (`j -0x16 ; -> 0x00c510`)
  - **Effect**: `0xA6 00` clears `0x2000BEF1` via `0x0025F6` and then chains into `0x00C510 -> 0x00E4E4(0, 1)` to stop the media pulse scheduler (`0x18c(gp) = 0`), cancel timers 1 and 4, and persist the disabled state via `0x001774`.

### Mod 2B: Media Pulse Timing & Hold Presets (`0x00E3E6`)

- **Disassembly (`0x00E41E..0x00E470`)**:
  ```text
  0x00e41e: 8547     c.li     a5, 1
  0x00e420: 63ea8706 bltu     a5, s0, 0x74   ; -> 0x00e494 (presets 2 and 3)
  0x00e424: 9307903e addi     a5, zero, 0x3e9 ; 1001 ms jitter modulus (0..1000 ms) <-- PATCH SITE
  0x00e428: 3375f502 remu     a0, a0, a5
  0x00e42c: 1304007d addi     s0, zero, 0x7d0 ; 2000 ms base interval (2.0 s)       <-- PATCH SITE
  0x00e430: 9c40     c.lw     a5, 0(s1)
  0x00e432: 83c74700 lbu      a5, 4(a5)
  0x00e436: 858b     c.andi   a5, 1          ; settings[4] bit 0 = timingVariation
  0x00e438: 91c3     c.beqz   a5, 4          ; -> 0x00e43c
  0x00e43a: 2a94     c.add    s0, a0
  0x00e43c: 1306803e addi     a2, zero, 0x3e8 ; 1000
  ...
  0x00e44c: 3304c402 mul      s0, s0, a2     ; s0 * 1000
  0x00e450: 13061027 addi     a2, zero, 0x271 ; 625 us per BLE OS tick
  0x00e454: 3356c402 divu     a2, s0, a2     ; ticks = (ms * 1000) / 625
  0x00e458: 8297     c.jalr   a5             ; arm timer 1
  ...
  0x00e468: 13060005 addi     a2, zero, 0x50 ; 80 ticks * 0.625 ms = 50 ms         <-- PATCH SITE
  0x00e46c: 9145     c.li     a1, 4          ; timer 4
  0x00e46e: 4101     c.addi   sp, 0x10
  0x00e470: 0283     c.jr     t1
  ```
- **Verified Timing Presets**:
  1. `pulse_timing_fast_1500ms` (conflict group `pulse_interval_preset`):
     - `0x00E424` (transport `0xE498`): `9307903e` (`addi a5, zero, 0x3e9`) -> `9307501f` (`addi a5, zero, 0x1f5`, `0..500` ms jitter)
     - `0x00E42C` (transport `0xE4A0`): `1304007d` (`addi s0, zero, 0x7d0`) -> `1304c05d` (`addi s0, zero, 0x5dc`, `1500` ms base)
  2. `pulse_timing_gentle_1000ms` (conflict group `pulse_interval_preset`):
     - `0x00E424` (transport `0xE498`): `9307903e` (`addi a5, zero, 0x3e9`) -> `9307b00f` (`addi a5, zero, 0xfb`, `0..250` ms jitter)
     - `0x00E42C` (transport `0xE4A0`): `1304007d` (`addi s0, zero, 0x7d0`) -> `1304803e` (`addi s0, zero, 0x3e8`, `1000` ms base)
  3. `pulse_hold_short_25ms`:
     - `0x00E468` (transport `0xE4DC`): `13060005` (`addi a2, zero, 0x50`, 80 ticks / 50 ms) -> `13068002` (`addi a2, zero, 0x28`, 40 ticks / 25 ms)

---

### Mod 3: `custom_fw_version_tag` — Custom `0xA0` Firmware Version Tag

- **Context**:
  Although the upstream server metadata labeled the archived runtime `fw_ver_new = 5376` (`0x1500` = `V1.5.00`), the binary's startup flash initializer (`0x001E5A` / `0x001E6A`) writes `0x10` (`V1.0.00`) to `0x08077B01`. When building the 76-byte `0xA0` status response in `0x00AF6C`, `0x00AFB6` loads that byte via `lbu a5, 0xd(sp)` and stores it into `status[2]` at `0x00AFC4: sb a5, 0x16(sp)`.
- **Disassembly (`0x00AFA8..0x00AFC8`)**:
  ```text
  0x00afa8: 8347c100 lbu      a5, 0xc(sp)    ; bootVersion from 0x08077B00
  0x00afac: 4169     c.lui    a3, 0x1a
  0x00afae: 230a0100 sb       zero, 0x14(sp) ; status[0] = 0x00
  0x00afb2: a30af100 sb       a5, 0x15(sp)   ; status[1] = bootVersion
  0x00afb6: 8347d100 lbu      a5, 0xd(sp)    ; <-- PATCH SITE (loads runtimeVersion)
  0x00afba: 979aff1f auipc    s5, 0x1fff9
  0x00afbe: 938a6a7f addi     s5, s5, 0x7f6
  0x00afc2: c169     c.lui    s3, 0x10
  0x00afc4: 230bf100 sb       a5, 0x16(sp)   ; status[2] = firmwareVersion
  ```
- **Patch Specification**:
  - **Payload offset**: `0x00AFB6` (linked `0x00012FB6`, flash `0x08012FB6`, page `43`, intra-page `0x3B6`, transport offset `0xB00E`)
  - **Before**: `83 47 d1 00` (`lbu a5, 0xd(sp)`)
  - **After (`--fw-version 0x16`, default `V1.6.00`)**: `93 07 60 01` (`addi a5, zero, 0x16`)
  - **After (`--fw-version 0x15`, `V1.5.00`)**: `93 07 50 01` (`addi a5, zero, 0x15`)
  - **Effect**: Directly populates `status[2]` with the chosen version byte (`0x01..0x7F`) without modifying `0x001E48` or causing an extra flash erase/write to `0x08077B00` on boot.

---

## 4. CLI Usage Examples

### Inspect a Stock or Patched Binary
```bash
python3 tools/firmware_patcher.py inspect latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin
```

### List All Available Patches
```bash
python3 tools/firmware_patcher.py list-patches
```

### Build a Community Patched `runtime.bin` (Ready for `TSL-Cmd` / `TSL-BOOT` Flashing)
```bash
python3 tools/firmware_patcher.py patch \
  --in latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin \
  --out work/runtime.community-v16.bin \
  --enable ignore_server_deauth_0xae,bypass_auth_check_0x1380,enable_0xa6_disable_cmd,custom_fw_version_tag \
  --fw-version 0x16 \
  --manifest-out work/runtime.community-v16.manifest.json
```

### Export the Machine-Readable Patch Catalog
```bash
python3 tools/firmware_patcher.py export-catalog --out analysis/patch_catalog.json
```

### Run the Unit & Disassembly Verification Test Suite
```bash
python3 -m unittest discover -s tools -p "test_*.py" -v
```
