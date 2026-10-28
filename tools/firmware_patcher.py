#!/usr/bin/env python3
"""Modular binary patcher and verifier for the archived TSL6 CH32V208 runtime firmware.

Supports both:
  - Transport-wrapped images (`runtime.bin`, 73,872 bytes = 72 pages * 1,026 bytes,
    where each page starts with a 2-byte big-endian page index 0..71 followed by
    1,024 payload bytes).
  - Stripped contiguous payload images (`work/runtime.payload.bin`, 73,728 bytes =
    72 * 1,024 bytes, linked at 0x00008000 / flash alias 0x08008000).

Usage:
  python3 tools/firmware_patcher.py inspect <bin> [--json]
  python3 tools/firmware_patcher.py list-patches [--json]
  python3 tools/firmware_patcher.py patch --in <runtime.bin> --out <patched.bin> \\
      --enable <patch_id,...> [--fw-version 0x16]
  python3 tools/firmware_patcher.py export-catalog --out analysis/patch_catalog.json
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PAGE_COUNT = 72
PAYLOAD_PAGE_SIZE = 1024
TRANSPORT_HEADER_SIZE = 2
TRANSPORT_PAGE_SIZE = TRANSPORT_HEADER_SIZE + PAYLOAD_PAGE_SIZE  # 1026
PAYLOAD_TOTAL_BYTES = PAGE_COUNT * PAYLOAD_PAGE_SIZE  # 73,728 (0x12000)
TRANSPORT_TOTAL_BYTES = PAGE_COUNT * TRANSPORT_PAGE_SIZE  # 73,872

LINKED_CODE_BASE = 0x00008000
FLASH_ALIAS_BASE = 0x08008000

STOCK_TRANSPORT_SHA256 = "b1b2a3aa5e71d88336719bccb5da822faffc05acf50b5b482e570f1981dabbd5"
STOCK_PAYLOAD_SHA256 = "7adcb4622f017714a4896060522ce0076e8f0ff94511845d1b9d15b49dd677fd"

# Safety invariants on the contiguous payload image:
# 1. Reset vector at 0x0000: `j 0xf89a` (6f f0 b0 09). TSL-BOOT checks byte 0 == 0x6F.
RESET_VECTOR_OFFSET = 0x0000
RESET_VECTOR_EXPECTED = bytes.fromhex("6ff0b009")

# 2. Startup boot-flag clear sequence at 0x1E6A..0x1E78:
#    0x001e6a: c147     c.li       a5, 0x10
#    0x001e6c: a304f100 sb         a5, 9(sp)
#    0x001e70: 2800     c.addi4spn a0, sp, 8
#    0x001e72: 23060100 sb         zero, 0xc(sp)   ; clears 0x08077B04 boot flag
#    0x001e76: 313f     c.jal      -0xe4           ; -> 0x001d92 (flash write)
BOOT_FLAG_CLEAR_OFFSET = 0x001E6A
BOOT_FLAG_CLEAR_EXPECTED = bytes.fromhex("c147a304f100280023060100313f")

DEFAULT_CUSTOM_FW_VERSION = 0x16


class PatchVerificationError(ValueError):
    """Raised when an input image or patch site fails binary verification."""


def payload_to_transport_offset(payload_offset: int) -> int:
    if not (0 <= payload_offset < PAYLOAD_TOTAL_BYTES):
        raise ValueError(f"Payload offset {payload_offset:#x} out of range [0, {PAYLOAD_TOTAL_BYTES:#x})")
    page_index = payload_offset // PAYLOAD_PAGE_SIZE
    intra_page = payload_offset % PAYLOAD_PAGE_SIZE
    return page_index * TRANSPORT_PAGE_SIZE + TRANSPORT_HEADER_SIZE + intra_page


def encode_rv32i_addi(rd: int, rs1: int, imm12: int) -> bytes:
    """Encode RV32I `addi rd, rs1, imm12` (opcode 0x13, funct3 0x0)."""
    if not (0 <= rd < 32 and 0 <= rs1 < 32):
        raise ValueError("Invalid RV32I register index")
    if not (-2048 <= imm12 <= 2047):
        raise ValueError(f"Immediate {imm12} out of signed 12-bit range [-2048, 2047]")
    word = ((imm12 & 0xFFF) << 20) | ((rs1 & 0x1F) << 15) | ((rd & 0x1F) << 7) | 0x13
    return struct.pack("<I", word)


def decode_rv32i_addi_zero_a5(raw: bytes) -> Optional[int]:
    """If `raw` is `addi a5, zero, imm12` (4 bytes), return unsigned/signed imm12."""
    if len(raw) != 4:
        return None
    word = struct.unpack("<I", raw)[0]
    if (word & 0x000FFFFF) != ((0 << 15) | (0 << 12) | (15 << 7) | 0x13):
        return None
    imm = (word >> 20) & 0xFFF
    if imm & 0x800:
        imm -= 0x1000
    return imm


def format_fw_version_label(ver_byte: int) -> str:
    major = (ver_byte >> 4) & 0x0F
    minor = ver_byte & 0x0F
    return f"V{major}.{minor}.00"


@dataclasses.dataclass(frozen=True)
class PatchSite:
    payload_offset: int
    orig_bytes: bytes
    patched_bytes: bytes
    orig_asm: str
    patched_asm: str
    description: str

    @property
    def size(self) -> int:
        return len(self.orig_bytes)

    @property
    def linked_address(self) -> int:
        return LINKED_CODE_BASE + self.payload_offset

    @property
    def flash_address(self) -> int:
        return FLASH_ALIAS_BASE + self.payload_offset

    @property
    def page_index(self) -> int:
        return self.payload_offset // PAYLOAD_PAGE_SIZE

    @property
    def intra_page_offset(self) -> int:
        return self.payload_offset % PAYLOAD_PAGE_SIZE

    @property
    def transport_offset(self) -> int:
        return payload_to_transport_offset(self.payload_offset)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_offset": f"{self.payload_offset:#06x}",
            "payload_offset_int": self.payload_offset,
            "linked_address": f"{self.linked_address:#010x}",
            "flash_address": f"{self.flash_address:#010x}",
            "page_index": self.page_index,
            "intra_page_offset": f"{self.intra_page_offset:#05x}",
            "transport_offset": f"{self.transport_offset:#06x}",
            "transport_offset_int": self.transport_offset,
            "size": self.size,
            "orig_hex": self.orig_bytes.hex(),
            "patched_hex": self.patched_bytes.hex(),
            "orig_asm": self.orig_asm,
            "patched_asm": self.patched_asm,
            "description": self.description,
        }


@dataclasses.dataclass(frozen=True)
class PatchSpec:
    patch_id: str
    category: str
    title: str
    summary: str
    function_context: str
    rationale: str
    sites: Tuple[PatchSite, ...]
    conflict_group: Optional[str] = None
    parameter_name: Optional[str] = None
    default_parameter_value: Optional[str] = None
    safety_notes: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "category": self.category,
            "title": self.title,
            "summary": self.summary,
            "function_context": self.function_context,
            "rationale": self.rationale,
            "conflict_group": self.conflict_group,
            "parameter_name": self.parameter_name,
            "default_parameter_value": self.default_parameter_value,
            "safety_notes": list(self.safety_notes),
            "sites": [s.to_dict() for s in self.sites],
        }


def build_patch_spec(patch_id: str, fw_version: int = DEFAULT_CUSTOM_FW_VERSION) -> PatchSpec:
    """Build a PatchSpec by ID, applying any user-supplied parameter (e.g., fw_version)."""
    if not (0x01 <= fw_version <= 0x7F):
        raise ValueError(f"fw_version must be in range 0x01..0x7F, got {fw_version:#x}")

    if patch_id == "ignore_server_deauth_0xae":
        return PatchSpec(
            patch_id="ignore_server_deauth_0xae",
            category="authorization",
            title="Ignore Remote Deauthorization Command (0xAE)",
            summary=(
                "Prevents BLE command 0xAE from wiping the persistent 16-bit activation token "
                "at flash 0x08077B02 or scheduling the 1000 ms deauthorization lockout timer."
            ),
            function_context="0xAE sub-dispatcher at 0x00BD8A..0x00BDC0 (branched from 0x00BCD4)",
            rationale=(
                "When the legacy WeChat Mini Program receives state:1 from iffrc.com, it sends "
                "BLE command 0xAE with the 14-byte UID. In stock firmware, 0x00BD8A validates "
                "the UID (0x12D4), checks 0x01A6, and if authorized (a0 != 0) calls 0x1E26(0) "
                "at 0x00BDAA to overwrite flash 0x08077B02 with 0x0000 and calls 0x5EF6 at "
                "0x00BDAE to schedule deauthorization. Replacing `c.beqz a0, 0xc` (11c5) at "
                "0x00BDA6 with `c.j 0xc` (31a0) unconditionally jumps to the 0x00BDB2 ACK reply "
                "builder (`0xAE 01`), preserving flash and RAM authorization state."
            ),
            sites=(
                PatchSite(
                    payload_offset=0x00BDA6,
                    orig_bytes=bytes.fromhex("11c5"),
                    patched_bytes=bytes.fromhex("31a0"),
                    orig_asm="c.beqz a0, 0xc ; -> 0x00bdb2",
                    patched_asm="c.j 0xc ; -> 0x00bdb2",
                    description=(
                        "Unconditionally branch over `c.li a0, 0; jal 0x1e26; jal 0x5ef6` "
                        "to the 0xAE ACK reply at 0x00BDB2."
                    ),
                ),
            ),
            safety_notes=(
                "2-byte RVC in-place branch replacement; no function size or stack change.",
                "Eliminates unnecessary flash erase/write cycles on 0x08077B00 when 0xAE is received.",
                "Preserves normal 0xAE [0x01] BLE acknowledgment so legacy apps do not hang.",
            ),
        )

    if patch_id == "bypass_auth_check_0x1380":
        return PatchSpec(
            patch_id="bypass_auth_check_0x1380",
            category="authorization",
            title="Always Set Local Authorization Flag (0xd3(gp) = 1)",
            summary=(
                "Forces the flash activation-token verifier at 0x001360 to write 1 into "
                "0xd3(gp) on boot even if flash 0x08077B02 was previously erased/zeroed."
            ),
            function_context="Activation token verifier 0x001360..0x00138A (called at boot from 0x001E78)",
            rationale=(
                "Function 0x001360 reads the stored 16-bit token at 0x08077B02 via 0x1DBA, "
                "compares it against the local CRC-16 token from 0x1316 (seed 0x5AA5, poly "
                "0x1021), converts the equality result via `seqz a0, a0` at 0x001380, and writes "
                "`sb a0, 0xd3(gp)` at 0x001384. `0xd3(gp)` has only one reader (`0x0001A6: "
                "lbu a0, 0xd3(gp)`). Replacing `seqz a0, a0` (`13351500`) at 0x001380 with "
                "`addi a0, zero, 1` (`13051000`) ensures `0xd3(gp)` is always 1 without flash writes."
            ),
            sites=(
                PatchSite(
                    payload_offset=0x001380,
                    orig_bytes=bytes.fromhex("13351500"),
                    patched_bytes=bytes.fromhex("13051000"),
                    orig_asm="seqz a0, a0",
                    patched_asm="addi a0, zero, 1",
                    description="Force authorization flag a0 = 1 prior to `sb a0, 0xd3(gp)` at 0x001384.",
                ),
            ),
            safety_notes=(
                "4-byte RV32I instruction replacement; does not alter flash contents at 0x08077B00.",
                "Safe companion to `ignore_server_deauth_0xae` for modules already deauthorized in flash.",
            ),
        )

    if patch_id == "enable_0xa6_disable_cmd":
        return PatchSpec(
            patch_id="enable_0xa6_disable_cmd",
            category="scheduler",
            title="Make 0xA6 00 Cleanly Disable Media Pulse Scheduler & AP Auto-Restore",
            summary=(
                "Routes the tail of the `0xA6 00` handler (`0x00C526`) into the `0xA1` scheduler "
                "disable path (`0x00C510`) after clearing `0x2000BEF1`, so `0xA6 00` stops both "
                "AP auto-restore and the `0xE4E4` autonomous media pulse timer."
            ),
            function_context="0xA6 handler (`0x00BFB4 -> 0x00C522..0x00C529`) and 0xA1 handler (`0x00C510..0x00C521`)",
            rationale=(
                "In stock firmware, `0xA6` (`0x00BFB4`) loads `a5 = lbu 0(s0)` and branches on "
                "`a5 == 0` (`0x00BFB8`) to `0x00C522`. `0x00C522` calls `0x25F6` (which only "
                "clears the RAM flag `0x2000BEF1`) and at `0x00C526` jumps to `0x00BCBA` without "
                "stopping the `0xE4E4` media pulse scheduler (`0x18c(gp)`). Because `s0` is "
                "callee-saved and still points to the `0xA6 00` payload (`0(s0) == 0`), patching "
                "`0x00C526` from `j -0x86c` (`-> 0x00bcba`) to `j -0x16` (`-> 0x00c510`) chains "
                "`0x25F6` directly into `0x00C510` (`lbu a0, 0(s0); c.li a1, 1; snez a0, a0; "
                "jal 0x00e4e4; j 0x00bcba`), stopping timers 1 & 4 and persisting the disabled state."
            ),
            sites=(
                PatchSite(
                    payload_offset=0x00C526,
                    orig_bytes=bytes.fromhex("6ff04ff9"),
                    patched_bytes=bytes.fromhex("6ff0bffe"),
                    orig_asm="j -0x86c ; -> 0x00bcba",
                    patched_asm="j -0x16 ; -> 0x00c510",
                    description=(
                        "After `jal 0x25f6` at 0x00C522, jump to 0x00C510 to invoke `0xE4E4(0, 1)` "
                        "before exiting to 0x00BCBA."
                    ),
                ),
            ),
            safety_notes=(
                "0x00BFB8 (`beqz a5, 0x56a -> 0x00c522`) is the sole branch targeting 0x00C522.",
                "s0 is preserved across `jal 0x25f6` (`0x25F6` only touches caller-saved a0/a5/ra).",
            ),
        )

    if patch_id == "pulse_timing_fast_1500ms":
        return PatchSpec(
            patch_id="pulse_timing_fast_1500ms",
            category="scheduler",
            title="Responsive Media Pulse Timing Preset (1500 ms Base + 0..500 ms Jitter)",
            summary=(
                "Adjusts the mode 0/1 & AP/FSD (`0xF`) media pulse timing in `0x00E3E6` from "
                "2000 ms + 0..1000 ms jitter down to 1500 ms + 0..500 ms jitter."
            ),
            function_context="Media pulse timing worker `0x00E3E6` (`0x00E424..0x00E43C`)",
            rationale=(
                "In `0x00E3E6`, when `settings[3] & 0xF` is `0`, `1`, or `0xF` (AP/FSD-gated "
                "mode, mapped to `s0 = 1` at `0x00E414`), `0x00E424` loads the jitter modulus "
                "`0x3E9` (1001 ms -> 0..1000 ms) into `a5` and `0x00E42C` loads the base pulse "
                "interval `0x7D0` (2000 ms) into `s0`. Updating `0x00E424` to `0x1F5` (501 ms) "
                "and `0x00E42C` to `0x5DC` (1500 ms) provides a faster 1.5 s..2.0 s cadence."
            ),
            conflict_group="pulse_interval_preset",
            sites=(
                PatchSite(
                    payload_offset=0x00E424,
                    orig_bytes=bytes.fromhex("9307903e"),
                    patched_bytes=encode_rv32i_addi(15, 0, 501),  # 9307501f
                    orig_asm="addi a5, zero, 0x3e9",
                    patched_asm="addi a5, zero, 0x1f5",
                    description="Set random jitter modulus to 501 ms (0..500 ms) for mode 0/1/0xF.",
                ),
                PatchSite(
                    payload_offset=0x00E42C,
                    orig_bytes=bytes.fromhex("1304007d"),
                    patched_bytes=encode_rv32i_addi(8, 0, 1500),  # 1304c05d
                    orig_asm="addi s0, zero, 0x7d0",
                    patched_asm="addi s0, zero, 0x5dc",
                    description="Set base pulse interval to 1500 ms (1.5 s) for mode 0/1/0xF.",
                ),
            ),
            safety_notes=(
                "Both constants fit in standard signed 12-bit RV32I `addi` immediates.",
                "Downstream tick conversion (`(ms * 1000) / 625` at 0x00E44C..0x00E454) is unchanged.",
            ),
        )

    if patch_id == "pulse_timing_gentle_1000ms":
        return PatchSpec(
            patch_id="pulse_timing_gentle_1000ms",
            category="scheduler",
            title="Compact Media Pulse Timing Preset (1000 ms Base + 0..250 ms Jitter)",
            summary=(
                "Adjusts the mode 0/1 & AP/FSD (`0xF`) media pulse timing in `0x00E3E6` from "
                "2000 ms + 0..1000 ms jitter to 1000 ms + 0..250 ms jitter."
            ),
            function_context="Media pulse timing worker `0x00E3E6` (`0x00E424..0x00E43C`)",
            rationale=(
                "Sets the `0x00E424` jitter modulus to `0xFB` (251 ms -> 0..250 ms) and the "
                "`0x00E42C` base interval to `0x3E8` (1000 ms) for a tight 1.0 s..1.25 s window."
            ),
            conflict_group="pulse_interval_preset",
            sites=(
                PatchSite(
                    payload_offset=0x00E424,
                    orig_bytes=bytes.fromhex("9307903e"),
                    patched_bytes=encode_rv32i_addi(15, 0, 251),  # 9307b00f
                    orig_asm="addi a5, zero, 0x3e9",
                    patched_asm="addi a5, zero, 0xfb",
                    description="Set random jitter modulus to 251 ms (0..250 ms) for mode 0/1/0xF.",
                ),
                PatchSite(
                    payload_offset=0x00E42C,
                    orig_bytes=bytes.fromhex("1304007d"),
                    patched_bytes=encode_rv32i_addi(8, 0, 1000),  # 1304803e
                    orig_asm="addi s0, zero, 0x7d0",
                    patched_asm="addi s0, zero, 0x3e8",
                    description="Set base pulse interval to 1000 ms (1.0 s) for mode 0/1/0xF.",
                ),
            ),
            safety_notes=(
                "Mutually exclusive with `pulse_timing_fast_1500ms` (conflict_group: pulse_interval_preset).",
            ),
        )

    if patch_id == "pulse_hold_short_25ms":
        return PatchSpec(
            patch_id="pulse_hold_short_25ms",
            category="scheduler",
            title="Shorten Scroll-Wheel Timer-4 Followup Delay (50 ms -> 25 ms)",
            summary=(
                "Reduces the timer-4 scroll-wheel pulse followup delay at `0x00E468` from "
                "80 ticks (`0x50` = 50 ms) to 40 ticks (`0x28` = 25 ms)."
            ),
            function_context="Media pulse timing worker `0x00E3E6` tail (`0x00E464..0x00E470`)",
            rationale=(
                "At the end of `0x00E3E6`, timer 4 (`a1 = 4`) is armed with `a2 = 0x50` (80 BLE OS "
                "ticks at 0.625 ms/tick = 50 ms). Replacing `addi a2, zero, 0x50` (`13060005`) "
                "with `addi a2, zero, 0x28` (`13068002`) halves the timer-4 delay to 25 ms."
            ),
            sites=(
                PatchSite(
                    payload_offset=0x00E468,
                    orig_bytes=bytes.fromhex("13060005"),
                    patched_bytes=encode_rv32i_addi(12, 0, 0x28),  # 13068002
                    orig_asm="addi a2, zero, 0x50",
                    patched_asm="addi a2, zero, 0x28",
                    description="Arm timer 4 with 40 ticks (25 ms) instead of 80 ticks (50 ms).",
                ),
            ),
            safety_notes=(
                "Independent of `pulse_interval_preset`; can be combined with any interval preset.",
            ),
        )

    if patch_id == "custom_fw_version_tag":
        patched_word = encode_rv32i_addi(15, 0, fw_version)
        return PatchSpec(
            patch_id="custom_fw_version_tag",
            category="version",
            title=f"Custom 0xA0 Firmware Version Tag ({fw_version:#04x} / {format_fw_version_label(fw_version)})",
            summary=(
                f"Populates `status[2]` (`firmwareVersion`) in the `0xA0` status response builder "
                f"(`0x00AF6C`) with `{fw_version:#04x}` (`{format_fw_version_label(fw_version)}`) "
                f"instead of reading `{0x10:#04x}` (`V1.0.00`) from flash `0x08077B01`."
            ),
            function_context="0xA0 76-byte status response builder `0x00AF6C` (`0x00AFB2..0x00AFC8`)",
            rationale=(
                "Although the vendor cloud metadata labeled the archived runtime `fw_ver_new=5376` "
                "(`0x1500` = `V1.5.00`), the binary's startup routine at `0x001E5A`/`0x001E6A` "
                "writes `0x10` (`V1.0.00`) to `0x08077B01`, and `0x00AF6C` loads that byte via "
                "`0x00AFB6: lbu a5, 0xd(sp)` (`8347d100`) before storing `status[2]` at "
                "`0x00AFC4: sb a5, 0x16(sp)`. Replacing the 4-byte `lbu a5, 0xd(sp)` at `0x00AFB6` "
                f"with `addi a5, zero, {fw_version:#x}` (`{patched_word.hex()}`) makes `0xA0` "
                f"report `{fw_version:#04x}` (`{format_fw_version_label(fw_version)}`) without "
                "modifying `0x001E48` or triggering an extra flash erase/write to `0x08077B00` on boot."
            ),
            parameter_name="fw_version",
            default_parameter_value=f"{DEFAULT_CUSTOM_FW_VERSION:#04x}",
            sites=(
                PatchSite(
                    payload_offset=0x00AFB6,
                    orig_bytes=bytes.fromhex("8347d100"),
                    patched_bytes=patched_word,
                    orig_asm="lbu a5, 0xd(sp)",
                    patched_asm=f"addi a5, zero, {fw_version:#x}",
                    description=(
                        f"Load immediate firmware version byte {fw_version:#04x} "
                        f"({format_fw_version_label(fw_version)}) into a5 for `sb a5, 0x16(sp)`."
                    ),
                ),
            ),
            safety_notes=(
                "Leaves startup flash-init routine `0x001E48..0x001E7C` untouched, avoiding extra flash wear.",
                "Supports any version byte 0x01..0x7F (e.g., 0x15 -> V1.5.00, 0x16 -> V1.6.00).",
            ),
        )

    raise KeyError(f"Unknown patch_id: {patch_id!r}")


PATCH_IDS: Tuple[str, ...] = (
    "ignore_server_deauth_0xae",
    "bypass_auth_check_0x1380",
    "enable_0xa6_disable_cmd",
    "pulse_timing_fast_1500ms",
    "pulse_timing_gentle_1000ms",
    "pulse_hold_short_25ms",
    "custom_fw_version_tag",
)


def get_all_patch_specs(fw_version: int = DEFAULT_CUSTOM_FW_VERSION) -> List[PatchSpec]:
    return [build_patch_spec(pid, fw_version=fw_version) for pid in PATCH_IDS]


def detect_image_format(raw_bytes: bytes) -> str:
    """Return 'transport' for 73,872-byte runtime.bin or 'payload' for 73,728-byte payload."""
    if len(raw_bytes) == TRANSPORT_TOTAL_BYTES:
        return "transport"
    if len(raw_bytes) == PAYLOAD_TOTAL_BYTES:
        return "payload"
    raise PatchVerificationError(
        f"Unsupported firmware image size: {len(raw_bytes)} bytes "
        f"(expected {TRANSPORT_TOTAL_BYTES} for transport runtime.bin or "
        f"{PAYLOAD_TOTAL_BYTES} for stripped runtime.payload.bin)"
    )


def unwrap_transport_image(transport_bytes: bytes) -> bytes:
    """Validate 72 * 1,026-byte transport pages and return contiguous 73,728-byte payload."""
    if len(transport_bytes) != TRANSPORT_TOTAL_BYTES:
        raise PatchVerificationError(
            f"Transport image must be {TRANSPORT_TOTAL_BYTES} bytes, got {len(transport_bytes)}"
        )
    payload_parts: List[bytes] = []
    for page_idx in range(PAGE_COUNT):
        start = page_idx * TRANSPORT_PAGE_SIZE
        page = transport_bytes[start : start + TRANSPORT_PAGE_SIZE]
        declared_idx = (page[0] << 8) | page[1]
        if declared_idx != page_idx:
            raise PatchVerificationError(
                f"Transport page {page_idx} at offset {start:#x} has invalid 2-byte big-endian "
                f"header {declared_idx:#06x} (expected {page_idx:#06x})"
            )
        payload_parts.append(page[TRANSPORT_HEADER_SIZE:])
    return b"".join(payload_parts)


def wrap_transport_image(payload_bytes: bytes) -> bytes:
    """Wrap a 73,728-byte contiguous payload into 72 * 1,026-byte transport pages."""
    if len(payload_bytes) != PAYLOAD_TOTAL_BYTES:
        raise PatchVerificationError(
            f"Payload image must be {PAYLOAD_TOTAL_BYTES} bytes, got {len(payload_bytes)}"
        )
    pages: List[bytes] = []
    for page_idx in range(PAGE_COUNT):
        header = struct.pack(">H", page_idx)
        start = page_idx * PAYLOAD_PAGE_SIZE
        pages.append(header + payload_bytes[start : start + PAYLOAD_PAGE_SIZE])
    return b"".join(pages)


def compute_page_checksums(transport_bytes: bytes) -> List[int]:
    """Compute the 16-bit unsigned byte-sum checksum for each 1,026-byte transport page."""
    if len(transport_bytes) != TRANSPORT_TOTAL_BYTES:
        raise PatchVerificationError(
            f"Transport image must be {TRANSPORT_TOTAL_BYTES} bytes, got {len(transport_bytes)}"
        )
    checksums: List[int] = []
    for page_idx in range(PAGE_COUNT):
        start = page_idx * TRANSPORT_PAGE_SIZE
        page = transport_bytes[start : start + TRANSPORT_PAGE_SIZE]
        checksums.append(sum(page) & 0xFFFF)
    return checksums


def verify_payload_safety_invariants(payload_bytes: bytes) -> Dict[str, Any]:
    """Check mandatory boot/runtime safety invariants on a 73,728-byte payload."""
    if len(payload_bytes) != PAYLOAD_TOTAL_BYTES:
        raise PatchVerificationError(
            f"Payload length {len(payload_bytes)} != {PAYLOAD_TOTAL_BYTES}"
        )
    reset_bytes = payload_bytes[RESET_VECTOR_OFFSET : RESET_VECTOR_OFFSET + len(RESET_VECTOR_EXPECTED)]
    if reset_bytes != RESET_VECTOR_EXPECTED:
        raise PatchVerificationError(
            f"Reset vector at 0x0000 is {reset_bytes.hex()}, expected {RESET_VECTOR_EXPECTED.hex()} "
            "(`j 0xf89a`; TSL-BOOT requires byte 0 == 0x6F)"
        )
    boot_clear_bytes = payload_bytes[
        BOOT_FLAG_CLEAR_OFFSET : BOOT_FLAG_CLEAR_OFFSET + len(BOOT_FLAG_CLEAR_EXPECTED)
    ]
    if boot_clear_bytes != BOOT_FLAG_CLEAR_EXPECTED:
        raise PatchVerificationError(
            f"Startup boot-flag clear sequence at {BOOT_FLAG_CLEAR_OFFSET:#06x} was modified "
            f"({boot_clear_bytes.hex()} != {BOOT_FLAG_CLEAR_EXPECTED.hex()}); refusing image "
            "to prevent a TSL-BOOT recovery loop"
        )
    return {
        "reset_vector_ok": True,
        "reset_vector_hex": reset_bytes.hex(),
        "boot_flag_clear_ok": True,
        "boot_flag_clear_offset": f"{BOOT_FLAG_CLEAR_OFFSET:#06x}",
    }


def inspect_patch_state(payload_bytes: bytes, spec: PatchSpec) -> Dict[str, Any]:
    """Inspect whether `spec` is in stock state, applied state, or modified state."""
    site_states: List[Dict[str, Any]] = []
    all_stock = True
    all_applied = True
    detected_parameter: Optional[str] = None

    for site in spec.sites:
        cur = payload_bytes[site.payload_offset : site.payload_offset + site.size]
        is_stock = cur == site.orig_bytes
        is_applied = cur == site.patched_bytes

        if spec.patch_id == "custom_fw_version_tag" and not is_stock:
            imm = decode_rv32i_addi_zero_a5(cur)
            if imm is not None and 0x01 <= imm <= 0x7F:
                is_applied = True
                detected_parameter = f"{imm:#04x} ({format_fw_version_label(imm)})"

        all_stock = all_stock and is_stock
        all_applied = all_applied and is_applied
        site_states.append(
            {
                "payload_offset": f"{site.payload_offset:#06x}",
                "transport_offset": f"{site.transport_offset:#06x}",
                "current_hex": cur.hex(),
                "orig_hex": site.orig_bytes.hex(),
                "patched_hex": site.patched_bytes.hex(),
                "status": "stock" if is_stock else ("applied" if is_applied else "unknown"),
            }
        )

    if all_stock:
        status = "stock"
    elif all_applied:
        status = "applied"
    else:
        status = "modified"

    result: Dict[str, Any] = {
        "patch_id": spec.patch_id,
        "title": spec.title,
        "status": status,
        "sites": site_states,
    }
    if detected_parameter is not None:
        result["detected_fw_version"] = detected_parameter
    return result


def inspect_firmware_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Inspect a transport or payload firmware binary and return structured metadata."""
    fmt = detect_image_format(raw_bytes)
    if fmt == "transport":
        payload_bytes = unwrap_transport_image(raw_bytes)
        transport_bytes = raw_bytes
    else:
        payload_bytes = raw_bytes
        transport_bytes = wrap_transport_image(payload_bytes)

    invariants = verify_payload_safety_invariants(payload_bytes)
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    transport_sha256 = hashlib.sha256(transport_bytes).hexdigest()
    checksums = compute_page_checksums(transport_bytes)

    patch_states = [
        inspect_patch_state(payload_bytes, spec) for spec in get_all_patch_specs()
    ]
    applied_patches = [p["patch_id"] for p in patch_states if p["status"] == "applied"]

    return {
        "format": fmt,
        "input_bytes": len(raw_bytes),
        "page_count": PAGE_COUNT,
        "payload_bytes": len(payload_bytes),
        "transport_bytes": len(transport_bytes),
        "payload_sha256": payload_sha256,
        "transport_sha256": transport_sha256,
        "is_stock_payload": payload_sha256 == STOCK_PAYLOAD_SHA256,
        "is_stock_transport": transport_sha256 == STOCK_TRANSPORT_SHA256,
        "safety_invariants": invariants,
        "applied_patches": applied_patches,
        "patch_states": patch_states,
        "page_checksums": checksums,
    }


def apply_patches(
    raw_bytes: bytes,
    enable_patch_ids: Sequence[str],
    fw_version: int = DEFAULT_CUSTOM_FW_VERSION,
    output_format: str = "same",
    allow_already_applied: bool = False,
) -> Tuple[bytes, Dict[str, Any]]:
    """Verify and apply selected patches to `raw_bytes`, returning `(patched_bytes, report)`."""
    if not enable_patch_ids:
        raise ValueError("At least one patch ID must be specified in enable_patch_ids")

    input_format = detect_image_format(raw_bytes)
    if output_format == "same":
        target_format = input_format
    elif output_format in ("transport", "payload"):
        target_format = output_format
    else:
        raise ValueError(f"Invalid output_format: {output_format!r}")

    payload = bytearray(
        unwrap_transport_image(raw_bytes) if input_format == "transport" else raw_bytes
    )
    verify_payload_safety_invariants(bytes(payload))

    # Deduplicate while preserving order
    ordered_ids: List[str] = []
    for pid in enable_patch_ids:
        cleaned = pid.strip()
        if not cleaned:
            continue
        if cleaned not in PATCH_IDS:
            raise KeyError(
                f"Unknown patch ID {cleaned!r}. Valid patch IDs: {', '.join(PATCH_IDS)}"
            )
        if cleaned not in ordered_ids:
            ordered_ids.append(cleaned)

    if not ordered_ids:
        raise ValueError("No valid patch IDs provided")

    specs = [build_patch_spec(pid, fw_version=fw_version) for pid in ordered_ids]

    # Check conflict groups and overlapping byte ranges
    seen_conflict_groups: Dict[str, str] = {}
    seen_offsets: Dict[int, str] = {}
    for spec in specs:
        if spec.conflict_group:
            prior = seen_conflict_groups.get(spec.conflict_group)
            if prior is not None:
                raise PatchVerificationError(
                    f"Patch {spec.patch_id!r} conflicts with {prior!r} "
                    f"(both belong to conflict group {spec.conflict_group!r})"
                )
            seen_conflict_groups[spec.conflict_group] = spec.patch_id
        for site in spec.sites:
            for byte_off in range(site.payload_offset, site.payload_offset + site.size):
                prior_patch = seen_offsets.get(byte_off)
                if prior_patch is not None:
                    raise PatchVerificationError(
                        f"Patch {spec.patch_id!r} overlaps with {prior_patch!r} at "
                        f"payload offset {byte_off:#06x}"
                    )
                seen_offsets[byte_off] = spec.patch_id

    # Verify all target sites before mutating anything
    for spec in specs:
        for site in spec.sites:
            cur = bytes(payload[site.payload_offset : site.payload_offset + site.size])
            if cur == site.orig_bytes:
                continue
            if allow_already_applied and cur == site.patched_bytes:
                continue
            raise PatchVerificationError(
                f"Verification failed for patch {spec.patch_id!r} at payload offset "
                f"{site.payload_offset:#06x} (linked {site.linked_address:#010x}, "
                f"transport {site.transport_offset:#06x}): expected original bytes "
                f"{site.orig_bytes.hex()}, found {cur.hex()}"
            )

    modified_pages = set()
    applied_details: List[Dict[str, Any]] = []
    for spec in specs:
        for site in spec.sites:
            payload[site.payload_offset : site.payload_offset + site.size] = site.patched_bytes
            modified_pages.add(site.page_index)
        applied_details.append(spec.to_dict())

    patched_payload = bytes(payload)
    verify_payload_safety_invariants(patched_payload)
    patched_transport = wrap_transport_image(patched_payload)

    out_bytes = patched_transport if target_format == "transport" else patched_payload
    old_transport = raw_bytes if input_format == "transport" else wrap_transport_image(raw_bytes)
    old_checksums = compute_page_checksums(old_transport)
    new_checksums = compute_page_checksums(patched_transport)

    page_diffs = []
    for p in sorted(modified_pages):
        page_diffs.append(
            {
                "page_index": p,
                "old_checksum": old_checksums[p],
                "new_checksum": new_checksums[p],
            }
        )

    report = {
        "input_format": input_format,
        "output_format": target_format,
        "enabled_patches": ordered_ids,
        "fw_version": f"{fw_version:#04x}" if "custom_fw_version_tag" in ordered_ids else None,
        "modified_pages": sorted(modified_pages),
        "page_checksum_changes": page_diffs,
        "payload_sha256": hashlib.sha256(patched_payload).hexdigest(),
        "transport_sha256": hashlib.sha256(patched_transport).hexdigest(),
        "page_checksums": new_checksums,
        "applied_patches": applied_details,
    }
    return out_bytes, report


def build_catalog_document() -> Dict[str, Any]:
    """Return the complete machine-readable patch catalog dictionary."""
    return {
        "schema_version": 1,
        "target_hardware": "TSL6 (WCH CH32V208, RISC-V RV32IMAC)",
        "reference_module_id": "535C62E239E339E31475FB10",
        "stock_image": {
            "transport_size_bytes": TRANSPORT_TOTAL_BYTES,
            "payload_size_bytes": PAYLOAD_TOTAL_BYTES,
            "page_count": PAGE_COUNT,
            "transport_page_size_bytes": TRANSPORT_PAGE_SIZE,
            "payload_page_size_bytes": PAYLOAD_PAGE_SIZE,
            "linked_code_base": f"{LINKED_CODE_BASE:#010x}",
            "flash_alias_base": f"{FLASH_ALIAS_BASE:#010x}",
            "transport_sha256": STOCK_TRANSPORT_SHA256,
            "payload_sha256": STOCK_PAYLOAD_SHA256,
        },
        "safety_invariants": [
            {
                "name": "reset_vector_jump",
                "payload_offset": f"{RESET_VECTOR_OFFSET:#06x}",
                "expected_hex": RESET_VECTOR_EXPECTED.hex(),
                "expected_asm": "j 0xf89a",
                "description": (
                    "TSL-BOOT (`boot.payload.bin` @ 0x002642) verifies `*(uint8_t*)0x08008000 == 0x6F` "
                    "before jumping into runtime firmware."
                ),
            },
            {
                "name": "startup_boot_flag_clear",
                "payload_offset": f"{BOOT_FLAG_CLEAR_OFFSET:#06x}",
                "expected_hex": BOOT_FLAG_CLEAR_EXPECTED.hex(),
                "expected_asm": "c.li a5, 0x10; sb a5, 9(sp); c.addi4spn a0, sp, 8; sb zero, 0xc(sp); c.jal 0x1d92",
                "description": (
                    "Runtime startup routine 0x001E48 clears the boot/upgrade request byte at "
                    "0x08077B04 (`0xc(sp)`) via 0x001D92 so the module boots into runtime normally."
                ),
            },
        ],
        "patches": [spec.to_dict() for spec in get_all_patch_specs()],
    }


def _parse_int(val: str) -> int:
    return int(val, 0)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="firmware_patcher.py",
        description="TSL6 community firmware binary inspector and modular patcher.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_inspect = sub.add_parser("inspect", help="Inspect a TSL6 runtime.bin or runtime.payload.bin image")
    p_inspect.add_argument("binary", type=Path, help="Path to runtime.bin or runtime.payload.bin")
    p_inspect.add_argument("--json", action="store_true", help="Emit JSON output")

    p_list = sub.add_parser("list-patches", help="List all verified binary patches in the catalog")
    p_list.add_argument("--json", action="store_true", help="Emit JSON output")

    p_patch = sub.add_parser("patch", help="Apply one or more verified binary patches")
    p_patch.add_argument("--in", dest="in_path", type=Path, required=True, help="Input firmware binary")
    p_patch.add_argument("--out", dest="out_path", type=Path, required=True, help="Output patched binary")
    p_patch.add_argument(
        "--enable",
        required=True,
        help="Comma-separated list of patch IDs to enable",
    )
    p_patch.add_argument(
        "--fw-version",
        type=_parse_int,
        default=DEFAULT_CUSTOM_FW_VERSION,
        help="Firmware version byte for custom_fw_version_tag (default: 0x16 -> V1.6.00)",
    )
    p_patch.add_argument(
        "--output-format",
        choices=("same", "transport", "payload"),
        default="same",
        help="Output binary format (default: same as input)",
    )
    p_patch.add_argument(
        "--allow-already-applied",
        action="store_true",
        help="Allow patches whose target bytes already match the patched state",
    )
    p_patch.add_argument(
        "--manifest-out",
        type=Path,
        default=None,
        help="Optional path to write a JSON patch report / page-checksum manifest",
    )

    p_export = sub.add_parser("export-catalog", help="Export machine-readable patch catalog JSON")
    p_export.add_argument(
        "--out",
        type=Path,
        default=Path("analysis/patch_catalog.json"),
        help="Output JSON path (default: analysis/patch_catalog.json)",
    )

    args = parser.parse_args(argv)

    if args.subcommand == "inspect":
        raw = args.binary.read_bytes()
        info = inspect_firmware_bytes(raw)
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            print(f"File:             {args.binary}")
            print(f"Format:           {info['format']} ({info['input_bytes']} bytes, {info['page_count']} pages)")
            print(f"Payload SHA-256:  {info['payload_sha256']} (stock={info['is_stock_payload']})")
            print(f"Transport SHA-256:{info['transport_sha256']} (stock={info['is_stock_transport']})")
            print(f"Safety checks:    reset_vector={info['safety_invariants']['reset_vector_ok']}, "
                  f"boot_flag_clear={info['safety_invariants']['boot_flag_clear_ok']}")
            print("Patch statuses:")
            for st in info["patch_states"]:
                extra = f" [{st['detected_fw_version']}]" if "detected_fw_version" in st else ""
                print(f"  - {st['patch_id']:<28} : {st['status'].upper()}{extra}")
        return 0

    if args.subcommand == "list-patches":
        catalog = build_catalog_document()
        if args.json:
            print(json.dumps(catalog, indent=2))
        else:
            for p in catalog["patches"]:
                print(f"{p['patch_id']} ({p['category']}) - {p['title']}")
                print(f"  Summary: {p['summary']}")
                for s in p["sites"]:
                    print(
                        f"  Site: payload={s['payload_offset']} linked={s['linked_address']} "
                        f"transport={s['transport_offset']} (page {s['page_index']}): "
                        f"{s['orig_hex']} ({s['orig_asm']}) -> {s['patched_hex']} ({s['patched_asm']})"
                    )
        return 0

    if args.subcommand == "patch":
        raw = args.in_path.read_bytes()
        patch_ids = [x.strip() for x in args.enable.split(",") if x.strip()]
        patched_bytes, report = apply_patches(
            raw,
            enable_patch_ids=patch_ids,
            fw_version=args.fw_version,
            output_format=args.output_format,
            allow_already_applied=args.allow_already_applied,
        )
        args.out_path.parent.mkdir(parents=True, exist_ok=True)
        args.out_path.write_bytes(patched_bytes)
        if args.manifest_out is not None:
            args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
            args.manifest_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {len(patched_bytes)} bytes ({report['output_format']}) to {args.out_path}")
        print(f"Enabled patches:  {', '.join(report['enabled_patches'])}")
        print(f"Modified pages:   {report['modified_pages']}")
        print(f"Payload SHA-256:  {report['payload_sha256']}")
        print(f"Transport SHA-256:{report['transport_sha256']}")
        return 0

    if args.subcommand == "export-catalog":
        catalog = build_catalog_document()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        print(f"Exported {len(catalog['patches'])} patches to {args.out}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
