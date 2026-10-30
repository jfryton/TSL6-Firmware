#!/usr/bin/env python3
"""Unit tests for tools/firmware_patcher.py and analysis/patch_catalog.json."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.firmware_patcher import (
    BOOT_FLAG_CLEAR_OFFSET,
    PAGE_COUNT,
    PATCH_IDS,
    PAYLOAD_TOTAL_BYTES,
    RESET_VECTOR_OFFSET,
    STOCK_PAYLOAD_SHA256,
    STOCK_TRANSPORT_SHA256,
    TRANSPORT_TOTAL_BYTES,
    PatchVerificationError,
    apply_patches,
    build_catalog_document,
    build_patch_spec,
    compute_page_checksums,
     inspect_firmware_bytes,
    main as patcher_main,
    payload_to_transport_offset,
    unwrap_transport_image,
    wrap_transport_image,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
STOCK_TRANSPORT_PATH = REPO_ROOT / "latest-tsl6-535C62E239E339E31475FB10" / "runtime" / "runtime.bin"
STOCK_MANIFEST_PATH = REPO_ROOT / "latest-tsl6-535C62E239E339E31475FB10" / "runtime" / "runtime.manifest.json"
STOCK_MAP_PATH = REPO_ROOT / "latest-tsl6-535C62E239E339E31475FB10" / "runtime" / "runtime.map.json"
STOCK_PAYLOAD_PATH = REPO_ROOT / "work" / "runtime.payload.bin"
CATALOG_JSON_PATH = REPO_ROOT / "analysis" / "patch_catalog.json"


class FirmwarePatcherTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.transport_bytes = STOCK_TRANSPORT_PATH.read_bytes()
        cls.payload_bytes = STOCK_PAYLOAD_PATH.read_bytes()
        cls.manifest = json.loads(STOCK_MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.runtime_map = json.loads(STOCK_MAP_PATH.read_text(encoding="utf-8"))

    def test_unwrap_and_wrap_roundtrip_matches_stock_files(self) -> None:
        self.assertEqual(len(self.transport_bytes), TRANSPORT_TOTAL_BYTES)
        self.assertEqual(len(self.payload_bytes), PAYLOAD_TOTAL_BYTES)

        unwrapped = unwrap_transport_image(self.transport_bytes)
        self.assertEqual(unwrapped, self.payload_bytes)

        rewrapped = wrap_transport_image(self.payload_bytes)
        self.assertEqual(rewrapped, self.transport_bytes)

    def test_stock_page_checksums_match_manifest(self) -> None:
        self.assertEqual(self.manifest["page_count"], PAGE_COUNT)
        self.assertEqual(self.manifest["byte_count"], TRANSPORT_TOTAL_BYTES)
        self.assertEqual(self.manifest["sha256"], STOCK_TRANSPORT_SHA256)

        checksums = compute_page_checksums(self.transport_bytes)
        self.assertEqual(len(checksums), PAGE_COUNT)
        expected_checksums = [
            p["checksum16"] for p in self.runtime_map["transport_pages"]["pages"]
        ]
        self.assertEqual(checksums, expected_checksums)

    def test_inspect_stock_transport_and_payload(self) -> None:
        info_t = inspect_firmware_bytes(self.transport_bytes)
        self.assertEqual(info_t["format"], "transport")
        self.assertTrue(info_t["is_stock_transport"])
        self.assertTrue(info_t["is_stock_payload"])
        self.assertEqual(info_t["applied_patches"], [])

        info_p = inspect_firmware_bytes(self.payload_bytes)
        self.assertEqual(info_p["format"], "payload")
        self.assertTrue(info_p["is_stock_transport"])
        self.assertTrue(info_p["is_stock_payload"])
        self.assertEqual(info_p["applied_patches"], [])

    def test_each_patch_verifies_and_applies_cleanly(self) -> None:
        for patch_id in PATCH_IDS:
            with self.subTest(patch_id=patch_id):
                spec = build_patch_spec(patch_id)
                for site in spec.sites:
                    t_off = payload_to_transport_offset(site.payload_offset)
                    self.assertEqual(t_off, site.transport_offset)
                    self.assertEqual(
                        self.payload_bytes[site.payload_offset : site.payload_offset + site.size],
                        site.orig_bytes,
                    )
                    self.assertEqual(
                        self.transport_bytes[t_off : t_off + site.size],
                        site.orig_bytes,
                    )

                patched_transport, report = apply_patches(
                    self.transport_bytes,
                    enable_patch_ids=[patch_id],
                )
                self.assertEqual(len(patched_transport), TRANSPORT_TOTAL_BYTES)
                self.assertEqual(report["enabled_patches"], [patch_id])
                self.assertNotEqual(report["payload_sha256"], STOCK_PAYLOAD_SHA256)
                self.assertNotEqual(report["transport_sha256"], STOCK_TRANSPORT_SHA256)

                inspected = inspect_firmware_bytes(patched_transport)
                self.assertIn(patch_id, inspected["applied_patches"])
                self.assertTrue(inspected["safety_invariants"]["reset_vector_ok"])
                self.assertTrue(inspected["safety_invariants"]["boot_flag_clear_ok"])

                # Verify that only bytes belonging to the patch sites changed in payload
                patched_payload = unwrap_transport_image(patched_transport)
                expected_payload = bytearray(self.payload_bytes)
                for site in spec.sites:
                    expected_payload[site.payload_offset : site.payload_offset + site.size] = (
                        site.patched_bytes
                    )
                self.assertEqual(patched_payload, bytes(expected_payload))

    def test_combined_community_bundle_applies_cleanly(self) -> None:
        bundle = [
            "ignore_server_deauth_0xae",
            "bypass_auth_check_0x1380",
            "enable_0xa6_disable_cmd",
            "pulse_timing_fast_1500ms",
            "pulse_hold_short_25ms",
            "custom_fw_version_tag",
            "unlock_steering_triggers_all_gears_0x8100",
        ]
        patched_transport, report = apply_patches(
            self.transport_bytes,
            enable_patch_ids=bundle,
            fw_version=0x16,
        )
        self.assertEqual(report["enabled_patches"], bundle)
        self.assertEqual(report["modified_pages"], [4, 32, 43, 47, 49, 57])

        inspected = inspect_firmware_bytes(patched_transport)
        self.assertEqual(set(inspected["applied_patches"]), set(bundle))
        ver_state = next(
            s for s in inspected["patch_states"] if s["patch_id"] == "custom_fw_version_tag"
        )
        self.assertEqual(ver_state["detected_fw_version"], "0x16 (V1.6.00)")

    def test_custom_fw_version_parameter_values(self) -> None:
        for ver, label in ((0x15, "0x15 (V1.5.00)"), (0x16, "0x16 (V1.6.00)"), (0x20, "0x20 (V2.0.00)")):
            patched, _ = apply_patches(
                self.payload_bytes,
                enable_patch_ids=["custom_fw_version_tag"],
                fw_version=ver,
            )
            info = inspect_firmware_bytes(patched)
            ver_state = next(
                s for s in info["patch_states"] if s["patch_id"] == "custom_fw_version_tag"
            )
            self.assertEqual(ver_state["status"], "applied")
            self.assertEqual(ver_state["detected_fw_version"], label)

        for invalid_ver in (0x00, -1, 0x80, 0xFF):
            with self.assertRaises(ValueError):
                apply_patches(
                    self.payload_bytes,
                    enable_patch_ids=["custom_fw_version_tag"],
                    fw_version=invalid_ver,
                )

    def test_conflicting_pulse_timing_presets_rejected(self) -> None:
        with self.assertRaises(PatchVerificationError):
            apply_patches(
                self.transport_bytes,
                enable_patch_ids=["pulse_timing_fast_1500ms", "pulse_timing_gentle_1000ms"],
            )

    def test_corrupted_images_and_mismatched_sites_rejected(self) -> None:
        # 1. Invalid length
        with self.assertRaises(PatchVerificationError):
            inspect_firmware_bytes(b"\x00" * 1024)

        # 2. Corrupted transport page header
        bad_header = bytearray(self.transport_bytes)
        bad_header[1026] = 0x00
        bad_header[1027] = 0x99
        with self.assertRaises(PatchVerificationError):
            inspect_firmware_bytes(bytes(bad_header))

        # 3. Corrupted reset vector at 0x0000
        bad_reset = bytearray(self.payload_bytes)
        bad_reset[RESET_VECTOR_OFFSET] = 0x00
        with self.assertRaises(PatchVerificationError):
            inspect_firmware_bytes(bytes(bad_reset))

        # 4. Corrupted startup boot-flag clear at 0x1E6A
        bad_boot_clear = bytearray(self.payload_bytes)
        bad_boot_clear[BOOT_FLAG_CLEAR_OFFSET] ^= 0xFF
        with self.assertRaises(PatchVerificationError):
            inspect_firmware_bytes(bytes(bad_boot_clear))

        # 5. Tampered patch site bytes
        bad_site = bytearray(self.payload_bytes)
        bad_site[0x00BDA6] = 0x00
        with self.assertRaises(PatchVerificationError):
            apply_patches(bytes(bad_site), enable_patch_ids=["ignore_server_deauth_0xae"])

    def test_catalog_json_is_up_to_date(self) -> None:
        self.assertTrue(CATALOG_JSON_PATH.is_file())
        on_disk = json.loads(CATALOG_JSON_PATH.read_text(encoding="utf-8"))
        expected = build_catalog_document()
        self.assertEqual(on_disk, expected)

    def test_capstone_disassembly_matches_catalog(self) -> None:
        try:
            from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC, Cs
        except ImportError:
            self.skipTest("Capstone not installed in this Python interpreter")

        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
        for patch_id in PATCH_IDS:
            spec = build_patch_spec(patch_id)
            for site in spec.sites:
                orig_insns = list(md.disasm(site.orig_bytes, site.payload_offset))
                patched_insns = list(md.disasm(site.patched_bytes, site.payload_offset))
                self.assertGreaterEqual(
                    len(orig_insns),
                    1,
                    f"Expected >= 1 instruction for {patch_id} orig at {site.payload_offset:#x}",
                )
                self.assertGreaterEqual(
                    len(patched_insns),
                    1,
                    f"Expected >= 1 instruction for {patch_id} patched at {site.payload_offset:#x}",
                )
                orig_text = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in orig_insns)
                patched_text = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in patched_insns)
                self.assertTrue(
                    site.orig_asm.startswith(orig_text),
                    f"{patch_id}: {site.orig_asm!r} does not start with {orig_text!r}",
                )
                self.assertTrue(
                    site.patched_asm.startswith(patched_text),
                    f"{patch_id}: {site.patched_asm!r} does not start with {patched_text!r}",
                )

    def test_cli_subcommands_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out_bin = tmp / "patched_runtime.bin"
            out_manifest = tmp / "patched_runtime.manifest.json"
            out_catalog = tmp / "catalog.json"

            with contextlib.redirect_stdout(io.StringIO()):
                rc = patcher_main(
                    [
                        "patch",
                        "--in",
                        str(STOCK_TRANSPORT_PATH),
                        "--out",
                        str(out_bin),
                        "--enable",
                        "ignore_server_deauth_0xae,enable_0xa6_disable_cmd,custom_fw_version_tag",
                        "--fw-version",
                        "0x16",
                        "--manifest-out",
                        str(out_manifest),
                    ]
                )
                self.assertEqual(rc, 0)
                self.assertTrue(out_bin.is_file())
                self.assertEqual(out_bin.stat().st_size, TRANSPORT_TOTAL_BYTES)
                self.assertTrue(out_manifest.is_file())

                rc_inspect = patcher_main(["inspect", str(out_bin), "--json"])
                self.assertEqual(rc_inspect, 0)

                rc_export = patcher_main(["export-catalog", "--out", str(out_catalog)])
                self.assertEqual(rc_export, 0)

            self.assertEqual(
                json.loads(out_catalog.read_text(encoding="utf-8")),
                build_catalog_document(),
            )


if __name__ == "__main__":
    unittest.main()
