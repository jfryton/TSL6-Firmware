#!/usr/bin/env python3
"""Generate the committed boot/bootloader analysis artifact.

Records the recovered structure of the TSL6 boot image: startup constants, the
update-command dispatcher, and the confirmed flash write/erase/verify flow.

Usage:
    gen_boot_analysis.py work/boot.payload.bin analysis/boot.json
"""
import json
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

RESET_TARGET = 0x1C28
LINKED_CODE_BASE = 0x1000
FLASH_ALIAS_BASE = 0x08001000
BOOT_SLOT_SIZE = 0x7000
RUNTIME_FLASH_ALIAS_BASE = 0x08008000
RUNTIME_SLOT_SIZE = 0x18000
RESIDENT_LIBRARY_BASE = 0x40000
RESIDENT_JUMP_TABLE_BASE = 0x40034
BLE_LIBRARY_VERSION = b"CH32V20x_BLE_LIB_V1.3"
UPDATE_DISPATCH = 0x121C
FLASH_PROGRAM = 0x110C


def md():
    return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


def resolve_constants(data):
    m = md()
    regs = {}
    for ins in m.disasm(data[RESET_TARGET:RESET_TARGET + 0x40], RESET_TARGET):
        mn = ins.mnemonic
        ops = ins.op_str.replace(",", " ").split()
        if mn == "auipc" and len(ops) == 2:
            regs[ops[0]] = (LINKED_CODE_BASE + ins.address
                            + (int(ops[1], 0) << 12)) & 0xFFFFFFFF
        elif mn in ("addi", "c.addi") and len(ops) == 3 and ops[1] in regs:
            regs[ops[0]] = (regs[ops[1]] + int(ops[2], 0)) & 0xFFFFFFFF
        if mn == "lw" and "gp" in regs and "sp" in regs:
            break
    return regs.get("gp"), regs.get("sp")


def assert_landmarks(data, gp, sp):
    """Keep safety-critical claims tied to the archived boot image bytes."""
    assert len(data) == 0x3000
    assert data[:4] == bytes.fromhex("6f109042")
    assert data[RESET_TARGET:RESET_TARGET + 8] == bytes.fromhex(
        "971100209381813d")
    assert (gp, sp) == (0x20004000, 0x20010000)
    assert data[0x2EB8:0x2EB8 + len(BLE_LIBRARY_VERSION)] == \
        BLE_LIBRARY_VERSION
    assert data[0x110C:0x1114] == bytes.fromhex("9387010898430111")
    assert data[0x1268:0x1294] == bytes.fromhex(
        "3787fff7a207c18f13948700a1835d8c4204b70702009387070241803e942a04"
        "e1672297938707f0e3e1e7fa")
    assert data[0x1332:0x133C] == bytes.fromhex("8347060005476395e702")
    assert data[0x2032:0x203A] == bytes.fromhex("b7270240c8c78280")
    assert data[0x203A:0x2058] == bytes.fromhex(
        "b7066745b7270240938636123797efcdd4c31307b79ad8c3d4d3d8d38280")
    assert data[0x2066:0x2094] == bytes.fromhex(
        "b7270240984bb7060200137505f0558f98cbc8cb984b1367070498cbd847058b"
        "75ff984b8176fd16758f98cb8280")
    assert data[0x2094:0x20F8] == bytes.fromhex(
        "372702401c4bc166137505f0d58f1ccb5c47858bf5ff372702405c47898bf5ff"
        "3727024013060010b386f50003a80600b306f50023a006015447898af5fe9107"
        "e394c7fe1c4bb7062000d58f1ccbb7270240d847058b75ff984bc176fd16758f"
        "98cb8280")
    assert (0x20020 << 10) == RUNTIME_FLASH_ALIAS_BASE
    assert ((0xF7FF8000 + RUNTIME_FLASH_ALIAS_BASE) & 0xFFFFFFFF) == 0
    assert (((0x20020 + 95) << 10) + 0xF7FF8000) & 0xFFFFFFFF == 0x17C00
    assert (((0x20020 + 96) << 10) + 0xF7FF8000) & 0xFFFFFFFF == 0x18000


def main():
    data = open(sys.argv[1], "rb").read()
    out_path = sys.argv[2]
    gp, sp = resolve_constants(data)
    assert_landmarks(data, gp, sp)
    obj = {
        "image": "boot",
        "payload_size": len(data),
        "payload_offset_base": "0x0 (all analysis code addresses are offsets)",
        "linked_code_base": hex(LINKED_CODE_BASE),
        "flash_alias_base": "0x%08x" % FLASH_ALIAS_BASE,
        "slot_size_bytes": BOOT_SLOT_SIZE,
        "resident_library_base": hex(RESIDENT_LIBRARY_BASE),
        "resident_jump_table_base": hex(RESIDENT_JUMP_TABLE_BASE),
        "reset_jump_target": hex(RESET_TARGET),
        "global_pointer_gp": hex(gp) if gp else None,
        "stack_pointer_sp": hex(sp) if sp else None,
        "update_dispatcher": hex(UPDATE_DISPATCH),
        "update_commands": {
            "0x55": "prepare runtime-image update; clears gp+0xaf and validates "
                    "the trailing 14-byte value via 0xc9a",
            "0x53": "begin runtime-image update; accepts only target byte 1 "
                    "after 14-byte validation, then sets gp+0xaf",
            "0x57": "write one 1026-byte transport page",
            "0x45": "finalize/report completion",
        },
        "write_page_flow": {
            "handler": hex(UPDATE_DISPATCH),
            "page_size_check": "0x402 (1026) validated before accepting a page",
            "page_index": "2-byte big-endian index; destination = "
                          "0x08008000 + index*0x400",
            "flash_alias_base": "0x%08x" % RUNTIME_FLASH_ALIAS_BASE,
            "slot_size_bytes": RUNTIME_SLOT_SIZE,
            "valid_page_indices": "0..95 (destinations 0x08008000..0x0801fc00)",
            "flash_program_fn": hex(FLASH_PROGRAM),
            "resident_copy_slot": "0x4004c tmos_memcpy; used only when "
                                  "payload+2 is not word-aligned",
            "erase": "0x110c calls local 0x2066 for one 0x100-byte fast erase; "
                     "the page handler invokes it four times per 1 KiB page",
            "program": "0x110c calls local 0x2094 for one 0x100-byte fast "
                       "program; invoked at offsets 0,0x100,0x200,0x300",
            "verify": "word-by-word read-back compare; mismatch aborts the page",
        },
        "flash_controller": {
            "base": "0x40022000",
            "registers": {
                "KEYR": "0x40022004",
                "STATR": "0x4002200c",
                "CTLR": "0x40022010",
                "ADDR": "0x40022014",
                "MODEKEYR": "0x40022024",
            },
            "functions": {
                "status_clear": "0x2032",
                "unlock_fast": "0x203a",
                "lock_fast": "0x2058",
                "erase_256": "0x2066",
                "program_256": "0x2094",
            },
            "clock_setup": "0x110c compares gp+0x80 to 144000000 Hz; it ORs "
                           "RCC CFGR0 at 0x40021004 with HPRE DIV2 (0x80) or "
                           "DIV4 (0x90), then clears those bits afterward",
            "error_handling": "polls BSY/WR_BSY without timeout; does not "
                              "test PGERR, WRPRTERR, or EOP; wrapper has no "
                              "status return",
        },
        "notes": [
            "This boot image programs only the runtime slot. The runtime image "
            "contains a complementary updater for the boot slot.",
            "Both images use low linked/execution views distinct from their "
            "0x08000000 flash aliases; the mapping mechanism remains unknown.",
            "This is the safety-critical mapping: do not exercise 0x55/0x53/"
            "0x57/0x52/0x45 without a hardware recovery path.",
        ],
    }
    with open(out_path, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    raise SystemExit(main())
