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
            regs[ops[0]] = (ins.address + (int(ops[1], 0) << 12)) & 0xFFFFFFFF
        elif mn in ("addi", "c.addi") and len(ops) == 3 and ops[1] in regs:
            regs[ops[0]] = (regs[ops[1]] + int(ops[2], 0)) & 0xFFFFFFFF
        if mn == "lw" and "gp" in regs and "sp" in regs:
            break
    return regs.get("gp"), regs.get("sp")


def main():
    data = open(sys.argv[1], "rb").read()
    out_path = sys.argv[2]
    gp, sp = resolve_constants(data)
    obj = {
        "image": "boot",
        "payload_size": len(data),
        "reset_jump_target": hex(RESET_TARGET),
        "global_pointer_gp": hex(gp) if gp else None,
        "stack_pointer_sp": hex(sp) if sp else None,
        "update_dispatcher": hex(UPDATE_DISPATCH),
        "update_commands": {
            "0x55": "prepare/select update target; clears in-progress flag at "
                    "gp+0xaf, validates target via 0xc9a",
            "0x53": "begin selected target; sets in-progress flag gp+0xaf, "
                    "selects boot(0)/runtime(1) slot",
            "0x57": "write one 1026-byte transport page",
            "0x45": "finalize/report completion",
        },
        "write_page_flow": {
            "handler": hex(UPDATE_DISPATCH),
            "page_size_check": "0x402 (1026) validated before accepting a page",
            "page_index": "2-byte big-endian prefix parsed to compute flash "
                          "destination",
            "flash_program_fn": hex(FLASH_PROGRAM),
            "erase": "resident flash erase pointer at 0x4000004c, granularity "
                     "0x400 (1 KiB page)",
            "program": "1024-byte payload written in 0x100-byte (256) chunks",
            "verify": "word-by-word read-back compare; mismatch aborts the page",
        },
        "flash_controller": {
            "control_register": "0x40021004 (read-modify-write, OR with 0x80 "
                                "or 0x90)",
            "note": "CH32V20x flash/option programming region; exact register "
                    "semantics not yet fully decoded",
            "size_variant_detect": "compares gp+0x80 size word against "
                                   "0x8954400 to pick control bit 0x80 vs 0x90",
        },
        "notes": [
            "The bootloader, not the runtime, performs the actual flash erase/"
            "program/verify. The runtime update dispatcher relays pages to it.",
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
