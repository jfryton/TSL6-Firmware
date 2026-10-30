#!/usr/bin/env python3
"""Generate committed machine-readable analysis artifacts for the runtime image.

Produces, under analysis/:
  - memory_map.json       linker constants + region model
  - command_dispatch.json BLE command -> handler offset table
  - action_table.json     253 action stubs: id, stub, worker, args, catalog label
  - rule_engine.json      rule-table structure facts

This script is deterministic and re-runnable. Regenerate after re-deriving any
landmark. All offsets are payload offsets (image base 0).

Usage:
    gen_analysis.py work/runtime.payload.bin analysis/
"""
import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

# --- landmarks confirmed by disassembly (see FIRMWARE_INTERNALS.md) ---
RESET_TARGET = 0xF89A
LINKED_CODE_BASE = 0x8000
FLASH_ALIAS_BASE = 0x08008000
RUNTIME_SLOT_SIZE = 0x18000
BOOT_FLASH_ALIAS_BASE = 0x08001000
RESIDENT_LIBRARY_BASE = 0x40000
RESIDENT_JUMP_TABLE_BASE = 0x40034
BLE_LIBRARY_VERSION = b"CH32V20x_BLE_LIB_V1.3"
MAIN_DISPATCH = 0xBDEA
MAIN_DISPATCH_END = 0xC120
UPDATE_DISPATCH = 0xBC76
ACTION_DISPATCH = 0xD16E
ACTION_TABLE_BASE = 0x11710
ACTION_TABLE_COUNT = 253
RULE_ENGINE = 0xE310
KEYCODE_PRIMITIVE = 0x33E2
A2_HANDLER = 0xC53C
CMD_REG = "s1"

# Backend action catalog labels (action namespace). Source: live funlist.js
# catalog observed by the Mini App / TSL-Cmd. Labels are correlated, not
# confirmed against vehicle-side behavior.
ACTION_CATALOG = {
    137: "AP speed +5",
    138: "AP speed -5",
    139: "Left scroll middle-button hold",
    140: "Play/pause",
    141: "Volume +1",
    142: "Volume -1",
    143: "Previous track",
    144: "Next track",
    145: "Voice assistant",
    146: "AP speed +1",
    147: "AP speed -1",
    148: "Following distance +1",
    149: "Following distance -1",
}


def md():
    return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


def s32(d, o):
    return struct.unpack_from("<i", d, o)[0]


def resolve_constants(data):
    m = md()
    regs = {}
    out = {}
    # Walk far enough to let each auipc be completed by its following addi.
    for ins in m.disasm(data[RESET_TARGET:RESET_TARGET + 0x40], RESET_TARGET):
        mn = ins.mnemonic
        ops = ins.op_str.replace(",", " ").split()
        if mn == "auipc" and len(ops) == 2:
            regs[ops[0]] = (LINKED_CODE_BASE + ins.address
                            + (int(ops[1], 0) << 12)) & 0xFFFFFFFF
        elif mn in ("addi", "c.addi") and len(ops) == 3 and ops[1] in regs:
            regs[ops[0]] = (regs[ops[1]] + int(ops[2], 0)) & 0xFFFFFFFF
        elif mn in ("addi", "c.addi") and len(ops) == 3 and ops[0] in regs \
                and ops[0] == ops[1]:
            regs[ops[0]] = (regs[ops[0]] + int(ops[2], 0)) & 0xFFFFFFFF
        # stop once the stack init copy loop begins (gp/sp both finalized)
        if mn == "lw" and "gp" in regs and "sp" in regs:
            break
    out["gp"] = regs.get("gp")
    out["sp"] = regs.get("sp")
    return out


def assert_landmarks(data, consts):
    """Keep linked-base and updater claims tied to this archived image."""
    assert len(data) == 0x12000
    assert data[:4] == bytes.fromhex("6ff0b009")
    assert data[RESET_TARGET:RESET_TARGET + 8] == bytes.fromhex(
        "97c1fe1f93816176")
    assert consts == {"gp": 0x20004000, "sp": 0x20010000}
    assert data[0x11B38:0x11B38 + len(BLE_LIBRARY_VERSION)] == \
        BLE_LIBRARY_VERSION
    assert data[0x28E:0x296] == bytes.fromhex("b707040003a3c704")
    assert data[0x1C22:0x1C4C] == bytes.fromhex(
        "37f7fff7a207c18f13948700a1835d8c4204b7070200910741803e942a04"
        "9d672297938707f0e3e2e7fa")
    assert data[0x1D24:0x1D30] == bytes.fromhex(
        "8347060085e38547a38af10c")
    assert (0x20004 << 10) == BOOT_FLASH_ALIAS_BASE
    assert ((0xF7FFF000 + BOOT_FLASH_ALIAS_BASE) & 0xFFFFFFFF) == 0
    assert (((0x20004 + 27) << 10) + 0xF7FFF000) & 0xFFFFFFFF == 0x6C00
    assert (((0x20004 + 28) << 10) + 0xF7FFF000) & 0xFFFFFFFF == 0x7000


def decode_stub(data, addr, limit=0x40):
    m = md()
    args = {}
    target = None
    kind = None
    for ins in m.disasm(data[addr:addr + limit], addr):
        mn = ins.mnemonic
        ops = ins.op_str.replace(",", " ").split()
        if mn in ("c.li", "li") and len(ops) == 2:
            try:
                args[ops[0]] = int(ops[1], 0) & 0xFFFFFFFF
            except ValueError:
                pass
        elif mn == "addi" and len(ops) == 3 and ops[1] == "zero":
            args[ops[0]] = int(ops[2], 0) & 0xFFFFFFFF
        elif mn in ("j", "c.j"):
            target = (ins.address + int(ops[-1], 0)) & 0xFFFFFFFF
            kind = "tail"
            break
        elif mn in ("jal", "c.jal"):
            target = (ins.address + int(ops[-1], 0)) & 0xFFFFFFFF
            kind = "call"
            break
        elif mn in ("c.jr", "jr", "ret"):
            kind = "ret"
            break
    keep = {k: v for k, v in args.items() if k in ("a0", "a1", "a2", "a3")}
    return kind, target, keep


def gen_action_table(data):
    rows = []
    for i in range(ACTION_TABLE_COUNT):
        off = ACTION_TABLE_BASE + i * 4
        stub = (ACTION_TABLE_BASE + s32(data, off)) & 0xFFFFFFFF
        kind, worker, args = decode_stub(data, stub)
        action_id = i + 1
        rows.append({
            "action_id": action_id,
            "stub": hex(stub),
            "dispatch": kind,
            "worker": hex(worker) if isinstance(worker, int) else None,
            "worker_resident": bool(isinstance(worker, int) and worker >= len(data)),
            "args": {k: v for k, v in sorted(args.items())},
            "catalog_label": ACTION_CATALOG.get(action_id),
        })
    # group
    groups = {}
    for r in rows:
        key = (r["worker"], tuple(sorted(r["args"].items())))
        groups.setdefault(key, []).append(r["action_id"])
    grouped = [
        {"worker": k[0], "args": dict(k[1]), "action_ids": v}
        for k, v in sorted(groups.items(), key=lambda kv: -len(kv[1]))
    ]
    return rows, grouped


def map_dispatch(data):
    """Decode the binary-search command ladder.

    The dispatcher is a balanced comparison tree over the command byte in
    CMD_REG. Only equality outcomes select a real handler:
      - `beq CMD, imm -> X`   : handler for `imm` is X (the branch target).
      - `bne CMD, imm -> U`   : `imm` matches by fall-through; handler is the
                                instruction after the branch (U is the unknown
                                path used when not equal).
    Range branches (`bltu`/`bgeu`) are tree navigation and are not handlers.
    """
    m = md()
    insns = list(m.disasm(data[MAIN_DISPATCH:MAIN_DISPATCH_END], MAIN_DISPATCH))
    imm = {}
    handlers = {}
    for idx, ins in enumerate(insns):
        mn = ins.mnemonic
        ops = ins.op_str.replace(",", " ").split()
        if mn in ("c.li", "li") and len(ops) == 2:
            try:
                imm[ops[0]] = int(ops[1], 0) & 0xFFFFFFFF
            except ValueError:
                pass
            continue
        if mn == "addi" and len(ops) == 3 and ops[1] == "zero":
            imm[ops[0]] = int(ops[2], 0) & 0xFFFFFFFF
            continue
        if mn in ("beq", "bne") and len(ops) == 3:
            a, b, disp = ops
            other = b if a == CMD_REG else (a if b == CMD_REG else None)
            if other is None or other not in imm:
                continue
            val = imm[other]
            if not (0x20 <= val <= 0xFF):
                continue
            tgt = (ins.address + int(disp, 0)) & 0xFFFFFFFF
            if mn == "beq":
                handler = tgt
            else:  # bne: match falls through to next instruction
                handler = insns[idx + 1].address if idx + 1 < len(insns) else None
            handlers.setdefault(val, {
                "command": val, "command_hex": hex(val),
                "compare_at": hex(ins.address), "compare": mn,
                "handler": hex(handler) if handler is not None else None,
            })
    return [handlers[k] for k in sorted(handlers)]


def main():
    data = open(sys.argv[1], "rb").read()
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    consts = resolve_constants(data)
    assert_landmarks(data, consts)
    memory_map = {
        "image": "runtime",
        "payload_size": len(data),
        "payload_offset_base": "0x0 (all analysis code addresses are offsets)",
        "linked_code_base": hex(LINKED_CODE_BASE),
        "flash_alias_base": "0x%08x" % FLASH_ALIAS_BASE,
        "slot_size_bytes": RUNTIME_SLOT_SIZE,
        "reset_jump_target": hex(RESET_TARGET),
        "global_pointer_gp": hex(consts["gp"]) if consts["gp"] else None,
        "stack_pointer_sp": hex(consts["sp"]) if consts["sp"] else None,
        "ram_base": "0x20000000",
        "ram_top": "0x20010000",
        "peripheral_base": "0x40000000",
        "resident_library_base": hex(RESIDENT_LIBRARY_BASE),
        "resident_jump_table_base": hex(RESIDENT_JUMP_TABLE_BASE),
        "notes": [
            "Payload offsets remain base-zero in analysis, but AUIPC absolute "
            "addresses must use the linked code base 0x8000.",
            "The boot updater programs this image at flash alias 0x08008000; "
            "the statically accepted slot is 0x18000 bytes (96 KiB).",
            "Startup transfers to a resident BLE library at 0x00040000; its "
            "jump table begins at 0x00040034. Its backing storage is not "
            "present in the downloaded image.",
            "gp-relative addressing (gp=%s) is used for the BLE state block, "
            "including the 256-byte shortcut table at gp+0x80." % (
                hex(consts["gp"]) if consts["gp"] else "?"),
        ],
    }

    rows, grouped = gen_action_table(data)
    action_table = {
        "dispatcher": hex(ACTION_DISPATCH),
        "table_base": hex(ACTION_TABLE_BASE),
        "entry_count": ACTION_TABLE_COUNT,
        "dispatch_algorithm": (
            "index=(action_id-1)&0xFF; reject if index>0xFC; "
            "target=table_base + s32(table_base+index*4)"),
        "shared_workers": {
            "0x33e2": "keycode/button primitive (validates 1..18, stores RAM "
                      "state byte 0x2000bf2c); used by media/AP/steering actions",
            "0x3a30": "action 139 latch: writes 0x0C to countdown byte "
                      "0x2000bf2d; handler branch 0x3cdc decrements it and "
                      "sets bits 6:5 of the current object to 0b10 whenever "
                      "the counter is nonzero; cadence/effect unknown",
            "0xf296": "one-hot bitfield control worker (actions 1-8)",
        },
        "entries": rows,
        "groups": grouped,
    }

    command_dispatch = {
        "dispatcher": hex(MAIN_DISPATCH),
        "command_register": CMD_REG,
        "unknown_command_path": "0xbcba",
        "update_dispatcher": hex(UPDATE_DISPATCH),
        "a2_handler": hex(A2_HANDLER),
        "shared_helpers": {
            "0xd02": "BLE frame builder/enqueue; emits 55 7f header and "
                     "checksum, then wakes the resident event loop",
            "0x110a": "15-slot delayed-callback/event scheduler; 12-byte "
                      "entries at RAM 0x2000be28; converts milliseconds to "
                      "625-us scheduler ticks",
            "0xb76c": "command reply builder; allocates via "
                      "tmos_msg_allocate (0x40070), copies through "
                      "tmos_memcpy (0x4004c), frames via 0xd02, then "
                      "releases through tmos_msg_deallocate (0x40068)",
            "0xb7c6": "module status reply builder",
            "0xb86e": "dashboard telemetry producer (35-byte 0xB0 packet, "
                      "rate-limited via gp+0x178 timestamp)",
            "0xbdb8": "command-reply tail used by 0xA2/0xBB handlers",
        },
        "resident_abi_table": {
            "library_base": hex(RESIDENT_LIBRARY_BASE),
            "jump_table_base": hex(RESIDENT_JUMP_TABLE_BASE),
            "note": "Resident function pointers are loaded from the BLE "
                    "library jump table at 0x00040034 and called indirectly. "
                    "The library base 0x00040000 is not the CH32V peripheral "
                    "region at 0x40000000.",
            "source": {
                "embedded_version": "CH32V20x_BLE_LIB_V1.3",
                "runtime_string_offset": "0x11b38",
                "openwch_commit":
                    "64be9554615df522899579633530fd234d685682",
                "header": "EVT/EXAM/BLE/LIB/wchble_rom.h",
                "base_macros": "LIB_FLASH_BASE_ADDRESSS=0x00040000; "
                               "FUNCITON_BASE_ADDRESSS="
                               "LIB_FLASH_BASE_ADDRESSS+0x34",
            },
            "known_slots": {
                "0x4003c": "tmos_memcmp(src1, src2, len); returns TRUE "
                           "when buffers are equal",
                "0x40040": "tmos_isbufset(buf, value, len); returns TRUE "
                           "when every byte equals value",
                "0x40048": "tmos_memset(dst, value, len)",
                "0x4004c": "tmos_memcpy(dst, src, len)",
                "0x40050": "tmos_set_event(task_id, event)",
                "0x40068": "tmos_msg_deallocate(msg_ptr)",
                "0x40070": "tmos_msg_allocate(len)",
                "0x4017c": "GAPRole_TerminateLink(conn_handle)",
            },
        },
        "update_writer": {
            "worker": "0x1bc8",
            "writes_image": "boot",
            "accepted_start_target": 0,
            "in_progress_flag": "gp+0xd5",
            "flash_alias_base": "0x%08x" % BOOT_FLASH_ALIAS_BASE,
            "slot_size_bytes": 0x7000,
            "valid_page_indices": "0..27",
            "page_transport_bytes": 0x402,
            "page_payload_bytes": 0x400,
            "flash_write_fn": "0x1b5e",
            "flash_granularity_bytes": 0x100,
            "flash_functions": {
                "status_clear": "0x10010",
                "unlock_fast": "0x10018",
                "lock_fast": "0x10036",
                "erase_256": "0x10044",
                "program_256": "0x10072",
            },
            "prepare_transition": "0x55 target 1 schedules callbacks at "
                                  "0xe1a (200 ms) and 0x1e16 (400 ms) to "
                                  "transfer runtime-target updates to boot mode",
            "verify": "1024-byte word-by-word read-back comparison",
            "error_handling": "polls flash busy flags without timeout; does "
                              "not test flash error bits",
        },
        "handlers": map_dispatch(data),
    }

    rule_engine = {
        "entry": hex(RULE_ENGINE),
        "primary_table": {
            "location": "gp+0x80",
            "size_bytes": 256,
            "scan": "offset 0..0xFE step 2; byte N = trigger, byte N+1 = action",
            "usable_pairs": 127,
            "action_call": hex(ACTION_DISPATCH),
            "stored_fields": "trigger,action only; no delay/sequence/pointer",
        },
        "secondary_tables": [
            {"location": "gp+0x84", "entries": 36, "stride_bytes": 7,
             "trigger": "9-bit value from first two bytes",
             "gate": "bit 1 of second byte enables the operation"},
            {"location": "gp+0x88", "entries": 36, "stride_bytes": 7,
             "trigger": "9-bit value from first two bytes",
             "gate": "bit 1 of second byte enables the operation"},
        ],
    }

    for name, obj in [
        ("memory_map.json", memory_map),
        ("action_table.json", action_table),
        ("command_dispatch.json", command_dispatch),
        ("rule_engine.json", rule_engine),
    ]:
        with open(os.path.join(outdir, name), "w") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
        print(f"wrote {os.path.join(outdir, name)}")


if __name__ == "__main__":
    raise SystemExit(main())
