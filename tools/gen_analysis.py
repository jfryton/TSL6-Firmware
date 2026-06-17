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
            regs[ops[0]] = (ins.address + (int(ops[1], 0) << 12)) & 0xFFFFFFFF
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
    memory_map = {
        "image": "runtime",
        "payload_size": len(data),
        "image_base": "0x0 (downloaded representation; not final flash offset)",
        "reset_jump_target": hex(RESET_TARGET),
        "global_pointer_gp": hex(consts["gp"]) if consts["gp"] else None,
        "stack_pointer_sp": hex(consts["sp"]) if consts["sp"] else None,
        "ram_base": "0x20000000",
        "peripheral_base": "0x40000000",
        "notes": [
            "Application code is self-contained within the 0x0-0x12000 payload.",
            "Hardware/BLE-stack entry points referenced from startup live in a "
            "resident region above the downloadable image; the server image is "
            "the updatable application/runtime slot only.",
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
                      "state byte 0x20003f2c); used by media/AP/steering actions",
            "0x3a30": "action 139 latch: writes 0x0C to countdown byte "
                      "0x20003f2d; decremented by periodic handler at 0x3ce0, "
                      "which sets a state bit when it expires (timed "
                      "steering-wheel hold/release)",
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
            "0x110a": "async BLE TX framer/enqueue; 15-slot, 12-byte queue at "
                      "RAM 0x20003e28; dispatches via resident notify pointer "
                      "0x40000050",
            "0xb76c": "command reply builder; allocates via resident pointer "
                      "0x40000070, then enqueues through 0x110a",
            "0xb7c6": "module status reply builder",
            "0xb86e": "dashboard telemetry producer (35-byte 0xB0 packet, "
                      "rate-limited via gp+0x178 timestamp)",
            "0xbdb8": "command-reply tail used by 0xA2/0xBB handlers",
        },
        "ble_stack_vtable": {
            "base": "0x40000000",
            "note": "Resident BLE-stack function pointers loaded via lui 0x40 "
                    "+ offset and called indirectly (jr/jalr). Not in image.",
            "known_slots": {
                "0x40000050": "BLE notify/send entry (used by TX framer 0x110a)",
                "0x40000070": "buffer allocator (used by reply builder 0xb76c)",
            },
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
