#!/usr/bin/env python3
"""Consolidate all TSL6 runtime analysis artifacts into one symbol map.

Aggregates the named landmarks recovered across the analysis JSON files into a
single, de-duplicated address->label table, then emits two outputs:

  1. analysis/symbols.json   - structured symbols (address, name, kind, source).
  2. analysis/symbols.ghidra - flat text for Ghidra's ImportSymbolsScript.py,
     one `name address kind` per line (kind: f=function, l=label), addresses as
     image-base-0 offsets. Rebase in Ghidra to the program image base.

Sources merged:
  - functions.json        every recovered function entry (sub_XXXX, or a better
                          name when a landmark matches the entry).
  - command_dispatch.json BLE command handlers + shared helpers + vtable slots.
  - action_table.json     shared action workers + the action dispatcher/table.
  - telemetry.json        the packer and each per-signal getter.
  - can_map.json          the CAN-ID dispatcher + each per-ID decoder.
  - rule_triggers.json    the rule engine + each trigger call site (as comments).
  - internal_commands.json D0/D1/D2/F0 handlers, helpers, HID-binding entry.
  - config_worker.json    the F0 worker, its sub-handlers, shared primitives.

For the boot image, pass `--boot` to merge `boot_functions.json` + `boot.json`
instead (boot landmarks: reset entry, update dispatcher, write-page handler,
flash-program function).

Deterministic and re-runnable.

Usage:
    gen_symbols.py        analysis/ analysis/symbols.json      analysis/symbols.ghidra
    gen_symbols.py --boot analysis/ analysis/boot_symbols.json analysis/boot_symbols.ghidra
"""
import json
import os
import re
import sys


def load(d, name):
    p = os.path.join(d, name)
    return json.load(open(p)) if os.path.exists(p) else None


def norm(s):
    """Make a label a valid C identifier fragment."""
    s = re.sub(r"[^0-9A-Za-z]+", "_", s).strip("_")
    return s or "x"


def parse_addr(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.startswith("0x"):
        try:
            return int(v, 16)
        except ValueError:
            return None
    return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    adir = args[0]
    out_json = args[1]
    out_ghidra = args[2]
    image = "boot" if "--boot" in flags else "runtime"

    # address -> {name, kind, source}; first writer with a "good" name wins,
    # but a function entry is always upgraded to its specific landmark name.
    syms = {}

    def add(addr, name, kind, source, force=False):
        if addr is None:
            return
        if addr in syms and not force:
            # keep the more specific (non sub_) name
            if syms[addr]["name"].startswith("sub_") and not name.startswith("sub_"):
                pass
            else:
                return
        syms[addr] = {"address": hex(addr), "name": name,
                      "kind": kind, "source": source}

    if image == "boot":
        build_boot(adir, add)
        rows = finalize(syms)
        write_outputs(rows, out_json, out_ghidra, image)
        return

    # 1. functions -> generic names first (lowest priority)
    fns = load(adir, "functions.json")
    if fns:
        for f in fns["functions"]:
            add(f["start"], "sub_%04x" % f["start"], "f", "functions")

    # 2. command dispatch
    cd = load(adir, "command_dispatch.json")
    if cd:
        add(parse_addr(cd.get("dispatcher")), "ble_cmd_dispatch", "f",
            "command_dispatch", force=True)
        add(parse_addr(cd.get("update_dispatcher")), "update_dispatch", "f",
            "command_dispatch", force=True)
        add(parse_addr(cd.get("a2_handler")), "cmd_A2_handler", "f",
            "command_dispatch", force=True)
        for off, desc in (cd.get("shared_helpers") or {}).items():
            a = parse_addr(off)
            label = {
                "0x110a": "ble_tx_framer", "0xb76c": "cmd_reply_builder",
                "0xb7c6": "status_reply_builder",
                "0xb86e": "telemetry_producer",
                "0xbdb8": "cmd_reply_tail",
            }.get(off, "helper_%s" % norm(off))
            add(a, label, "f", "command_dispatch", force=True)
        for h in cd.get("handlers", []):
            a = parse_addr(h.get("handler"))
            add(a, "cmd_%s_handler" % h["command_hex"][2:].upper(), "f",
                "command_dispatch", force=True)

    # 3. action table
    at = load(adir, "action_table.json")
    if at:
        add(parse_addr(at.get("dispatcher")), "action_dispatch", "f",
            "action_table", force=True)
        for off, desc in (at.get("shared_workers") or {}).items():
            a = parse_addr(off)
            label = {
                "0x33e2": "keycode_primitive",
                "0x3a30": "action139_latch",
                "0xf296": "onehot_bitfield_worker",
            }.get(off, "worker_%s" % norm(off))
            add(a, label, "f", "action_table", force=True)
        for e in at.get("entries", []):
            w = parse_addr(e.get("worker"))
            if w is not None and w < (fns["function_count"] and 0x12000):
                # name action workers that live in-image
                pass  # workers already covered by shared_workers / functions

    # 4. telemetry
    tel = load(adir, "telemetry.json")
    if tel:
        add(parse_addr(tel.get("producer")), "telemetry_packer", "f",
            "telemetry", force=True)
        for fld in tel.get("fields", []):
            a = parse_addr(fld.get("getter"))
            add(a, "get_%s" % norm(fld.get("label", "signal")), "f",
                "telemetry")

    # 5. CAN map
    cm = load(adir, "can_map.json")
    if cm:
        add(parse_addr(cm.get("dispatcher")), "can_id_dispatch", "f",
            "can_map", force=True)
        for r in cm.get("ids", []):
            a = parse_addr(r.get("decoder"))
            if a is None:
                continue
            cid = r["can_id_hex"][2:].upper()
            if r.get("stored_raw"):
                add(a, "can_raw_frame_store", "f", "can_map", force=True)
            else:
                add(a, "can_decode_%s" % cid, "f", "can_map", force=True)

    # 6. rule engine + triggers
    re_ = load(adir, "rule_engine.json")
    if re_:
        add(parse_addr(re_.get("entry")), "rule_engine", "f", "rule_engine",
            force=True)
    # rule_triggers.json's action_dispatch is the same 0xd16e already named
    # from action_table.json; no separate symbol needed.

    # 7. internal commands
    ic = load(adir, "internal_commands.json")
    if ic:
        for h in ic.get("handlers", []):
            add(parse_addr(h.get("handler")),
                "cmd_%s_handler" % h["command_hex"][2:].upper(), "f",
                "internal_commands", force=True)
            for hk, hv in (h.get("helpers") or {}).items():
                add(parse_addr(hk), "icmd_helper_%s" % norm(hk), "f",
                    "internal_commands")
        nb = ic.get("hid_name_binding")
        if nb:
            a = parse_addr((nb.get("entry") or "").split("-")[0])
            add(a, "hid_name_binding", "f", "internal_commands", force=True)

    # 8. config worker
    cw = load(adir, "config_worker.json")
    if cw:
        add(parse_addr(cw.get("entry")), "f0_config_worker", "f",
            "config_worker", force=True)
        for hk, hv in (cw.get("shared_primitives") or {}).items():
            a = parse_addr(hk)
            if a is not None and a < 0x12000:
                add(a, "cfg_%s" % norm(hk), "f", "config_worker")
        for sh in cw.get("sub_handlers", []):
            add(parse_addr(sh.get("target")),
                "f0_sub%d" % sh["selector"], "l", "config_worker")

    rows = finalize(syms)
    write_outputs(rows, out_json, out_ghidra, image)


def finalize(syms):
    rows = [syms[a] for a in sorted(syms)]
    # Ensure unique labels: if two addresses share a name, suffix with address.
    seen = {}
    for r in rows:
        if r["name"] in seen:
            r["name"] = "%s_%s" % (r["name"], r["address"][2:])
        else:
            seen[r["name"]] = r["address"]
    return rows


def write_outputs(rows, out_json, out_ghidra, image):
    doc = {
        "image": image,
        "image_base": "0x0 (rebase to program image base in Ghidra)",
        "symbol_count": len(rows),
        "named_count": sum(1 for r in rows if not r["name"].startswith("sub_")),
        "kinds": {"f": "function entry", "l": "code label"},
        "symbols": rows,
    }
    with open(out_json, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")

    with open(out_ghidra, "w") as f:
        f.write("# TSL6 %s symbols for Ghidra ImportSymbolsScript.py\n" % image)
        f.write("# format: name address kind (f=function, l=label)\n")
        f.write("# addresses are image-base-0 offsets; rebase as needed.\n")
        for r in rows:
            f.write("%s %s %s\n" % (r["name"], r["address"], r["kind"]))

    print("wrote %s (%d symbols, %d named) and %s" % (
        out_json, len(rows), doc["named_count"], out_ghidra))


def build_boot(adir, add):
    """Merge boot-image artifacts into the symbol table."""
    # 1. boot functions -> generic names
    bf = load(adir, "boot_functions.json")
    if bf:
        for f in bf["functions"]:
            add(f["start"], "sub_%04x" % f["start"], "f", "boot_functions")

    # 2. boot landmarks from boot.json
    b = load(adir, "boot.json")
    if b:
        add(parse_addr(b.get("reset_jump_target")), "boot_reset_entry", "f",
            "boot", force=True)
        add(parse_addr(b.get("update_dispatcher")), "update_dispatch", "f",
            "boot", force=True)
        wp = b.get("write_page_flow") or {}
        add(parse_addr(wp.get("handler")), "write_page_handler", "f", "boot",
            force=True)
        add(parse_addr(wp.get("flash_program_fn")), "flash_program", "f",
            "boot", force=True)
        # update_commands keys are command bytes, not addresses; skip.


if __name__ == "__main__":
    raise SystemExit(main())
