#!/usr/bin/env python3
"""Strip 1026-byte transport pages into a contiguous executable payload.

The vendor backend returns firmware as a stream of 1026-byte transport pages.
Each page is:

    byte 0      page index high (big-endian)
    byte 1      page index low
    bytes 2..   1024 bytes of executable payload

Removing the two-byte index from every page yields the contiguous image that
the MCU actually executes. All payload offsets used in the analysis docs refer
to the stripped image produced here.

Usage:
    extract_payload.py INPUT.bin OUTPUT.bin
"""
import hashlib
import sys

PAGE = 1026
PAYLOAD = 1024


def strip(transport: bytes) -> bytes:
    out = bytearray()
    for off in range(0, len(transport), PAGE):
        page = transport[off:off + PAGE]
        if len(page) < 3:
            break
        out += page[2:2 + PAYLOAD]
    return bytes(out)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    transport = open(sys.argv[1], "rb").read()
    payload = strip(transport)
    open(sys.argv[2], "wb").write(payload)
    print(f"transport: {len(transport)} bytes  sha256={hashlib.sha256(transport).hexdigest()}")
    print(f"payload:   {len(payload)} bytes  sha256={hashlib.sha256(payload).hexdigest()}")
    print(f"pages:     {len(transport) // PAGE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
