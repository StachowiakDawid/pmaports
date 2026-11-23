#!/usr/bin/env python3
"""Watch the Shannon IPC channels exposed by s5000ap-boot (patch 0257).

Opens /dev/umts_ipc0, umts_ipc1 and umts_rfs0 read-only in spirit (nothing is
ever written) and prints one line per frame: channel, length and the IPC
header.  Payload bytes are NOT printed unless --dump N is given, because FMT
payloads can carry SIM/subscriber data.  Run as root on the phone after
`s5000ap-load.py boot`.

  FMT header (ipc0/ipc1): u16 length, u8 mseq, u8 aseq, u8 group, u8 index, u8 type
  RFS header (rfs0):      u32 length, u8 index, u8 id
"""
import argparse
import os
import select
import struct
import sys
import time

DEVS = ("umts_ipc0", "umts_ipc1", "umts_rfs0")


def describe(name, buf):
    if name == "umts_rfs0" and len(buf) >= 6:
        length, index, rid = struct.unpack_from("<IBB", buf)
        return f"rfs len {length} cmd 0x42{index:02x} id {rid}"
    if len(buf) >= 7:
        length, mseq, aseq, group, index, typ = struct.unpack_from("<HBBBBB", buf)
        return (f"fmt len {length} mseq {mseq} aseq {aseq} "
                f"cmd 0x{group:02x}{index:02x} type {typ}")
    return "short frame"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", type=int, default=0,
                    help="also print N payload bytes per frame (may show SIM data)")
    ap.add_argument("--time", type=float, default=0, help="stop after N seconds")
    args = ap.parse_args()

    fds = {}
    for d in DEVS:
        fds[os.open(f"/dev/{d}", os.O_RDONLY | os.O_NONBLOCK)] = d
    p = select.poll()
    for fd in fds:
        p.register(fd, select.POLLIN)
    t0 = time.time()
    while not args.time or time.time() - t0 < args.time:
        for fd, _ in p.poll(500):
            try:
                buf = os.read(fd, 65536)
            except BlockingIOError:
                continue
            name = fds[fd]
            hdr = 6 if name == "umts_rfs0" else 7
            line = f"{time.time() - t0:8.3f} {name:9} {len(buf):5}B {describe(name, buf)}"
            if args.dump:
                line += " | " + buf[hdr:hdr + args.dump].hex(" ")
            print(line, flush=True)


if __name__ == "__main__":
    sys.exit(main())
