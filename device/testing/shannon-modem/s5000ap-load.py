#!/usr/bin/env python3
"""Manual CP boot spike for the s5000ap-boot kernel module.

Runs on the phone as root, one step per call.  The radio partition is only
ever opened read-only; efs/sec_efs/cpefs are never opened at all.  The NV
area of the CP memory gets a blank (0xff) image unless --nv names a scratch
copy.  The loader itself sends no IPC message; with module 0257 the link comes
up by itself and /dev/umts_ipc0 and /dev/umts_rfs0 carry IPC for user space.

  s5000ap-load.py plan                 parse the TOC, print what would be done
  s5000ap-load.py boot [--nv F]        the whole sequence below, then wait for
                                       the link (module auto_link=1, 0257)
  s5000ap-load.py step <name>          status | mbox | reinit | load | secure |
                                       on | boot_on | dl_start | handshake | off
                                       ipc (read-only look, any time after reinit)
  link bring-up after INIT_START (P2): pktproc | sbd_init | pif_done |
                                       link_reset | init_end | sbd | sbd_rx
  With auto_link=1 (default since 0257) the module does the link bring-up.

Order = the order cbd uses (disassembled): reinit (SECURITY_REQ mode 2, which
powers the CP) comes before the image is loaded, and `on` (AP2CP_CFG) only
after `secure`.  AP2CP_CFG must never be touched while the CP is off.
"""
import argparse
import os
import struct
import sys
import time
import zlib

DBG = "/sys/kernel/debug/s5000ap"
CP_BASE = 0x40000000          # CP view of the start of its memory
CHUNK = 4096
VSS_MAGIC_OFF = 0x700000       # DS DT abox-vss samsung,magic-offset


def parse_toc(img):
    toc = {}
    for i in range(16):
        ent = os.pread(img, 32, i * 32)
        name = ent[:12].rstrip(b"\0").decode("ascii", "replace")
        if not name:
            break
        b_off, m_off, size, crc, _ = struct.unpack("<5I", ent[12:])
        toc[name] = dict(b_off=b_off, m_off=m_off, size=size, crc=crc)
    for need in ("TOC", "BOOT", "MAIN", "NV"):
        if need not in toc:
            sys.exit(f"invalid TOC: no {need}")
    return toc


def read_exact(img, size, off):
    """Read in bounded chunks: a single large pread on a block device can
    come back short, which showed up once as a spurious MAIN CRC mismatch."""
    out = bytearray()
    while len(out) < size:
        part = os.pread(img, min(size - len(out), 1 << 20), off + len(out))
        if not part:
            sys.exit(f"short read at {off + len(out):#x}")
        out += part
    return bytes(out)


def section(img, ent):
    return read_exact(img, ent["size"], ent["b_off"])


def ctl(cmd):
    print(f"ctl: {cmd}")
    # One unbuffered write.  A buffered file object flushes again on close
    # after a failed write, which issued a failing step twice.
    fd = os.open(f"{DBG}/ctl", os.O_WRONLY)
    try:
        os.write(fd, cmd.encode())
    except OSError as e:
        sys.exit(f"step failed: {e} (see dmesg | grep s5000ap); not retried")
    finally:
        os.close(fd)


def put(mem, off, data, what):
    print(f"load {what}: {len(data):#x} bytes at +{off:#x}")
    for i in range(0, len(data), CHUNK):
        part = data[i:i + CHUNK]
        if os.pwrite(mem, part, off + i) != len(part):
            sys.exit("short write")
    for i in range(0, len(data), CHUNK):
        if os.pread(mem, min(CHUNK, len(data) - i), off + i) != data[i:i + CHUNK]:
            sys.exit(f"{what}: read-back mismatch at +{off + i:#x}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=("plan", "step", "boot", "restart"))
    ap.add_argument("name", nargs="?")
    ap.add_argument("--image", default="/dev/disk/by-partlabel/radio")
    ap.add_argument("--nv", help="scratch NV copy (default: blank 0xff image)")
    ap.add_argument("--link-wait", type=int, default=40,
                    help="boot: seconds to wait for the link (default 40)")
    args = ap.parse_args()

    img = os.open(args.image, os.O_RDONLY)
    toc = parse_toc(img)
    for name, e in toc.items():
        print(f"{name:7} b_off {e['b_off']:#9x} m_off {e['m_off']:#10x} "
              f"size {e['size']:#9x} crc {e['crc']:#010x}")
    for name in ("BOOT", "MAIN", "VSS"):
        if name in toc and zlib.crc32(section(img, toc[name])) != toc[name]["crc"]:
            sys.exit(f"{name}: CRC mismatch")
    print("BOOT/MAIN/VSS CRC ok")
    secure = f"secure 0 {toc['BOOT']['size']:#x} {toc['MAIN']['size']:#x}"

    if args.action == "plan":
        print("boot:  status, mbox, reinit, load[ --nv], secure, on, boot_on, ipc, dl_start, ipc, handshake")
        print("link:  (INIT_START) pktproc, sbd_init, pif_done, (PHONE_START) link_reset, init_end, sbd, sbd_rx, off")
        print(f"secure step would be: {secure}")
        return
    if args.action in ("boot", "restart"):
        if args.action == "boot":
            steps = ("status", "mbox", "reinit", "load", "secure", "on",
                     "boot_on", "dl_start", "handshake")
        else:
            # CP restart without an AP reboot (cbd's silent reset = the boot
            # sequence again): the re-init must give the image area back
            # (module refuses otherwise), VSS stays from the first boot.
            steps = ("status", "off", "mbox_reset", "reinit", "probe", "load_novss",
                     "secure", "on", "boot_on", "dl_start", "handshake", "boot_off")
        for st in steps:
            print(f"== {st}")
            do_step(st, img, toc, secure, args.nv)
        end = time.time() + args.link_wait
        while time.time() < end:
            with open(f"{DBG}/link_up") as f:
                if f.read().strip() == "Y":
                    print("LINK UP: /dev/umts_ipc0 /dev/umts_rfs0 ready")
                    return
            time.sleep(0.5)
        ctl("sbd")
        sys.exit("link did not come up; see dmesg | grep s5000ap (CP still on: run 'step off')")
    do_step(args.name, img, toc, secure, args.nv)
    print("done; see dmesg | grep s5000ap")


def do_step(step, img, toc, secure, nv_path):
    if step in ("mbox", "on", "dl_start", "boot_on", "status", "off", "ipc",
                "pktproc", "sbd_init", "pif_done", "link_reset", "init_end",
                "sbd", "sbd_rx", "mbox_reset", "boot_off"):
        ctl(step)
    elif step == "probe":
        # one small read of the image area: proves EL3 opened it before any write
        mem = os.open(f"{DBG}/cpmem", os.O_RDONLY)
        try:
            os.pread(mem, 4, toc["TOC"]["m_off"] - CP_BASE)
        except OSError as e:
            sys.exit(f"probe: CP image area not reachable ({e}); not loading")
        finally:
            os.close(mem)
        print("probe: CP image area readable")
    elif step == "reinit":
        ctl("secure 2 0 0")
    elif step in ("load", "load_novss"):
        mem = os.open(f"{DBG}/cpmem", os.O_RDWR)
        put(mem, toc["TOC"]["m_off"] - CP_BASE,
            read_exact(img, toc["TOC"]["size"], 0), "TOC")
        for name in ("BOOT", "MAIN") + (("VSS",) if step == "load" else ()):
            if name in toc:
                put(mem, toc[name]["m_off"] - CP_BASE, section(img, toc[name]), name)
        if nv_path:
            with open(nv_path, "rb") as f:
                nv = f.read()
            if len(nv) != toc["NV"]["size"]:
                sys.exit("NV copy has the wrong size")
        else:
            nv = b"\xff" * toc["NV"]["size"]
        put(mem, toc["NV"]["m_off"] - CP_BASE, nv, "NV (scratch)" if nv_path else "NV (blank)")
        if step == "load" and "VSS" in toc:
            # downstream abox-vss probe: clear the "CP magic" at VSS + 0x700000 before the
            # CP boots; the ABOX firmware polls it and starts VSS once the CP sets it
            put(mem, toc["VSS"]["m_off"] - CP_BASE + VSS_MAGIC_OFF, b"\0" * 16, "VSS magic (clear)")
    elif step == "secure":
        ctl(secure)
    elif step == "handshake":
        # cbd waits up to 30 s for each answer; so does the module.
        ctl("udl 0x900d")       # expect a00d back
        ctl("udl 0x9f00")       # expect af00 back
    else:
        sys.exit(f"unknown step {step}")


if __name__ == "__main__":
    main()
