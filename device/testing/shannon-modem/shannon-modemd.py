#!/usr/bin/env python3
"""Minimal userspace for the Shannon S5000AP CP on pmOS (s5000ap-boot, patches 0257/0258).

Two jobs, both following stock libsec-ril.so (reverse engineered):

  RFS server  /dev/umts_rfs0   answers the CP's NV and file requests from a SCRATCH copy
                               of the EFS (see shannon-efs-scratch.sh).  Every host path is
                               confined to --efs; the real efs/cpefs partitions are never
                               opened.  Refuses to start unless --efs is on tmpfs.
  FMT client  /dev/umts_ipc0   waits for PWR_UP, puts the radio into LPM (airplane) at once,
                               then asks for version, SIM status, registration, operator and
                               signal.  The radio stays off unless the daemon was started with
                               --allow-radio AND `radio on` is written to the control FIFO.

Privacy: no payload is ever printed.  IMEI/IMSI/serials are never requested; LAC/cell id,
SMS bodies and phone numbers are not printed.  NV data stays in the scratch directory.

  shannon-modemd.py --efs /run/shannon-efs [--allow-radio] [--ctl /run/shannon/ctl]
  echo "get reg" > /run/shannon/ctl        (get ver|pin|reg|net|icon, radio off|on, quit)
"""
import argparse
import errno
import signal
import hashlib
import os
import queue
import re
import shutil
import ipaddress
import stat
import struct
import subprocess
import sys
import threading
import time

RFS_DEV = "/dev/umts_rfs0"
FMT_DEV = "/dev/umts_ipc0"
FMT2_DEV = "/dev/umts_ipc1"
NV_NAME = "nv_data.bin"
NV_SIZE = 0x100000
NV_SECRET = b"Samsung_Android_RIL"
MAX_RFS = 0x80000
DATA_MAX = 0x80000
FILE_CHUNK = 0x40000
PATH_FIELD = 0x400
MAX_FDS = 64

T0 = time.monotonic()
_log_lock = threading.Lock()


def log(*a):
    with _log_lock:
        print(f"{time.monotonic() - T0:9.3f}", *a, flush=True)


# --------------------------------------------------------------------------- RFS

RFS_NAMES = {
    0x01: "NV_READ_ITEM", 0x02: "NV_WRITE_ITEM", 0x03: "READ_FILE", 0x04: "WRITE_FILE",
    0x05: "LSEEK_FILE", 0x06: "CLOSE_FILE", 0x07: "PUT_FILE", 0x08: "GET_FILE",
    0x09: "RENAME_FILE", 0x0A: "GET_FILE_INFO", 0x0B: "UNLINK_FILE", 0x0C: "MAKE_DIR",
    0x0D: "REMOVE_DIR", 0x0E: "OPEN_DIR", 0x0F: "READ_DIR", 0x10: "CLOSE_DIR",
    0x11: "OPEN_FILE", 0x12: "FTRUNCATE_FILE", 0x13: "GET_HANDLE_INFO", 0x14: "CREATE_FILE",
    0x15: "NV_WRITE_ALL_ITEM", 0x16: "NV_BUFFER_MESSAGE", 0x17: "NV_RESTORE",
}
# open() flags the CP may pass (arm64 values == Python's on the phone); O_SYNC is added
# like the stock RIL, O_NOFOLLOW/O_CLOEXEC for safety.
OPEN_OK = (os.O_ACCMODE | os.O_CREAT | os.O_EXCL | os.O_TRUNC | os.O_APPEND |
           os.O_NONBLOCK | os.O_DSYNC | os.O_SYNC)


class Refused(Exception):
    pass


class Rfs:
    def __init__(self, efs, verbose):
        self.efs = os.path.realpath(efs)
        self.nv = os.path.join(self.efs, NV_NAME)
        self.verbose = verbose
        self.fds = {}            # host fd -> path, only fds opened for the CP
        self.nvbuf = None        # (offset, bytearray) while NV_BUFFER_MESSAGE is open
        self.stats = {}

    # path mapping (Nv::MakeRfsDirectoryName), confined to the scratch dir
    def host(self, raw):
        p = raw.split(b"\0", 1)[0].decode("latin-1")
        if any(c == ".." for c in p.split("/")):
            raise Refused("'..' in path")
        if p.startswith(("err", "/data/vendor/log")):
            sub = "log"
        elif p.startswith(("Audio_OEM", "Audio_IFX", "CP_AUDIO_SLSI", "RF_NVM",
                           "CP_OMC_AUDIO_SLSI")):
            sub = "etc"          # stock: /system/etc, /vendor/firmware; not mirrored
        else:
            sub = "root"
        h = os.path.normpath(os.path.join(self.efs, sub, p.lstrip("/")))
        real = os.path.realpath(h)
        if not (real == self.efs or real.startswith(self.efs + "/")):
            raise Refused(f"outside scratch: {p}")
        return h, p

    def path_at(self, buf, len_off, path_off, cap=PATH_FIELD):
        n = min(struct.unpack_from("<I", buf, len_off)[0], cap)
        return self.host(bytes(buf[path_off:path_off + n]))

    def fd(self, buf, off):
        fd = struct.unpack_from("<i", buf, off)[0]
        if fd not in self.fds:
            raise OSError(errno.EBADF, "not a CP handle")
        return fd

    # response shapes (spec 1.5)
    @staticmethod
    def r14(cmd, rid, ret, err=0):
        return struct.pack("<IBBiI", 14, cmd, rid, ret, err)

    @staticmethod
    def r18(cmd, rid, ret, err=0):
        return struct.pack("<IBBIiI", 18, cmd, rid, 0, ret, err)

    @staticmethod
    def rinfo(cmd, rid, st=None, err=0):
        if st is None:
            return struct.pack("<IBBiHI6s6sI", 32, cmd, rid, -1, 0, 0, b"", b"", err)

        def tm(t):
            x = time.localtime(t)
            return bytes([max(0, x.tm_year - 2000) & 0xFF, x.tm_mon, x.tm_mday,
                          x.tm_hour, x.tm_min, x.tm_sec])
        typ = 1 if stat.S_ISDIR(st.st_mode) else 2
        return struct.pack("<IBBiHI6s6sI", 32, cmd, rid, 0, typ, st.st_size & 0xFFFFFFFF,
                           tm(st.st_ctime), tm(st.st_mtime), 0)

    # NV file helpers (scratch copy only)
    def nv_update_md5(self):
        with open(self.nv, "rb") as f:
            data = f.read()
        if len(data) != NV_SIZE:
            log(f"rfs: {NV_NAME} has size {len(data):#x}, md5 not updated")
            return
        with open(self.nv + ".md5", "w") as f:
            f.write(hashlib.md5(data + NV_SECRET).hexdigest())

    def nv_write(self, off, data):
        if off + len(data) > NV_SIZE:
            raise OSError(errno.EINVAL, "beyond the NV file")
        fd = os.open(self.nv, os.O_RDWR | os.O_SYNC | os.O_NOFOLLOW)
        try:
            n = os.pwrite(fd, data, off)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.nv_update_md5()
        if off in (0x180014, 0x181469):
            log(f"rfs: CP wrote NV item {off:#x} (identity/lock area) - scratch copy only")
        return n

    def handle(self, buf):
        cmd, rid = buf[4], buf[5]
        name = RFS_NAMES.get(cmd, f"cmd{cmd:#x}")
        self.stats[name] = self.stats.get(name, 0) + 1
        what = ""
        try:
            rsp, what = self._handle(cmd, rid, buf)
        except Refused as e:
            log(f"rfs: {name} id {rid}: REFUSED {e}")
            rsp = self.refused(cmd, rid)
        if what and (self.verbose or rsp is None or what.startswith("ERR")):
            log(f"rfs: {name} id {rid}: {what}" + ("" if rsp is not None else " (no response)"))
        return rsp

    def refused(self, cmd, rid):
        if cmd in (0x01, 0x02):
            return struct.pack("<IBBBII", 15, cmd, rid, 0, 0, 0)
        if cmd in (0x0A, 0x13):
            return self.rinfo(cmd, rid, None, errno.EACCES)
        if cmd in (0x05, 0x07):
            return self.r18(cmd, rid, -1, errno.EACCES)
        if cmd in (0x03, 0x08):
            return struct.pack("<IBBiI", 14, cmd, rid, 0 if cmd == 3 else -1, errno.EACCES)
        if cmd in (0x15, 0x16):
            return struct.pack("<IBBB6x", 13, cmd, rid, 0)
        return self.r14(cmd, rid, -1, errno.EACCES)

    def _handle(self, cmd, rid, b):
        u32 = lambda o: struct.unpack_from("<I", b, o)[0]
        if cmd == 0x01:                                   # NV_READ_ITEM
            off, size = u32(6), min(u32(10), DATA_MAX)
            try:
                with open(self.nv, "rb") as f:
                    f.seek(off)
                    data = f.read(size)
                ok = 1
            except OSError as e:
                data, ok = b"", 0
                return (struct.pack("<IBBBII", 15, cmd, rid, 0, off, 0),
                        f"ERR off {off:#x} size {size:#x}: {e}")
            return (struct.pack("<IBBBII", 15 + len(data), cmd, rid, ok, off, len(data)) + data,
                    f"off {off:#x} size {size:#x} -> {len(data):#x}")
        if cmd in (0x02, 0x15):                           # NV_WRITE_ITEM / WRITE_ALL
            off, size = u32(6), min(u32(10), DATA_MAX)
            data = bytes(b[14:14 + size])
            if cmd == 0x02 and self.nvbuf is not None:
                boff, nb = self.nvbuf
                if not (boff <= off and off + len(data) <= boff + len(nb)):
                    return (struct.pack("<IBBBII", 15, cmd, rid, 0, off, 0),
                            f"ERR buffered write {off:#x}+{len(data):#x} outside buffer")
                nb[off - boff:off - boff + len(data)] = data
                return (struct.pack("<IBBBII", 15, cmd, rid, 1, off, 0xFFFFFFFF),
                        f"buffered off {off:#x} size {len(data):#x}")
            try:
                n, ok = self.nv_write(off, data), 1
            except OSError as e:
                n, ok = 0, 0
                what = f"ERR off {off:#x} size {len(data):#x}: {e}"
            else:
                what = f"off {off:#x} size {len(data):#x}"
            if cmd == 0x02:
                return (struct.pack("<IBBBII", 15, cmd, rid, ok, off,
                                    n if ok else 0xFFFFFFFF), what)
            return struct.pack("<IBBBIH", 13, cmd, rid, ok, off, n & 0xFFFF), what
        if cmd == 0x16:                                   # NV_BUFFER_MESSAGE
            mode, off, size = b[6], u32(7), u32(11)
            ok = 1
            if mode == 1:
                if size > NV_SIZE or off + size > NV_SIZE:
                    ok, what = 0, f"ERR start {off:#x}+{size:#x} too big"
                else:
                    with open(self.nv, "rb") as f:
                        f.seek(off)
                        self.nvbuf = (off, bytearray(f.read(size).ljust(size, b"\xff")))
                    what = f"start off {off:#x} size {size:#x}"
            else:
                if self.nvbuf is None:
                    ok, what = 0, "ERR end without start"
                else:
                    boff, nb = self.nvbuf
                    self.nvbuf = None
                    try:
                        self.nv_write(boff, bytes(nb))
                        what = f"end: wrote {boff:#x}+{len(nb):#x}"
                    except OSError as e:
                        ok, what = 0, f"ERR end: {e}"
            return struct.pack("<IBBB6x", 13, cmd, rid, ok), what
        if cmd == 0x17:                                   # NV_RESTORE (scratch backup)
            bak = os.path.join(self.efs, ".nv_data.bak")
            try:
                shutil.copyfile(bak, self.nv)
                self.nv_update_md5()
                return self.r14(cmd, rid, 0), "restored scratch nv_data.bin from scratch .nv_data.bak"
            except OSError as e:
                return self.r14(cmd, rid, -1, e.errno or errno.EIO), f"ERR {e}"

        if cmd == 0x11:                                   # OPEN_FILE
            flags = u32(6)
            h, p = self.path_at(b, 10, 14)
            try:
                os.makedirs(os.path.dirname(h), 0o775, exist_ok=True)
                if len(self.fds) >= MAX_FDS:
                    raise OSError(errno.EMFILE, "too many CP handles")
                fd = os.open(h, (flags & OPEN_OK) | os.O_SYNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o775)
                self.fds[fd] = p
                return self.r14(cmd, rid, fd), f"{p} flags {flags:#x} -> fd {fd}"
            except OSError as e:
                return self.r14(cmd, rid, -1, e.errno), f"ERR {p} flags {flags:#x}: {e.strerror}"
        if cmd == 0x14:                                   # CREATE_FILE
            h, p = self.path_at(b, 6, 10)
            try:
                if len(self.fds) >= MAX_FDS:
                    raise OSError(errno.EMFILE, "too many CP handles")
                fd = os.open(h, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW |
                             os.O_CLOEXEC, 0o775)
                self.fds[fd] = p
                return self.r14(cmd, rid, fd), f"{p} -> fd {fd}"
            except OSError as e:
                return self.r14(cmd, rid, -1, e.errno), f"ERR {p}: {e.strerror}"
        if cmd == 0x03:                                   # READ_FILE
            try:
                fd = self.fd(b, 6)
                data = os.read(fd, min(u32(10), FILE_CHUNK))
                return (struct.pack("<IBBiI", 14 + len(data), cmd, rid, len(data), 0) + data,
                        f"fd {fd} ({self.fds[fd]}) -> {len(data):#x}")
            except OSError as e:
                return struct.pack("<IBBiI", 14, cmd, rid, 0, e.errno), f"ERR {e.strerror}"
        if cmd == 0x04:                                   # WRITE_FILE
            try:
                fd = self.fd(b, 6)
                n = os.write(fd, bytes(b[14:14 + min(u32(10), DATA_MAX)]))
                return self.r14(cmd, rid, n), f"fd {fd} ({self.fds[fd]}) {n:#x}"
            except OSError as e:
                return self.r14(cmd, rid, -1, e.errno), f"ERR {e.strerror}"
        if cmd == 0x05:                                   # LSEEK_FILE
            try:
                fd = self.fd(b, 6)
                off, whence = u32(10), struct.unpack_from("<i", b, 14)[0]
                pos = os.lseek(fd, off, whence)
                return self.r18(cmd, rid, pos), f"fd {fd} {off:#x}/{whence} -> {pos:#x}"
            except OSError as e:
                return self.r18(cmd, rid, -1, e.errno), f"ERR {e.strerror}"
        if cmd == 0x06:                                   # CLOSE_FILE
            try:
                fd = self.fd(b, 6)
                p = self.fds.pop(fd)
                os.close(fd)
                return self.r14(cmd, rid, 0), f"fd {fd} ({p})"
            except OSError as e:
                return self.r14(cmd, rid, -1, e.errno), f"ERR {e.strerror}"
        if cmd == 0x13:                                   # GET_HANDLE_INFO
            try:
                fd = self.fd(b, 6)
                return self.rinfo(cmd, rid, os.fstat(fd)), f"fd {fd}"
            except OSError as e:
                return self.rinfo(cmd, rid, None, e.errno), f"ERR {e.strerror}"
        if cmd == 0x07:                                   # PUT_FILE
            flags = u32(6)
            h, p = self.path_at(b, 10, 14)
            size = min(u32(0x40E), DATA_MAX)
            try:
                fd = os.open(h, (flags & OPEN_OK) | os.O_SYNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o775)
                try:
                    os.write(fd, bytes(b[0x412:0x412 + size]))
                finally:
                    os.close(fd)
                return self.r18(cmd, rid, size), f"{p} {size:#x}"
            except OSError as e:
                return self.r18(cmd, rid, -1, e.errno), f"ERR {p}: {e.strerror}"
        if cmd == 0x08:                                   # GET_FILE
            h, p = self.path_at(b, 6, 10, 0x3FF)
            size = min(u32(0x40A), FILE_CHUNK)
            try:
                fd = os.open(h, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    data = os.read(fd, size)
                finally:
                    os.close(fd)
                cnt, err, what = len(data), 0, f"{p} -> {len(data):#x}"
            except OSError as e:
                data, cnt, err, what = b"", -1, e.errno, f"ERR {p}: {e.strerror}"
            return (struct.pack("<IBBiI", 14 + FILE_CHUNK, cmd, rid, cnt, err) +
                    data.ljust(FILE_CHUNK, b"\0")), what
        if cmd == 0x09:                                   # RENAME_FILE
            ho, po = self.path_at(b, 6, 10)
            hn, pn = self.path_at(b, 0x40A, 0x40E)
            try:
                os.rename(ho, hn)
                return self.r14(cmd, rid, 0), f"{po} -> {pn}"
            except OSError as e:
                return self.r14(cmd, rid, -1, e.errno), f"ERR {po} -> {pn}: {e.strerror}"
        if cmd == 0x0A:                                   # GET_FILE_INFO
            h, p = self.path_at(b, 6, 10)
            try:
                return self.rinfo(cmd, rid, os.lstat(h)), p
            except OSError as e:
                return self.rinfo(cmd, rid, None, e.errno), f"ERR {p}: {e.strerror}"
        if cmd == 0x0B:                                   # UNLINK_FILE
            h, p = self.path_at(b, 6, 10)
            try:
                os.unlink(h)
                return self.r14(cmd, rid, 0), p
            except OSError as e:
                return self.r14(cmd, rid, -1, e.errno), f"ERR {p}: {e.strerror}"
        if cmd == 0x0C:                                   # MAKE_DIR
            h, p = self.path_at(b, 6, 10, 0x3FF)
            try:
                os.makedirs(h, 0o775, exist_ok=True)
                return self.r14(cmd, rid, 0), p
            except OSError as e:
                return self.r14(cmd, rid, -1, e.errno), f"ERR {p}: {e.strerror}"
        return None, "not handled by the stock RIL either"


def rfs_loop(rfs, stop):
    fd = os.open(RFS_DEV, os.O_RDWR)
    log(f"rfs: serving {rfs.efs}")
    pend = None
    while not stop.is_set():
        try:
            chunk = os.read(fd, 0x100000)
        except InterruptedError:
            continue
        if not chunk:
            continue
        if pend is None:
            if len(chunk) < 6:
                log(f"rfs: short frame {len(chunk)}")
                continue
            total = struct.unpack_from("<I", chunk)[0]
            if total > MAX_RFS + 0x1000 or total < 6:
                log(f"rfs: bad frame length {total:#x}, dropped")
                continue
            pend = bytearray(chunk)
        else:
            pend += chunk
        if len(pend) < total:
            continue
        if len(pend) > total:
            log(f"rfs: overflow {len(pend):#x} > {total:#x}, dropped")
            pend = None
            continue
        rsp = rfs.handle(pend)
        pend = None
        if rsp is not None:
            try:
                os.write(fd, rsp)
            except OSError as e:
                log(f"rfs: write failed: {e}")


# --------------------------------------------------------------------------- FMT

GROUPS = {0x01: "PWR", 0x02: "CALL", 0x04: "SMS", 0x05: "SEC", 0x06: "PB", 0x07: "DISP",
          0x08: "NET", 0x09: "SND", 0x0A: "MISC", 0x0B: "SVC", 0x0C: "SS", 0x0D: "GPRS",
          0x0E: "SAT", 0x0F: "CFG", 0x10: "IMEI", 0x11: "GPS", 0x12: "SAP", 0x13: "FACTORY",
          0x16: "IMS", 0x27: "SYSTEM", 0x80: "GEN"}
SUBS = {(0x01, 0x01): "PHONE_PWR_UP", (0x01, 0x02): "PHONE_PWR_OFF", (0x01, 0x03): "PHONE_RESET",
        (0x01, 0x07): "PHONE_STATE", (0x05, 0x01): "PIN_STATUS", (0x0A, 0x01): "ME_VERSION",
        (0x0A, 0x02): "ME_IMSI", (0x0A, 0x03): "ME_SN", (0x08, 0x03): "SERVING_NETWORK",
        (0x08, 0x05): "REGIST", (0x07, 0x01): "ICON_INFO", (0x07, 0x06): "RSSI_INFO",
        (0x04, 0x01): "SEND_MSG", (0x04, 0x02): "INCOMING_MSG", (0x04, 0x06): "DELIVER_REPORT",
        (0x04, 0x07): "DEVICE_READY", (0x80, 0x01): "PHONE_RES",
        (0x0D, 0x01): "DEFINE_PDP_CONTEXT", (0x0D, 0x04): "PDP_CONTEXT",
        (0x0D, 0x09): "IP_CONFIGURATION", (0x0D, 0x10): "CALL_STATUS",
        (0x0D, 0x03): "PS", (0x0D, 0x14): "ATTACH_APN", (0x0D, 0x19): "LTE_CA_STATUS",
        (0x0A, 0x0F): "SCREEN_STATE",
        (0x02, 0x01): "OUTGOING", (0x02, 0x02): "INCOMING", (0x02, 0x03): "RELEASE",
        (0x02, 0x04): "ANSWER", (0x02, 0x05): "STATUS", (0x02, 0x06): "LIST",
        (0x02, 0x07): "BURST_DTMF", (0x02, 0x09): "WAITING", (0x09, 0x09): "CLOCK_CTRL",
        (0x27, 0x01): "CP_CHANNEL_INFO", (0x05, 0x09): "IMS_AUTH", (0x16, 0x08): "IMS_REGI"}
RX_TYPES = {1: "INDI", 2: "RESP", 3: "NOTI"}
EXEC, GET, SET, CFRM, EVENT = 1, 2, 3, 4, 5
PIN = {0x00: "ready", 0x03: "PIN/PUK lock", 0x05: "network lock", 0x80: "no card",
       0x81: "card error", 0x82: "init complete", 0x83: "phonebook ready",
       0x84: "blocked", 0x88: "removed", 0x89: "inserted", 0x8C: "eSIM no profile"}
REG = {0x01: "not registered", 0x08: "not registered", 0x02: "home", 0x20: "home",
       0x22: "home", 0x03: "searching", 0x04: "denied", 0x09: "denied", 0x06: "roaming",
       0x07: "emergency only", 0x0A: "emergency only"}
ACT = {0x01: "GSM", 0x02: "GPRS", 0x03: "EDGE", 0x04: "UMTS", 0x05: "HSPA", 0x21: "LTE",
       0x22: "TD-SCDMA", 0x24: "NR", 0xFF: "any"}

QUERIES = {
    "ver": (0x0A, 0x01, GET, b"\xff"),
    "pin": (0x05, 0x01, GET, b""),
    "reg": (0x08, 0x05, GET, b"\xff\x02"),
    "regps": (0x08, 0x05, GET, b"\xff\x03"),
    "net": (0x08, 0x03, GET, b""),
    "icon": (0x07, 0x01, GET, b"\x01"),
    "imeicheck": (0x0A, 0x03, GET, b"\x01"),
    "smsc": (0x04, 0x0A, GET, b""),
    "smsready": (0x04, 0x07, SET, b""),          # stock IpcTxSetDeviceReady
    "voicepref": (0x0A, 0x2D, GET, b""),         # MISC_DEVICE_CAPA: voice domain pref   # answer is checked, never printed
}


# GSM 03.38 default alphabet (basic table); anything else goes out as UCS-2.
GSM7 = ("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
        "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")


def sms_submit_pdu(number, text):
    """SMS-SUBMIT TPDU (3GPP 23.040), single part, no validity period, SCA from the SIM.
    Returns (pdu, coding) or raises ValueError."""
    intl = number.startswith("+")
    digits = number[1:] if intl else number
    if not digits.isdigit() or not 3 <= len(digits) <= 20:
        raise ValueError("number must be digits, optionally with a leading +")
    bcd = bytearray()
    d = digits + ("F" if len(digits) % 2 else "")
    for k in range(0, len(d), 2):
        bcd.append(int(d[k + 1], 16) << 4 | int(d[k]))
    da = bytes([len(digits), 0x91 if intl else 0x81]) + bytes(bcd)
    if all(c in GSM7 for c in text):
        if len(text) > 160:
            raise ValueError("more than 160 GSM characters (multipart not supported yet)")
        bits, nbits, ud = 0, 0, bytearray()
        for c in text:
            bits |= GSM7.index(c) << nbits
            nbits += 7
            while nbits >= 8:
                ud.append(bits & 0xFF)
                bits >>= 8
                nbits -= 8
        if nbits:
            ud.append(bits & 0xFF)
        dcs, udl, coding = 0x00, len(text), "gsm7"
    else:
        ud = bytearray(text.encode("utf-16-be"))
        if len(ud) > 140:
            raise ValueError("more than 70 characters with non-GSM letters (multipart not supported yet)")
        dcs, udl, coding = 0x08, len(ud), "ucs2"
    # first octet 0x01 = SMS-SUBMIT, TP-MR 0 (CP assigns), PID 0
    return bytes([0x01, 0x00]) + da + bytes([0x00, dcs, udl]) + bytes(ud), coding


def luhn_ok(digits):
    s = 0
    for k, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if k % 2 else 1)
        s += d - 9 if d > 9 else d
    return s % 10 == 0


class Fmt:
    def __init__(self, allow_radio, sms_file, apn=None, radio_state=None, data_state=None,
                 netdev="wwan0"):
        self.fd = os.open(FMT_DEV, os.O_RDWR)
        self.sms_file = sms_file
        self.apn = apn
        self.radio_state = radio_state
        self.data_state = data_state
        self.netdev = netdev
        self.ps_registered = False
        self.data_phase = "down"      # down | defining | activating | up
        self.ims_phase = "down"       # IMS PDN test (ctl "ims up|down"): down | defining | activating | up
        self.data_retry_at = 0.0
        # state for the MBIM function (identities are kept in memory only, never logged)
        self.st = dict(radio=False, sim=None, sw=None, imei=None, imsi=None, iccid=None,
                       ps=None, act=None, plmn=None, rssi=None, rsrp=None, rsrq=None, bars=0,
                       ipcfg=None)
        self.mbim = None              # MbimFunction while ModemManager holds the port
        self.mbim_connect = False     # ModemManager asked for a data connection
        self.lazy_timer = None        # pending real deactivation after an MBIM disconnect
        self.radio_after_apn = False  # radio on waits for the attach APN's answer
        self.fresh_cp = False         # the launcher booted/restarted the CP for us
        self.calls = []
        self.call_kind = self.call_inhibit = None     # see call_presence()
        try:
            os.unlink(self.CALL_FLAG)                   # stale, from a previous run
        except OSError:
            pass
        self.at = None                # AtEmulator (ModemManager voice)
        self.ims = None               # shannon_volte.ImsManager (VoLTE; idle unless commanded)
        self.sms_result = None        # (event, [result, mr]) while a send waits
        self.allow_radio = allow_radio
        self.mseq = 0
        self.lock = threading.Lock()
        self.powered = threading.Event()
        self.raw = set()
        self.smsc = None          # SCA bytes as the CP reports them (04 0A RESP payload)
        # SMS_SEND_MSG +9: stock sends 0x00 for every non-AT&T network (DomainSelector
        # domain 2 -> ConvertDomainToIPC 0x00); +8 msg type: 0x02 = single/last part,
        # 0x01 = more parts follow (libsec-ril DoSendSms)
        self.sms_domain = 0x00

    def send(self, group, index, typ, payload=b""):
        with self.lock:
            self.mseq = (self.mseq + 1) & 0xFF
            msg = struct.pack("<HBBBBB", 7 + len(payload), self.mseq, 0, group, index,
                              typ) + payload
            try:
                os.write(self.fd, msg)
            except OSError as e:
                log(f"fmt: send {self.name(group, index)} failed: {e}")
                return False
        log(f"fmt: > {self.name(group, index)} type {typ} len {len(msg)}")
        return True

    @staticmethod
    def name(g, i):
        return f"{GROUPS.get(g, f'{g:#04x}')}_{SUBS.get((g, i), f'{i:#04x}')}"

    def radio(self, on, save=False):
        if on and not self.allow_radio:
            log("fmt: radio on refused (start the daemon with --allow-radio)")
            return
        self.send(0x01, 0x07, EXEC, b"\x02\x02" if on else b"\x01\x00")
        if save and self.radio_state:
            try:
                with open(self.radio_state + ".tmp", "w") as f:
                    f.write("on\n" if on else "off\n")
                os.replace(self.radio_state + ".tmp", self.radio_state)
            except OSError as e:
                log(f"fmt: saving radio state failed: {e}")

    def saved_radio_on(self):
        try:
            with open(self.radio_state) as f:
                return f.read().strip() == "on"
        except (OSError, TypeError):
            return False

    RAW_OK = {0x01, 0x07, 0x08, 0x0B, 0x0D, 0x0F, 0x16, 0x27}   # config groups, no identities

    def getraw(self, g, i, payload):
        if g not in self.RAW_OK:
            log(f"fmt: getraw refused for group {g:#04x} (may carry SIM/subscriber data)")
            return
        self.raw.add((g, i))
        self.send(g, i, GET, payload)

    PDP_TYPES = {"ip": 0x02, "ipv6": 0x05, "ipv4v6": 0x06}

    def set_attach_apn(self, apn, pdp="ipv4v6"):
        """GPRS 0D 14 SET, 201-byte layout (libsec-ril 0x31e208):
        +7 home(1), +8 cid 1, +9 PDP type, +0x0A APN[101], +0x86 user[32], +0xA6 pass[32],
        +0xC6 auth (0 none), +0xC7 roaming PDP type, +0xC8 0."""
        a = apn.encode("ascii")
        if len(a) > 100 or pdp not in self.PDP_TYPES:
            log("fmt: setapn: APN too long or bad PDP type (ip|ipv6|ipv4v6)")
            return
        typ = self.PDP_TYPES[pdp]
        body = bytearray(201 - 7)
        body[0], body[1], body[2] = 1, 1, typ
        body[3:3 + len(a)] = a
        body[0xC6 - 7], body[0xC7 - 7], body[0xC8 - 7] = 0, typ, 0
        log(f"fmt: initial attach APN '{apn}' {pdp}")
        self.send(0x0D, 0x14, SET, bytes(body))

    def send_sms(self, number, text):
        """SMS_SEND_MSG EXEC (spec 3.11): net type 2 (3GPP), single, domain 2, len, SCA+TPDU.
        Number and text are never logged."""
        try:
            pdu, coding = sms_submit_pdu(number, text)
        except ValueError as e:
            log(f"fmt: sms not sent: {e}")
            return
        if self.smsc is None:
            log("fmt: sms not sent: SMSC unknown yet (get smsc)")
            self.query("smsc")
            return
        body = self.smsc + pdu
        log(f"fmt: sending SMS ({coding}, {len(text)} chars; recipient and text not shown)")
        self.send(0x04, 0x01, EXEC, bytes([0x02, 0x02, self.sms_domain, len(body)]) + body)

    # ------------------------------------------------------------------ data call
    # DEFINE_PDP_CONTEXT 0D 01 SET (149 B) + PDP_CONTEXT 0D 04 SET (legacy 112 B) for cid 1,
    # then IP_CONFIGURATION / CALL_STATUS NOTIs.
    def data_wanted(self):
        try:
            with open(self.data_state) as f:
                return f.read().strip() == "on"
        except (OSError, TypeError):
            return False

    def set_data(self, on):
        if self.data_state:
            try:
                with open(self.data_state + ".tmp", "w") as f:
                    f.write("on\n" if on else "off\n")
                os.replace(self.data_state + ".tmp", self.data_state)
            except OSError as e:
                log(f"fmt: saving data state failed: {e}")
        if on:
            self.data_retry_at = 0.0
            self.maybe_data_up()
        else:
            self.data_down(send=True)

    def maybe_data_up(self):
        if (self.allow_radio and self.apn and self.ps_registered and self.data_phase == "down"
                and (self.mbim_connect or (not self.mbim and self.data_wanted()))
                and time.monotonic() >= self.data_retry_at):
            a = self.apn.encode("ascii")
            body = bytearray(149 - 7)
            body[0], body[1], body[2] = 1, 1, self.PDP_TYPES["ipv4v6"]
            body[3:3 + len(a)] = a
            self.data_phase = "defining"
            log("fmt: data: defining cid 1")
            self.send(0x0D, 0x01, SET, bytes(body))

    def data_activate(self):
        body = bytearray(112 - 7)
        body[0], body[1] = 1, 1                  # activate (internet), cid 1; no auth
        self.data_phase = "activating"
        log("fmt: data: activating cid 1")
        self.send(0x0D, 0x04, SET, bytes(body))

    # ------------------------------------------------------------------ IMS PDN (VoLTE test)
    # cid 2, APN "ims", IPv4v6, P-CSCF request (+0x85), activate with action 3 (IMS profile).
    # Test only: the result (accepted / cause, P-CSCF count) is logged, no interface is set up.
    IMS_CID = 2

    def ims_auto_retry(self):
        """VOLTE automatic start that waited for the internet data call (maybe_auto)."""
        if self.ims and self.ims.auto_waiting and self.ps_registered \
                and self.st.get("act") == 0x21 and self.st.get("volte"):
            self.ims.maybe_auto(True)

    def ims_up(self, apn="ims"):
        if self.ims_phase != "down":
            log(f"fmt: ims: already {self.ims_phase}")
            return
        if not (self.allow_radio and self.ps_registered):
            log("fmt: ims: not PS registered")
            return
        if self.data_phase in ("defining", "activating"):
            log("fmt: ims: internet data call is being set up, try again")
            return
        a = apn.encode("ascii")[:100]
        body = bytearray(149 - 7)
        body[0], body[1], body[2] = 1, self.IMS_CID, self.PDP_TYPES["ipv4v6"]
        body[3:3 + len(a)] = a
        body[0x85 - 7] = 3                       # P-CSCF for IPv4v6 (DATA-PATH 1.2)
        self.ims_phase = "defining"
        log(f"fmt: ims: defining cid {self.IMS_CID} APN '{apn}'")
        self.send(0x0D, 0x01, SET, bytes(body))

    def ims_activate(self):
        body = bytearray(112 - 7)
        body[0], body[1] = 3, self.IMS_CID       # action 3 = IMS profile
        self.ims_phase = "activating"
        log(f"fmt: ims: activating cid {self.IMS_CID}")
        self.send(0x0D, 0x04, SET, bytes(body))

    def ims_down(self):
        if self.ims and self.ims.ua:
            self.ims.deregister()
        body = bytearray(112 - 7)
        body[0], body[1] = 0, self.IMS_CID
        log(f"fmt: ims: deactivating cid {self.IMS_CID}")
        self.send(0x0D, 0x04, SET, bytes(body))
        self.ims_phase = "down"

    def ims_ip_config(self, p):
        """P-CSCF lists (+0x1E v4 x3, +0x3A v6 x3, frame offsets); addresses not logged."""
        mask = struct.unpack_from("<H", p, 1)[0] if len(p) >= 3 else 0
        v4 = sum(1 for k in range(3) if len(p) >= 0x17 + 4 * k + 4 and any(p[0x17 + 4 * k:0x1B + 4 * k]))
        v6 = sum(1 for k in range(3) if len(p) >= 0x33 + 16 * k + 16 and any(p[0x33 + 16 * k:0x43 + 16 * k]))
        self.ims_phase = "up"
        if self.ims:
            return "ims: IP config: " + self.ims.on_ip_config(p)
        return (f"ims: IP config cid {p[0]} mask {mask:#06x}, ipv4 {'yes' if mask & 1 else 'no'}, "
                f"ipv6 {'yes' if mask & 0x40 else 'no'}, P-CSCF v4 x{v4}, v6 x{v6}")

    def data_down(self, send=False, retry=False):
        if send and self.data_phase != "down":
            body = bytearray(112 - 7)
            body[0], body[1] = 0, 1              # deactivate cid 1
            self.send(0x0D, 0x04, SET, bytes(body))
        if self.data_phase == "up" and not self.mbim:
            self.ip("addr", "flush", "dev", self.netdev)
            self.ip("link", "set", self.netdev, "down")
            log("fmt: data: down")
        self.data_phase = "down"
        if retry:
            self.data_retry_at = time.monotonic() + 15

    def ip(self, *args):
        r = subprocess.run(["ip", *args], capture_output=True, text=True)
        if r.returncode:
            log(f"fmt: data: ip {args[0]} {args[1]} failed: {r.stderr.strip()[:100]}")
        return r.returncode == 0

    def ip_config(self, p):
        """IP_CONFIGURATION NOTI: +0 cid, +1 u16 mask, +3 v4, +7/+0xB DNS, +0x23 v6 (link
        local IID), +0x98 u32 MTU (low half v4).  Addresses are applied, never logged."""
        if len(p) < 0x13 or p[0] != 1:
            return "ignored"
        mask = struct.unpack_from("<H", p, 1)[0]
        v4 = ipaddress.IPv4Address(bytes(p[3:7])) if mask & 1 else None
        dns = [ipaddress.IPv4Address(bytes(p[o:o + 4])) for o in (7, 11)
               if bytes(p[o:o + 4]) != b"\0\0\0\0"]
        mtu = 1500
        if (mask & (1 << 13)) and len(p) >= 0x9C:
            mtu = struct.unpack_from("<I", p, 0x98)[0] & 0xFFFF or 1500
        v6_iid = bytes(p[0x2B:0x33]) if (mask & (1 << 6)) and len(p) >= 0x33 else None
        dns6 = [ipaddress.IPv6Address(bytes(p[o:o + 16])) for o in (0x63, 0x73)
                if len(p) >= o + 16 and any(p[o:o + 16])] if v6_iid else []
        if os.environ.get("SHANNON_IPCFG_LAYOUT"):
            # debug: which byte ranges are non-zero (no values)
            nz = [k for k in range(len(p)) if p[k]]
            runs, s0 = [], None
            for k in nz + [None]:
                if s0 is None:
                    s0 = prev = k
                elif k is None or k != prev + 1:
                    runs.append(f"{s0 + 7:#x}-{prev + 7:#x}")
                    s0 = prev = k
                else:
                    prev = k
            log(f"fmt: data: IP config mask {mask:#06x}, non-zero at " + " ".join(runs))
        if not v4:
            return "no IPv4 address"
        # Point-to-point raw IP: NetworkManager only makes a default route with a gateway.
        # Like the Samsung stack, use a.b.c.1 (or .2 if that is our own address).
        o = v4.packed
        gw = ipaddress.IPv4Address(o[:3] + bytes([2 if o[3] == 1 else 1]))
        self.st["ipcfg"] = dict(ipv4=str(v4), ipv4_prefix=32, ipv4_gateway=str(gw),
                                dns4=[str(d) for d in dns], mtu=mtu,
                                ipv6=str(ipaddress.IPv6Address(b"\xfe\x80" + b"\0" * 6 + v6_iid))
                                if v6_iid and any(v6_iid) else None,
                                ipv6_prefix=64, dns6=[str(d) for d in dns6])
        if self.mbim:
            self.data_phase = "up"
            self.ims_auto_retry()
            self.mbim.notify_connect()
            self.mbim.notify_ip_configuration()
            return "kept for ModemManager (MBIM)"
        self.sysctl(f"net/ipv6/conf/{self.netdev}/addr_gen_mode", "1")   # no kernel LL
        self.ip("link", "set", self.netdev, "mtu", str(min(mtu, 2048)))
        self.ip("addr", "flush", "dev", self.netdev)
        self.ip("link", "set", self.netdev, "up")
        self.ip("addr", "add", f"{v4}/32", "dev", self.netdev)
        if v6_iid and any(v6_iid):
            # The CP gives fe80::IID; the global prefix comes in a router advertisement
            # (the CP forwards RS/RA as packets).  "ip token" makes SLAAC use the IID;
            # the kernel refuses tokens on NOARP links, and a point-to-point link without
            # header_ops keeps its neighbours NUD_NOARP anyway.
            iid = ipaddress.IPv6Address(b"\0" * 8 + v6_iid)
            ll = ipaddress.IPv6Address(b"\xfe\x80" + b"\0" * 6 + v6_iid)
            self.ip("link", "set", self.netdev, "arp", "on")
            self.sysctl(f"net/ipv6/conf/{self.netdev}/accept_ra", "2")
            self.ip("token", "set", str(iid), "dev", self.netdev)
            self.ip("-6", "addr", "add", f"{ll}/64", "dev", self.netdev, "nodad")
        # metric above Wi-Fi's (600) so Wi-Fi stays preferred while connected
        self.ip("route", "replace", "default", "dev", self.netdev, "metric", "700")
        if dns or dns6:
            subprocess.run(["resolvectl", "dns", self.netdev, *map(str, dns + dns6)],
                           capture_output=True)
            subprocess.run(["resolvectl", "default-route", self.netdev, "yes"],
                           capture_output=True)
        self.data_phase = "up"
        self.ims_auto_retry()
        return (f"applied: IPv4 /32, {len(dns)} DNS, MTU {mtu}" +
                (f", IPv6 link-local + SLAAC token, {len(dns6)} v6 DNS" if v6_iid else
                 ", no IPv6 from the network"))

    @staticmethod
    def sysctl(key, value):
        try:
            with open(f"/proc/sys/{key}", "w") as f:
                f.write(value)
        except OSError as e:
            log(f"fmt: data: sysctl {key.split('/')[-1]}: {e}")

    # ------------------------------------------------------------------ voice calls
    # libsec-ril IpcProtocol41Call.  Numbers are never logged.
    CALL_STATES = {1: "active", 2: "held", 3: "dialing", 4: "alerting", 5: "incoming",
                   6: "waiting"}

    EMERGENCY = ("112", "911", "999", "000", "110", "118", "08", "119")

    def dial(self, number, allow_emergency=False):
        intl = number.startswith("+")
        digits = number[1:] if intl else number
        if not digits or not all(c.isdigit() or c in "*#" for c in digits) or len(digits) > 40:
            log("call: dial refused: number must be digits (optional leading +)")
            return False
        emerg = digits in self.EMERGENCY
        if emerg and not allow_emergency:
            log("call: emergency numbers are not dialled by this test command")
            return False
        a = digits.encode()
        body = bytearray(99 - 7)
        body[0:5] = bytes([0x00, 0x03 if emerg else 0x01, 0x00, len(a), 0x11 if intl else 0x21])
        body[5:5 + len(a)] = a
        log(f"call: dialling ({len(a)} digits, number not shown){' EMERGENCY' if emerg else ''}")
        self.send(0x02, 0x01, EXEC, bytes(body))
        return True

    # Hangup in any call state (also dialing, while CSFB is still moving to 2G/3G).
    # CALL_RELEASE is resent if the CP rejects it (GEN_PHONE_RES error) or if the
    # calls it was meant for still exist RELEASE_CHECK s later, up to RELEASE_TRIES.
    RELEASE_TRIES = 8
    RELEASE_CHECK = 4.0

    def release_call(self, attempt=0):
        if attempt == 0:
            self.release_ids = {e["id"] for e in self.calls} or {None}
        elif not self._release_left():
            return
        self.release_attempt = attempt
        log(f"call: release{f' (retry {attempt})' if attempt else ''}")
        self.send(0x02, 0x03, EXEC)
        if attempt + 1 < self.RELEASE_TRIES:
            t = threading.Timer(self.RELEASE_CHECK, self.release_call, (attempt + 1,))
            t.daemon = True
            t.start()

    def _release_left(self):
        ids = getattr(self, "release_ids", None)
        if not ids:
            return False
        left = ids & {e["id"] for e in self.calls}
        if not left:
            self.release_ids = None
        return bool(left)

    def dtmf(self, c):
        body = bytearray(91 - 7)
        body[0], body[1], body[2] = 1, 1, ord(c)
        self.send(0x02, 0x07, EXEC, bytes(body))

    def call_list(self):
        self.send(0x02, 0x06, GET)

    # ---- voice call audio (ABOX VSS) ----
    # Stock order at call start: ABOX Audio Mode IN_CALL + Sound Type, SND AUDIO_PATH,
    # call PCMs (RDMA4/WDMA2) started, SND CLOCK_CTRL 1, SND SPKR_VOLUME; reversed at the end.
    CALL_AUDIO = "/usr/libexec/shannon/call-audio"
    AUDIO_PATHS = {"earpiece": 0x01, "speaker": 0x06}
    VOLUME_TYPES = {"earpiece": 0x01, "speaker": 0x11}
    call_audio_on = False
    audio_dev = "earpiece"
    call_volume = 4                                  # 0..5

    def call_audio_event(self, on):
        if on == self.call_audio_on:
            return
        self.call_audio_on = on
        t = threading.Thread(target=self._call_audio, args=(on,), daemon=True)
        t.start()

    def _run_call_audio(self, *args):
        if not os.access(self.CALL_AUDIO, os.X_OK) or os.path.exists("/run/shannon/no-call-audio"):
            return
        try:
            r = subprocess.run([self.CALL_AUDIO, *args], capture_output=True, text=True, timeout=20)
            for l in (r.stderr or "").splitlines():
                log(f"audio: {l}")
        except (OSError, subprocess.TimeoutExpired) as e:
            log(f"audio: {args[0]} failed: {e}")

    _audio_lock = threading.Lock()
    _inhibit = None

    def _call_audio(self, on):
        with self._audio_lock:
            if on:
                if not self._inhibit:
                    try:
                        self._inhibit = subprocess.Popen(
                            ["systemd-inhibit", "--what=sleep", "--who=shannon-modem",
                             "--why=voice call", "sleep", "infinity"])
                    except OSError:
                        self._inhibit = None
                dev = self.audio_dev
                self.send(0x09, 0x03, SET, bytes([self.AUDIO_PATHS[dev], 0x00]))   # AUDIO_PATH
                self._run_call_audio("start", dev)
                self.send(0x09, 0x09, EXEC, b"\x01")                               # CLOCK_CTRL on
                self.send(0x09, 0x01, SET, bytes([self.VOLUME_TYPES[dev], self.call_volume]))
                self.send(0x09, 0x02, SET, bytes([1 if self.call_mute else 0]))    # MUTE
            else:
                self.send(0x09, 0x09, EXEC, b"\x00")                               # CLOCK_CTRL off
                self._run_call_audio("stop")
                if self._inhibit:
                    self._inhibit.terminate()
                    self._inhibit = None

    call_mute = False

    def set_mute(self, on):
        """Microphone mute (GNOME Calls via callaudiod): CS call -> SND MUTE 09 02
        (value 1 = TX mute, 0 = unmute); VoLTE call ->
        the AP media sends silence."""
        self.call_mute = bool(on)
        with self._audio_lock:          # not in the middle of a call-audio start/stop
            if self.call_audio_on:
                self.send(0x09, 0x02, SET, bytes([1 if on else 0]))
        if self.ims:
            try:
                self.ims.mute(on)
            except Exception as e:
                log(f"mute: ims: {e!r}")
        log(f"audio: microphone {'muted' if on else 'on'}")

    def set_audio_dev(self, dev):
        if dev not in self.AUDIO_PATHS:
            return
        self.audio_dev = dev
        log(f"audio: output {dev}")
        if self.ims:
            self.ims.route_audio(dev)
        with self._audio_lock:          # not in the middle of a call-audio start/stop
            if self.call_audio_on:
                self.send(0x09, 0x03, SET, bytes([self.AUDIO_PATHS[dev], 0x00]))
                self._run_call_audio("route", dev)
                self.send(0x09, 0x01, SET, bytes([self.VOLUME_TYPES[dev], self.call_volume]))

    # ---- calls polish ----
    def calls_gone(self):
        """Last call (CS and IMS) ended: the next call starts unmuted on the earpiece,
        as on stock (Telecom).  The volume stays, it is the user's setting.
        shannon-callaudio-bridge re-sends GNOME Calls' state when the next call starts."""
        if self.call_mute or self.audio_dev != "earpiece":
            log("audio: call ended, mute off / earpiece for the next call")
        self.call_mute = False
        self.audio_dev = "earpiece"

    resync_audio = False              # set by main() after reattaching to a running CP

    def resync_call_audio(self):
        """After a daemon restart during a CS call no CALL_STATUS comes for the existing
        call: start the call-audio path from the first call list instead (once)."""
        if not self.resync_audio:
            return
        self.resync_audio = False
        if any(e["state"] in (1, 2, 4) for e in self.calls):     # active, held, alerting
            log("audio: call in progress after a restart, starting the call path")
            self.call_audio_event(True)

    # Missed incoming calls nobody could see (no GNOME Calls running, e.g. before the
    # first login): one line per call "<epoch> <users running gnome-calls or -> <number>"
    # in MISSED_FILE (dir root:audio 0750, file 0640; like the SMS inbox, never logged).
    # shannon-callaudio-bridge shows them as a notification after login and clears them
    # through the audio FIFO ("missed clear <epoch>").
    MISSED_FILE = "/var/lib/shannon-calls/missed-calls"   # /var/lib/shannon is 0700
    MISSED_GROUP = "netdev"   # the phone user (pmOS: netdev, not audio)

    # Processes that show incoming and missed calls themselves: GNOME Calls (Phosh) and
    # Plasma Dialer's kde-telephony-daemon (comm is cut to 15 characters).
    CALLS_UI_COMMS = ("gnome-calls", "kde-telephony-d")

    @classmethod
    def calls_ui_users(cls):
        """Users with a calls UI process (GNOME Calls, or Plasma Dialer's daemon)."""
        import pwd
        users = set()
        try:
            pids = [d for d in os.listdir("/proc") if d.isdigit()]
        except OSError:
            return users
        for pid in pids:
            try:
                with open(f"/proc/{pid}/comm") as f:
                    if f.read().strip() not in cls.CALLS_UI_COMMS:
                        continue
                uid = os.stat(f"/proc/{pid}").st_uid
                users.add(pwd.getpwuid(uid).pw_name)
            except (OSError, KeyError):
                continue
        return users

    def track_missed(self, entries):
        ring = getattr(self, "_ringing", None)
        if ring is None:
            ring = self._ringing = {}
        now_ids = set()
        for e in entries:
            key = (e["id"], e["dir"])
            now_ids.add(key)
            if e["dir"] == 1:                                   # outgoing
                continue
            r = ring.get(key)
            if r is None and e["state"] in (5, 6):              # new incoming / waiting
                users = self.calls_ui_users()
                ring[key] = r = dict(t=int(time.time()), number=e["number"],
                                     ui=sorted(users), answered=False)
                log("call: incoming, calls UI " + (f"running ({','.join(r['ui'])})" if users
                                                   else "NOT running (before login?)"))
            if r is not None and e["state"] in (1, 2):          # answered (active / held)
                r["answered"] = True
        for key in [k for k in ring if k not in now_ids]:
            r = ring.pop(key)
            if not r["answered"]:
                self.record_missed(r)

    def record_missed(self, r):
        log(f"call: missed incoming call (number not shown), calls UI at ring time: "
            f"{','.join(r['ui']) or 'none'}")
        num = "".join(c for c in r["number"] if c.isdigit() or c in "+*#") or "unknown"
        line = f"{r['t']} {','.join(r['ui']) or '-'} {num}\n"
        try:
            import grp
            try:
                gid = grp.getgrnam(self.MISSED_GROUP).gr_gid
            except KeyError:
                gid = -1
            d = os.path.dirname(self.MISSED_FILE)
            os.makedirs(d, 0o750, exist_ok=True)
            fd = os.open(self.MISSED_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                os.write(fd, line.encode())
                os.fsync(fd)
                if gid >= 0 and os.geteuid() == 0:
                    os.chown(d, 0, gid)
                    os.chmod(d, 0o750)
                    os.fchown(fd, 0, gid)
                    os.fchmod(fd, 0o640)
            finally:
                os.close(fd)
        except OSError as e:
            log(f"call: missed call not saved: {e}")

    def missed_clear(self, upto):
        """Drop the missed-call lines with a time <= upto (shown by the bridge)."""
        try:
            with open(self.MISSED_FILE) as f:
                lines = f.readlines()
        except OSError:
            return

        def shown(l):
            t = l.split(" ", 1)[0]
            return t.isdigit() and int(t) <= upto
        keep = [l for l in lines if not shown(l)]
        try:
            st = os.stat(self.MISSED_FILE)
            tmp = self.MISSED_FILE + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            try:
                os.write(fd, "".join(keep).encode())
                os.fchown(fd, st.st_uid, st.st_gid)
                os.fchmod(fd, 0o640)
            finally:
                os.close(fd)
            os.replace(tmp, self.MISSED_FILE)
            log(f"call: {len(lines) - len(keep)} missed call(s) shown and cleared")
        except OSError as e:
            log(f"call: missed calls not cleared: {e}")

    def decode_call_list(self, p):
        if not p:
            return "empty"
        n, k, out, entries = p[0], 1, [], []
        for _ in range(min(n, 8)):
            if len(p) < k + 8:
                break
            cid, cdir, st, mpty, nl, nt = p[k + 2], p[k + 3], p[k + 4], p[k + 5], p[k + 6], p[k + 7]
            num = bytes(p[k + 8:k + 8 + nl]).decode("ascii", "replace")
            k += 8 + nl
            intl = nt == 0x10 or num.startswith("+")
            if intl and not num.startswith("+"):
                num = "+" + num
            entries.append(dict(id=cid, dir=cdir, state=st, mpty=mpty, number=num, intl=intl))
            out.append(f"#{cid} {'out' if cdir == 1 else 'in'} "
                       f"{self.CALL_STATES.get(st, st)}{' mpty' if mpty else ''} ({nl} digits)")
        self.calls = entries
        self.resync_call_audio()
        self.call_presence(self.all_calls())
        if self.at:
            self.at.calls_changed(self.all_calls())
        return f"{n} call(s): " + ", ".join(out) if out else "no calls"

    def all_calls(self):
        """CS calls (ids 1..7) + IMS calls (ids 8..15) for the AT emulator."""
        return self.calls + (self.ims.entries() if self.ims else [])

    def ims_calls_changed(self):
        allc = self.all_calls()
        self.call_presence(allc)
        if self.at:
            self.at.calls_changed(allc)

    # While a call exists: CALL_FLAG ("<pid> incoming|call") tells the device's
    # resuspend helper to light the screen and not suspend, and a logind sleep block
    # inhibitor keeps the system up.  The inhibitor's `cat` exits when our pipe closes,
    # so a daemon crash cannot leave it behind; the helper checks the pid in the flag.
    CALL_FLAG = "/run/shannon/call-active"
    # kernel r152+: while set, the modem driver refuses system suspend (-EBUSY), which
    # also aborts a suspend already started before the call arrived
    CALL_KNOB = "/sys/devices/platform/soc@0/15920000.modem/call_active"

    def call_knob(self, on):
        try:
            with open(self.CALL_KNOB, "w") as f:
                f.write("1" if on else "0")
        except OSError:
            pass                      # older kernel without the attribute

    def call_presence(self, entries):
        self.track_missed(entries)
        kind = ("incoming" if any(e["state"] in (5, 6) for e in entries) else "call") \
            if entries else None
        if kind == getattr(self, "call_kind", None):
            return
        self.call_kind = kind
        inh = getattr(self, "call_inhibit", None)
        try:
            if kind:
                tmp = self.CALL_FLAG + ".tmp"
                with open(tmp, "w") as f:
                    f.write(f"{os.getpid()} {kind}\n")
                os.chmod(tmp, 0o644)
                os.replace(tmp, self.CALL_FLAG)
                self.call_knob(True)
                if not inh or inh.poll() is not None:
                    self.call_inhibit = subprocess.Popen(
                        ["systemd-inhibit", "--what=sleep", "--mode=block",
                         "--who=shannon-modem", "--why=voice call", "cat"],
                        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
            else:
                try:
                    os.unlink(self.CALL_FLAG)
                except FileNotFoundError:
                    pass
                self.call_knob(False)
                if inh:
                    inh.stdin.close()
                    inh.wait(timeout=5)
                    self.call_inhibit = None
                self.calls_gone()
            log(f"call: presence {kind or 'none'} (flag + sleep inhibitor "
                f"{'held' if kind else 'released'})")
        except (OSError, subprocess.SubprocessError) as e:
            log(f"call: presence {kind}: {e}")

    def ps_attach(self):
        self.send(0x0D, 0x03, SET, b"\x01\x00\x00")

    def query(self, what):
        q = QUERIES.get(what)
        if not q:
            log(f"fmt: unknown query {what} (have {', '.join(QUERIES)})")
            return
        self.send(*q)

    def decode(self, m):
        ln, mseq, aseq, g, i, t = struct.unpack_from("<HBBBBB", m)
        p = m[7:]
        if getattr(self, "idle", None):
            self.idle.count(g, i, t)                  # screen-off idle accounting
        head = f"fmt: < {self.name(g, i)} {RX_TYPES.get(t, t)} len {ln} aseq {aseq}"
        info = ""
        if (g, i) == (0x80, 0x01) and len(p) >= 5:
            code = struct.unpack_from("<H", p, 3)[0]
            info = f"for {self.name(p[0], p[1])}: {'OK' if code == 0x8000 else f'error {code:#06x}'}"
            if (p[0], p[1]) == (0x05, 0x09) and code != 0x8000 and self.ims:
                info += " | " + self.ims.on_auth_response(p, error=True)
            if (p[0], p[1]) == (0x0D, 0x14) and self.radio_after_apn:
                self.radio_after_apn = False
                self.radio(True)
            if (p[0], p[1]) == (0x0D, 0x01) and self.ims_phase == "defining" \
                    and self.data_phase != "defining":
                if code == 0x8000:
                    self.ims_activate()
                else:
                    self.ims_phase = "down"
            elif (p[0], p[1]) == (0x0D, 0x04) and self.ims_phase == "activating" \
                    and self.data_phase != "activating":
                if code != 0x8000:
                    self.ims_phase = "down"
            elif (p[0], p[1]) == (0x0D, 0x01) and self.data_phase == "defining":
                if code == 0x8000:
                    self.data_activate()
                else:
                    self.data_down(retry=True)
            elif (p[0], p[1]) == (0x0D, 0x04) and self.data_phase == "activating" and code != 0x8000:
                self.data_down(retry=True)
        elif (g, i) == (0x01, 0x01) and t == 3:
            info = "modem powered up"
            self.on_pwr_up()
        elif (g, i) == (0x01, 0x07) and p:
            info = f"radio {'ON' if p[0] in (2, 3, 4) else 'OFF/LPM'} (state {p[0]})"
            if t in (2, 3):
                self.st["radio"] = p[0] in (2, 3, 4)
            if self.mbim:
                self.mbim.notify_radio()
        elif (g, i) == (0x05, 0x01) and len(p) >= 2:
            info = f"SIM {PIN.get(p[0], f'{p[0]:#04x}')} (facility {p[1]})"
            self.st["sim"] = p[0]
            if p[0] in (0x00, 0x82, 0x83) and not self.st["imsi"]:
                self.send(0x0A, 0x02, GET)            # IMSI, kept for MBIM only
            if self.mbim:
                self.mbim.notify_subscriber()
        elif (g, i) == (0x0A, 0x01) and len(p) >= 33:
            sw = p[1:33].split(b"\0", 1)[0].decode("ascii", "replace")
            info = f"SW version {sw}"
            self.st["sw"] = sw
        elif (g, i) == (0x08, 0x05) and len(p) >= 3:
            dom = {1: "?", 2: "CS", 3: "PS"}.get(p[1], p[1])
            info = f"{dom} {REG.get(p[2], f'{p[2]:#04x}')} act {ACT.get(p[0], f'{p[0]:#04x}')}"
            if p[1] in (1, 3):            # 3 = PS, 1 = combined (NOTI after attach)
                self.ps_registered = p[2] in (0x02, 0x06, 0x20, 0x22)
                self.st["ps"], self.st["act"] = p[2], p[0]
                if self.mbim:
                    self.mbim.notify_registration()
                    self.mbim.notify_packet_service()
                if self.ps_registered:
                    self.maybe_data_up()
                elif self.data_phase != "down":
                    self.data_down()
            if len(p) >= 11:
                info += f" (status {p[2]:#04x}, reject cause {p[10]}"
                if len(p) >= 20 and p[0] != 0x24:
                    info += f", band {p[19]}"
                    # +20/+21 of the frame: network VoLTE (IMS voice over PS) / IMS
                    # emergency support, 1 = yes, 2 = no (RFS-IPC-SPEC 3.8)
                    yn = {1: "yes", 2: "no"}
                    info += f", volte {yn.get(p[13], p[13])}, ims-emc {yn.get(p[14], p[14])}"
                    if p[1] in (1, 3):
                        # kept for P-Access-Network-Info only, never logged
                        tac = struct.unpack_from("<H", p, 11)[0] or struct.unpack_from("<H", p, 4)[0]
                        self.st.update(tac=tac, eci=struct.unpack_from("<I", p, 6)[0],
                                       volte=p[13] == 1)
                        if self.ims and self.ps_registered and p[0] == 0x21:
                            self.ims.maybe_auto(p[13] == 1)
                info += ")"
        elif (g, i) == (0x08, 0x03) and len(p) >= 9:
            plmn = p[3:9].decode("ascii", "replace").rstrip("#")
            info = f"operator {plmn} {REG.get(p[1], f'{p[1]:#04x}')} act {ACT.get(p[2], f'{p[2]:#04x}')}"
            self.st["plmn"] = plmn if plmn.isdigit() and plmn.strip("0") else None
            if self.mbim:
                self.mbim.notify_registration()
        elif (g, i) == (0x07, 0x06) and len(p) >= 6:
            info = f"rssi -{p[0]} dBm, lte rsrp -{p[4]} rsrq -{p[5]}"
            self.st.update(rssi=-p[0] if p[0] else None, rsrp=-p[4] if p[4] else None,
                           rsrq=-p[5] if p[5] not in (0, 0xFF) else None)
            if self.mbim:
                self.mbim.notify_signal()
        elif (g, i) == (0x07, 0x01) and len(p) >= 2:
            info = f"bars {p[1]}"
            self.st["bars"] = min(p[1], 5)
        elif (g, i) == (0x04, 0x0A) and t == 2 and p:
            # fixed 12-byte field: RP address = length octet + TON/NPI + BCD, then padding
            self.smsc = bytes(p[:p[0] + 1]) if 0 < p[0] < len(p) else None
            info = (f"SMSC {len(p)} bytes, first {p[0]:#04x}, type {p[1]:#04x}" if len(p) > 1
                    else "SMSC empty")
        elif (g, i) == (0x04, 0x01) and t in (2, 3) and len(p) >= 4:
            res = struct.unpack_from("<H", p, 1)[0]
            info = f"SMS send result {'OK' if res == 0 else f'{res:#06x}'} (TP-MR {p[3]}"
            info += f", RP PDU {p[4]} bytes)" if len(p) >= 5 else ")"
            if t == 3 and self.sms_result:
                ev, out = self.sms_result
                out[:] = [res, p[3]]
                ev.set()
        elif (g, i) == (0x02, 0x05) and len(p) >= 6:
            st = p[3]
            names = {0: "idle", 1: "dialing", 2: "alerting", 3: "connected", 4: "released",
                     5: "connecting"}
            info = (f"call #{p[2]} {names.get(st, st)} (type {struct.unpack_from('<H', p)[0]}, "
                    f"cause {p[4]}/{p[5]})")
            if st in (2, 3):                              # alerting (ringback) / connected
                self.call_audio_event(True)
            elif st == 4:
                if not any(e["id"] != p[2] for e in self.calls):
                    self.call_audio_event(False)
                if self.at:
                    self.at.call_ended(p[2], p[5])
            self.call_list()
        elif (g, i) == (0x02, 0x06) and t == 2:
            info = self.decode_call_list(p)
        elif (g, i) in ((0x02, 0x02), (0x02, 0x09)):
            info = "incoming call" if i == 2 else "call waiting"
            self.call_list()
        elif (g, i) == (0x0D, 0x09) and t == 3 and p and p[0] == self.IMS_CID:
            info = self.ims_ip_config(p)
        elif (g, i) == (0x0D, 0x09) and t == 3:
            info = "data: " + self.ip_config(p)
        elif (g, i) == (0x0D, 0x10) and len(p) >= 3:
            st = p[1]
            info = f"cid {p[0]} {'connected' if st == 1 else f'state {st:#04x}'} (cause {p[2]})"
            if p[0] == self.IMS_CID and self.ims_phase != "down":
                info = "ims: " + info
                if st not in (0x01, 0x0A, 0x0B):
                    self.ims_phase = "down"
                    if self.ims:
                        self.ims.on_pdn_down()
            if p[0] == 1 and st not in (0x01, 0x0A, 0x0B) and self.data_phase != "down":
                self.data_down(retry=not self.mbim)
                self.st["ipcfg"] = None
            if self.mbim and p[0] == 1:
                self.mbim.notify_connect()
        elif (g, i) == (0x0D, 0x03) and len(p) >= 3:
            info = f"PS {'attached' if p[0] == 1 else f'state {p[0]}'} (cause {p[2]})"
        elif (g, i) == (0x04, 0x02):
            # Store first, acknowledge only once the PDU is safely on disk; otherwise
            # answer "memory full" so the network keeps the message and retries later.
            saved = self.store_sms(p)
            info = "SMS received (content not shown), " + ("saved" if saved else "NOT saved, rejected")
            if saved and self.mbim:
                self.mbim.notify_sms(self.sms_count())
            if len(p) >= 5 and p[0] == 2:
                tpid = p[4]
                res = b"\x00\x00" if saved else b"\x16\x80"      # 0x8016 = memory full
                self.send(0x04, 0x06, EXEC, bytes([2]) + res + bytes([tpid, 0]))
        elif (g, i) == (0x0A, 0x03) and len(p) >= 2:
            sn = p[2:2 + min(p[1], 32)].split(b"\0", 1)[0]
            dig = sn.decode("ascii", "replace")
            info = (f"IMEI check (value not shown): type {p[0]} len {len(sn)} "
                    f"digits {dig.isdigit()} all-zero {set(dig) <= {'0'}} "
                    f"luhn {dig.isdigit() and len(dig) == 15 and luhn_ok(dig)}")
            if dig.isdigit() and len(dig) >= 15 and luhn_ok(dig[:15]):
                self.st["imei"] = dig[:15]
            if dig.isdigit() and len(dig) > 15:
                info += " | luhn of 15-digit windows: " + " ".join(
                    f"@{k}:{luhn_ok(dig[k:k + 15])}" for k in range(len(dig) - 14))
        elif (g, i) == (0x0A, 0x2D) and t == 2 and len(p) >= 2:
            vd = {0: "CS only", 1: "IMS pref, CS fallback", 2: "IMS only", 3: "CS pref, IMS fallback"}
            info = f"voice domain LTE {p[0]} ({vd.get(p[0], '?')}), 3G {p[1]} ({vd.get(p[1], '?')})"
        elif (g, i) == (0x05, 0x09):
            info = self.ims.on_auth_response(p) if self.ims else "SIM auth (not shown)"
        elif (g, i) == (0x0A, 0x02):
            info = "(identity data, not shown)"
            if t == 2 and p and 0 < p[0] <= 15:
                imsi = p[1:1 + p[0]].decode("ascii", "replace")
                if imsi.isdigit():
                    self.st["imsi"] = imsi
                    # VOLTE=register|mmtel: the PS/LTE registration may have come
                    # before the IMSI; at a stable signal no further NET_REGIST NOTI
                    # would trigger the automatic start (live 2026-11-21)
                    if self.ims and self.ps_registered and self.st.get("act") == 0x21 \
                            and self.st.get("volte"):
                        self.ims.maybe_auto(True)
            if self.mbim:
                self.mbim.notify_subscriber()
        elif (g, i) == (0x05, 0x0C) and len(p) >= 2:
            info = "(ICCID, not shown)"
            n = min(p[0], len(p) - 1, 10)
            d = "".join(f"{b & 0xF:x}{b >> 4:x}" for b in p[1:1 + n]).rstrip("f")
            if d.isdigit() and 18 <= len(d) <= 20:
                self.st["iccid"] = d
        if not info and (g, i) in self.raw and g in self.RAW_OK and t == 2:
            info = "raw " + p[:64].hex(" ")
        if (g, i) == (0x80, 0x01) and len(p) >= 2 and (p[0], p[1]) in self.raw:
            info += " (raw GET answered by GEN_PHONE_RES)"
        log(head + (" | " + info if info else ""))

    def store_sms(self, p):
        """Append the raw SMS_INCOMING_MSG payload (SMSC + TPDU, spec 3.11) as one hex line
        to a root-only file.  Decode later with any PDU tool; it is never logged."""
        try:
            os.makedirs(os.path.dirname(self.sms_file), 0o700, exist_ok=True)
            fd = os.open(self.sms_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, f"{int(time.time())} {p.hex()}\n".encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            return True
        except OSError as e:
            log(f"fmt: storing SMS failed: {e}")
            return False

    def sms_records(self):
        """Inbox lines -> [(index from 1, payload bytes)]; plus the read/deleted sidecar."""
        out = []
        try:
            with open(self.sms_file) as f:
                for k, line in enumerate(f, 1):
                    try:
                        out.append((k, bytes.fromhex(line.split()[1])))
                    except (IndexError, ValueError):
                        pass
        except OSError:
            pass
        return out

    def sms_count(self):
        return len(self.sms_records())

    def sms_flags(self):
        import json
        try:
            with open(self.sms_file + ".state") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def sms_set_flag(self, index, flag):
        import json
        st = self.sms_flags()
        if index is None:
            for k, _ in self.sms_records():
                st[str(k)] = "deleted"
        else:
            st[str(index)] = flag
        tmp = self.sms_file + ".state.tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, self.sms_file + ".state")

    def send_sms_pdu(self, pdu, timeout=30):
        """SMSC+TPDU from ModemManager; waits for the SEND_MSG result NOTI."""
        if pdu and pdu[0] == 0 and self.smsc:
            pdu = self.smsc + pdu[1:]
        ev, out = threading.Event(), []
        self.sms_result = (ev, out)
        try:
            log(f"fmt: sending SMS for ModemManager ({len(pdu)} bytes, content not shown)")
            self.send(0x04, 0x01, EXEC, bytes([0x02, 0x02, self.sms_domain, len(pdu)]) + pdu)
            if not ev.wait(timeout) or not out:
                return False, 0
            return out[0] == 0, out[1]
        finally:
            self.sms_result = None

    def _radio_on_fallback(self):
        if self.radio_after_apn:
            log("fmt: no answer to the attach APN in 3 s; radio on anyway")
            self.radio_after_apn = False
            self.radio(True)

    ABOX_VSS = "/sys/kernel/debug/18c50000.audio-controller/vss"

    def on_pwr_up(self):
        # CP online: ABOX_START_VSS, as the downstream modem notifier (kernel 0281)
        try:
            with open(self.ABOX_VSS, "w") as f:
                f.write("start")
            log("audio: ABOX VSS start sent")
        except OSError as e:
            log(f"audio: ABOX VSS start: {e}")
        # A PWR_UP after a CP restart: whatever data session we had is gone.  Tell
        # ModemManager (CONNECT deactivated) so NetworkManager connects again.
        if self.ims and (self.ims.ua or self.ims_phase != "down"):
            self.ims_phase = "down"
            self.ims.on_pdn_down("CP (re)started")
        if self.data_phase != "down" or self.st["ipcfg"]:
            log("fmt: CP (re)started: previous data session dropped")
            if self.lazy_timer:
                self.lazy_timer.cancel()
                self.lazy_timer = None
            self.data_phase = "down"
            self.st["ipcfg"] = None
            self.mbim_connect = False
            if self.mbim:
                self.mbim.notify_connect()
        self.powered.clear()
        self.powered.set()
        if getattr(self, "idle", None):
            self.idle.on_pwr_up()             # CP forgot the screen state; PDA_ACTIVE is 1
        # The CP boots online (stock RIL: "Online booting"): go to LPM before anything else,
        # give it the initial attach APN (without one it stays in limited service), then
        # restore the radio state the user last chose.
        self.radio(False)
        want_on = self.allow_radio and self.saved_radio_on()
        if self.apn:
            # radio on only once the CP took the APN: if it processes "on" first it
            # attaches without one and stays in limited service (seen 2026-11-20)
            self.radio_after_apn = want_on
            self.set_attach_apn(self.apn)
            if want_on:
                threading.Timer(3.0, self._radio_on_fallback).start()
        elif want_on:
            self.radio(True)
        for q in ("ver", "pin", "reg", "net", "icon", "smsc", "smsready", "imeicheck"):
            self.query(q)

    def loop(self, stop):
        buf = bytearray()
        while not stop.is_set():
            try:
                chunk = os.read(self.fd, 0x10000)
            except InterruptedError:
                continue
            buf += chunk
            while len(buf) >= 7:
                ln = struct.unpack_from("<H", buf)[0]
                if ln < 7 or ln > 0x8400:
                    log(f"fmt: bad length {ln}, dropping {len(buf)} bytes")
                    buf.clear()
                    break
                if len(buf) < ln:
                    break
                m, buf = bytes(buf[:ln]), buf[ln:]
                try:
                    self.decode(m)
                except Exception as e:      # never let one odd message kill the client
                    log(f"fmt: decode error {e!r}")
            if 0 < len(buf) < 7 and not chunk:
                buf.clear()


def watch_only(dev, stop):
    """Second SIM channel: log headers only."""
    try:
        fd = os.open(dev, os.O_RDONLY)
    except OSError:
        return
    while not stop.is_set():
        m = os.read(fd, 0x10000)
        if len(m) >= 7:
            ln, _, _, g, i, t = struct.unpack_from("<HBBBBB", m)
            log(f"fmt1: < {Fmt.name(g, i)} {RX_TYPES.get(t, t)} len {ln}")


def mm_dial(number):
    """Place an outgoing call via ModemManager (mmcli).  -> True if MM took it.
    The number is never logged."""
    if not re.fullmatch(r"\+?[0-9*#]{3,20}", number):
        return False
    try:
        r = subprocess.run(["mmcli", "-m", "any", f"--voice-create-call=number={number}"],
                           capture_output=True, text=True, timeout=10)
        m = re.search(r"/org/freedesktop/ModemManager1/Call/(\d+)", r.stdout)
        if r.returncode or not m:
            return False
    except (OSError, subprocess.TimeoutExpired):
        return False
    # The call object exists now: never fall back to the IPC dial after this point
    # (a second call confuses MM's call list and it drops its call).
    try:
        r = subprocess.run(["mmcli", "-o", m.group(1), "--start"],
                           capture_output=True, text=True, timeout=30)
        err = re.sub(r"\+?\d{6,}", "<num>", (r.stderr or "").strip())[:160]
        log(f"ctl: dial via ModemManager: call {m.group(1)} "
            + ("started" if r.returncode == 0 else f"start returned {r.returncode}: {err}"))
    except (OSError, subprocess.TimeoutExpired) as e:
        log(f"ctl: dial via ModemManager: call {m.group(1)} start: {e.__class__.__name__}")
    return True


AUDIO_CTL = "/run/shannon-audio/ctl"
AUDIO_CMDS = {"audio": ("earpiece", "speaker"), "mute": ("on", "off"),
              "volume": tuple("012345")}


def audio_ctl_loop(fmt, stop, group="netdev"):
    """Second FIFO for the session user (GNOME Calls buttons via shannon-callaudio-bridge):
    group netdev (the phone user) writable, accepts only audio/mute/volume lines and forwards them to the main FIFO
    handler's code paths."""
    import grp
    d = os.path.dirname(AUDIO_CTL)
    os.makedirs(d, 0o755, exist_ok=True)
    if os.path.lexists(AUDIO_CTL) and not stat.S_ISFIFO(os.lstat(AUDIO_CTL).st_mode):
        os.unlink(AUDIO_CTL)
    if not os.path.exists(AUDIO_CTL):
        os.mkfifo(AUDIO_CTL, 0o620)
    try:
        os.chown(AUDIO_CTL, 0, grp.getgrnam(group).gr_gid)
        os.chmod(AUDIO_CTL, 0o620)
    except (KeyError, OSError) as e:
        log(f"ctl-audio: {e!r}")
    while not stop.is_set():
        with open(AUDIO_CTL) as f:
            for line in f:
                w = line.split()
                if len(w) == 3 and w[:2] == ["missed", "clear"] and w[2].isdigit():
                    fmt.missed_clear(int(w[2]))
                    continue
                if len(w) != 2 or w[1] not in AUDIO_CMDS.get(w[0], ()):
                    continue
                log(f"ctl-audio: {w[0]} {w[1]}")
                if w[0] == "audio":
                    fmt.set_audio_dev(w[1])
                elif w[0] == "mute":
                    fmt.set_mute(w[1] == "on")
                else:
                    fmt.call_volume = int(w[1])
                    if fmt.call_audio_on:
                        fmt.send(0x09, 0x01, SET,
                                 bytes([fmt.VOLUME_TYPES[fmt.audio_dev], fmt.call_volume]))


def ctl_loop(path, fmt, stop):
    os.makedirs(os.path.dirname(path), 0o700, exist_ok=True)
    # A plain file here (an `echo > ctl` while the daemon was down) would be re-read
    # forever: replace anything that is not a FIFO.
    if os.path.lexists(path) and not stat.S_ISFIFO(os.lstat(path).st_mode):
        log(f"ctl: {path} was not a FIFO; replacing it")
        os.unlink(path)
    if not os.path.exists(path):
        os.mkfifo(path, 0o600)
    while not stop.is_set():
        with open(path) as f:
            for line in f:
                w = line.split()
                if not w:
                    continue
                log(f"ctl: {w[0]}" + ("" if w[0] in ("sms", "dial") else
                                      " " + " ".join(w[1:2] if w[0] == "ims" else w[1:])))
                if w[0] == "get" and len(w) == 2:
                    fmt.query(w[1])
                elif w[0] == "getraw" and len(w) >= 3:
                    fmt.getraw(int(w[1], 16), int(w[2], 16), bytes.fromhex("".join(w[3:])))
                elif w[0] == "setapn" and len(w) in (2, 3):
                    fmt.set_attach_apn(w[1], w[2] if len(w) == 3 else "ipv4v6")
                elif w[0] == "sms" and len(w) >= 3:
                    if fmt.allow_radio:
                        fmt.send_sms(w[1], line.rstrip("\n").split(None, 2)[2])
                    else:
                        log("ctl: sms refused (start with --allow-radio)")
                elif w[0] == "smsdomain" and len(w) == 2:
                    fmt.sms_domain = int(w[1], 16) & 0xFF
                    log(f"ctl: SMS domain {fmt.sms_domain:#04x}")
                elif w[0] == "dial" and len(w) == 2:
                    # Through ModemManager when it runs, so GNOME Calls shows the call
                    # (MM only adopts calls it placed itself); the IPC dial otherwise.
                    if fmt.allow_radio and not mm_dial(w[1]):
                        fmt.dial(w[1])
                elif w[0] == "answer" and len(w) == 1:
                    fmt.send(0x02, 0x04, EXEC)
                elif w[0] == "hangup" and len(w) == 1:
                    fmt.release_call()
                elif w[0] == "calls" and len(w) == 1:
                    fmt.call_list()
                elif w[0] == "audio" and len(w) == 2 and w[1] in ("earpiece", "speaker"):
                    fmt.set_audio_dev(w[1])
                elif w[0] == "mute" and len(w) == 2 and w[1] in ("on", "off"):
                    fmt.set_mute(w[1] == "on")
                elif w[0] == "volume" and len(w) == 2 and w[1].isdigit() and int(w[1]) <= 5:
                    fmt.call_volume = int(w[1])
                    if fmt.call_audio_on:
                        fmt.send(0x09, 0x01, SET,
                                 bytes([fmt.VOLUME_TYPES[fmt.audio_dev], fmt.call_volume]))
                elif w[0] == "data" and len(w) == 2 and w[1] in ("on", "off"):
                    fmt.set_data(w[1] == "on")
                elif w[0] == "ims" and len(w) in (2, 3) and w[1] in ("up", "down"):
                    if w[1] == "up":
                        fmt.ims_up(*w[2:])
                    elif fmt.ims:
                        fmt.ims.down()
                    else:
                        fmt.ims_down()
                elif w[0] == "ims" and len(w) >= 2 and fmt.ims and w[1] in (
                        "register", "deregister", "status", "akatest", "dial", "answer", "hangup",
                        "netup", "ping"):
                    if w[1] == "register" and fmt.allow_radio:
                        fmt.ims.register(mmtel=len(w) > 2 and w[2] == "mmtel")
                    elif w[1] == "deregister":
                        threading.Thread(target=fmt.ims.deregister, daemon=True).start()
                    elif w[1] == "status":
                        fmt.ims.status()
                    elif w[1] == "akatest":
                        fmt.ims.akatest(w[2] if len(w) > 2 else None)
                    elif w[1] == "dial" and len(w) == 3:
                        if not fmt.ims.dial(w[2]):
                            log("ims: dial refused (not MMTel-registered, or emergency/bad number)")
                    elif w[1] == "answer":
                        fmt.ims.answer()
                    elif w[1] == "hangup":
                        fmt.ims.hangup()
                    elif w[1] == "netup":
                        fmt.ims.netup()
                    elif w[1] == "ping":
                        fmt.ims.ping()
                elif w[0] == "psattach" and len(w) == 1:
                    if fmt.allow_radio:
                        fmt.ps_attach()
                    else:
                        log("ctl: psattach refused (start with --allow-radio)")
                elif w[0] == "radio" and len(w) == 2 and w[1] in ("on", "off"):
                    fmt.radio(w[1] == "on", save=True)
                elif w[0] == "idle" and len(w) == 2 and w[1] in ("on", "off", "status") \
                        and getattr(fmt, "idle", None):
                    if w[1] == "status":
                        fmt.idle.status()
                    else:
                        fmt.idle.set_enabled(w[1] == "on")
                elif w[0] == "quit":
                    stop.set()
                    if getattr(fmt, "idle", None):
                        fmt.idle.restore()
                    if fmt.ims:
                        fmt.ims.shutdown()
                    os._exit(0)
                else:
                    log("ctl: get ver|pin|reg|regps|net|icon|imeicheck, getraw G I [hex], "
                        "setapn APN [ip|ipv6|ipv4v6], psattach, radio on|off, data on|off, "
                        "idle on|off|status, sms NUMBER TEXT, ims up|down|register [mmtel]|deregister|status|"
                        "akatest [isim|usim]|netup|ping|dial N|answer|hangup, quit")


REG_MBIM = {0x02: "home", 0x20: "home", 0x22: "home", 0x06: "roaming", 0x03: "searching",
            0x04: "denied", 0x09: "denied", 0x01: "deregistered", 0x08: "deregistered",
            0x07: "searching", 0x0A: "searching"}
ACT_MBIM = {0x21: "lte", 0x24: "nr", 0x04: "umts", 0x05: "umts", 0x01: "gsm", 0x02: "gsm",
            0x03: "gsm"}


# The CP only reports the PLMN (NET_SERVING_NETWORK); network names (NET identity,
# EMM INFORMATION) are not sent on Play.  Name the operator from
# mobile-broadband-provider-info, preferring the primary="true" provider.
MBPI = "/usr/share/mobile-broadband-provider-info/serviceproviders.xml"
_provider_names = {}


def provider_name(plmn):
    if not plmn or len(plmn) < 5 or not plmn.isdigit():
        return None
    if plmn in _provider_names:
        return _provider_names[plmn]
    name = None
    try:
        import xml.etree.ElementTree as ET
        mcc, mnc = plmn[:3], plmn[3:]
        best = None
        for prov in ET.parse(MBPI).getroot().iter("provider"):
            if any(n.get("mcc") == mcc and n.get("mnc") == mnc for n in prov.iter("network-id")):
                nm = (prov.findtext("name") or "").strip()
                if nm and (best is None or prov.get("primary") == "true"):
                    best = nm
                    if prov.get("primary") == "true":
                        break
        name = best
    except Exception as e:
        log(f"mbim: operator name lookup failed: {type(e).__name__}")
    _provider_names[plmn] = name
    log(f"mbim: operator {plmn} named {name!r} (mobile-broadband-provider-info)")
    return name


class MbimBackend:
    """Answers mbim_function.MbimFunction from the daemon's cached state (fast, no IPC
    round trips); actions go out as IPC and complete through notify_*()."""

    def __init__(self, fmt):
        self.f = fmt

    def device_ids(self):
        return dict(imei=self.f.st["imei"], firmware=self.f.st["sw"], hardware="beyond2lte",
                    model="SM-G975F", manufacturer="Samsung")

    def sim(self):
        s = self.f.st["sim"]
        state = ("initializing" if s is None else "ready" if s in (0x00, 0x82, 0x83)
                 else "absent" if s in (0x80, 0x88) else "locked" if s in (0x03, 0x05, 0x06,
                 0x07, 0x08) else "error")
        return dict(state=state, imsi=self.f.st["imsi"], iccid=self.f.st["iccid"], msisdn=[])

    def radio(self):
        return self.f.st["radio"]

    def set_radio(self, on):
        self.f.radio(on, save=True)

    def registration(self):
        ps = self.f.st["ps"]
        return dict(state=REG_MBIM.get(ps, "unknown") if ps is not None else "unknown",
                    plmn=self.f.st["plmn"], provider=provider_name(self.f.st["plmn"]),
                    act=ACT_MBIM.get(self.f.st["act"]))

    def provider_name(self, plmn):
        return provider_name(plmn)

    def packet_attached(self):
        return self.f.ps_registered

    def signal(self):
        # MBIM 1.0 only has an RSSI scale; on LTE the CP's "RSSI" is really RSRP, which
        # sits 20-30 dB lower, so map RSRP -140..-44 onto the RSSI range -113..-51.
        rsrp, rssi = self.f.st["rsrp"], self.f.st["rssi"]
        if rsrp is not None:
            rssi = round(-113 + (max(-140, min(-44, rsrp)) + 140) * 62 / 96)
        return dict(rssi_dbm=rssi, rsrp_dbm=rsrp, rsrq_db=self.f.st["rsrq"],
                    bars=self.f.st["bars"])

    # NetworkManager disconnects every device at system suspend and connects again
    # at resume.  Tearing the PDN down each time makes the CP signal (CALL_STATUS,
    # CA status...) a few seconds later, which wakes the AP again: a wake loop.  So an
    # MBIM disconnect only drops the session towards ModemManager; the PDN stays up
    # for LAZY_DOWN seconds and a reconnect within that time reuses it.
    LAZY_DOWN = 600

    def connect(self, apn, ip_type, user, password, auth):
        if apn and apn != self.f.apn:
            log("mbim: connect with a different APN than the attach APN; using it")
            self.f.apn = apn
        if self.f.lazy_timer:
            self.f.lazy_timer.cancel()
            self.f.lazy_timer = None
        self.f.mbim_connect = True
        self.f.data_retry_at = 0.0
        if self.f.data_phase == "up" and self.f.st["ipcfg"]:
            log("mbim: connect: reusing the PDN that is still up")
            self.f.mbim.notify_connect()
            return
        self.f.maybe_data_up()
        if self.f.data_phase == "down":       # not registered yet: report it
            self.f.mbim.notify_connect()

    def disconnect(self):
        self.f.mbim_connect = False
        if self.f.data_phase == "up" and self.LAZY_DOWN > 0:
            if self.f.lazy_timer:
                self.f.lazy_timer.cancel()
            self.f.lazy_timer = threading.Timer(self.LAZY_DOWN, self._really_down)
            self.f.lazy_timer.daemon = True
            self.f.lazy_timer.start()
            log(f"mbim: disconnect: PDN kept up for {self.LAZY_DOWN} s")
        else:
            self._really_down()
        if self.f.mbim:
            self.f.mbim.notify_connect()

    def _really_down(self):
        self.f.lazy_timer = None
        if self.f.mbim_connect:
            return
        log("mbim: deactivating the PDN")
        self.f.data_down(send=True)
        self.f.st["ipcfg"] = None

    def connection(self):
        if not self.f.mbim_connect and self.f.lazy_timer:
            return dict(state="deactivated", ip_type="ipv4v6")   # kept up underneath
        ph = self.f.data_phase
        state = {"up": "activated", "defining": "activating", "activating": "activating"}.get(
            ph, "deactivated")
        if state == "activated" and not self.f.st["ipcfg"]:
            state = "activating"
        return dict(state=state, ip_type="ipv4v6")

    def ip_config(self):
        return self.f.st["ipcfg"]

    def sms_list(self):
        flags = self.f.sms_flags()
        out = []
        for k, p in self.f.sms_records():
            fl = flags.get(str(k), "new")
            if fl == "deleted" or len(p) < 7 or p[0] != 2:
                continue
            ln = p[5]
            out.append(dict(index=k, status=fl, pdu=bytes(p[6:6 + ln])))
        return out

    def sms_send(self, pdu):
        return self.f.send_sms_pdu(pdu)

    def sms_delete(self, index):
        self.f.sms_set_flag(index, "deleted")

    def sms_mark_read(self, index):
        self.f.sms_set_flag(index, "old")

    def smsc(self):
        s = self.f.smsc
        if not s or len(s) < 2:
            return None
        digits = "".join(f"{b & 0xF:x}{b >> 4:x}" for b in s[2:]).rstrip("f")
        return ("+" if s[1] == 0x91 else "") + digits


class AtEmulator:
    """Voice for ModemManager over the WWAN AT port (/dev/wwan0at0 <-> /dev/umts_at).
    Only the call commands are emulated; everything else stays on MBIM.
    Numbers are passed to the host but never logged."""

    def __init__(self, fmt, fd):
        self.f, self.fd = fmt, fd
        self.lock = threading.Lock()
        self.known = {}               # call id -> last state, for RING / NO CARRIER

    def out(self, s):
        with self.lock:
            try:
                os.write(self.fd, s.encode())
            except OSError as e:
                log(f"at: write failed: {e}")

    def ok(self):
        self.out("\r\nOK\r\n")

    def ims_calls(self):
        return self.f.ims.entries() if self.f.ims else []

    def calls_changed(self, entries):
        for e in entries:
            prev = self.known.get(e["id"])
            if e["state"] in (5, 6) and prev not in (5, 6):
                typ = 145 if e["intl"] else 129
                if e["state"] == 5:
                    # +CLIP before RING: MM creates the call from whichever URC it
                    # parses first; from +CLIP it is exported with the number set.
                    # Plasma Dialer reads the number once, at CallAdded,
                    # so a RING parsed alone would show
                    # "No Caller ID".
                    self.out(f'\r\n+CLIP: "{e["number"]}",{typ},,,,0\r\n\r\nRING\r\n')
                else:
                    self.out(f'\r\n+CCWA: "{e["number"]}",{typ},1\r\n')
            self.known[e["id"]] = e["state"]
        gone = set(self.known) - {e["id"] for e in entries}
        for cid in gone:
            self.known.pop(cid, None)

    def call_ended(self, cid, cause):
        if cid in self.known:
            self.known.pop(cid, None)
        # MM stops polling while every call is active: the end must be signalled
        self.out("\r\nNO CARRIER\r\n")

    def clcc_index(self, key, live):
        """+CLCC index for a call: a fresh index per new call, round robin over 1..7.
        The CP numbers every new call #0 again; reusing index 1 made ModemManager
        attach it to the previous, terminated call object, so DTMF on the next
        call failed with "Invalid call index" (live 2026-11-21)."""
        idx = getattr(self, "_clcc_idx", None)
        if idx is None:
            idx = self._clcc_idx = {}
            self._clcc_next = 1
        for k in [k for k in idx if k not in live]:
            del idx[k]
        if key not in idx:
            used = set(idx.values())
            for _ in range(7):
                n = self._clcc_next
                self._clcc_next = n % 7 + 1
                if n not in used:
                    idx[key] = n
                    break
            else:
                idx[key] = (max(used) % 7) + 1
        return idx[key]

    def clcc(self):
        rows = ""
        calls = self.f.all_calls()
        live = {(e["id"], e["dir"]) for e in calls}
        for e in calls:
            d = 0 if e["dir"] == 1 else 1
            stat = max(0, e["state"] - 1)
            n = self.clcc_index((e["id"], e["dir"]), live)
            rows += (f'\r\n+CLCC: {n},{d},{stat},0,{1 if e["mpty"] else 0},'
                     f'"{e["number"]}",{145 if e["intl"] else 129}')
        self.out(rows + ("\r\n" if rows else "") + "\r\nOK\r\n")
        self.f.call_list()            # refresh for the next poll

    def handle(self, line):
        c = line.strip()
        u = c.upper()
        if not u:
            return
        verb = u.split("=")[0].split("?")[0]
        log(f"at: {verb if not u.startswith('ATD') else 'ATD'}")
        if u in ("AT", "ATE0", "ATV1", "AT+CMEE=1", "ATX4", "AT&C1", "ATH", "AT+CLCC=?",
                 "AT+CLIP=1", "AT+CLIP=0", "AT+CRC=1", "AT+CRC=0", "AT+CCWA=1", "AT+CCWA=0",
                 "AT+CCWA=1,1", "AT+CCWA=1,0") or u.startswith("AT+VTD="):
            if u == "ATH" and self.f.calls:
                self.f.release_call()
            if u == "ATH" and self.ims_calls():
                self.f.ims.hangup()
            self.ok()
        elif u == "AT+CCWA=1,2":
            self.out("\r\n+CCWA: 1,1\r\n\r\nOK\r\n")
        elif u == "AT+CLCC":
            self.clcc()
        elif u.startswith("ATD"):
            num = c[3:].rstrip(";").strip()
            # VoLTE when MMTel-registered (never for emergency numbers: the UA refuses
            # them and they go to CS below), otherwise CS
            if self.f.allow_radio and self.f.ims and self.f.ims.can_call() and \
                    self.f.ims.dial(num):
                log("at: ATD over IMS")
                self.ok()
            elif self.f.allow_radio and self.f.dial(num, allow_emergency=True):
                self.ok()
            else:
                self.out("\r\nNO CARRIER\r\n")
        elif u == "ATA":
            self.ok()
            if self.f.ims and self.f.ims.has_incoming():
                self.f.ims.answer()
            else:
                self.f.send(0x02, 0x04, EXEC)
        elif u in ("AT+CHUP", "AT+CHLD=0") or u.startswith("AT+CHLD=1"):
            self.ok()
            if self.ims_calls():
                self.f.ims.hangup()
            if self.f.calls or not self.ims_calls():
                self.f.release_call()
        elif u.startswith("AT+CHLD="):
            op = {"AT+CHLD=2": 4, "AT+CHLD=3": 6}.get(u)
            if op:
                body = bytearray(92 - 7)
                body[0] = op
                self.f.send(0x0C, 0x07, SET, bytes(body))
                self.ok()
            else:
                self.out("\r\nERROR\r\n")
        elif u.startswith("AT+VTS="):
            # 27.007: AT+VTS=<DTMF> (also quoted) or AT+VTS={<DTMF>,<duration>}
            d = c[7:].strip().lstrip("{").strip().strip('"').upper()
            if d and d[0] in "0123456789*#ABCD":
                if self.ims_calls():
                    self.f.ims.dtmf(d[0])
                else:
                    self.f.dtmf(d[0])
                self.ok()
            else:
                self.out("\r\nERROR\r\n")
        else:
            self.out("\r\nERROR\r\n")


def at_bridge(fmt, stop, dev="/dev/umts_at"):
    try:
        fd = os.open(dev, os.O_RDWR)
    except OSError as e:
        log(f"at: {dev}: {e}; no voice for ModemManager")
        return
    at = AtEmulator(fmt, fd)
    fmt.at = at
    log("at: bridge ready (voice)")
    buf = ""
    while not stop.is_set():
        try:
            data = os.read(fd, 4096)
        except InterruptedError:
            continue
        if not data:
            continue
        buf += data.decode("ascii", "replace")
        while "\r" in buf or "\n" in buf:
            idx = min(i for i in (buf.find("\r"), buf.find("\n")) if i >= 0)
            line, buf = buf[:idx], buf[idx + 1:]
            try:
                at.handle(line)
            except Exception as e:     # never stall the host on a bug
                log(f"at: error {e!r}")
                at.out("\r\nERROR\r\n")
        if len(buf) > 4096:
            buf = ""


def mbim_bridge(fmt, stop, dev="/dev/umts_mbim"):
    """ModemManager <-> /dev/wwan0mbim0 <-> kernel <-> here.  Markers: ff ff ff ff = host
    opened the port, fe ff ff ff = host closed it."""
    try:
        import mbim_function
    except ImportError as e:
        log(f"mbim: module missing ({e}); ModemManager support off")
        return
    try:
        fd = os.open(dev, os.O_RDWR)
    except OSError as e:
        log(f"mbim: {dev}: {e}; ModemManager support off")
        return
    lock = threading.Lock()

    def write(msg):
        with lock:
            os.write(fd, msg)

    fn = mbim_function.MbimFunction(MbimBackend(fmt), write, log=log, apn=fmt.apn or "",
                                    netdev=fmt.netdev)
    log("mbim: bridge ready")
    while not stop.is_set():
        try:
            data = os.read(fd, 0x10000)
        except InterruptedError:
            continue
        if data == b"\xff\xff\xff\xff":
            log("mbim: host opened the port (ModemManager)")
            fn.reset()
            if fmt.data_phase == "up" and not fmt.mbim:
                # our own data session: hand the link over to ModemManager/NetworkManager
                fmt.data_down(send=True)
                fmt.st["ipcfg"] = None
            fmt.mbim = fn
        elif data == b"\xfd\xff\xff\xff":
            # kernel: the host already had the port open when we attached (daemon restart)
            log("mbim: host already attached; resuming its session")
            fn.assume_open()
            fmt.mbim = fn
            if fmt.fresh_cp:
                # the CP was (re)booted under a running ModemManager: its data
                # session died with the old CP, let NetworkManager reconnect
                log("mbim: fresh CP: reporting the old data session as gone")
                fn.notify_connect()
        elif data == b"\xfe\xff\xff\xff":
            log("mbim: host closed the port")
            fmt.mbim = None
            fmt.mbim_connect = False
            fn.reset()
            fmt.maybe_data_up()                 # back to the daemon's own data handling
        elif data:
            if not fmt.mbim:
                # ModemManager held the port while the daemon restarted: no OPEN will come
                if len(data) >= 4 and struct.unpack_from("<I", data)[0] != 1:
                    log("mbim: host already attached; resuming its session")
                    fn.assume_open()
                fmt.mbim = fn
            fn.feed(data)


# --------------------------------------------------------------------------- IDLE
# Screen-off policy towards the CP.  Two levers:
#  1. MISC 0A 0F EVENT <0|1> (stock IpcTxSetScreenState, byte-identical).  The CP
#     uses it for fast dormancy, HSDPA status and IMS weak-cell logic; it does NOT
#     gate DISP_RSSI_INFO / ICON / NET REG NTFs.
#  2. PDA_ACTIVE (AP2CP united status ISSR2 bit 5, kernel attribute pda_active,
#     kernel patch 0296, linux-postmarketos-exynos9820 r148+).  With it low the CP firmware
#     holds back RSSI, icon, REG, serving network, CP channel info, PS barring and
#     eMBMS NTFs ("PDA_ACTIVE low, Don't Send ...") and drops its MIF lock ("MIF
#     unlock by AP sleep"); on high it re-sends registration/band state.  Calls and
#     SMS are not gated.  The stock 9820 kernel never lowers it: not stock behaviour.
PDA_KNOB = "/sys/devices/platform/soc@0/15920000.modem/pda_active"


class Idle:
    """Drives both levers from the debounced display state.  tick() is called once a
    second by screen_watch; ctl "idle on|off|status" switches lever 2 at run time,
    lever 1 and the NOTI accounting always run."""

    def __init__(self, fmt, enabled=True, knob=PDA_KNOB, on_after=4, pda_delay=5):
        self.fmt, self.enabled, self.knob = fmt, enabled, knob
        self.on_after = on_after      # "on" only after the panel stayed on this long: a
        #                               resume flashes it on until the dark-wake helper
        #                               turns it off, and that must not wake the CP's reports
        self.pda_delay = pda_delay    # screen off this long before PDA_ACTIVE goes low
        self.lock = threading.Lock()
        self.sent = None              # screen state last told to the CP
        self.resend = False           # CP restarted: it forgot the screen state
        self.on_since = None
        self.pda = None               # PDA_ACTIVE we last wrote (None: unknown)
        self.pda_low_since = None
        self.knob_ok = None           # attribute present (None: not checked yet)
        self.counts = {}              # NOTIs while the screen is off, (g, i) -> n
        self.counted_since = None
        self.retry_at = 0.0           # failed write: back off until then
        self.backoff = 0.0
        self.checked_at = 0.0         # last re-read of the attribute while low

    def on_pwr_up(self):
        """CP (re)started: s5000ap step_on set PDA_ACTIVE 1 and the screen state is reset."""
        with self.lock:
            self.resend, self.pda = True, None

    def count(self, g, i, t):
        if t == 3 and self.sent is False:
            with self.lock:
                self.counts[(g, i)] = self.counts.get((g, i), 0) + 1

    def restore(self):
        """Daemon exit: leave the CP with PDA_ACTIVE 1 (nothing else would raise it)."""
        if self.pda is False and self.knob_ok:
            try:
                with open(self.knob, "w") as f:
                    f.write("1")
                log("idle: PDA_ACTIVE 1 -> CP (exit)")
            except OSError:
                pass

    def in_call(self):
        try:
            return bool(self.fmt.all_calls())
        except Exception:
            return bool(getattr(self.fmt, "calls", None))

    def set_enabled(self, on):
        with self.lock:
            self.enabled = on
        log(f"idle: PDA_ACTIVE policy {'on' if on else 'off'}")

    def status(self):
        log(f"idle: policy {'on' if self.enabled else 'off'}, screen "
            f"{ {None: '?', True: 'on', False: 'off'}[self.sent]} -> CP, PDA_ACTIVE "
            f"{ {None: '?', True: 1, False: 0}[self.pda]}"
            f"{'' if self.knob_ok is not False else ' (no pda_active attribute)'}, "
            f"{sum(self.counts.values())} NOTIs counted while off")

    def _summary(self, now):
        c, self.counts = self.counts, {}
        since, self.counted_since = self.counted_since, None
        if since is None:
            return
        top = ", ".join(f"{self.fmt.name(g, i)} {n}" for (g, i), n in
                        sorted(c.items(), key=lambda kv: -kv[1])[:6])
        log(f"idle: screen was off {now - since:.0f} s: {sum(c.values())} NOTIs"
            + (f" ({top})" if top else ""))

    def _write_pda(self, v, now):
        if self.knob_ok is None:
            self.knob_ok = os.path.exists(self.knob)
            if not self.knob_ok:
                log(f"idle: {self.knob} missing (kernel without the pda_active "
                    "attribute): screen state only")
        if self.knob_ok:
            if now < self.retry_at:
                return
            try:
                with open(self.knob, "w") as f:
                    f.write("1" if v else "0")
            except OSError as e:
                # e.g. ENOLINK after a CP crash: back off 5 s .. 5 min, log on change only
                if not self.backoff:
                    log(f"idle: PDA_ACTIVE {int(v)}: {e} (backing off)")
                self.backoff = min(max(self.backoff * 2, 5.0), 300.0)
                self.retry_at = now + self.backoff
                return
            if self.backoff:
                log("idle: PDA_ACTIVE write works again")
            self.backoff, self.retry_at = 0.0, 0.0
            low = (f" (was low {now - self.pda_low_since:.0f} s)"
                   if v and self.pda_low_since is not None else "")
            log(f"idle: PDA_ACTIVE {int(v)} -> CP{low}")
        was_low = self.pda is False
        self.pda = v
        self.pda_low_since = None if v else now
        if v and was_low and self.knob_ok:
            # the CP re-sends REG/band itself on high (traces "PDA_ACTIVE high (...)");
            # ask for the rest that it held back while low
            for q in ("reg", "regps", "net", "icon"):
                self.fmt.query(q)

    def tick(self, on, now):
        """on: True/False display state, None unknown (no DSI connector)."""
        f = self.fmt
        cp_up = f.powered.is_set() or f.st["sw"] is not None
        with self.lock:
            self.on_since = (self.on_since or now) if on else None
            want = None
            if on is False and (self.sent is not False or self.resend):
                want = False
            elif on and (self.sent is not True or self.resend) \
                    and now - self.on_since >= self.on_after:
                want = True
            if want is not None and cp_up:
                f.send(0x0A, 0x0F, EVENT, b"\x01" if want else b"\x00")
                log(f"fmt: screen {'on' if want else 'off'} -> CP")
                if want and self.sent is False:
                    self._summary(now)
                elif not want and self.sent is not False:
                    self.counted_since = now      # also the start of the PDA delay
                self.sent, self.resend = want, False
            if not cp_up:
                return
            # follows the debounced state told to the CP, so a resume flash of the
            # panel does not raise PDA_ACTIVE (and the CP's re-send burst) either
            low = (self.enabled and self.sent is False and self.counted_since is not None
                   and now - self.counted_since >= self.pda_delay and not self.in_call())
            if self.pda is False and self.knob_ok and now - self.checked_at >= 30:
                # the kernel raises it by itself (CP restart, resume repair): notice
                self.checked_at = now
                try:
                    with open(self.knob) as fh:
                        if fh.read().strip() == "1":
                            log("idle: PDA_ACTIVE was raised by the kernel")
                            self.pda = True
                except OSError:
                    pass
            if self.pda is None or self.pda == low:
                self._write_pda(not low, now)


def screen_watch(idle, stop, poll=1):
    """Feed the display state (DRM DSI dpms) to the Idle policy once a second."""
    import glob
    while not stop.is_set():
        on = None
        for p in glob.glob("/sys/class/drm/card*-DSI-*/dpms"):
            try:
                with open(p) as f:
                    on = bool(on) or f.read().strip() == "On"
            except OSError:
                pass
        try:
            idle.tick(on, time.monotonic())
        except Exception as e:          # never let the policy kill the thread
            log(f"idle: {e!r}")
        time.sleep(poll)


def link_watch(stop, marker=None, grace=20, good_after=60):
    """Exit (so systemd restarts the service) when the link that was up stays down, e.g.
    after a CP crash.  Once the link has been up for good_after seconds, remove the
    boot marker: this CP boot did not take the phone down."""
    path, was_up, down_since = "/sys/kernel/debug/s5000ap/link_up", False, None
    up_since = None
    while not stop.is_set():
        try:
            with open(path) as f:
                up = f.read().strip() == "Y"
        except OSError:
            up = False
        if up:
            was_up, down_since = True, None
            up_since = up_since or time.monotonic()
            if marker and time.monotonic() - up_since > good_after:
                try:
                    os.unlink(marker)
                    os.sync()
                except FileNotFoundError:
                    pass
                marker = None
        elif was_up:
            down_since = down_since or time.monotonic()
            if time.monotonic() - down_since > grace:
                log("link down for good (CP crash?); exiting for a restart")
                os._exit(3)
        time.sleep(2)


def fs_type(path):
    best, typ = "", None
    with open("/proc/mounts") as f:
        for line in f:
            dev, mnt, fst = line.split()[:3]
            if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
                best, typ = mnt, fst
    return typ


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--efs", required=True, help="scratch EFS copy (tmpfs)")
    ap.add_argument("--ctl", default="/run/shannon/ctl", help="control FIFO")
    ap.add_argument("--allow-radio", action="store_true",
                    help="permit `radio on` (only with the user's own SIM, user present)")
    ap.add_argument("--sms", default="/var/lib/shannon/sms-inbox.txt",
                    help="received SMS PDUs are appended here (0600), then acknowledged")
    ap.add_argument("--apn", help="initial attach APN sent at every CP power-up")
    ap.add_argument("--radio-state", help="file keeping the user's last radio on/off choice")
    ap.add_argument("--fresh-cp", action="store_true",
                    help="the CP was just booted or restarted (old data sessions are gone)")
    ap.add_argument("--boot-marker", help="file removed once the CP link has been up a while")
    ap.add_argument("--data-state", help="file keeping the user's mobile data on/off choice")
    ap.add_argument("--no-fmt", action="store_true", help="RFS server only")
    ap.add_argument("--no-idle", action="store_true",
                    help="start with the PDA_ACTIVE screen-off policy off")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every RFS request")
    args = ap.parse_args()

    efs = os.path.realpath(args.efs)
    if fs_type(efs) != "tmpfs":
        sys.exit(f"{efs} is not on tmpfs; refusing (the scratch copy must not be a real EFS)")
    if not os.path.isfile(os.path.join(efs, NV_NAME)):
        sys.exit(f"no {NV_NAME} in {efs}; run shannon-efs-scratch.sh first")

    stop = threading.Event()
    rfs = Rfs(efs, args.verbose)
    threads = [threading.Thread(target=rfs_loop, args=(rfs, stop), daemon=True)]
    if not args.no_fmt:
        fmt = Fmt(args.allow_radio, args.sms, args.apn, args.radio_state, args.data_state)
        fmt.fresh_cp = args.fresh_cp
        fmt.idle = Idle(fmt, enabled=not args.no_idle)
        try:
            import shannon_volte
            fmt.ims = shannon_volte.ImsManager(fmt, log)
            log(f"ims: VoLTE support loaded (VOLTE={fmt.ims.mode}, netdev {fmt.ims.net.dev})")
        except Exception as e:          # VoLTE is optional: never block the modem
            log(f"ims: VoLTE support not available: {e!r}")

        def on_term(signum, frame):
            fmt.idle.restore()
            # deregister from IMS (REGISTER Expires 0) before systemd's SIGKILL (10 s)
            if fmt.ims:
                fmt.ims.shutdown()
            os._exit(0)
        signal.signal(signal.SIGTERM, on_term)
        threads += [threading.Thread(target=fmt.loop, args=(stop,), daemon=True),
                    threading.Thread(target=watch_only, args=(FMT2_DEV, stop), daemon=True),
                    threading.Thread(target=ctl_loop, args=(args.ctl, fmt, stop), daemon=True),
                    threading.Thread(target=audio_ctl_loop, args=(fmt, stop), daemon=True),
                    threading.Thread(target=mbim_bridge, args=(fmt, stop), daemon=True),
                    threading.Thread(target=screen_watch, args=(fmt.idle, stop), daemon=True),
                    threading.Thread(target=at_bridge, args=(fmt, stop), daemon=True)]
    threads.append(threading.Thread(target=link_watch, args=(stop, args.boot_marker),
                                    daemon=True))
    for t in threads:
        t.start()
    if not args.no_fmt:
        # reattached to a running CP (no PWR_UP will come): learn its state
        time.sleep(1)
        try:
            with open("/sys/kernel/debug/s5000ap/link_up") as f:
                link = f.read().strip() == "Y"
        except OSError:
            link = False
        if link and not fmt.powered.is_set():
            for q in ("pin", "ver", "imeicheck", "regps", "net", "icon", "smsc"):
                fmt.query(q)
            fmt.send(0x01, 0x07, GET)              # radio state (answered as a RESP)
            fmt.resync_audio = True                # a call may be up: see resync_call_audio
            fmt.call_list()
    log(f"ready (radio {'may be turned on' if args.allow_radio else 'stays off'})")
    try:
        while True:
            time.sleep(30)
            if rfs.stats:
                log("rfs stats: " + ", ".join(f"{k} {v}" for k, v in sorted(rfs.stats.items())))
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
