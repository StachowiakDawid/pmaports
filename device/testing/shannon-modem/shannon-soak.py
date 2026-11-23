#!/usr/bin/env python3
"""Overnight soak logger for the beyond2lte modem (read-only).

Every --interval minutes (counted on CLOCK_BOOTTIME, i.e. including suspend) it logs one
line with battery %, current, voltage, suspend entries / time asleep since the last line,
wake reasons (exynos9820-suspend WAKEUP_STAT from the kernel log, beyond2lte-resuspend
verdicts), the top wakeup sources, CP link state, modem/registration/data state from
ModemManager, and counts of notable shannon-modem journal events.  On SIGINT/SIGTERM or
after --hours it writes a summary.

The script never wakes the phone itself: while the phone deep-sleeps, the sample is
taken at the next wake (the CP, RTC timers or the power key wake it); the line says how
long the phone slept.  Use --hold to keep it awake instead (a logind sleep inhibitor,
for a no-suspend soak).

Read-only: it only reads sysfs/procfs, /sys/kernel/debug/s5000ap/link_up, the journal
and `mmcli` output.  It never writes the modem FIFOs, never reads
/sys/kernel/debug/pinctrl/*, and never prints IMEI/IMSI/ICCID, phone numbers or SMS
content (only whitelisted mmcli keys and event COUNTS from the journal are used).

  sudo systemd-run --unit=shannon-soak -p Nice=10 \\
      /usr/bin/python3 /root/shannon-soak.py --interval 10 --hours 10 \\
      --log /var/log/shannon-soak.log
  journalctl -u shannon-soak -f        (or tail -f /var/log/shannon-soak.log)
  systemctl stop shannon-soak          (writes the summary)
"""
import argparse
import glob
import os
import re
import signal
import subprocess
import sys
import time

LINK_UP = "/sys/kernel/debug/s5000ap/link_up"
SUSPEND_STATS = "/sys/power/suspend_stats"
CP_DEV = "/sys/devices/platform/soc@0/15920000.modem"
CALL_FLAG = "/run/shannon/call-active"

# whitelisted mmcli -K keys (nothing that identifies the SIM, the device or a person)
MM_KEYS = {
    "modem.generic.state": "state",
    "modem.generic.access-technologies.value[1]": "act",
    "modem.generic.signal-quality.value": "sig",
    "modem.3gpp.registration-state": "reg",
    "modem.3gpp.operator-code": "plmn",
    "modem.3gpp.packet-service-state": "ps",
}

# shannon-modem journal events that are counted (the lines themselves are never printed)
DAEMON_EVENTS = {
    "sms_rx": r"SMS received",
    "call": r"call: presence (incoming|call) ",
    "missed": r"call: missed incoming call",
    "link_lost": r"link down for good",
    "data_down": r"fmt: data: down",
    "reg_noti": r"REGIST NOTI len \d+ aseq \d+ \| ",
    "rfs_err": r"rfs: .*ERR",
    "ims_reg_fail": r"ims: registration failed",
    "daemon_start": r"rfs: serving ",
}

WAKE_RE = re.compile(r"exynos9820-suspend: resumed.*WAKEUP_STAT (0x[0-9a-fA-F]+)")
WAKE_BITS = {0x1: "rtc", 0x100: "cp", 0x1000: "power-key"}


def read(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def boottime():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def battery():
    out = {}
    for d in glob.glob("/sys/class/power_supply/*"):
        t = read(os.path.join(d, "type"))
        if t == "Battery" and "cap" not in out:
            cap = read(os.path.join(d, "capacity"))
            cur = read(os.path.join(d, "current_now"))
            vol = read(os.path.join(d, "voltage_now"))
            out["cap"] = int(cap) if cap and cap.lstrip("-").isdigit() else None
            out["ma"] = int(cur) / 1000 if cur and cur.lstrip("-").isdigit() else None
            out["mv"] = int(vol) / 1000 if vol and vol.isdigit() else None
            out["status"] = read(os.path.join(d, "status"), "?")
        elif t in ("Mains", "USB") and read(os.path.join(d, "online")) == "1":
            out["ac"] = True
    return out


def suspend_stats():
    s = {}
    for k in ("success", "fail"):
        v = read(os.path.join(SUSPEND_STATS, k))
        s[k] = int(v) if v and v.isdigit() else None
    return s


def wakeup_sources():
    out = {}
    for d in glob.glob("/sys/class/wakeup/wakeup*"):
        name = read(os.path.join(d, "name"))
        ev = read(os.path.join(d, "event_count"))
        if name and ev and ev.isdigit():
            out[name] = out.get(name, 0) + int(ev)
    return out


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def mm_state():
    out, bearers = {}, []
    for line in run(["mmcli", "-m", "any", "-K"]).splitlines():
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k in MM_KEYS:
            out[MM_KEYS[k]] = v or "--"
        elif k.startswith("modem.generic.bearers.value"):
            bearers.append(v)
    if not out:
        return {"state": "no-modem"}
    conn = "no"
    for b in bearers:
        if b.startswith("/org/freedesktop/ModemManager1/Bearer/"):
            for l in run(["mmcli", "-b", b.rsplit("/", 1)[1], "-K"]).splitlines():
                if l.startswith("bearer.status.connected") and l.split(":", 1)[1].strip() == "yes":
                    conn = "yes"
    out["data"] = conn
    return out


def journal_since(since_epoch, args):
    return run(["journalctl", "-q", "--no-pager", "-o", "cat",
                "--since", f"@{int(since_epoch)}"] + args, timeout=30)


def wake_reasons(since_epoch):
    hist = {}
    for m in WAKE_RE.finditer(journal_since(since_epoch, ["-k"])):
        v = int(m.group(1), 16)
        names = [n for b, n in WAKE_BITS.items() if v & b] or [f"{v:#x}"]
        key = "+".join(names)
        hist[key] = hist.get(key, 0) + 1
    rs = {}
    for l in journal_since(since_epoch, ["-u", "beyond2lte-resuspend"]).splitlines():
        m = re.search(r"beyond2lte-resuspend: (\w+) wake", l)
        if m:
            rs[m.group(1)] = rs.get(m.group(1), 0) + 1
    return hist, rs


def daemon_events(since_epoch):
    text = journal_since(since_epoch, ["-u", "shannon-modem"])
    return {k: len(re.findall(p, text)) for k, p in DAEMON_EVENTS.items()}


def fmt_counts(d):
    return ",".join(f"{k}:{v}" for k, v in sorted(d.items()) if v) or "-"


class Soak:
    def __init__(self, args):
        self.args = args
        self.log_f = open(args.log, "a", buffering=1) if args.log else None
        self.t0_epoch = time.time()
        self.t0_boot = boottime()
        self.t0_mono = time.monotonic()
        self.bat0 = battery()
        self.ss0 = suspend_stats()
        self.ws0 = wakeup_sources()
        self.prev = dict(epoch=self.t0_epoch, boot=self.t0_boot, mono=self.t0_mono,
                         ss=self.ss0, ws=self.ws0)
        self.samples = []
        self.tot_wakes, self.tot_rs, self.tot_ev = {}, {}, {}
        self.link_down_samples = 0
        self.states = {}

    def out(self, s):
        line = time.strftime("%Y-%m-%d %H:%M:%S ") + s
        print(line, flush=True)
        if self.log_f:
            self.log_f.write(line + "\n")

    def sample(self):
        now_e, now_b, now_m = time.time(), boottime(), time.monotonic()
        p = self.prev
        bat = battery()
        ss = suspend_stats()
        ws = wakeup_sources()
        link = read(LINK_UP, "?")
        mm = mm_state()
        hist, rs = wake_reasons(p["epoch"])
        ev = daemon_events(p["epoch"])
        d_boot, d_mono = now_b - p["boot"], now_m - p["mono"]
        slept = max(0.0, d_boot - d_mono)
        susp = (ss["success"] - p["ss"]["success"]) if None not in (ss["success"], p["ss"]["success"]) else None
        top = sorted(((v - p["ws"].get(k, 0), k) for k, v in ws.items()), reverse=True)
        top = [f"{k}:{n}" for n, k in top[:4] if n > 0]
        cpfloor = f"{read(os.path.join(CP_DEV, 'cp_mif_khz'), '-')}/{read(os.path.join(CP_DEV, 'cp_int_khz'), '-')}"
        call = "yes" if os.path.exists(CALL_FLAG) else "no"
        self.out(
            f"bat {bat.get('cap')}% {bat.get('ma')} mA {bat.get('mv')} mV {bat.get('status')}"
            f"{' AC' if bat.get('ac') else ''} | span {d_boot / 60:.1f} min slept {slept / 60:.1f} min"
            f" ({100 * slept / d_boot if d_boot else 0:.0f} %) suspends {susp} fail "
            f"{ss['fail']} | wakes {fmt_counts(hist)} resuspend {fmt_counts(rs)}"
            f" | wakeup-src {','.join(top) or '-'} | cp link {link} floor {cpfloor} call {call}"
            f" | mm {mm.get('state', '?')} reg {mm.get('reg', '?')} {mm.get('act', '?')}"
            f" sig {mm.get('sig', '?')} ps {mm.get('ps', '?')} data {mm.get('data', '?')}"
            f" | events {fmt_counts(ev)}")
        self.samples.append(dict(t=now_b, bat=bat, slept=slept, span=d_boot))
        for k, v in hist.items():
            self.tot_wakes[k] = self.tot_wakes.get(k, 0) + v
        for k, v in rs.items():
            self.tot_rs[k] = self.tot_rs.get(k, 0) + v
        for k, v in ev.items():
            self.tot_ev[k] = self.tot_ev.get(k, 0) + v
        if link != "Y":
            self.link_down_samples += 1
        key = f"{mm.get('reg', '?')}/{mm.get('act', '?')}/data {mm.get('data', '?')}"
        self.states[key] = self.states.get(key, 0) + 1
        self.prev = dict(epoch=now_e, boot=now_b, mono=now_m, ss=ss, ws=ws)

    def summary(self):
        now_b, now_m = boottime(), time.monotonic()
        span = now_b - self.t0_boot
        slept = max(0.0, span - (now_m - self.t0_mono))
        bat = battery()
        c0, c1 = self.bat0.get("cap"), bat.get("cap")
        ss = suspend_stats()
        susp = (ss["success"] - self.ss0["success"]) if None not in (ss["success"], self.ss0["success"]) else None
        fail = (ss["fail"] - self.ss0["fail"]) if None not in (ss["fail"], self.ss0["fail"]) else None
        ma = [s["bat"]["ma"] for s in self.samples if s["bat"].get("ma") is not None]
        drop = (c0 - c1) if None not in (c0, c1) else None
        hours = span / 3600
        self.out("==== soak summary ====")
        self.out(f"duration {hours:.2f} h, asleep {slept / 3600:.2f} h "
                 f"({100 * slept / span if span else 0:.0f} %), samples {len(self.samples)}")
        self.out(f"battery {c0}% -> {c1}% (drop {drop} %, "
                 f"{drop / hours if drop is not None and hours > 0 else 0:.2f} %/h); "
                 f"current at samples avg {sum(ma) / len(ma) if ma else 0:.0f} mA "
                 f"min {min(ma) if ma else 0:.0f} max {max(ma) if ma else 0:.0f} "
                 f"(samples are taken awake; the fuel-gauge %/h is the better sleep figure)")
        self.out(f"suspends {susp} failed {fail}; wakes {fmt_counts(self.tot_wakes)}; "
                 f"resuspend verdicts {fmt_counts(self.tot_rs)}")
        self.out(f"cp link not up in {self.link_down_samples} of {len(self.samples)} samples; "
                 f"modem states {fmt_counts(self.states)}")
        self.out(f"shannon-modem events {fmt_counts(self.tot_ev)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interval", type=float, default=10, help="minutes between samples")
    ap.add_argument("--hours", type=float, default=0, help="stop after this long (0 = until stopped)")
    ap.add_argument("--log", help="also append the lines to this file")
    ap.add_argument("--hold", action="store_true",
                    help="hold a logind sleep inhibitor (no-suspend soak)")
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("note: not root, CP link state and the kernel log may be unreadable", file=sys.stderr)
    if args.hold:
        os.execvp("systemd-inhibit", ["systemd-inhibit", "--what=sleep", "--who=shannon-soak",
                                      "--why=soak test", sys.executable, os.path.abspath(__file__)]
                  + [a for a in sys.argv[1:] if a != "--hold"])
    s = Soak(args)
    stop = {"now": False}

    def on_sig(signum, frame):
        stop["now"] = True
    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)
    s.out(f"soak start: interval {args.interval} min, hours {args.hours or 'until stopped'}, "
          f"battery {s.bat0.get('cap')}%, cp link {read(LINK_UP, '?')}")
    s.sample()
    next_t = boottime() + args.interval * 60
    end_t = s.t0_boot + args.hours * 3600 if args.hours else None
    while not stop["now"]:
        time.sleep(5)               # monotonic: stops in suspend; boottime catches up after
        b = boottime()
        if b >= next_t:
            s.sample()
            next_t = b + args.interval * 60
        if end_t and b >= end_t:
            break
    s.sample()
    s.summary()


if __name__ == "__main__":
    main()
