"""VoLTE glue for shannon-modemd: IMS PDN interface, SIM AKA, the IMS UA's lifecycle and
its hooks (AT emulator calls, CS fallback, media, P-Access-Network-Info).

Everything is OFF unless someone runs `ims ...` ctl commands or sets
VOLTE=register|mmtel in /etc/shannon/modem.conf.

The one place that depends on how the CP delivers IMS-PDN (cid 2) packets is
ImsNet (IMS_NETDEV / IMS_LINK_ID): by default a second WWAN link `wwan1` (link id 1 =
SIPC channel 11 = stock rmnet1), which needs kernel support for WWAN link 1
in s5000ap-boot.  Addresses are applied, never logged.
"""

import ipaddress
import os
import secrets
import subprocess
import threading
import time

import shannon_ims as ims

CONF = "/etc/shannon/modem.conf"
CALL_AUDIO = "/usr/libexec/shannon/call-audio"
SIM_APPS = {"isim": 0, "usim": 2}
AUTH_RESULTS = {0: "ok", 3: "mac", 4: "sync", 5: "sync"}


def read_conf(path=CONF):
    """Shell-style KEY=value file -> dict (no expansion; quotes stripped)."""
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                else:
                    v = v.split("#", 1)[0].strip()
                out[k.strip()] = v
    except OSError:
        pass
    return out


def parse_ims_ip_config(p):
    """GPRS IP_CONFIGURATION payload (frame offset - 7) for the IMS cid:
    -> dict(v4, iid, pcscf6 [..], pcscf4 [..], mtu)."""
    mask = int.from_bytes(p[1:3], "little") if len(p) >= 3 else 0
    v4 = ipaddress.IPv4Address(bytes(p[3:7])) if mask & 1 and len(p) >= 7 and any(p[3:7]) else None
    iid = bytes(p[0x2B:0x33]) if mask & 0x40 and len(p) >= 0x33 and any(p[0x2B:0x33]) else None
    # first half of the IPv6 address: fe80:: (prefix comes by RA) or a full global prefix
    pre = bytes(p[0x23:0x2B]) if iid else b""
    v6kind = ("link-local" if pre[:2] == b"\xfe\x80" else "global" if any(pre) else "iid-only") \
        if iid else "none"
    pc4, pc6 = [], []
    for k in range(3):
        o = 0x17 + 4 * k
        if len(p) >= o + 4 and any(p[o:o + 4]):
            pc4.append(ipaddress.IPv4Address(bytes(p[o:o + 4])))
        o = 0x33 + 16 * k
        if len(p) >= o + 16 and any(p[o:o + 16]):
            pc6.append(ipaddress.IPv6Address(bytes(p[o:o + 16])))
    if len(p) >= 0x9E:                       # frame len >= 0xA5: P-CSCF #4..#8
        for k in range(5):
            o = 0x9D + 4 * k
            if len(p) >= o + 4 and any(p[o:o + 4]):
                pc4.append(ipaddress.IPv4Address(bytes(p[o:o + 4])))
            o = 0xB1 + 16 * k
            if len(p) >= o + 16 and any(p[o:o + 16]):
                pc6.append(ipaddress.IPv6Address(bytes(p[o:o + 16])))
    mtu = 1500
    if mask & (1 << 13) and len(p) >= 0x9C:
        mtu = int.from_bytes(p[0x98:0x9C], "little") & 0xFFFF or 1500
    return dict(v4=v4, iid=iid, v6pre=pre if v6kind == "global" else None, v6kind=v6kind,
                mask=mask, pcscf4=pc4, pcscf6=pc6, mtu=mtu)


def parse_sim_auth(p):
    """SEC_IMS_AUTH RESP payload: +0 type, +1 result, then length-prefixed fields
    (type 0: RES, CK, IK; type 2: RES, CK, IK, Kc; sync: AUTS) [I field framing]."""
    if len(p) < 2:
        return ims.AkaResult("error")
    kind = AUTH_RESULTS.get(p[1], "error")
    fields, k = [], 2
    while k < len(p) and len(fields) < 4:
        n = p[k]
        if n == 0 or k + 1 + n > len(p):
            if n == 0:
                fields.append(b"")
                k += 1
                continue
            break
        fields.append(bytes(p[k + 1:k + 1 + n]))
        k += 1 + n
    if kind == "ok":
        if len(fields) < 3 or not fields[0] or len(fields[1]) != 16 or len(fields[2]) != 16:
            return ims.AkaResult("error")
        return ims.AkaResult("ok", res=fields[0], ck=fields[1], ik=fields[2])
    if kind == "sync":
        auts = next((f for f in fields if len(f) == 14), b"")
        return ims.AkaResult("sync", auts=auts) if auts else ims.AkaResult("error")
    return ims.AkaResult(kind)


class ImsNet:
    """The IMS PDN's netdev: link, fe80::IID + SLAAC token, RA prefix (no default route
    in the main table), and a policy-routing table for the UA's source address."""

    def __init__(self, conf, log, runner=None, sysctl=None):
        self.dev = conf.get("IMS_NETDEV", "wwan1")
        self.link_id = conf.get("IMS_LINK_ID", "1")
        self.parent = conf.get("IMS_WWAN_DEV", "wwan0")
        self.table = conf.get("IMS_ROUTE_TABLE", "1002")
        self.override = conf.get("IMS_LOCAL_IP") or None
        self.ra_wait = float(conf.get("IMS_RA_WAIT", "20"))
        self.log = log
        self.run = runner or self._ip
        self.sysctl = sysctl or self._sysctl
        self.created = False
        self.addr = None

    @staticmethod
    def _ip(*args):
        r = subprocess.run(["ip", *args], capture_output=True, text=True)
        return r.returncode, r.stdout

    @staticmethod
    def _sysctl(key, value):
        try:
            with open(f"/proc/sys/{key}", "w") as f:
                f.write(value)
            return True
        except OSError:
            return False

    def exists(self):
        return os.path.exists(f"/sys/class/net/{self.dev}")

    def up(self, cfg, shared_with=None):
        """-> local address (str) or None.  Blocks up to IMS_RA_WAIT s for the RA."""
        if self.dev == shared_with:
            self.log(f"ims: net: {self.dev} is the internet netdev: not touching the link "
                     "(shared mode)")
        else:
            if not self.exists() and self.link_id not in ("", "none"):
                rc, _ = self.run("link", "add", "dev", self.dev, "parentdev", self.parent,
                                 "type", "wwan", "linkid", self.link_id)
                self.created = rc == 0
                self.log(f"ims: net: create {self.dev} (WWAN link {self.link_id}): "
                         + ("ok" if rc == 0 else "FAILED (kernel without a second link?)"))
            if not self.exists():
                self.log(f"ims: net: no {self.dev}; set IMS_NETDEV")
                return None
            d = self.dev
            for k, v in (("addr_gen_mode", "1"), ("accept_ra", "2"), ("accept_ra_defrtr", "0"),
                         ("accept_ra_pinfo", "1"), ("accept_dad", "0"), ("autoconf", "1")):
                self.sysctl(f"net/ipv6/conf/{d}/{k}", v)
            self.run("addr", "flush", "dev", d)
            self.run("link", "set", d, "mtu", str(min(cfg["mtu"], 2048)))
            self.run("link", "set", d, "up")
            if cfg["iid"]:
                iid = ipaddress.IPv6Address(b"\0" * 8 + cfg["iid"])
                ll = ipaddress.IPv6Address(b"\xfe\x80" + b"\0" * 6 + cfg["iid"])
                self.run("link", "set", d, "arp", "on")
                self.run("token", "set", str(iid), "dev", d)
                self.run("-6", "addr", "add", f"{ll}/64", "dev", d, "nodad")
                if cfg.get("v6pre"):
                    # The CP hands the IMS PDN a complete global address in IP_CONFIGURATION
                    # (Play, 2026-11-20): no RA follows on the user plane, so set it here.
                    g = ipaddress.IPv6Address(cfg["v6pre"] + cfg["iid"])
                    self.run("-6", "addr", "add", f"{g}/128", "dev", d, "nodad")
            if cfg["v4"]:
                self.run("addr", "add", f"{cfg['v4']}/32", "dev", d)
        addr = self.override
        if not addr and cfg["pcscf6"] and cfg["iid"]:
            end = time.monotonic() + self.ra_wait
            while time.monotonic() < end and not addr:
                addr = self.global6()
                if not addr:
                    time.sleep(0.5)
            if not addr:
                self.log(f"ims: net: no global IPv6 on {self.dev} after {int(self.ra_wait)} s "
                         "(no RA?  IMS_LOCAL_IP can force one)")
        if not addr and cfg["v4"] and cfg["pcscf4"]:
            addr = str(cfg["v4"])
        if not addr:
            return None
        self.addr = addr
        fam = "-6" if ":" in addr else "-4"
        self.run(fam, "rule", "del", "from", addr, "lookup", self.table)
        self.run(fam, "rule", "add", "from", addr, "lookup", self.table, "pref", self.table)
        self.run(fam, "route", "replace", "default", "dev", self.dev, "table", self.table)
        self.log(f"ims: net: {self.dev} ready ({'IPv6 global' if fam == '-6' else 'IPv4'}, "
                 f"policy table {self.table}, no main-table default route)")
        return addr

    def global6(self):
        rc, out = self.run("-6", "-o", "addr", "show", "dev", self.dev, "scope", "global")
        for line in (out or "").splitlines():
            f = line.split()
            if "inet6" in f:
                a = f[f.index("inet6") + 1].split("/")[0]
                if "tentative" not in f:
                    return a
        return None

    def down(self, shared_with=None):
        if self.addr:
            fam = "-6" if ":" in self.addr else "-4"
            self.run(fam, "rule", "del", "from", self.addr, "lookup", self.table)
            self.run(fam, "route", "flush", "table", self.table)
        self.addr = None
        if self.dev != shared_with and self.exists():
            self.run("addr", "flush", "dev", self.dev)
            self.run("link", "set", self.dev, "down")
            if self.created:
                self.run("link", "del", "dev", self.dev)
                self.created = False


class ImsManager:
    def __init__(self, fmt, log, conf=None, net=None):
        self.f = fmt
        self.log = log
        self.conf = conf if conf is not None else read_conf()
        self.cfg = ims.ImsConfig.from_conf(self.conf)
        self.mode = self.conf.get("VOLTE", "no").lower()          # no | register | mmtel
        self.net = net or ImsNet(self.conf, log)
        self.app = self.conf.get("IMS_AKA_APP", "auto").lower()   # auto | isim | usim
        self.ua = None
        self.ipcfg = None
        self.local_ip = None
        self.want = None              # pending register request: mmtel bool
        self.auto_done = False
        self.auto_waiting = False
        self.auto_backoff = 0.0       # re-arm delay after a network-side IMS loss
        self.auto_not_before = 0.0
        self.lock = threading.Lock()
        self.auth_wait = None         # (event, [result]) while SEC_IMS_AUTH is outstanding
        self.auth_lock = threading.Lock()
        self.audio_on = False

    # ------------------------------------------------------------ SIM AKA
    def sim_auth(self, typ, rand, autn, timeout=6.0):
        with self.auth_lock:
            return self._sim_auth(typ, rand, autn, timeout)

    def _sim_auth(self, typ, rand, autn, timeout):
        ev, out = threading.Event(), []
        self.auth_wait = (ev, out)
        try:
            self.f.send(0x05, 0x09, 2, bytes([typ, len(rand)]) + rand + bytes([len(autn)]) + autn)
            if not ev.wait(timeout) or not out:
                return ims.AkaResult("error")
            return out[0]
        finally:
            self.auth_wait = None

    def on_auth_response(self, p, error=False):
        """From Fmt.decode: SEC_IMS_AUTH RESP (or GEN_PHONE_RES error)."""
        r = ims.AkaResult("error") if error else parse_sim_auth(p)
        if self.auth_wait:
            self.auth_wait[1].append(r)
            self.auth_wait[0].set()
        return (f"SIM auth (contents not shown): type {p[0] if p else '?'}, result "
                f"{p[1] if len(p) > 1 else '?'} = {r.kind}, RES {len(r.res)} B, CK {len(r.ck)} B, "
                f"IK {len(r.ik)} B, AUTS {len(r.auts)} B") if not error else "SIM auth: error"

    def aka(self, rand, autn):
        apps = [self.app] if self.app in SIM_APPS else ["isim", "usim"]
        r = ims.AkaResult("error")
        for a in apps:
            r = self.sim_auth(SIM_APPS[a], rand, autn)
            self.log(f"ims: SIM AKA via {a.upper()}: {r.kind}")
            if r.kind != "error":
                if self.app == "auto":
                    self.app = a          # remember what works
                break
        return r

    def akatest(self, app=None):
        """Random RAND/AUTN: the SIM must answer MAC failure (no SQN change)."""
        apps = [app] if app in SIM_APPS else ["isim", "usim"]

        def run():
            for a in apps:
                r = self.sim_auth(SIM_APPS[a], secrets.token_bytes(16), secrets.token_bytes(16))
                self.log(f"ims: akatest {a.upper()}: {r.kind}"
                         + (" (expected: mac = path works)" if r.kind == "mac" else ""))
        threading.Thread(target=run, daemon=True).start()

    # ------------------------------------------------------------ identity / PANI
    def identity(self):
        st = self.f.st
        imsi = st.get("imsi")
        if not imsi:
            raise ValueError("IMSI not known yet")
        plmn = st.get("plmn") or ""
        mnc_len = int(self.conf.get("IMS_MNC_LEN", "0") or 0) or \
            (len(plmn) - 3 if plmn and imsi.startswith(plmn) and len(plmn) in (5, 6) else 2)
        imei = st.get("imei") if self.cfg.sip_instance else None
        return ims.Identity(imsi, mnc_len=mnc_len, domain=self.conf.get("IMS_DOMAIN") or None,
                            imei=imei)

    def pani(self):
        st = self.f.st
        plmn, tac, eci = st.get("plmn"), st.get("tac"), st.get("eci")
        if not (plmn and tac is not None and eci is not None and st.get("act") == 0x21):
            return None
        return f"{plmn}{tac:04X}{eci & 0xFFFFFFF:07X}"

    # ------------------------------------------------------------ PDN
    def on_ip_config(self, p):
        cfg = parse_ims_ip_config(p)
        self.ipcfg = cfg
        if self.want is not None:
            threading.Thread(target=self._bring_up, daemon=True).start()
        return (f"P-CSCF v6 x{len(cfg['pcscf6'])}, v4 x{len(cfg['pcscf4'])}, "
                f"IPv6 {cfg['v6kind']}, {'IPv4' if cfg['v4'] else 'no IPv4'}, "
                f"MTU {cfg['mtu']}, mask {cfg['mask']:#06x}")

    def _bring_up(self):
        with self.lock:
            if self.ua or not self.ipcfg:
                return
            cfg = self.ipcfg
            addr = self.local_ip or self.net.up(cfg, shared_with=self.f.netdev)
            if not addr:
                self.log("ims: no usable local address; not registering")
                return
            self.local_ip = addr
            pcscfs = cfg["pcscf6"] if ":" in addr else cfg["pcscf4"]
            if self.conf.get("IMS_PCSCF"):
                pcscfs = [ipaddress.ip_address(x) for x in self.conf["IMS_PCSCF"].split()]
            if not pcscfs:
                self.log("ims: no P-CSCF of the local address family")
                return
            if self.want is None:
                return
            try:
                ident = self.identity()
            except ValueError as e:
                self.log(f"ims: {e}")
                return
            hooks = dict(aka=self.aka, calls_changed=self._calls_changed,
                         call_ended=self._call_ended, registered=self._registered,
                         cs_fallback=self._cs_fallback, pani=self.pani, media=self._media)
            self.ua = ims.ImsUa(self.cfg, ident, addr, pcscfs, self.log, hooks)
            self.ua.start()
            self.ua.register(mmtel=self.want)
            self.log(f"ims: UA started ({len(pcscfs)} P-CSCF, MMTel {'on' if self.want else 'off'})")

    def on_pdn_down(self, why="PDN down"):
        """IMS PDN gone (or CP restart): no deregistration possible, just clean up."""
        self.log(f"ims: {why}: UA stopped without deregistration")
        ua, self.ua = self.ua, None
        self.ipcfg = None
        self.local_ip = None
        dropped = ua.entries() if ua else []

        def cleanup():                              # off the FMT reader thread
            if ua:
                ua.reg_state = "idle"               # no network: skip the REGISTER Expires 0
                ua.stop(0.1)
            self.net.down(shared_with=self.f.netdev)
            for e in dropped:
                self._call_ended(e["id"], "IMS PDN lost")
            self._calls_changed([])
        threading.Thread(target=cleanup, daemon=True).start()
        if self.auto_done and self.want is not None:
            # lost on the network side (detach, PDN release, CP restart), not "ims down":
            # the automatic start was spent, so VoLTE stayed off until a daemon
            # restart (live 2026-11-22).  Re-arm it, with a backoff against a network
            # that keeps dropping the IMS PDN.
            self.auto_done = False
            self.auto_backoff = min(max(self.auto_backoff * 2, 15.0), 300.0)
            self.auto_not_before = time.monotonic() + self.auto_backoff
            self.log(f"ims: automatic start re-armed (in {self.auto_backoff:.0f} s)")
            t = threading.Timer(self.auto_backoff + 1, self._auto_kick)
            t.daemon = True
            t.start()

    def _auto_kick(self):
        """Backoff over: start now if still LTE + VoLTE, else on the next registration."""
        if not self.auto_done:
            self.auto_waiting = True
            self.f.ims_auto_retry()

    # ------------------------------------------------------------ ctl
    def register(self, mmtel=False):
        if not self.f.st.get("imsi"):
            self.log("ims: register: IMSI not known yet")
            return
        self.want = bool(mmtel)
        self.cfg.mmtel = self.want
        if self.ua:
            self.ua.register(mmtel=self.want)
        elif self.ipcfg:
            threading.Thread(target=self._bring_up, daemon=True).start()
        else:
            self.f.ims_up()                         # PDN first; on_ip_config continues

    def netup(self):
        """Stage A: bring up the IMS netdev (PDN must be up) without starting the UA."""
        def run():
            with self.lock:
                if not self.ipcfg:
                    self.log("ims: netup: no IMS IP config yet (ims up first)")
                    return
                self.local_ip = self.local_ip or self.net.up(self.ipcfg, shared_with=self.f.netdev)
        threading.Thread(target=run, daemon=True).start()

    def ping(self):
        """ping each P-CSCF from the IMS address; only loss/RTT are logged."""
        def run():
            cfg, addr = self.ipcfg, self.local_ip
            if not (cfg and addr):
                self.log("ims: ping: interface not ready (ims netup or ims register first)")
                return
            for k, pc in enumerate(cfg["pcscf6"] if ":" in addr else cfg["pcscf4"]):
                try:
                    r = subprocess.run(["ping", "-c", "3", "-W", "2", "-I", addr, str(pc)],
                                       capture_output=True, text=True, timeout=15)
                    summ = [l for l in r.stdout.splitlines() if "loss" in l or "min/avg" in l]
                    red = ims.Redactor()
                    self.log(f"ims: ping P-CSCF #{k}: " + red(" | ".join(summ) or "no answer"))
                except (OSError, subprocess.TimeoutExpired) as e:
                    self.log(f"ims: ping P-CSCF #{k}: {e.__class__.__name__}")
        threading.Thread(target=run, daemon=True).start()

    def deregister(self, timeout=4.0):
        self.want = None
        ua, self.ua = self.ua, None
        if ua:
            ua.stop(timeout)

    def down(self):
        self.deregister()
        self.f.ims_down()
        self.net.down(shared_with=self.f.netdev)
        self.ipcfg = self.local_ip = None

    def status(self):
        s = self.ua.status() if self.ua else "ims: UA not running"
        s += (f"; PDN {self.f.ims_phase}, netdev {self.net.dev}"
              f"{' (address ready)' if self.local_ip else ''}, mode {self.mode}, AKA app {self.app}")
        self.log(s)

    def maybe_auto(self, volte_supported):
        """VOLTE=register|mmtel in modem.conf: register once after PS attach on LTE."""
        if self.mode not in ("register", "mmtel") or self.auto_done or not volte_supported:
            return
        if self.f.ims_phase != "down" or not self.f.st.get("imsi"):
            return
        if time.monotonic() < self.auto_not_before:
            return                                  # re-arm backoff; _auto_kick follows
        if self.f.data_phase in ("defining", "activating"):
            # ims_up() would refuse now and the one automatic start would be spent
            # (live 2026-11-21); the modem daemon retries once the internet call is up
            if not self.auto_waiting:
                self.log("ims: automatic start waits for the internet data call")
            self.auto_waiting = True
            return
        self.auto_waiting = False
        self.auto_done = True
        self.log(f"ims: automatic start (VOLTE={self.mode})")
        self.register(mmtel=self.mode == "mmtel")

    def shutdown(self):
        if self.ua:
            self.log("ims: daemon stopping: deregistering")
            self.deregister(3.0)

    # ------------------------------------------------------------ calls
    def can_call(self):
        return bool(self.ua and self.ua.can_call())

    def entries(self):
        return self.ua.entries() if self.ua else []

    def _calls_changed(self, entries):
        self.f.ims_calls_changed()

    def _call_ended(self, cid, cause):
        if self.f.at:
            self.f.at.call_ended(cid, cause)

    def _cs_fallback(self, number):
        self.log("ims: CS fallback dial")
        self.f.dial(number, allow_emergency=False)

    def _registered(self, state):
        self.log(f"ims: registration state: {state}")
        if state == "registered":
            self.auto_backoff = 0.0
        if self.conf.get("IMS_CP_REGI", "no") == "yes":
            # IMS_REGI SET: state, feature 1 = VoLTE, net type, ECMP, RAT 6 LTE
            on = state == "registered" and self.cfg.mmtel
            nettype = int(self.conf.get("IMS_CP_REGI_NETTYPE", "1"))
            self.f.send(0x16, 0x08, 3, bytes([1, 1, nettype, 0, 6, 0]) if on else bytes(6))

    def _media(self, call, local_ip):
        import shannon_media as media
        script = self.conf.get("IMS_CALL_AUDIO", CALL_AUDIO)
        mgr = self

        def audio(rate):
            dev = getattr(mgr.f, "audio_dev", "earpiece")
            setup = media.voip_audio_setup(script, dev, mgr.log)
            mgr.audio_on = True
            now = getattr(mgr.f, "audio_dev", "earpiece")
            if now != dev:                  # speaker toggled during voip-start
                mgr.route_audio(now)
            play, rec, ch = media.audio_commands(setup, rate)
            return dict(play_cmd=play, rec_cmd=rec, rec_channels=ch)

        class Media(media.RtpMedia):
            def stop(self):
                super().stop()
                others = [c for c in mgr.ua.calls.values()
                          if c.media and c.media is not self] if mgr.ua else []
                if mgr.audio_on and not others:
                    mgr.audio_on = False
                    mgr.muted = False           # every call starts unmuted
                    try:
                        subprocess.run([script, "voip-stop"], capture_output=True, timeout=15)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
        m = Media(call.rtp_sock, self.log, audio=audio, aec=self.cfg_aec())
        # the daemon's value is the truth (set_mute, reset by calls_gone): our own copy
        # can be stale when a muted call ended before it had media
        self.muted = bool(getattr(self.f, "call_mute", getattr(self, "muted", False)))
        m.muted = self.muted
        call.rtp_sock = None
        return m

    def cfg_aec(self):
        """IMS_AEC=speex (default no): speexdsp echo canceller in the media loop."""
        if self.conf.get("IMS_AEC", "no").lower() != "speex":
            return None
        import shannon_media as media
        tail = int(self.conf.get("IMS_AEC_TAIL_MS", "300") or 300)
        return lambda samples, rate: media.SpeexAec(samples, rate, tail_ms=tail)

    def route_audio(self, dev):
        if self.audio_on:
            script = self.conf.get("IMS_CALL_AUDIO", CALL_AUDIO)
            try:
                subprocess.run([script, "voip-route", dev], capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                pass

    # AT emulator entry points (thread safe: the UA queues them)
    def dial(self, number):
        return bool(self.ua) and self.ua.dial(number)

    def has_incoming(self):
        return bool(self.ua and self.ua.has_incoming())

    def answer(self):
        self.ua.answer()

    def hangup(self):
        if self.ua:
            self.ua.hangup()

    def dtmf(self, d):
        if self.ua:
            self.ua.dtmf(d)

    def mute(self, on):
        """Mic mute for VoLTE calls (media on the AP)."""
        self.muted = bool(on)
        if self.ua:
            for c in list(self.ua.calls.values()):
                if getattr(c, "media", None) is not None:
                    c.media.muted = self.muted
