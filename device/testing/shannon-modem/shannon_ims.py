"""Minimal IMS (VoLTE) user agent for shannon-modemd.

SIP over the IMS PDN, IMS-AKA (AKAv1-MD5) with the SIM doing the AKA computation
(SEC_IMS_AUTH over Samsung IPC, supplied by the daemon as a callback), sec-agree
(RFC 3329 / TS 33.203) with IPsec ESP transport SAs set up through `ip xfrm`,
reg-event SUBSCRIBE, voice calls (INVITE, 100rel/PRACK, UPDATE, QoS preconditions
answered statically, CANCEL/BYE, session timer) and SDP offer/answer for AMR-WB/AMR
(octet-aligned and bandwidth-efficient) plus telephone-event.  RTP/codecs are in
shannon_media.py.

Safety: nothing here logs identities (IMSI/IMPI/IMPU/MSISDN/IMEI), keys (CK/IK/RES),
digest values or IP addresses: every log line goes through Redactor.  Emergency
numbers and sos URNs are refused (they stay on CS).  SMS over IP is not advertised.

Pure standard library; one thread per UA (selectors), public methods are thread safe.
"""

import base64
import hashlib
import ipaddress
import os
import queue
import random
import re
import secrets
import selectors
import socket
import struct
import subprocess
import threading
import time


# Timers must keep running through system suspend (re-REGISTER after 50 min while the
# phone sleeps): CLOCK_BOOTTIME counts suspended time, CLOCK_MONOTONIC does not.
_CLOCK = getattr(time, "CLOCK_BOOTTIME", None)


def _now():
    return time.clock_gettime(_CLOCK) if _CLOCK is not None else time.monotonic()


CLOCK_BOOTTIME_ALARM = 9        # linux/time.h: wakes the system from suspend (CAP_WAKE_ALARM)

# ---------------------------------------------------------------------------- constants

MMTEL_ICSI = "urn:urn-7:3gpp-service.ims.icsi.mmtel"
MMTEL_ICSI_ENC = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
ALLOW = "INVITE, ACK, CANCEL, BYE, UPDATE, PRACK, NOTIFY, OPTIONS, INFO, REFER, MESSAGE"
EMERGENCY_NUMBERS = {"112", "911", "999", "000", "110", "118", "119", "08", "997", "998"}
T1, T2, T4 = 0.5, 4.0, 5.0

COMPACT = {"v": "Via", "f": "From", "t": "To", "i": "Call-ID", "m": "Contact",
           "l": "Content-Length", "c": "Content-Type", "k": "Supported", "e": "Content-Encoding",
           "s": "Subject", "o": "Event", "x": "Session-Expires", "r": "Refer-To",
           "u": "Allow-Events", "a": "Accept-Contact", "b": "Referred-By", "j": "Reject-Contact",
           "d": "Request-Disposition", "y": "Identity"}
CANON = {h.lower(): h for h in (
    "Via", "From", "To", "Call-ID", "CSeq", "Contact", "Content-Length", "Content-Type",
    "Max-Forwards", "Route", "Record-Route", "Supported", "Require", "Proxy-Require",
    "Allow", "Expires", "Min-Expires", "Authorization", "WWW-Authenticate",
    "Proxy-Authenticate", "Proxy-Authorization", "Authentication-Info", "Security-Client",
    "Security-Server", "Security-Verify", "Service-Route", "Path", "P-Associated-URI",
    "P-Asserted-Identity", "P-Preferred-Identity", "P-Access-Network-Info",
    "P-Preferred-Service", "Accept-Contact", "User-Agent", "Server", "RSeq", "RAck",
    "Event", "Subscription-State", "Accept", "Session-Expires", "Min-SE", "Reason",
    "Allow-Events", "Unsupported", "Retry-After", "P-Early-Media", "Privacy",
    "Content-Disposition", "Warning")}


def is_emergency(target):
    """True for numbers/URIs that must never go over this UA (they stay on CS)."""
    t = target.strip().lower()
    if "urn:service:sos" in t or re.match(r"^(sips?:|tel:)?sos([@;.]|$)", t):
        return True
    digits = re.sub(r"[^0-9+*#]", "", t.split("@")[0].split(";")[0])
    d = digits.lstrip("+")
    return d in EMERGENCY_NUMBERS or (digits.startswith("+") and d[-3:] in ("112", "911")
                                      and len(d) <= 5)


# ---------------------------------------------------------------------------- redaction

class Redactor:
    """Removes identities, keys, digest values and IP addresses from log text."""

    PARAMS = re.compile(r'\b(nonce|response|auts|cnonce|opaque|rspauth|nextnonce)=("[^"]*"|[^,;\s]*)',
                        re.I)
    IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
    IPV6 = re.compile(r"(?<![\w:])(?=[0-9a-fA-F:]*:[0-9a-fA-F]*:)[0-9a-fA-F:]{2,39}(?![\w:])")
    DIGITS = re.compile(r"\d{7,}")
    IMEI_URN = re.compile(r"urn:gsma:imei:[0-9-]+", re.I)
    CELL = re.compile(r"((?:utran|eutran)-cell-id-3gpp|cgi-3gpp|i-wlan-node-id)=[0-9A-Za-z]+", re.I)

    def __init__(self):
        self.secret = {}

    def add(self, value, label):
        if value and len(str(value)) >= 3:
            self.secret[str(value)] = label

    def __call__(self, text):
        text = str(text)
        for v in sorted(self.secret, key=len, reverse=True):
            text = text.replace(v, f"<{self.secret[v]}>")
        text = self.PARAMS.sub(lambda m: f"{m.group(1)}=<{len(m.group(2).strip(chr(34)))}>", text)
        text = self.IMEI_URN.sub("urn:gsma:imei:<imei>", text)
        text = self.CELL.sub(lambda m: f"{m.group(1)}=<cell>", text)
        text = self.IPV6.sub("<ip6>", text)
        text = self.IPV4.sub("<ip4>", text)
        text = self.DIGITS.sub(lambda m: f"<{len(m.group(0))}d>", text)
        return text


# ---------------------------------------------------------------------------- identity

class Identity:
    """IMS identities derived from the IMSI (TS 23.003 13.3/13.4B), or given (ISIM)."""

    def __init__(self, imsi=None, mnc_len=2, impi=None, impu=None, domain=None, imei=None):
        if imsi:
            if not (imsi.isdigit() and 14 <= len(imsi) <= 15):
                raise ValueError("bad IMSI")
            mcc, mnc = imsi[:3], imsi[3:3 + mnc_len]
            domain = domain or f"ims.mnc{int(mnc):03d}.mcc{mcc}.3gppnetwork.org"
            impi = impi or f"{imsi}@{domain}"
            impu = impu or f"sip:{imsi}@{domain}"
        if not (impi and impu and domain):
            raise ValueError("need an IMSI or IMPI+IMPU+domain")
        self.imsi, self.impi, self.impu, self.domain, self.imei = imsi, impi, impu, domain, imei
        self.associated = []          # from P-Associated-URI after registration
        self.msisdn = None

    def instance_urn(self):
        """+sip.instance value (RFC 7254: TAC-SNR-spare 0)."""
        if self.imei and len(self.imei) >= 14 and self.imei[:14].isdigit():
            return f"urn:gsma:imei:{self.imei[:8]}-{self.imei[8:14]}-0"
        return None

    def preferred(self):
        """Default public identity for calls (first sip: entry of P-Associated-URI)."""
        for u in self.associated:
            if u.startswith("sip:"):
                return u
        return self.associated[0] if self.associated else self.impu

    def redact_into(self, r):
        r.add(self.imsi, "imsi")
        r.add(self.impi, "impi")
        r.add(self.impu, "impu")
        r.add(self.imei, "imei")
        for u in self.associated:
            r.add(u, "impu")
            m = re.search(r"\+?\d{7,}", u)
            if m:
                r.add(m.group(0), "msisdn")


# ---------------------------------------------------------------------------- SIP message

def split_commas(value):
    """Split a header value at top-level commas (not inside quotes or <...>)."""
    out, cur, q, a = [], [], False, 0
    for ch in value:
        if ch == '"' and (not cur or cur[-1] != "\\"):
            q = not q
        elif not q and ch == "<":
            a += 1
        elif not q and ch == ">":
            a = max(0, a - 1)
        if ch == "," and not q and not a:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def parse_params(s):
    """';a=b;c' -> {'a': 'b', 'c': None} (keys lower-case, quotes removed)."""
    out = {}
    for part in re.findall(r';\s*([^;=\s]+)\s*(?:=\s*("(?:[^"\\]|\\.)*"|[^;]*))?', s):
        k, v = part[0].lower(), part[1].strip() if part[1] else None
        if v and v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v if part[1] else None
    return out


def parse_nameaddr(v):
    """'"x" <sip:a@b;p>;tag=1' -> (display, uri, params)."""
    v = v.strip()
    m = re.match(r'^\s*(?:"((?:[^"\\]|\\.)*)"|([^<"]*?))\s*<([^>]*)>(.*)$', v)
    if m:
        return (m.group(1) or m.group(2) or "").strip(), m.group(3), parse_params(m.group(4))
    uri, _, rest = v.partition(";")
    return "", uri.strip(), parse_params(";" + rest if rest else "")


def uri_host_port(uri):
    """sip:user@[v6]:port;params -> (host, port or None)."""
    u = uri.split(":", 1)[1] if ":" in uri else uri
    u = u.split(";")[0].split("?")[0]
    hp = u.rsplit("@", 1)[-1]
    if hp.startswith("["):
        host, _, rest = hp[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    host, _, port = hp.partition(":")
    return host, int(port) if port.isdigit() else None


def host_for_uri(ip):
    return f"[{ip}]" if ":" in str(ip) else str(ip)


class SipMessage:
    def __init__(self, start, headers=None, body=b""):
        self.start = start
        self.headers = list(headers or [])
        self.body = body if isinstance(body, bytes) else body.encode()

    # -- start line
    @property
    def is_request(self):
        return not self.start.startswith("SIP/2.0")

    @property
    def method(self):
        return self.start.split()[0] if self.is_request else self.cseq[1]

    @property
    def uri(self):
        return self.start.split()[1]

    @property
    def status(self):
        return 0 if self.is_request else int(self.start.split()[1])

    @property
    def reason(self):
        return "" if self.is_request else self.start.split(None, 2)[2] if len(
            self.start.split(None, 2)) > 2 else ""

    # -- headers
    def get(self, name, default=None):
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default

    def get_all(self, name, split=True):
        n = name.lower()
        out = []
        for k, v in self.headers:
            if k.lower() == n:
                out += split_commas(v) if split else [v]
        return out

    def set(self, name, value):
        self.remove(name)
        self.headers.append((name, value))

    def add(self, name, value, first=False):
        if first:
            self.headers.insert(0, (name, value))
        else:
            self.headers.append((name, value))

    def remove(self, name):
        n = name.lower()
        self.headers = [(k, v) for k, v in self.headers if k.lower() != n]

    def has_option(self, header, tag):
        return any(t.strip().lower() == tag for v in self.get_all(header) for t in [v])

    @property
    def cseq(self):
        n, m = (self.get("CSeq") or "0 X").split()
        return int(n), m.upper()

    @property
    def call_id(self):
        return self.get("Call-ID")

    @property
    def branch(self):
        v = self.get_all("Via")
        return parse_params(";" + v[0].split(";", 1)[1]).get("branch") if v and ";" in v[0] else None

    def tag(self, which):
        v = self.get(which)
        return parse_nameaddr(v)[2].get("tag") if v else None

    # -- wire format
    def encode(self):
        hs = [(k, v) for k, v in self.headers if k.lower() != "content-length"]
        lines = [self.start] + [f"{k}: {v}" for k, v in hs] + [f"Content-Length: {len(self.body)}"]
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + self.body

    @classmethod
    def parse(cls, data):
        head, sep, body = data.partition(b"\r\n\r\n")
        if not sep:
            head, sep, body = data.partition(b"\n\n")
        lines = head.decode("utf-8", "replace").replace("\r\n", "\n").split("\n")
        while lines and not lines[0].strip():
            lines.pop(0)
        if not lines:
            raise ValueError("empty message")
        start, headers = lines[0].strip(), []
        if not (start.startswith("SIP/2.0 ") or start.endswith(" SIP/2.0")):
            raise ValueError("not SIP")
        for ln in lines[1:]:
            if ln[:1] in (" ", "\t") and headers:
                headers[-1] = (headers[-1][0], headers[-1][1] + " " + ln.strip())
                continue
            k, _, v = ln.partition(":")
            k = k.strip()
            k = COMPACT.get(k, k) if len(k) == 1 else CANON.get(k.lower(), k)
            headers.append((k, v.strip()))
        msg = cls(start, headers, b"")
        n = msg.get("Content-Length")
        msg.body = body[:int(n)] if n and n.strip().isdigit() else body
        return msg

    def summary(self):
        n, m = self.cseq
        return (f"{self.method} {self.uri.split(':')[0]}:..." if self.is_request
                else f"{self.status} {self.reason}") + f" (CSeq {n} {m})"


def stream_frames(buf):
    """Split complete SIP messages off a TCP byte buffer -> (messages, rest)."""
    out = []
    while True:
        while buf[:2] == b"\r\n":            # keep-alive CRLFs
            buf = buf[2:]
        i = buf.find(b"\r\n\r\n")
        if i < 0:
            return out, buf
        m = re.search(rb"(?im)^(?:content-length|l)\s*:\s*(\d+)", buf[:i])
        n = int(m.group(1)) if m else 0
        if len(buf) < i + 4 + n:
            return out, buf
        out.append(buf[:i + 4 + n])
        buf = buf[i + 4 + n:]


def new_branch():
    return "z9hG4bK" + secrets.token_hex(8)


def new_tag():
    return secrets.token_hex(5)


# ---------------------------------------------------------------------------- digest / AKA

def md5hex(b):
    return hashlib.md5(b if isinstance(b, bytes) else b.encode()).hexdigest()


def parse_challenge(value):
    """'Digest realm="x", nonce="y", algorithm=AKAv1-MD5, qop="auth"' -> dict."""
    scheme, _, rest = value.strip().partition(" ")
    out = {"scheme": scheme.lower()}
    for m in re.finditer(r'([\w-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^,\s]+)', rest):
        v = m.group(2)
        out[m.group(1).lower()] = v[1:-1] if v.startswith('"') else v
    return out


def digest_response(username, realm, password, method, uri, nonce, nc=None, cnonce=None,
                    qop=None):
    """RFC 2617 response; for AKAv1-MD5 (RFC 3310) password = RES as raw bytes,
    or b"" when reporting a synchronisation failure (auts)."""
    ha1 = md5hex(f"{username}:{realm}:".encode() + bytes(password))
    ha2 = md5hex(f"{method}:{uri}")
    if qop:
        return md5hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return md5hex(f"{ha1}:{nonce}:{ha2}")


def aka_nonce_split(nonce):
    raw = base64.b64decode(nonce + "=" * (-len(nonce) % 4))
    if len(raw) < 32:
        raise ValueError("AKA nonce too short")
    return raw[:16], raw[16:32]


class AkaResult:
    """kind: ok (res/ck/ik), sync (auts), mac (network authentication failed), error."""

    def __init__(self, kind, res=b"", ck=b"", ik=b"", auts=b""):
        self.kind, self.res, self.ck, self.ik, self.auts = kind, res, ck, ik, auts

    def __repr__(self):
        return (f"AkaResult({self.kind}, res {len(self.res)} B, ck {len(self.ck)} B, "
                f"ik {len(self.ik)} B, auts {len(self.auts)} B)")


def authorization(ident, realm, uri, method, chal=None, aka=None):
    """Authorization header value.  chal=None: the empty initial one (24.229 5.1.1.2.1)."""
    if chal is None:
        return (f'Digest username="{ident.impi}",realm="{realm}",uri="{uri}",nonce="",'
                f'response="",algorithm=AKAv1-MD5')
    qop = None
    if chal.get("qop"):
        opts = [q.strip() for q in chal["qop"].split(",")]
        qop = "auth" if "auth" in opts else None
    nc, cnonce = "00000001", secrets.token_hex(8)
    pw = aka.res if aka.kind == "ok" else b""
    resp = digest_response(ident.impi, chal.get("realm", realm), pw, method, uri,
                           chal.get("nonce", ""), nc, cnonce, qop)
    h = (f'Digest username="{ident.impi}",realm="{chal.get("realm", realm)}",uri="{uri}",'
         f'nonce="{chal.get("nonce", "")}",response="{resp}",algorithm={chal.get("algorithm", "AKAv1-MD5")}')
    if qop:
        h += f",cnonce=\"{cnonce}\",qop={qop},nc={nc}"
    if chal.get("opaque") is not None:
        h += f',opaque="{chal["opaque"]}"'
    if aka.kind == "sync":
        h += f',auts="{base64.b64encode(aka.auts).decode()}"'
    return h


# ---------------------------------------------------------------------------- sec-agree / xfrm

AUTH_ALGS = {"hmac-sha-1-96": "hmac(sha1)", "hmac-md5-96": "hmac(md5)"}
ENC_ALGS = {"null": "cipher_null", "aes-cbc": "cbc(aes)", "des-ede3-cbc": "cbc(des3_ede)"}
# Three offers: with all six (+ md5/aes, sha1/3des, md5/3des) the initial REGISTER is
# 1608 B and Play never answered the UDP fragments (live 2026-11-20); this list got 401.
DEFAULT_OFFER = [("hmac-sha-1-96", "aes-cbc"), ("hmac-sha-1-96", "null"),
                 ("hmac-md5-96", "null")]
ALL_OFFERS = [("hmac-sha-1-96", "aes-cbc"), ("hmac-sha-1-96", "null"),
              ("hmac-md5-96", "aes-cbc"), ("hmac-md5-96", "null"),
              ("hmac-sha-1-96", "des-ede3-cbc"), ("hmac-md5-96", "des-ede3-cbc")]


def security_client(offer, spi_c, spi_s, port_c, port_s):
    return ", ".join(
        f"ipsec-3gpp;prot=esp;mod=trans;spi-c={spi_c};spi-s={spi_s};port-c={port_c};"
        f"port-s={port_s};ealg={e};alg={a}" for a, e in offer)


def parse_security(values):
    """Security-Server/-Client entries -> [dict(mech, alg, ealg, spi_c, spi_s, port_c, port_s, q)]."""
    out = []
    for v in values:
        mech, _, rest = v.partition(";")
        p = parse_params(";" + rest)
        try:
            out.append(dict(mech=mech.strip().lower(), alg=(p.get("alg") or "").lower(),
                            ealg=(p.get("ealg") or "null").lower(), prot=(p.get("prot") or "esp"),
                            mod=(p.get("mod") or "trans"),
                            spi_c=int(p.get("spi-c") or 0), spi_s=int(p.get("spi-s") or 0),
                            port_c=int(p.get("port-c") or 0), port_s=int(p.get("port-s") or 0),
                            q=float(p.get("q") or 0.1), raw=v))
        except ValueError:
            continue
    return out


def choose_security(server_entries, offer):
    """Highest-q ipsec-3gpp entry we offered and support (RFC 3329 2.3)."""
    ok = [e for e in server_entries if e["mech"] == "ipsec-3gpp" and e["prot"] == "esp"
          and e["mod"] == "trans" and (e["alg"], e["ealg"]) in offer
          and e["spi_c"] and e["spi_s"] and e["port_c"] and e["port_s"]]
    if not ok:
        return None
    return max(ok, key=lambda e: (e["q"], -offer.index((e["alg"], e["ealg"]))))


def esp_keys(alg, ealg, ck, ik):
    """TS 33.203 Annex I: IK for MD5-96, IK||0^32 for SHA1-96; CK for AES-CBC,
    CK1||CK2||CK1 for 3DES-CBC; none for null."""
    akey = ik if alg == "hmac-md5-96" else ik + b"\0" * 4
    if ealg == "aes-cbc":
        ekey = ck
    elif ealg == "des-ede3-cbc":
        ekey = ck[:8] + ck[8:16] + ck[:8]
    else:
        ekey = b""
    return akey, ekey


class SaSet:
    """The four transport-mode ESP SAs of one sec-agree (33.203 7.1) and their
    policies (UDP and TCP), as `ip xfrm` argument lists."""

    def __init__(self, ue, pc, ue_spi_c, ue_spi_s, ue_port_c, ue_port_s, srv, ck, ik,
                 reqid_base=0x1a00):
        self.ue, self.pc = str(ue), str(pc)
        self.ue_spi_c, self.ue_spi_s = ue_spi_c, ue_spi_s
        self.ue_port_c, self.ue_port_s = ue_port_c, ue_port_s
        self.pc_spi_c, self.pc_spi_s = srv["spi_c"], srv["spi_s"]
        self.pc_port_c, self.pc_port_s = srv["port_c"], srv["port_s"]
        self.alg, self.ealg = srv["alg"], srv["ealg"]
        self.akey, self.ekey = esp_keys(self.alg, self.ealg, ck, ik)
        self.reqid = reqid_base
        self.plen = 128 if ":" in self.ue else 32

    def flows(self):
        """(src, dst, sport, dport, spi, reqid, dir) for the 4 SAs."""
        u, p, r = self.ue, self.pc, self.reqid
        return [
            (u, p, self.ue_port_c, self.pc_port_s, self.pc_spi_s, r + 0, "out"),   # our requests
            (u, p, self.ue_port_s, self.pc_port_c, self.pc_spi_c, r + 1, "out"),   # our responses
            (p, u, self.pc_port_s, self.ue_port_c, self.ue_spi_c, r + 2, "in"),    # their responses
            (p, u, self.pc_port_c, self.ue_port_s, self.ue_spi_s, r + 3, "in"),    # their requests
        ]

    def add_commands(self):
        cmds = []
        for src, dst, sport, dport, spi, reqid, d in self.flows():
            enc = ["enc", ENC_ALGS[self.ealg], ("0x" + self.ekey.hex()) if self.ekey else ""]
            cmds.append(["xfrm", "state", "add", "src", src, "dst", dst, "proto", "esp",
                         "spi", f"{spi:#010x}", "reqid", str(reqid), "mode", "transport",
                         "replay-window", "32",
                         "auth-trunc", AUTH_ALGS[self.alg], "0x" + self.akey.hex(), "96", *enc])
        for src, dst, sport, dport, spi, reqid, d in self.flows():
            for proto in ("udp", "tcp"):
                cmds.append(["xfrm", "policy", "update", "src", f"{src}/{self.plen}",
                             "dst", f"{dst}/{self.plen}", "proto", proto, "sport", str(sport),
                             "dport", str(dport), "dir", d, "tmpl", "src", src, "dst", dst,
                             "proto", "esp", "reqid", str(reqid), "mode", "transport"])
        return cmds

    def selectors(self):
        return {(f[0], f[1], f[2], f[3], f[6]) for f in self.flows()}

    def del_commands(self, keep=None):
        """keep: an SaSet whose policies (same selectors, replaced by `update`) stay."""
        cmds = []
        kept = keep.selectors() if keep else set()
        for src, dst, sport, dport, spi, reqid, d in self.flows():
            if (src, dst, sport, dport, d) in kept:
                continue
            for proto in ("udp", "tcp"):
                cmds.append(["xfrm", "policy", "delete", "src", f"{src}/{self.plen}",
                             "dst", f"{dst}/{self.plen}", "proto", proto, "sport", str(sport),
                             "dport", str(dport), "dir", d])
        for src, dst, sport, dport, spi, reqid, d in self.flows():
            cmds.append(["xfrm", "state", "delete", "src", src, "dst", dst, "proto", "esp",
                         "spi", f"{spi:#010x}"])
        return cmds


class Xfrm:
    """Runs `ip xfrm` commands.  Arguments contain keys and addresses: never logged."""

    def __init__(self, log, runner=None):
        self.log = log
        self.runner = runner or self._run
        self.sets = []

    @staticmethod
    def _run(argv):
        r = subprocess.run(["ip", *argv], capture_output=True, text=True)
        return r.returncode, r.stderr.strip()

    def install(self, sa):
        failed = 0
        for c in sa.add_commands():
            rc, err = self.runner(c)
            if rc:
                failed += 1
                self.log(f"ims: xfrm {c[1]} {c[2]} failed ({err[:60]})")
        self.sets.append(sa)
        self.log(f"ims: IPsec SAs installed: alg {sa.alg}, ealg {sa.ealg}, 4 SAs, 8 policies"
                 + (f", {failed} FAILED" if failed else ""))
        return failed == 0

    def remove(self, sa, keep=None):
        for c in sa.del_commands(keep):
            self.runner(c)
        if sa in self.sets:
            self.sets.remove(sa)

    def remove_all(self):
        for sa in list(self.sets):
            self.remove(sa)


# ---------------------------------------------------------------------------- SDP

AMR_BITS = {"AMR": [95, 103, 118, 134, 148, 159, 204, 244, 39],
            "AMR-WB": [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]}


class Codec:
    def __init__(self, pt, name, rate, octet_align=False, mode_set=None, extra=""):
        self.pt, self.name, self.rate = pt, name, rate
        self.octet_align, self.mode_set, self.extra = octet_align, mode_set, extra
        self.te_pt = None         # negotiated telephone-event payload type
        self.ptime = 20

    def __repr__(self):
        return (f"{self.name}/{self.rate} pt {self.pt} "
                f"{'octet-aligned' if self.octet_align else 'bandwidth-efficient'}"
                + (f" modes {self.mode_set}" if self.mode_set else "")
                + (f" DTMF pt {self.te_pt}" if self.te_pt is not None else ""))


class Sdp:
    """Small SDP model: one audio m-line."""

    def __init__(self):
        self.ip, self.port, self.pts = None, 0, []
        self.rtpmap, self.fmtp = {}, {}
        self.direction, self.ptime = "sendrecv", None
        self.curr, self.des, self.conf = [], [], []
        self.bw = []

    @classmethod
    def parse(cls, body):
        s = cls()
        txt = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        sess_ip = None
        in_audio = False
        for ln in txt.replace("\r\n", "\n").split("\n"):
            ln = ln.strip()
            if len(ln) < 2 or ln[1] != "=":
                continue
            t, v = ln[0], ln[2:]
            if t == "m":
                f = v.split()
                in_audio = f[0] == "audio" and not s.pts
                if in_audio:
                    s.port = int(f[1])
                    s.pts = [int(x) for x in f[3:] if x.isdigit()]
            elif t == "c":
                ip = v.split()[-1].split("/")[0]
                if in_audio:
                    s.ip = ip
                elif sess_ip is None:
                    sess_ip = ip
            elif t == "b" and in_audio:
                s.bw.append(v)
            elif t == "a" and (in_audio or not s.pts):
                k, _, val = v.partition(":")
                if k == "rtpmap":
                    pt, _, enc = val.partition(" ")
                    s.rtpmap[int(pt)] = enc.strip()
                elif k == "fmtp":
                    pt, _, par = val.partition(" ")
                    if pt.isdigit():
                        s.fmtp[int(pt)] = par.strip()
                elif k in ("sendrecv", "sendonly", "recvonly", "inactive"):
                    s.direction = k
                elif k == "ptime":
                    s.ptime = val
                elif k == "curr":
                    s.curr.append(val.split())
                elif k == "des":
                    s.des.append(val.split())
                elif k == "conf":
                    s.conf.append(val.split())
        s.ip = s.ip or sess_ip
        return s

    def fmtp_params(self, pt):
        out = {}
        for item in self.fmtp.get(pt, "").split(";"):
            k, _, v = item.strip().partition("=")
            if k:
                out[k.strip().lower()] = v.strip()
        return out

    def codecs(self):
        out = []
        for pt in self.pts:
            enc = self.rtpmap.get(pt)
            if not enc:
                continue
            name, _, rest = enc.partition("/")
            rate = int(rest.split("/")[0]) if rest.split("/")[0].isdigit() else 8000
            p = self.fmtp_params(pt)
            ms = [int(x) for x in p.get("mode-set", "").split(",") if x.strip().isdigit()] or None
            out.append(Codec(pt, name.upper() if name.upper() in ("AMR", "AMR-WB") else name,
                             rate, p.get("octet-align") == "1", ms))
        return out

    def wants_preconditions(self):
        return any(d[0] == "qos" for d in self.des)


def sdp_build(ip, port, sess_id, version, codecs, te_pts=None, direction="sendrecv",
              precond=None, bw_as=49):
    """codecs: [Codec]; te_pts: {rate: pt}; precond: dict(local, remote, want_conf)."""
    fam = "IP6" if ":" in str(ip) else "IP4"
    pts = [c.pt for c in codecs] + list((te_pts or {}).values())
    l = ["v=0", f"o=- {sess_id} {version} IN {fam} {ip}", "s=-", f"c=IN {fam} {ip}",
         "t=0 0", f"m=audio {port} RTP/AVP {' '.join(map(str, pts))}",
         f"b=AS:{bw_as}", "b=RS:0", "b=RR:0"]
    for c in codecs:
        l.append(f"a=rtpmap:{c.pt} {c.name}/{c.rate}/1")
        f = []
        if c.octet_align:
            f.append("octet-align=1")
        if c.mode_set:
            f.append("mode-set=" + ",".join(map(str, c.mode_set)))
        f.append("mode-change-capability=2;max-red=0")
        l.append(f"a=fmtp:{c.pt} " + ";".join(f))
    for rate, pt in (te_pts or {}).items():
        l += [f"a=rtpmap:{pt} telephone-event/{rate}", f"a=fmtp:{pt} 0-15"]
    l += ["a=ptime:20", "a=maxptime:240"]
    if precond:
        l += [f"a=curr:qos local {precond['local']}", f"a=curr:qos remote {precond['remote']}",
              "a=des:qos mandatory local sendrecv", "a=des:qos optional remote sendrecv"
              if precond.get("offer") else "a=des:qos mandatory remote sendrecv"]
        if precond.get("want_conf"):
            l.append("a=conf:qos remote sendrecv")
    l.append(f"a={direction}")
    return ("\r\n".join(l) + "\r\n").encode()


def default_offer_codecs(wb=True, nb=True):
    out = []
    if wb:
        out += [Codec(104, "AMR-WB", 16000), Codec(110, "AMR-WB", 16000, octet_align=True)]
    if nb:
        out += [Codec(102, "AMR", 8000), Codec(108, "AMR", 8000, octet_align=True)]
    return out


def negotiate(remote, wb=True, nb=True):
    """Answer selection: the first AMR-WB/AMR payload of the remote list we support,
    with telephone-event at the same clock rate.  None if nothing fits."""
    te = {c.rate: c.pt for c in remote.codecs() if c.name.lower() == "telephone-event"}
    for c in remote.codecs():
        if (c.name == "AMR-WB" and wb) or (c.name == "AMR" and nb):
            c.te_pt = te.get(c.rate)
            return c
    return None


def direction_answer(d):
    return {"sendonly": "recvonly", "recvonly": "sendonly"}.get(d, d)


# ---------------------------------------------------------------------------- config

class ImsConfig:
    """Options (modem.conf IMS_* keys).  Defaults are conservative."""

    DEFAULTS = dict(
        user_agent="SM-G975F Samsung IMS 6.0",
        mmtel=False,                  # +g.3gpp.icsi-ref mmtel + audio in Contact
        expires=600000,
        unprot_port=5060,
        pcscf_port=5060,
        udp_max=1300,                 # RFC 3261 18.1.1: larger requests go over TCP
        unprot_udp_max=1400,          # unprotected REGISTER: TCP above this (no ESP overhead;
                                      # IPv6 + UDP headers leave 1452 B in a 1500 B MTU)
        prot_transport="auto",        # auto: by size (udp_max); tcp: every protected request
        sec_offer=DEFAULT_OFFER,
        ipsec=True,                   # False only for lab/loopback tests
        sip_instance=True,
        pani=True,                    # P-Access-Network-Info
        access_type="3GPP-E-UTRAN-FDD",
        uri_format="sip",             # sip: sip:+48..@domain;user=phone, tel: tel:+48..
        country_code="",              # e.g. 48: national numbers become +48..; "" = phone-context
        precondition="auto",          # auto: offer without, retry on 421; yes: always offer
        amr_wb=True, amr_nb=True,
        session_expires=1800,
        subscribe_reg=True,
        cs_fallback=True,             # INVITE failed before any 18x -> CS dial
        trace=None,                   # path for a redacted SIP trace (0600), None = off
        reg_retry_min=60, reg_retry_max=1800,
    )

    def __init__(self, **kw):
        for k, v in self.DEFAULTS.items():
            setattr(self, k, kw.pop(k, v))
        if kw:
            raise TypeError(f"unknown IMS options {sorted(kw)}")

    @classmethod
    def from_conf(cls, conf):
        """modem.conf dict (strings) -> ImsConfig."""
        yes = lambda k, d: conf.get(k, "yes" if d else "no").lower() in ("yes", "1", "on", "true")
        kw = dict(
            user_agent=conf.get("IMS_USER_AGENT", cls.DEFAULTS["user_agent"]),
            mmtel=conf.get("VOLTE", "no").lower() == "mmtel",
            expires=int(conf.get("IMS_EXPIRES", 600000)),
            ipsec=yes("IMS_IPSEC", True), sip_instance=yes("IMS_SIP_INSTANCE", True),
            pani=yes("IMS_PANI", True), uri_format=conf.get("IMS_URI_FORMAT", "sip"),
            country_code=conf.get("IMS_COUNTRY_CODE", ""),
            precondition=conf.get("IMS_PRECONDITION", "auto"),
            amr_wb=yes("IMS_AMR_WB", True), amr_nb=yes("IMS_AMR_NB", True),
            subscribe_reg=yes("IMS_SUBSCRIBE_REG", True), cs_fallback=yes("IMS_CS_FALLBACK", True),
            trace=conf.get("IMS_TRACE") or None,
            pcscf_port=int(conf.get("IMS_PCSCF_PORT", 5060)),
            unprot_port=int(conf.get("IMS_UNPROT_PORT", 5060)),
            prot_transport=conf.get("IMS_TRANSPORT", "auto").lower(),
            unprot_udp_max=int(conf.get("IMS_UNPROT_UDP_MAX", 1400)),
        )
        if conf.get("IMS_SEC_ALGS"):
            kw["sec_offer"] = [tuple(x.split("/")) for x in conf["IMS_SEC_ALGS"].split()]
        return cls(**kw)


# ---------------------------------------------------------------------------- transport

class Transport:
    """UDP + TCP sockets of the UA: one unprotected UDP socket, and per sec-agree the
    protected client port (UDP, TCP client) and server port (UDP, TCP listener)."""

    def __init__(self, ua):
        self.ua = ua
        self.sel = ua.sel
        self.socks = {}        # name -> socket
        self.tcp = {}          # (peer, port, localport) -> [socket, buffer]

    def family(self, ip):
        return socket.AF_INET6 if ":" in str(ip) else socket.AF_INET

    def udp(self, name, ip, port):
        s = socket.socket(self.family(ip), socket.SOCK_DGRAM)
        s.bind((str(ip), port))
        s.setblocking(False)
        self.socks[name] = s
        self.sel.register(s, selectors.EVENT_READ, ("udp", name))
        return s.getsockname()[1]

    def tcp_listen(self, name, ip, port):
        s = socket.socket(self.family(ip), socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((str(ip), port))
        s.listen(4)
        s.setblocking(False)
        self.socks[name] = s
        self.sel.register(s, selectors.EVENT_READ, ("listen", name))

    def close(self, name):
        s = self.socks.pop(name, None)
        if s:
            try:
                self.sel.unregister(s)
            except (KeyError, ValueError):
                pass
            s.close()

    def close_all(self):
        for n in list(self.socks):
            self.close(n)
        for key in list(self.tcp):
            self._tcp_drop(key)

    def _tcp_drop(self, key):
        c = self.tcp.pop(key, None)
        if c:
            try:
                self.sel.unregister(c[0])
            except (KeyError, ValueError):
                pass
            c[0].close()

    def send_udp(self, name, data, dest):
        try:
            self.socks[name].sendto(data, dest)
            return True
        except (OSError, KeyError) as e:
            self.ua.log(f"ims: udp send failed: {e.__class__.__name__}")
            return False

    def connect(self, local_ip, local_port, dest):
        """TCP connection from local_port (0 = any) to dest -> its local port, or None."""
        key = (dest[0], dest[1], local_port)
        if local_port and key in self.tcp:
            return local_port
        s = socket.socket(self.family(local_ip), socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            if local_port and hasattr(socket, "SO_REUSEPORT"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind((str(local_ip), local_port))
            s.settimeout(5)
            s.connect(dest)
        except OSError as e:
            self.ua.log(f"ims: tcp connect failed: {e.__class__.__name__} {e.errno}")
            s.close()
            return None
        s.setblocking(False)
        local_port = s.getsockname()[1]
        key = (dest[0], dest[1], local_port)
        self.tcp[key] = [s, b""]
        self.sel.register(s, selectors.EVENT_READ, ("tcp", key))
        return local_port

    def send_tcp(self, local_ip, local_port, dest, data):
        key = (dest[0], dest[1], local_port)
        c = self.tcp.get(key)
        if not c:
            if self.connect(local_ip, local_port, dest) is None:
                return False
            c = self.tcp[key]
        try:
            c[0].setblocking(True)
            c[0].sendall(data)
            c[0].setblocking(False)
            return True
        except OSError as e:
            self.ua.log(f"ims: tcp send failed: {e.__class__.__name__}")
            self._tcp_drop(key)
            return False

    def on_event(self, kind, name, sock):
        if kind == "udp":
            try:
                data, src = sock.recvfrom(65535)
            except OSError:
                return
            self.ua.on_data(data, ("udp", name, src[:2]))
        elif kind == "listen":
            try:
                s, src = sock.accept()
            except OSError:
                return
            s.setblocking(False)
            key = (src[0], src[1], sock.getsockname()[1])
            self.tcp[key] = [s, b""]
            self.sel.register(s, selectors.EVENT_READ, ("tcp", key))
        elif kind == "tcp":
            key = name
            c = self.tcp.get(key)
            if not c:
                return
            try:
                data = sock.recv(65535)
            except BlockingIOError:
                return
            except OSError:
                data = b""
            if not data:
                self._tcp_drop(key)
                return
            c[1] += data
            msgs, c[1] = stream_frames(c[1])
            for m in msgs:
                self.ua.on_data(m, ("tcp", key, (key[0], key[1])))
            if len(c[1]) > 65536:
                self._tcp_drop(key)


# ---------------------------------------------------------------------------- transactions

class ClientTx:
    def __init__(self, ua, msg, route, cb):
        self.ua, self.msg, self.route, self.cb = ua, msg, route, cb
        self.branch, self.method = msg.branch, msg.method
        self.key = (self.branch, self.method)
        self.data = msg.encode()
        self.done = False
        self.got_provisional = False
        self.start = _now()
        self.interval = T1
        self.next = self.start + T1 if route[0] == "udp" else None
        self.deadline = self.start + 64 * T1

    def send(self):
        return self.ua.send_raw(self.data, self.route)

    def tick(self, now):
        if self.done:
            return
        if now >= self.deadline and not (self.method == "INVITE" and self.got_provisional):
            self.done = True
            self.cb(None)
            return
        if self.next and now >= self.next and not (self.method == "INVITE" and self.got_provisional):
            self.send()
            self.interval = min(self.interval * 2, T2 if self.method != "INVITE" else 64 * T1)
            self.next = now + self.interval

    def on_response(self, r):
        if self.done:
            return
        if r.status < 200:
            self.got_provisional = True
            if self.method != "INVITE" and self.next:
                self.next = _now() + T2
            self.cb(r)
            return
        self.done = True
        if self.method == "INVITE" and r.status >= 300:
            self.ua.send_raw(self.ua.ack_for_failure(self.msg, r).encode(), self.route)
        self.cb(r)


# ---------------------------------------------------------------------------- calls

class Call:
    STATES = {"active": 1, "held": 2, "dialing": 3, "alerting": 4, "incoming": 5, "waiting": 6}

    def __init__(self, cid, direction, number):
        self.id, self.dir, self.number = cid, direction, number
        self.intl = number.startswith("+")
        self.state = "dialing" if direction == "out" else "incoming"
        self.call_id = secrets.token_hex(12)
        self.local_tag, self.remote_tag = new_tag(), None
        self.local_uri = self.remote_uri = self.remote_target = None
        self.route_set = []
        self.local_cseq, self.remote_cseq = 1, None
        self.invite = None            # MO: our INVITE; MT: their INVITE (+ route)
        self.invite_route = None
        self.invite_tx = None
        self.codec = None
        self.local_sdp = self.remote_sdp = None
        self.sdp_version = 1
        self.sess_id = random.randint(10 ** 9, 2 ** 31)
        self.media = None
        self.rtp_port = None
        self.rtp_sock = None
        self.rseq = random.randint(1, 1000)
        self.pending_rel = None       # (msg bytes, route, rseq, next, interval, deadline)
        self.answer_sent = False      # SDP answer already sent reliably (MT)
        self.precond = False
        self.got_18x = False
        self.cancel_pending = False
        self.ended = False
        self.refresh_at = None
        self.session_expires = None
        self.we_refresh = False
        self.ack_route = None
        self.final_2xx = None         # MT: our 200 bytes until ACK
        self.final_next = None
        self.retried_precond = False

    def entry(self):
        return dict(id=self.id, dir=1 if self.dir == "out" else 2,
                    state=self.STATES.get(self.state, 1), mpty=0, number=self.number,
                    intl=self.intl, ims=True)


# ---------------------------------------------------------------------------- the UA

class ImsUa:
    """IMS UA.  hooks (all optional callables):
        aka(rand, autn) -> AkaResult           SIM AKA (blocking, from the UA thread)
        calls_changed(entries)                 call list for the AT emulator
        call_ended(call_id, cause)
        registered(state: str)                 'registered' | 'deregistered' | 'failed'
        cs_fallback(number)                    dial on CS instead
        pani() -> str|None                     utran-cell-id-3gpp value (MCC MNC TAC ECI)
        media(call, local_ip) -> media object  with start(remote_ip, port, codec), stop(), dtmf(c)
        rtp_socket(local_ip) -> (sock, port)   optional override for RTP port allocation
    """

    FIRST_CALL_ID = 8          # CS call ids are 1..7
    SUB_RETRY_DELAY = 5        # s: new reg-event subscription after a failed refresh

    def __init__(self, cfg, ident, local_ip, pcscfs, log, hooks=None, xfrm_runner=None):
        self.cfg, self.ident = cfg, ident
        self.local_ip = str(local_ip)
        self.pcscfs = [str(p) for p in pcscfs]
        self.pcscf = self.pcscfs[0] if self.pcscfs else None
        self.hooks = hooks or {}
        self.red = Redactor()
        ident.redact_into(self.red)
        self.red.add(self.local_ip, "ue")
        for k, p in enumerate(self.pcscfs):
            self.red.add(p, f"pcscf{k}")
        self._log = log
        self.sel = selectors.DefaultSelector()
        self.tr = Transport(self)
        self.xfrm = Xfrm(self.log, xfrm_runner)
        self.cmds = queue.Queue()
        self._wr, self._ww = socket.socketpair()
        self._wr.setblocking(False)
        self.sel.register(self._wr, selectors.EVENT_READ, ("wake", None))
        # wake alarm for the re-REGISTER (Linux, root); None elsewhere (tests)
        self.alarm_fd = None
        if hasattr(os, "timerfd_create") and os.geteuid() == 0:
            try:
                self.alarm_fd = os.timerfd_create(CLOCK_BOOTTIME_ALARM,
                                                  flags=os.TFD_NONBLOCK | os.TFD_CLOEXEC)
                self.sel.register(self.alarm_fd, selectors.EVENT_READ, ("alarm", None))
            except OSError as e:
                self.alarm_fd = None
                self.log(f"ims: no wake alarm ({e.__class__.__name__}): re-REGISTER may be "
                         "late while suspended")
        self.can_inhibit = self.alarm_fd is not None   # root on Linux: systemd-inhibit
        self.timers = []               # [when, fn]
        self.ctx = {}                  # branch -> ClientTx
        self.srv = {}                  # (branch, method) -> (response bytes, route, expiry)
        self.calls = {}
        self.thread = None
        self.running = False
        # registration
        self.reg_state = "idle"        # idle|unprot|prot|registered|dereg|failed
        self.reg_call_id = None
        self.reg_cseq = 0
        self.reg_from_tag = None
        self.sa = None
        self.old_sa = None
        self.sec_srv = None            # chosen Security-Server entry
        self.sec_verify = None         # header value echoed in protected requests
        self.spi_c = self.spi_s = self.port_c = self.port_s = None
        self.service_route = []
        self.reg_expires = 0
        self.reg_refresh_at = None
        self.realm = ident.domain
        self.chal_count = 0
        self.sync_failures = 0
        self.reg_fail_count = 0
        self.dereg_event = threading.Event()
        self.sub = None                # reg-event subscription: dict(call_id, tags, cseq)
        self.mmtel = cfg.mmtel
        self.next_call_id = self.FIRST_CALL_ID
        self.trace_fd = None
        if cfg.trace:
            try:
                self.trace_fd = os.open(cfg.trace, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            except OSError:
                self.trace_fd = None

    # ------------------------------------------------------------ plumbing
    def log(self, s):
        self._log(self.red(s))

    def trace(self, direction, data):
        if self.trace_fd is None:
            return
        txt = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        try:
            os.write(self.trace_fd, (f"--- {time.strftime('%H:%M:%S')} {direction}\n"
                                     + self.red(txt) + "\n").encode())
        except OSError:
            pass

    def hook(self, name, *a, default=None):
        f = self.hooks.get(name)
        if not f:
            return default
        try:
            return f(*a)
        except Exception as e:           # a hook bug must not kill the UA
            self.log(f"ims: hook {name} failed: {e!r}")
            return default

    def start(self):
        self.running = True
        self.tr.udp("unprot", self.local_ip, self.cfg.unprot_port)
        self.thread = threading.Thread(target=self._loop, name="ims-ua", daemon=True)
        self.thread.start()

    def call(self, fn, *a):
        """Run fn(*a) on the UA thread."""
        self.cmds.put((fn, a))
        try:
            self._ww.send(b"x")
        except OSError:
            pass

    def arm_alarm(self, delay):
        """Wake the system from suspend `delay` s from now (0 = disarm)."""
        if self.alarm_fd is None:
            return
        try:
            os.timerfd_settime(self.alarm_fd, initial=max(delay, 1) if delay else 0)
        except OSError as e:
            self.log(f"ims: wake alarm: {e.__class__.__name__}")

    _awake = None

    def keep_awake(self, seconds, why):
        """Block suspend for a while (logind inhibitor; beyond2lte-resuspend honours it)."""
        if self._awake and self._awake.poll() is None:
            return
        try:
            self._awake = subprocess.Popen(
                ["systemd-inhibit", "--what=sleep", "--mode=block", "--who=shannon-ims",
                 f"--why={why}", "sleep", str(seconds)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            self._awake = None

    def at(self, delay, fn):
        self.timers.append([_now() + delay, fn])

    def _loop(self):
        while self.running:
            now = _now()
            wait = 0.2
            for t in self.timers:
                wait = min(wait, max(0, t[0] - now))
            for key, _ in self.sel.select(wait):
                kind, name = key.data
                if kind == "wake":
                    try:
                        self._wr.recv(4096)
                    except OSError:
                        pass
                elif kind == "alarm":
                    try:
                        os.read(self.alarm_fd, 8)
                    except OSError:
                        pass
                    self.log("ims: woken for the re-REGISTER")
                    self.keep_awake(90, "IMS re-registration")
                else:
                    try:
                        self.tr.on_event(kind, name, key.fileobj)
                    except Exception as e:
                        self.log(f"ims: transport error {e!r}")
            while True:
                try:
                    fn, a = self.cmds.get_nowait()
                except queue.Empty:
                    break
                try:
                    fn(*a)
                except Exception as e:
                    self.log(f"ims: command error {e!r}")
            now = _now()
            due = [t for t in self.timers if t[0] <= now]
            self.timers = [t for t in self.timers if t[0] > now]
            for t in due:
                try:
                    t[1]()
                except Exception as e:
                    self.log(f"ims: timer error {e!r}")
            for tx in list(self.ctx.values()):
                tx.tick(now)
                if tx.done and now - tx.start > 64 * T1:
                    self.ctx.pop(tx.key, None)
            for k in [k for k, v in self.srv.items() if v[2] < now]:
                self.srv.pop(k, None)
            self._tick_calls(now)
        self.tr.close_all()
        for s in (self._wr, self._ww):
            s.close()
        self.sel.close()

    def stop(self, timeout=4.0):
        """Deregister (if registered), remove SAs, stop the thread."""
        if not self.running:
            return
        if self.reg_state == "registered":
            self.dereg_event.clear()
            self.call(self._deregister)
            self.dereg_event.wait(timeout)
        self.running = False
        self.call(lambda: None)
        if self.thread:
            self.thread.join(2)
        for c in list(self.calls.values()):
            self._media_stop(c)
        self.xfrm.remove_all()
        if self.trace_fd is not None:
            os.close(self.trace_fd)
            self.trace_fd = None

    # ------------------------------------------------------------ sending
    def send_raw(self, data, route):
        kind, local, dest = route
        self.trace(f"> {kind}", data)
        if kind == "udp":
            return self.tr.send_udp(local, data, dest)
        return self.tr.send_tcp(self.local_ip, local, dest, data)

    @staticmethod
    def _route_wants_tcp(msg):
        """The next hop (first Route, RFC 3261 16.12 / 3263) asks for TCP."""
        r = msg.get_all("Route")
        return bool(r) and ";transport=tcp" in r[0].lower()

    def protected_route(self, size, dest=None, tcp=False):
        dest = dest or (self.pcscf, self.sec_srv["port_s"])
        if tcp or size > self.cfg.udp_max or self.cfg.prot_transport == "tcp":
            return ("tcp", self.port_c, dest)
        return ("udp", "prot_c", dest)

    def via(self, route):
        transport = "TCP" if route[0] == "tcp" else "UDP"
        port = route[1] if route[0] == "tcp" else self.tr.socks[route[1]].getsockname()[1]
        return f"SIP/2.0/{transport} {host_for_uri(self.local_ip)}:{port};branch={new_branch()};rport"

    def send_request(self, msg, cb, route=None):
        """Adds Via (transport picked by size), sends, tracks the client transaction."""
        if route is None:
            route = self.protected_route(len(msg.encode()) + 120,
                                         tcp=self._route_wants_tcp(msg))
        msg.remove("Via")
        msg.add("Via", self.via(route), first=True)
        tx = ClientTx(self, msg, route, cb)
        self.ctx[tx.key] = tx
        self.log(f"ims: > {msg.summary()} via {route[0]}")
        tx.send()
        return tx

    def common(self, msg):
        msg.set("Max-Forwards", "70")
        msg.set("User-Agent", self.cfg.user_agent)
        if self.cfg.pani and msg.is_request and msg.method not in ("ACK", "CANCEL"):
            # RFC 7315 / 24.229: not in ACK and CANCEL
            cell = self.hook("pani")
            msg.set("P-Access-Network-Info", self.cfg.access_type
                    + (f";utran-cell-id-3gpp={cell}" if cell else ""))
        if self.sec_verify and self.reg_state in ("prot", "registered", "dereg"):
            msg.set("Security-Verify", self.sec_verify)
            msg.set("Require", "sec-agree")
            msg.set("Proxy-Require", "sec-agree")

    def respond(self, req, status, reason, route, headers=(), body=b"", to_tag=None):
        r = SipMessage(f"SIP/2.0 {status} {reason}")
        for h in ("Via",):
            for v in req.get_all(h, split=False):
                r.add(h, v)
        for h in ("Record-Route",):
            if 100 < status < 300:
                for v in req.get_all(h, split=False):
                    r.add(h, v)
        frm, to = req.get("From"), req.get("To")
        if to_tag and to and "tag=" not in to:
            to += f";tag={to_tag}"
        r.add("From", frm)
        r.add("To", to)
        r.add("Call-ID", req.call_id)
        r.add("CSeq", req.get("CSeq"))
        for k, v in headers:
            r.add(k, v)
        r.add("User-Agent", self.cfg.user_agent)
        if body:
            r.add("Content-Type", "application/sdp")
        r.body = body
        data = r.encode()
        self.log(f"ims: > {status} {reason} for {req.method}")
        self.send_raw(data, route)
        if req.branch and req.method != "ACK" and status >= 200:
            self.srv[(req.branch, req.method)] = (data, route, _now() + 32)
        return r

    def ack_for_failure(self, inv, r):
        a = SipMessage(f"ACK {inv.uri} SIP/2.0")
        a.add("Via", inv.get_all("Via", split=False)[0])
        for k in ("Route",):
            for v in inv.get_all(k, split=False):
                a.add(k, v)
        a.add("Max-Forwards", "70")
        a.add("From", inv.get("From"))
        a.add("To", r.get("To"))
        a.add("Call-ID", inv.call_id)
        a.add("CSeq", f"{inv.cseq[0]} ACK")
        if inv.get("Security-Verify"):
            a.add("Security-Verify", inv.get("Security-Verify"))
            a.add("Proxy-Require", "sec-agree")
            a.add("Require", "sec-agree")
        return a

    # ------------------------------------------------------------ receiving
    def on_data(self, data, src):
        """src = (kind, local name|tcp key, (ip, port))."""
        try:
            m = SipMessage.parse(data)
        except ValueError as e:
            first = data.split(b"\r\n", 1)[0][:40].decode("ascii", "replace")
            first = first.split(" sip:")[0].split(" tel:")[0]      # no request URI
            self.log(f"ims: unparsable {src[0]} message ({len(data)} B, {first!r}): {e}")
            return
        self.trace(f"< {src[0]}", data)
        kind, local, peer = src
        if kind == "udp":
            route = ("udp", local, peer)
        else:
            route = ("tcp", local[2], peer)
        if m.is_request:
            self.log(f"ims: < {m.summary()}")
            dup = self.srv.get((m.branch, m.method))
            if dup and m.method != "ACK":
                self.send_raw(dup[0], dup[1])
                return
            if m.method != "ACK" and peer[0] != self.pcscf and self.reg_state != "idle":
                self.log("ims: request from a host other than the P-CSCF ignored")
                return
            self.on_request(m, route)
        else:
            self.log(f"ims: < {m.summary()}")
            tx = self.ctx.get((m.branch, m.cseq[1]))
            if tx and not tx.done:
                tx.on_response(m)
            elif m.cseq[1] == "INVITE" and 200 <= m.status < 300:
                # retransmitted 2xx: ACK again
                c = self._call_by_callid(m.call_id)
                if c and c.ack_route:
                    self._send_ack(c, m)

    # ------------------------------------------------------------ registration
    def register(self, mmtel=None):
        self.call(self._register_start, mmtel)

    def deregister(self):
        self.call(self._deregister)

    def _alloc_ports(self):
        """Pick port-c/port-s (sockets bound before they are announced) and SPIs."""
        for _ in range(20):
            pc = random.randrange(20000, 60000, 2)
            ps = pc + 1
            try:
                self.tr.close("prot_c")
                self.tr.close("prot_s")
                self.tr.close("prot_s_tcp")
                self.tr.udp("prot_c", self.local_ip, pc)
                self.tr.udp("prot_s", self.local_ip, ps)
                self.tr.tcp_listen("prot_s_tcp", self.local_ip, ps)
                break
            except OSError:
                continue
        else:
            raise OSError("no free protected ports")
        self.port_c, self.port_s = pc, ps
        self.spi_c = random.randint(0x1000, 0x7FFFFFFF)
        self.spi_s = random.randint(0x1000, 0x7FFFFFFF)
        while self.spi_s == self.spi_c:
            self.spi_s = random.randint(0x1000, 0x7FFFFFFF)

    def contact(self, expires=None):
        c = f"<sip:{host_for_uri(self.local_ip)}:{self.port_s}>"
        if self.mmtel:
            c += f';+g.3gpp.icsi-ref="{MMTEL_ICSI_ENC}";audio'
        urn = self.ident.instance_urn() if self.cfg.sip_instance else None
        if urn:
            c += f';+sip.instance="<{urn}>"'
        if expires is not None:
            c += f";expires={expires}"
        return c

    def _register_msg(self, expires, auth, sec=None):
        """sec: (spi_c, spi_s, port_c, port_s) announced in Security-Client."""
        spi_c, spi_s, port_c, port_s = sec or (self.spi_c, self.spi_s, self.port_c, self.port_s)
        m = SipMessage(f"REGISTER sip:{self.ident.domain} SIP/2.0")
        self.reg_cseq += 1
        m.add("From", f"<{self.ident.impu}>;tag={self.reg_from_tag}")
        m.add("To", f"<{self.ident.impu}>")
        m.add("Call-ID", self.reg_call_id)
        m.add("CSeq", f"{self.reg_cseq} REGISTER")
        m.add("Contact", self.contact())
        m.add("Expires", str(expires))
        m.add("Supported", "path, sec-agree")
        m.add("Allow", ALLOW)
        m.add("Authorization", auth)
        m.add("Security-Client", security_client(self.cfg.sec_offer, spi_c, spi_s, port_c, port_s))
        m.add("Require", "sec-agree")
        m.add("Proxy-Require", "sec-agree")
        self.common(m)
        return m

    def _register_start(self, mmtel=None):
        if self.reg_state in ("unprot", "prot", "dereg"):
            self.log(f"ims: register: busy ({self.reg_state})")
            return
        if mmtel is not None:
            self.mmtel = mmtel
        if self.reg_state == "registered":
            self._refresh()
            return
        if not self.pcscf:
            self.log("ims: register: no P-CSCF")
            return
        self.reg_call_id = secrets.token_hex(12)
        self.reg_from_tag = new_tag()
        self.reg_cseq = 0
        self.chal_count = self.sync_failures = 0
        self.sec_verify, self.sec_srv = None, None
        self._alloc_ports()
        self.reg_state = "unprot"
        self.log(f"ims: REGISTER (initial, unprotected, MMTel {'on' if self.mmtel else 'off'}, "
                 f"{len(self.cfg.sec_offer)} sec-agree offers)")
        m = self._register_msg(self.cfg.expires,
                               authorization(self.ident, self.ident.domain,
                                             f"sip:{self.ident.domain}", "REGISTER"))
        self._send_unprot(m)

    def _send_unprot(self, m):
        """Unprotected REGISTER to P-CSCF:5060: UDP, or TCP when it would not fit in one
        datagram (never IP fragments, RFC 3261 18.1.1).  The TCP connection's
        local port is ephemeral; the 401 comes back on the connection."""
        dest = (self.pcscf, self.cfg.pcscf_port)
        udp = ("udp", "unprot", dest)
        size = len(m.encode()) + len(self.via(udp)) + len("Via: \r\n")
        route = udp
        if size > self.cfg.unprot_udp_max:
            # ephemeral local port: a fixed 5060 could hit our own TIME_WAIT 4-tuple
            lport = self.tr.connect(self.local_ip, 0, dest)
            self.log(f"ims: initial REGISTER is {size} B (> {self.cfg.unprot_udp_max}): "
                     + ("TCP" if lport else "TCP connect failed, UDP"))
            if lport:
                route = ("tcp", lport, dest)
        return self.send_request(m, self._on_register_resp, route)

    def _on_register_resp(self, r):
        if r is None:
            self.log(f"ims: REGISTER timed out ({self.reg_state})")
            return self._reg_failed("timeout", next_pcscf=True)
        if r.status < 200:
            return
        if r.status == 401:
            return self._on_challenge(r)
        if r.status == 423 and r.get("Min-Expires", "").isdigit():
            self.log("ims: 423 Interval Too Brief: retrying with Min-Expires")
            self.cfg.expires = int(r.get("Min-Expires"))
            self.reg_state = "idle"
            return self._register_start()
        if 200 <= r.status < 300:
            return self._on_registered(r)
        self.log(f"ims: REGISTER rejected: {r.status} {r.reason}"
                 + (f", Reason {r.get('Reason')}" if r.get("Reason") else ""))
        self._reg_failed(f"{r.status}", permanent=r.status in (403, 404))

    def _on_challenge(self, r):
        self.chal_count += 1
        if self.chal_count > 3:
            return self._reg_failed("too many challenges", permanent=True)
        www = r.get("WWW-Authenticate")
        chal = parse_challenge(www) if www else {}
        alg = chal.get("algorithm", "")
        srv_entries = parse_security(r.get_all("Security-Server"))
        self.log(f"ims: 401: algorithm {alg}, qop {chal.get('qop')}, Security-Server: "
                 + (", ".join(f"{e['alg']}/{e['ealg']} q={e['q']}" for e in srv_entries) or "none"))
        if alg.upper() != "AKAV1-MD5" or not chal.get("nonce"):
            return self._reg_failed(f"unsupported challenge {alg}", permanent=True)
        try:
            rand, autn = aka_nonce_split(chal["nonce"])
        except ValueError:
            return self._reg_failed("bad nonce", permanent=True)
        aka = self.hook("aka", rand, autn) or AkaResult("error")
        self.log(f"ims: SIM AKA: {aka.kind} (RES {len(aka.res)} B, CK {len(aka.ck)} B, "
                 f"IK {len(aka.ik)} B, AUTS {len(aka.auts)} B)")
        uri = f"sip:{self.ident.domain}"
        if aka.kind == "sync":
            self.sync_failures += 1
            if self.sync_failures > 1:
                return self._reg_failed("repeated SQN sync failure", permanent=True)
            m = self._register_msg(self.cfg.expires,
                                   authorization(self.ident, self.realm, uri, "REGISTER", chal, aka))
            if self.reg_state == "unprot":
                return self._send_unprot(m)
            return self.send_request(m, self._on_register_resp, self.protected_route(1))
        if aka.kind != "ok":
            # MAC failure: the network failed authentication - never retry automatically
            return self._reg_failed(f"AKA {aka.kind}", permanent=True)
        srv = choose_security(srv_entries, self.cfg.sec_offer)
        if not srv:
            return self._reg_failed("no acceptable Security-Server", permanent=True)
        if self.sa:
            # re-authentication (refresh): new SAs on the new port-c, same port-s;
            # the old set is removed 30 s after the new registration succeeded
            self.old_sa = self.sa
            self.sa = None
        self.sec_srv = srv
        self.sec_verify = ", ".join(e["raw"] for e in srv_entries)
        if self.cfg.ipsec:
            sa = SaSet(self.local_ip, self.pcscf, self.spi_c, self.spi_s, self.port_c,
                       self.port_s, srv, aka.ck, aka.ik,
                       reqid_base=0x1a00 + (0x10 if self.old_sa and self.old_sa.reqid == 0x1a00 else 0))
            if not self.xfrm.install(sa):
                self.xfrm.remove(sa, keep=self.old_sa)
                return self._reg_failed("xfrm setup failed", permanent=True)
            self.sa = sa
        self.reg_state = "prot"
        self.log(f"ims: REGISTER (protected, {srv['alg']}/{srv['ealg']})")
        self.last_auth = authorization(self.ident, self.realm, uri, "REGISTER", chal, aka)
        m = self._register_msg(self.cfg.expires, self.last_auth)
        m.set("Security-Verify", self.sec_verify)
        self.send_request(m, self._on_register_resp, self.protected_route(len(m.encode()) + 120))

    def _auth_again(self):
        """Authorization for a re-/de-REGISTER over the SAs: repeat the last nonce and
        response.  The empty initial form makes Play answer 500 "AKA IP+Port conflict"."""
        return getattr(self, "last_auth", None) or authorization(
            self.ident, self.realm, f"sip:{self.ident.domain}", "REGISTER")

    def _on_registered(self, r):
        exp = None
        contacts = r.get_all("Contact")
        for c in contacts:
            _, uri, p = parse_nameaddr(c)
            host, port = uri_host_port(uri)
            try:
                same = ipaddress.ip_address(host) == ipaddress.ip_address(self.local_ip)
            except ValueError:
                same = False
            if ((same and port == self.port_s) or len(contacts) == 1) and \
                    (p.get("expires") or "").isdigit():
                exp = int(p["expires"])
        if exp is None and (r.get("Expires") or "").isdigit():
            exp = int(r.get("Expires"))
        exp = exp if exp is not None else self.cfg.expires
        if self.reg_state == "dereg" or exp == 0:
            return self._deregistered("200 OK")
        self.service_route = [v for v in r.get_all("Service-Route")]
        self.ident.associated = [parse_nameaddr(v)[1] for v in r.get_all("P-Associated-URI")]
        self.ident.redact_into(self.red)
        self.reg_expires = exp
        self.reg_state = "registered"
        self.reg_fail_count = 0
        refresh = exp * 0.5 if exp < 1200 else exp - 600
        self.reg_refresh_at = _now() + refresh
        self.at(refresh, self._refresh_due)
        self._arm_wake()
        self.log(f"ims: REGISTERED: expires {exp} s (refresh in {int(refresh)} s), "
                 f"{len(self.service_route)} Service-Route, {len(self.ident.associated)} "
                 f"associated URIs, MMTel {'on' if self.mmtel else 'off'}")
        if self.old_sa:
            old = self.old_sa
            self.old_sa = None
            self.at(30, lambda: self.xfrm.remove(old, keep=self.sa))
        self.hook("registered", "registered")
        if self.cfg.subscribe_reg and not self.sub:
            self._subscribe()

    def _refresh_due(self):
        if self.reg_state == "registered" and self.reg_refresh_at and \
                _now() >= self.reg_refresh_at - 1:
            self._refresh()

    def _refresh(self):
        """Re-REGISTER over the current SAs.  It announces new SPIs and a new port-c
        (port-s stays, 24.229 5.1.1.4.1); they are used only if the network
        challenges again (new keys -> new SA set), otherwise the old SAs stay."""
        if self.reg_state != "registered":
            return
        self.log("ims: re-REGISTER")
        new_pc = None
        for _ in range(20):
            cand = random.randrange(20000, 60000, 2)
            if cand in (self.port_c, self.port_s):
                continue
            try:
                self.tr.udp("prot_c_new", self.local_ip, cand)
                new_pc = cand
                break
            except OSError:
                continue
        if new_pc is None:
            self.log("ims: re-REGISTER: no free port")
            return
        pend = (random.randint(0x1000, 0x7FFFFFFF), random.randint(0x1000, 0x7FFFFFFF), new_pc)
        m = self._register_msg(self.cfg.expires, self._auth_again(),
                               sec=(pend[0], pend[1], new_pc, self.port_s))
        m.set("Security-Verify", self.sec_verify)
        self.common(m)

        def cb(r):
            if r is not None and r.status == 401:
                # adopt what this REGISTER announced: the new SA set uses it
                self.spi_c, self.spi_s = pend[0], pend[1]
                self.tr.close("prot_c")
                self.tr.socks["prot_c"] = self.tr.socks.pop("prot_c_new")
                self.sel.modify(self.tr.socks["prot_c"], selectors.EVENT_READ, ("udp", "prot_c"))
                self.port_c = new_pc
            else:
                self.tr.close("prot_c_new")
            return self._on_register_resp(r)
        self.send_request(m, cb, self.protected_route(len(m.encode()) + 120))

    def _reg_failed(self, why, permanent=False, next_pcscf=False):
        prev = self.reg_state
        self.reg_state = "failed"
        if self.sa:
            self.xfrm.remove(self.sa)
            self.sa = None
        self.sec_verify = self.sec_srv = None
        self.log(f"ims: registration failed ({why}); "
                 + ("no automatic retry" if permanent else "will retry"))
        self.hook("registered", "failed")
        if next_pcscf and len(self.pcscfs) > 1:
            k = self.pcscfs.index(self.pcscf)
            self.pcscf = self.pcscfs[(k + 1) % len(self.pcscfs)]
        if not permanent and prev != "dereg":
            self.reg_fail_count += 1
            delay = min(self.cfg.reg_retry_min * 2 ** (self.reg_fail_count - 1),
                        self.cfg.reg_retry_max)
            self.log(f"ims: next REGISTER attempt in {int(delay)} s")
            self.at(delay, self._retry)
        if prev == "dereg":
            self.dereg_event.set()

    def _retry(self):
        if self.reg_state == "failed" and self.running:
            self.reg_state = "idle"
            self._register_start()

    def _deregister(self):
        for c in list(self.calls.values()):
            self._hangup(c)
        if self.reg_state != "registered":
            self.log(f"ims: deregister: not registered ({self.reg_state})")
            self._cleanup_reg()
            self.dereg_event.set()
            return
        self.reg_state = "dereg"
        m = self._register_msg(0, self._auth_again())
        m.set("Contact", self.contact(expires=0))
        # No new Security-Client offer: the same SPIs/ports again make Play answer
        # 500 "AKA IP+Port conflict".  Security-Verify keeps the current SA set.
        m.remove("Security-Client")
        m.set("Security-Verify", self.sec_verify)
        self.log("ims: REGISTER Expires 0 (deregistration)")

        tries = [0]

        def cb(r):
            if r is not None and r.status == 401 and not tries[0]:
                # challenged deregistration: answer over the existing SAs
                tries[0] = 1
                www = r.get("WWW-Authenticate")
                chal = parse_challenge(www) if www else {}
                try:
                    rand, autn = aka_nonce_split(chal.get("nonce", ""))
                except ValueError:
                    return self._deregistered("401 without a usable nonce")
                aka = self.hook("aka", rand, autn) or AkaResult("error")
                if aka.kind != "ok":
                    return self._deregistered(f"401, AKA {aka.kind}")
                m2 = self._register_msg(0, authorization(self.ident, self.realm,
                                                         f"sip:{self.ident.domain}", "REGISTER",
                                                         chal, aka))
                m2.set("Contact", self.contact(expires=0))
                m2.set("Security-Verify", self.sec_verify)
                return self.send_request(m2, cb, self.protected_route(len(m2.encode()) + 120))
            if r is None or r.status >= 200:
                self._deregistered(f"{r.status if r else 'timeout'}")
        self.send_request(m, cb, self.protected_route(len(m.encode()) + 120))
        self.at(3.5, lambda: self.reg_state == "dereg" and self._deregistered("timeout"))

    def _deregistered(self, why):
        self.log(f"ims: DEREGISTERED ({why})")
        self._cleanup_reg()
        self.hook("registered", "deregistered")
        self.dereg_event.set()

    def _cleanup_reg(self):
        self.arm_alarm(0)
        self.reg_state = "idle"
        self.sub = None
        self.reg_refresh_at = None
        self.xfrm.remove_all()
        self.sa = self.old_sa = None
        self.sec_verify = self.sec_srv = None
        for n in ("prot_c", "prot_s", "prot_s_tcp"):
            self.tr.close(n)
        for key in list(self.tr.tcp):
            self.tr._tcp_drop(key)

    # ------------------------------------------------------------ reg event
    def _routes(self, msg):
        msg.add("Route", self._pcscf_route())
        for r in self.service_route:
            msg.add("Route", r)

    def _pcscf_route(self):
        port = self.sec_srv["port_s"] if self.sec_srv else self.cfg.pcscf_port
        return f"<sip:{host_for_uri(self.pcscf)}:{port};lr>"

    def _register_pending(self):
        return any(not tx.done and tx.method == "REGISTER" for tx in self.ctx.values())

    def _subscribe(self, expires=None, fresh=False, retry=False):
        """reg-event subscription (24.229 5.1.1.3).  The first SUBSCRIBE is an initial
        request (Route: P-CSCF + Service-Route, Request-URI = our IMPU).  A refresh is a
        request inside the subscription dialog (RFC 6665 4.1.2.1, RFC 3261 12.2.1.1):
        Request-URI = remote target (Contact of the 2xx / last NOTIFY), Route = the
        dialog route set (Record-Route), To tag = the notifier's tag.  fresh: start a new
        dialog (after a failed refresh); retry: this is that one new attempt."""
        exp = self.cfg.expires if expires is None else expires
        if fresh:
            self.sub = None
        s = self.sub or dict(call_id=secrets.token_hex(12), tag=new_tag(), cseq=0,
                             remote_tag=None, route_set=None, target=None, refresh_at=None,
                             retry=retry)
        s["cseq"] += 1
        s["refresh_at"] = None
        self.sub = s
        in_dialog = s["remote_tag"] is not None
        aor = self.ident.preferred()
        if in_dialog:
            m = SipMessage(f"SUBSCRIBE {s['target'] or aor} SIP/2.0")
            for r in s["route_set"] or [self._pcscf_route()]:
                m.add("Route", r)
        else:
            m = SipMessage(f"SUBSCRIBE {aor} SIP/2.0")
            self._routes(m)
        m.add("From", f"<{aor}>;tag={s['tag']}")
        m.add("To", f"<{aor}>" + (f";tag={s['remote_tag']}" if in_dialog else ""))
        m.add("Call-ID", s["call_id"])
        m.add("CSeq", f"{s['cseq']} SUBSCRIBE")
        m.add("Contact", f"<sip:{host_for_uri(self.local_ip)}:{self.port_s}>")
        m.add("Event", "reg")
        m.add("Accept", "application/reginfo+xml")
        m.add("Expires", str(exp))
        if not in_dialog:
            m.add("P-Preferred-Identity", f"<{aor}>")
        self.common(m)

        def gone(why):
            if self.sub is not s:
                return
            self.sub = None
            if in_dialog and not s["retry"] and self.reg_state == "registered" and exp:
                self.log(f"ims: reg-event refresh failed ({why}): new subscription in "
                         f"{self.SUB_RETRY_DELAY} s")
                self.at(self.SUB_RETRY_DELAY, lambda: self.reg_state == "registered" and self.sub is None
                        and self._subscribe(retry=True))

        def cb(r):
            if r is None:
                self.log("ims: SUBSCRIBE reg timed out")
                gone("timeout")
            elif 200 <= r.status < 300:
                s["remote_tag"] = s["remote_tag"] or r.tag("To")
                if s["route_set"] is None:
                    # the 2xx creates the dialog (unless a NOTIFY already did)
                    s["route_set"] = list(reversed(r.get_all("Record-Route")))
                    if r.get("Contact"):
                        s["target"] = parse_nameaddr(r.get_all("Contact")[0])[1]
                e = r.get("Expires") or ""
                e = int(e) if e.isdigit() else exp
                self.log(f"ims: reg-event subscription active ({e} s, route set "
                         f"{len(s['route_set'])})")
                if e:
                    s["refresh_at"] = _now() + max(60, e - 600 if e > 1200 else e / 2)
                    self.at(s["refresh_at"] - _now(), lambda: self._sub_refresh_due(s))
                    self._arm_wake()
            elif r.status >= 300:
                self.log(f"ims: SUBSCRIBE reg: {r.status} {r.reason}")
                gone(f"{r.status}")
        self.send_request(m, cb)

    def _sub_refresh_due(self, s):
        if self.reg_state != "registered" or self.sub is not s or not s["refresh_at"]:
            return
        if _now() < s["refresh_at"] - 1:
            return
        if self._register_pending():
            # never interleave with a re-REGISTER (they used to coincide: same formula
            # when the subscription has the registration's expiry)
            self.at(3, lambda: self._sub_refresh_due(s))
            return
        self._subscribe()

    def _arm_wake(self):
        """Wake alarm 20 s before the earliest of re-REGISTER / reg-event refresh."""
        due = [t for t in (self.reg_refresh_at,
                           self.sub and self.sub.get("refresh_at")) if t]
        if due and self.reg_state == "registered":
            self.arm_alarm(max(1, min(due) - _now() - 20))

    def _on_notify(self, m, route):
        self.respond(m, 200, "OK", route)
        if (m.get("Event") or "").split(";")[0].strip() != "reg":
            return
        s = self.sub
        if s and m.call_id == s["call_id"] and m.tag("To") == s["tag"]:
            # NOTIFY is a target refresh request (RFC 6665 4.1.2.4); it creates the dialog
            # if it beats the 2xx (route set = Record-Route in order, as a UAS)
            s["remote_tag"] = s["remote_tag"] or m.tag("From")
            if s["route_set"] is None:
                s["route_set"] = m.get_all("Record-Route")
            if m.get("Contact"):
                s["target"] = parse_nameaddr(m.get_all("Contact")[0])[1]
        body = m.body.decode("utf-8", "replace")
        st = (m.get("Subscription-State") or "").split(";")[0].strip()
        ours = re.findall(r'<contact[^>]*state="(\w+)"[^>]*event="(\w+)"', body)
        terminated = [e for s, e in ours if s == "terminated"]
        self.log(f"ims: reg NOTIFY: subscription {st}, {len(ours)} contacts"
                 + (f", terminated: {','.join(sorted(set(terminated)))}" if terminated else ""))
        if st == "terminated":
            self.sub = None
        if "deactivated" in terminated or "rejected" in terminated or "unregistered" in terminated:
            if self.reg_state == "registered" and not any(s == "active" for s, _ in ours):
                self.log("ims: network ended our registration; registering again")
                self._cleanup_reg()
                self.hook("registered", "deregistered")
                self.at(5, self._register_start)
        elif "shortened" in terminated or re.search(r'event="shortened"', body):
            self.at(2, self._refresh)

    # ------------------------------------------------------------ requests from the network
    def on_request(self, m, route):
        meth = m.method
        if meth == "INVITE":
            c = self._call_by_callid(m.call_id)
            if c:
                return self._on_reinvite(c, m, route)
            return self._on_invite(m, route)
        if meth == "ACK":
            c = self._call_by_callid(m.call_id)
            if c and c.final_2xx:
                c.final_2xx = None
                if c.state != "active":
                    c.state = "active"
                    self._changed()
            return
        if meth == "NOTIFY":
            return self._on_notify(m, route)
        if meth == "OPTIONS":
            return self.respond(m, 200, "OK", route, [("Allow", ALLOW), ("Accept", "application/sdp")])
        c = self._call_by_callid(m.call_id)
        if meth == "PRACK":
            if c and c.pending_rel:
                c.pending_rel = None
            self.respond(m, 200 if c else 481, "OK" if c else "Call/Transaction Does Not Exist",
                         route)
            if c and getattr(c, "after_prack", None):
                fn, c.after_prack = c.after_prack, None
                fn()
            return
        if meth == "UPDATE":
            return self._on_update(c, m, route)
        if meth == "CANCEL":
            self.respond(m, 200 if c else 481, "OK" if c else "Call/Transaction Does Not Exist",
                         route)
            if c and c.dir == "in" and c.state in ("incoming", "waiting") and c.invite:
                self.respond(c.invite, 487, "Request Terminated", c.invite_route,
                             to_tag=c.local_tag)
                self._end(c, "cancelled")
            return
        if meth == "BYE":
            self.respond(m, 200 if c else 481, "OK" if c else "Call/Transaction Does Not Exist",
                         route)
            if c:
                self._end(c, "remote hangup")
            return
        if meth == "MESSAGE":
            # SMS stays on CS/SGs (no +g.3gpp.smsip): make the network fall back
            return self.respond(m, 480, "Temporarily Unavailable", route)
        if meth == "INFO" and c:
            return self.respond(m, 200, "OK", route)
        self.respond(m, 405, "Method Not Allowed", route, [("Allow", ALLOW)])

    # ------------------------------------------------------------ calls: helpers
    def _call_by_callid(self, cid):
        for c in self.calls.values():
            if c.call_id == cid:
                return c
        return None

    def entries(self):
        return [c.entry() for c in self.calls.values() if not c.ended]

    def _changed(self):
        self.hook("calls_changed", self.entries())

    def can_call(self):
        return self.reg_state == "registered" and self.mmtel

    def _alloc_rtp(self):
        r = self.hook("rtp_socket", self.local_ip)
        if r:
            return r
        fam = socket.AF_INET6 if ":" in self.local_ip else socket.AF_INET
        for _ in range(30):
            port = random.randrange(30000, 50000, 2)
            s = socket.socket(fam, socket.SOCK_DGRAM)
            try:
                s.bind((self.local_ip, port))
                return s, port
            except OSError:
                s.close()
        raise OSError("no RTP port")

    def _target_uri(self, number):
        n = number
        if not n.startswith("+") and self.cfg.country_code and n.isdigit() and not n.startswith("0"):
            n = "+" + self.cfg.country_code + n
        if self.cfg.uri_format == "tel":
            return f"tel:{n}" if n.startswith("+") else f"tel:{n};phone-context={self.ident.domain}"
        if n.startswith("+"):
            return f"sip:{n}@{self.ident.domain};user=phone"
        return f"sip:{n};phone-context={self.ident.domain}@{self.ident.domain};user=phone"

    def _local_sdp(self, c, codecs, te, precond=None):
        c.local_sdp = sdp_build(self.local_ip, c.rtp_port, c.sess_id, c.sdp_version, codecs, te,
                                precond=precond)
        return c.local_sdp

    def _dialog_request(self, c, method, body=b"", extra=()):
        m = SipMessage(f"{method} {c.remote_target} SIP/2.0")
        for r in c.route_set:
            m.add("Route", r)
        if not c.route_set:
            self._routes(m)
        c.local_cseq += 1
        m.add("From", f"<{c.local_uri}>;tag={c.local_tag}")
        m.add("To", f"<{c.remote_uri}>" + (f";tag={c.remote_tag}" if c.remote_tag else ""))
        m.add("Call-ID", c.call_id)
        m.add("CSeq", f"{c.local_cseq} {method}")
        m.add("Contact", self._call_contact())
        for k, v in extra:
            m.add(k, v)
        self.common(m)
        if body:
            m.add("Content-Type", "application/sdp")
            m.body = body
        return m

    def _call_contact(self):
        c = f'<sip:{host_for_uri(self.local_ip)}:{self.port_s}>;+g.3gpp.icsi-ref="{MMTEL_ICSI_ENC}";audio'
        urn = self.ident.instance_urn() if self.cfg.sip_instance else None
        if urn:
            c += f';+sip.instance="<{urn}>"'
        return c

    def _media_start(self, c):
        if c.media or not c.remote_sdp or not c.codec:
            return
        rs = c.remote_sdp
        if not rs.ip or not rs.port:
            return
        c.media = self.hook("media", c, self.local_ip)
        if not c.media:
            self.log(f"ims: no media backend (codec {c.codec!r})")
            return
        media, codec = c.media, c.codec

        def run():
            try:
                media.start(rs.ip, rs.port, codec)
                self.log(f"ims: media started: {codec!r}")
            except Exception as e:
                self.log(f"ims: media start failed: {e!r}")
        # call-audio voip-start + pw-cat spawn take seconds: on the UA thread they held
        # back ACK retransmissions, PRACK/UPDATE answers and the INVITE 2xx timer
        c.media_thread = threading.Thread(target=run, name="ims-media-start", daemon=True)
        c.media_thread.start()

    def _media_stop(self, c):
        if c.media:
            media, c.media = c.media, None
            t = getattr(c, "media_thread", None)

            def stop():
                if t:
                    t.join(30)              # never stop half-started media
                try:
                    media.stop()
                except Exception as e:
                    self.log(f"ims: media stop failed: {e!r}")
            if t and t.is_alive() and threading.current_thread() is not t:
                threading.Thread(target=stop, name="ims-media-stop", daemon=True).start()
            else:
                stop()
        if c.rtp_sock:
            try:
                c.rtp_sock.close()
            except OSError:
                pass
            c.rtp_sock = None

    def _end(self, c, cause, silent=False):
        """silent: the call continues on CS (fallback): no call_ended (NO CARRIER)."""
        if c.ended:
            return
        c.ended = True
        c.state = "ended"
        self._media_stop(c)
        self.log(f"ims: call #{c.id} ended ({cause})")
        self.calls.pop(c.id, None)
        if not silent:
            self.hook("call_ended", c.id, cause)
        self._changed()

    def _tick_calls(self, now):
        for c in list(self.calls.values()):
            p = c.pending_rel
            if p and now >= p[3]:
                if now > p[5]:
                    c.pending_rel = None
                    if c.invite and c.state in ("incoming",):
                        self.respond(c.invite, 504, "Server Time-out", c.invite_route,
                                     to_tag=c.local_tag)
                        self._end(c, "PRACK timeout")
                    continue
                self.send_raw(p[0], p[1])
                c.pending_rel = (p[0], p[1], p[2], now + min(p[4] * 2, T2), min(p[4] * 2, T2), p[5])
            if c.final_2xx and c.final_next and now >= c.final_next[0] and c.invite_route[0] == "udp":
                if now - c.final_next[2] > 64 * T1:
                    c.final_2xx = None
                    self._hangup(c)          # no ACK
                else:
                    self.send_raw(c.final_2xx, c.invite_route)
                    iv = min(c.final_next[1] * 2, T2)
                    c.final_next = (now + iv, iv, c.final_next[2])
            if c.refresh_at and now >= c.refresh_at and c.state == "active":
                c.refresh_at = now + (c.session_expires or 1800) / 2
                m = self._dialog_request(c, "UPDATE", extra=[
                    ("Session-Expires", f"{c.session_expires};refresher=uac"),
                    ("Supported", "timer")])
                self.send_request(m, lambda r: None)

    def _session_timer(self, c, msg, we_are_uac):
        se = msg.get("Session-Expires")
        if not se:
            return
        n = se.split(";")[0].strip()
        if not n.isdigit():
            return
        c.session_expires = int(n)
        p = parse_params(";" + se.split(";", 1)[1]) if ";" in se else {}
        ref = p.get("refresher")
        c.we_refresh = (ref == "uac" and we_are_uac) or (ref == "uas" and not we_are_uac)
        if c.we_refresh:
            c.refresh_at = _now() + c.session_expires / 2

    # ------------------------------------------------------------ MO calls
    def dial(self, number):
        """Returns False (synchronously) when the call must go to CS instead."""
        if is_emergency(number):
            self.log("ims: emergency number: not over IMS (CS)")
            return False
        if not self.can_call():
            return False
        if not re.fullmatch(r"\+?[0-9*#]{1,40}", number):
            return False
        self.call(self._dial, number)
        return True

    def _new_call_id(self):
        used = set(self.calls)
        for k in range(8):
            cid = self.FIRST_CALL_ID + (self.next_call_id - self.FIRST_CALL_ID + k) % 8
            if cid not in used:
                self.next_call_id = self.FIRST_CALL_ID + (cid - self.FIRST_CALL_ID + 1) % 8
                return cid
        raise RuntimeError("too many calls")

    def _dial(self, number, precond=None, cid=None):
        cid = cid or self._new_call_id()
        c = Call(cid, "out", number)
        c.retried_precond = bool(precond)
        c.rtp_sock, c.rtp_port = self._alloc_rtp()
        c.local_uri = self.ident.preferred()
        c.remote_uri = c.remote_target = self._target_uri(number)
        if precond is None:
            precond = self.cfg.precondition == "yes"
        c.precond = precond
        codecs = default_offer_codecs(self.cfg.amr_wb, self.cfg.amr_nb)
        te = {16000: 100, 8000: 101} if self.cfg.amr_wb else {8000: 101}
        if not self.cfg.amr_nb:
            te = {16000: 100}
        body = self._local_sdp(c, codecs, te, dict(local="sendrecv", remote="none", offer=True)
                               if precond else None)
        m = SipMessage(f"INVITE {c.remote_uri} SIP/2.0")
        self._routes(m)
        m.add("From", f"<{c.local_uri}>;tag={c.local_tag}")
        m.add("To", f"<{c.remote_uri}>")
        m.add("Call-ID", c.call_id)
        m.add("CSeq", f"{c.local_cseq} INVITE")
        m.add("Contact", self._call_contact())
        m.add("Accept-Contact", f'*;+g.3gpp.icsi-ref="{MMTEL_ICSI_ENC}"')
        m.add("P-Preferred-Service", MMTEL_ICSI)
        m.add("P-Preferred-Identity", f"<{c.local_uri}>")
        m.add("Allow", ALLOW)
        m.add("Supported", "100rel, timer, replaces" + (", precondition" if precond else ""))
        if precond:
            m.add("Require", "precondition")
        m.add("Session-Expires", str(self.cfg.session_expires))
        m.add("Min-SE", "90")
        m.add("Accept", "application/sdp")
        m.add("Content-Type", "application/sdp")
        m.body = body
        self.common(m)
        if precond and m.get("Require") == "sec-agree":
            m.set("Require", "sec-agree, precondition")
        c.invite = m
        self.calls[cid] = c
        self._changed()
        self.log(f"ims: MO call #{cid} ({len(number)} digits, number not shown)"
                 + (" with preconditions" if precond else ""))
        c.invite_tx = self.send_request(m, lambda r: self._on_invite_resp(c, r))
        c.invite_route = c.invite_tx.route

    def _update_dialog_from_resp(self, c, r):
        if r.tag("To") and not c.remote_tag:
            c.remote_tag = r.tag("To")
        if r.get("Contact"):
            c.remote_target = parse_nameaddr(r.get_all("Contact")[0])[1]
        rr = r.get_all("Record-Route")
        if rr:
            c.route_set = list(reversed(rr))

    def _on_invite_resp(self, c, r):
        if c.ended:
            return
        if r is None:
            self.log(f"ims: call #{c.id}: INVITE timed out")
            return self._mo_failed(c, 408, "timeout")
        if r.status == 100:
            if c.cancel_pending:
                self._send_cancel(c)
            return
        if r.status < 200:
            c.got_18x = True
            self._update_dialog_from_resp(c, r)
            if r.body and (r.get("Content-Type") or "").startswith("application/sdp"):
                self._mo_answer(c, r.body)
            if r.status == 180 and c.state == "dialing":
                c.state = "alerting"
                self._changed()
            rseq = r.get("RSeq") or ""
            if r.has_option("Require", "100rel") and rseq.isdigit() and \
                    int(rseq) > getattr(c, "last_rseq", -1):
                c.last_rseq = int(rseq)             # retransmissions are not PRACKed again
                self._send_prack(c, r)
            if c.cancel_pending:
                self._send_cancel(c)
            return
        if 200 <= r.status < 300:
            self._update_dialog_from_resp(c, r)
            if r.body and not c.remote_sdp:
                self._mo_answer(c, r.body)
            self._session_timer(c, r, True)
            self._send_ack(c, r)
            if c.cancel_pending:
                self._hangup(c)
                return
            c.state = "active"
            self._media_start(c)
            self._changed()
            return
        if r.status == 421 and "precondition" in (r.get("Require") or "") and not c.retried_precond:
            self.log(f"ims: call #{c.id}: network requires preconditions, retrying")
            c.ended = True
            self._media_stop(c)
            self.calls.pop(c.id, None)
            return self._dial(c.number, precond=True, cid=c.id)
        self._mo_failed(c, r.status, r.reason)

    def _mo_failed(self, c, status, reason):
        fallback = (self.cfg.cs_fallback and not c.got_18x and not c.cancel_pending
                    and (status in (380, 408, 500, 503, 504, 488, 606) or status == 0))
        self._end(c, f"{status} {reason}", silent=fallback)
        if fallback:
            self.log(f"ims: call #{c.id}: falling back to CS")
            self.hook("cs_fallback", c.number)

    def _mo_answer(self, c, body):
        sdp = Sdp.parse(body)
        codec = negotiate(sdp, self.cfg.amr_wb, self.cfg.amr_nb)
        if not codec:
            self.log(f"ims: call #{c.id}: answer has no usable codec")
            return
        c.remote_sdp, c.codec = sdp, codec
        self.log(f"ims: call #{c.id}: SDP answer: {codec!r}"
                 + (", preconditions" if sdp.wants_preconditions() else ""))
        if any(x[:3] == ["qos", "remote", "sendrecv"] for x in sdp.conf):
            # the answerer wants to know when our resources are ready: they are
            c.sdp_version += 1
            te = {codec.rate: codec.te_pt} if codec.te_pt is not None else {}
            body2 = self._local_sdp(c, [codec], te, dict(local="sendrecv", remote="sendrecv"))
            m = self._dialog_request(c, "UPDATE", body2)
            self.send_request(m, lambda r: None)
        self._media_start(c)        # early media

    def _send_prack(self, c, r):
        m = self._dialog_request(c, "PRACK", extra=[("RAck", f"{r.get('RSeq')} {r.cseq[0]} INVITE")])
        self.send_request(m, lambda resp: None)

    def _send_ack(self, c, r):
        a = SipMessage(f"ACK {c.remote_target} SIP/2.0")
        for rt in c.route_set:
            a.add("Route", rt)
        if not c.route_set:
            self._routes(a)
        a.add("From", f"<{c.local_uri}>;tag={c.local_tag}")
        a.add("To", r.get("To"))
        a.add("Call-ID", c.call_id)
        a.add("CSeq", f"{r.cseq[0]} ACK")
        self.common(a)
        if c.invite_route and c.invite_route[0] == "tcp":
            # the INVITE and its 2xx went over TCP (> udp_max): the ACK follows on that
            # connection.  Over UDP a lost ACK is only repaired by the far end's next 2xx
            # retransmission (live: three 200 retransmissions, the last +9.8 s)
            route = c.invite_route
        else:
            route = self.protected_route(len(a.encode()) + 120, tcp=self._route_wants_tcp(a))
        a.add("Via", self.via(route), first=True)
        c.ack_route = route
        self.log(f"ims: > ACK (CSeq {r.cseq[0]}) via {route[0]}")
        self.send_raw(a.encode(), route)

    def _send_cancel(self, c):
        inv = c.invite
        m = SipMessage(f"CANCEL {inv.uri} SIP/2.0")
        m.add("Via", inv.get_all("Via", split=False)[0])
        for v in inv.get_all("Route", split=False):
            m.add("Route", v)
        m.add("From", inv.get("From"))
        m.add("To", inv.get("To"))
        m.add("Call-ID", inv.call_id)
        m.add("CSeq", f"{inv.cseq[0]} CANCEL")
        m.add("Reason", 'SIP;cause=487;text="Call terminated by user"')
        self.common(m)
        c.cancel_pending = False
        c.cancel_sent = True
        tx = ClientTx(self, m, c.invite_route, lambda r: None)
        self.ctx[tx.key] = tx
        tx.send()
        self.log(f"ims: > CANCEL call #{c.id}")
        self.at(8, lambda: not c.ended and self._end(c, "cancelled"))

    # ------------------------------------------------------------ MT calls
    def _on_invite(self, m, route):
        if not self.can_call():
            return self.respond(m, 480, "Temporarily Unavailable", route)
        if is_emergency(m.uri):
            return self.respond(m, 403, "Forbidden", route)
        busy = [c for c in self.calls.values() if not c.ended]
        if busy:
            return self.respond(m, 486, "Busy Here", route)
        if not m.body:
            return self.respond(m, 488, "Not Acceptable Here", route)   # no late offer
        sdp = Sdp.parse(m.body)
        codec = negotiate(sdp, self.cfg.amr_wb, self.cfg.amr_nb)
        if not codec:
            return self.respond(m, 488, "Not Acceptable Here", route)
        caller = m.get("P-Asserted-Identity") or m.get("From") or ""
        num = ""
        for v in split_commas(caller):
            u = parse_nameaddr(v)[1]
            mm = re.match(r"(?:tel:|sips?:)(\+?[0-9*#]+)", u)
            if mm:
                num = mm.group(1)
                break
        cid = self._new_call_id()
        c = Call(cid, "in", num)
        c.call_id = m.call_id
        c.remote_tag = m.tag("From")
        c.local_uri = parse_nameaddr(m.get("To"))[1]
        c.remote_uri = parse_nameaddr(m.get("From"))[1]
        c.remote_target = parse_nameaddr(m.get_all("Contact")[0])[1] if m.get("Contact") else c.remote_uri
        c.route_set = m.get_all("Record-Route")
        c.remote_cseq = m.cseq[0]
        c.invite, c.invite_route = m, route
        c.remote_sdp, c.codec = sdp, codec
        c.rtp_sock, c.rtp_port = self._alloc_rtp()
        c.precond = sdp.wants_preconditions() and ("precondition" in (m.get("Require") or "")
                                                   or "precondition" in (m.get("Supported") or ""))
        rel = m.has_option("Require", "100rel") or (c.precond and m.has_option("Supported", "100rel"))
        c.reliable = rel
        self.calls[cid] = c
        self.respond(m, 100, "Trying", route)
        if self.can_inhibit:
            # woken from suspend by this INVITE: with preconditions the call (and with it
            # the daemon's call flag + inhibitor) shows only after the caller's UPDATE;
            # the resuspend helper's 5 s modem-wake window may be shorter than that
            self.keep_awake(45, "IMS incoming call setup")
        self._session_timer(c, m, False)
        self.log(f"ims: MT call #{cid}: {codec!r}" + (", preconditions" if c.precond else "")
                 + (", 100rel" if rel else ""))
        te = {codec.rate: codec.te_pt} if codec.te_pt is not None else {}
        if c.precond:
            remote_state = "none"
            for x in sdp.curr:
                if x[:2] == ["qos", "local"]:
                    remote_state = x[2]
            body = self._local_sdp(c, [codec], te, dict(local="sendrecv", remote=remote_state,
                                                       want_conf=remote_state != "sendrecv"))
            c.answer_sent = True
            self._provisional(c, 183, "Session Progress", body, reliable=True)
            if remote_state == "sendrecv":
                c.after_prack = lambda: self._ring(c)
            # otherwise ring once the caller's UPDATE says its QoS is ready
        else:
            self._ring(c)

    def _provisional(self, c, status, reason, body=b"", reliable=False):
        hdrs = [("Contact", self._call_contact()), ("Allow", ALLOW)]
        if reliable:
            c.rseq += 1
            hdrs += [("Require", "100rel"), ("RSeq", str(c.rseq))]
        if c.precond:
            hdrs.append(("Require", "precondition"))
        if body:
            hdrs.append(("P-Early-Media", "supported"))
        r = self.respond(c.invite, status, reason, c.invite_route, hdrs, body, to_tag=c.local_tag)
        if reliable:
            now = _now()
            c.pending_rel = (r.encode(), c.invite_route, c.rseq, now + T1, T1, now + 64 * T1)

    def _ring(self, c):
        if c.ended or c.state != "incoming" or getattr(c, "rung", False):
            return
        c.rung = True
        te = {c.codec.rate: c.codec.te_pt} if c.codec.te_pt is not None else {}
        if c.reliable and not c.answer_sent:
            body = self._local_sdp(c, [c.codec], te)
            c.answer_sent = True
            self._provisional(c, 180, "Ringing", body, reliable=True)
        else:
            self._provisional(c, 180, "Ringing", reliable=c.reliable and c.precond)
        self._changed()

    def _on_update(self, c, m, route):
        if not c:
            return self.respond(m, 481, "Call/Transaction Does Not Exist", route)
        hdrs = [("Contact", self._call_contact())]
        if m.get("Session-Expires"):
            self._session_timer(c, m, False)
            hdrs += [("Session-Expires", m.get("Session-Expires")), ("Require", "timer")]
        if not m.body:
            return self.respond(m, 200, "OK", route, hdrs)
        sdp = Sdp.parse(m.body)
        codec = negotiate(sdp, self.cfg.amr_wb, self.cfg.amr_nb)
        if not codec:
            return self.respond(m, 488, "Not Acceptable Here", route)
        c.remote_sdp = sdp
        if not c.codec or (codec.name, codec.pt) != (c.codec.name, c.codec.pt):
            c.codec = codec
        c.sdp_version += 1
        te = {c.codec.rate: c.codec.te_pt} if c.codec.te_pt is not None else {}
        precond = None
        if sdp.curr or sdp.des:
            remote_state = "none"
            for x in sdp.curr:
                if x[:2] == ["qos", "local"]:
                    remote_state = x[2]
            precond = dict(local="sendrecv", remote=remote_state)
        body = self._local_sdp(c, [c.codec], te, precond)
        self.respond(m, 200, "OK", route, hdrs, body)
        if c.dir == "in" and c.state == "incoming":
            ready = not precond or precond["remote"] == "sendrecv"
            if ready:
                self._ring(c)
        elif c.media:
            pass

    def _on_reinvite(self, c, m, route):
        self.respond(m, 100, "Trying", route)
        hdrs = [("Contact", self._call_contact())]
        if m.get("Session-Expires"):
            self._session_timer(c, m, False)
            hdrs += [("Session-Expires", m.get("Session-Expires")), ("Require", "timer")]
        if m.body:
            sdp = Sdp.parse(m.body)
            codec = negotiate(sdp, self.cfg.amr_wb, self.cfg.amr_nb)
            if not codec:
                return self.respond(m, 488, "Not Acceptable Here", route)
            c.remote_sdp = sdp
        c.sdp_version += 1
        te = {c.codec.rate: c.codec.te_pt} if c.codec.te_pt is not None else {}
        body = self._local_sdp(c, [c.codec], te)
        r = self.respond(m, 200, "OK", route, hdrs, body, to_tag=c.local_tag)
        now = _now()
        c.final_2xx, c.final_next = r.encode(), (now + T1, T1, now)
        c.invite_route = route

    def answer(self, call_id=None):
        self.call(self._answer, call_id)

    def has_incoming(self):
        return any(c.dir == "in" and c.state == "incoming" for c in self.calls.values())

    def _answer(self, call_id=None):
        c = next((x for x in self.calls.values() if x.dir == "in" and x.state == "incoming"
                  and (call_id is None or x.id == call_id)), None)
        if not c:
            return
        hdrs = [("Contact", self._call_contact()), ("Allow", ALLOW), ("Supported", "100rel, timer")]
        if c.session_expires:
            ref = "uac" if not c.we_refresh else "uas"
            hdrs += [("Session-Expires", f"{c.session_expires};refresher={ref}"), ("Require", "timer")]
        body = b""
        if not c.answer_sent:
            te = {c.codec.rate: c.codec.te_pt} if c.codec.te_pt is not None else {}
            body = self._local_sdp(c, [c.codec], te)
            c.answer_sent = True
        c.pending_rel = None
        r = self.respond(c.invite, 200, "OK", c.invite_route, hdrs, body, to_tag=c.local_tag)
        now = _now()
        c.final_2xx, c.final_next = r.encode(), (now + T1, T1, now)
        c.state = "active"
        self._media_start(c)
        self._changed()

    def hangup(self, call_id=None):
        self.call(self._hangup_id, call_id)

    def _hangup_id(self, call_id):
        for c in list(self.calls.values()):
            if call_id is None or c.id == call_id:
                self._hangup(c)

    def _hangup(self, c):
        if c.ended:
            return
        if c.dir == "in" and c.state == "incoming":
            self.respond(c.invite, 486, "Busy Here", c.invite_route, to_tag=c.local_tag)
            return self._end(c, "rejected")
        if c.dir == "out" and c.state in ("dialing", "alerting"):
            if c.invite_tx and c.invite_tx.got_provisional:
                self._send_cancel(c)
            else:
                c.cancel_pending = True
                self.at(10, lambda: not c.ended and self._end(c, "cancel timeout"))
            self._media_stop(c)
            return
        m = self._dialog_request(c, "BYE")
        self.send_request(m, lambda r: None)
        self._end(c, "local hangup")

    def dtmf(self, digit):
        self.call(self._dtmf, digit)

    def _dtmf(self, digit):
        for c in self.calls.values():
            if c.state == "active" and c.media:
                c.media.dtmf(digit)

    def status(self):
        s = f"ims: registration {self.reg_state}, MMTel {'on' if self.mmtel else 'off'}"
        if self.sec_srv:
            s += f", IPsec {self.sec_srv['alg']}/{self.sec_srv['ealg']}"
        if self.reg_state == "registered" and self.reg_refresh_at:
            s += f", refresh in {int(self.reg_refresh_at - _now())} s"
        s += f", reg-event {'subscribed' if self.sub else 'no'}, {len(self.calls)} call(s)"
        return s
