"""MBIM 1.0 *function side* emulation for shannon-modemd (Samsung IPC modem -> MBIM host).

The kernel bridge exposes /dev/wwan0mbim0 to ModemManager (libmbim, usually through
mbim-proxy) and relays every control message in both directions.  This module turns the
host's MBIM control messages into calls on a small `backend` object (implemented by the
daemon) and turns the daemon's state changes into MBIM indications.

    fn = MbimFunction(backend, write=bridge_write, log=print)
    fn.feed(bytes_from_bridge)          # reader thread
    fn.notify_registration()            # any thread, whenever the daemon's state changes

Pure stdlib.  Nothing personal (IMEI, IMSI, ICCID, MSISDN, APN credentials, SMS PDUs) is
ever logged: log lines carry only message types, service/CID names and status codes.
"""
import os
import socket
import struct
import threading

__all__ = ["MbimFunction"]

# --------------------------------------------------------------------------- constants

MSG_OPEN = 0x00000001
MSG_CLOSE = 0x00000002
MSG_COMMAND = 0x00000003
MSG_HOST_ERROR = 0x00000004
MSG_OPEN_DONE = 0x80000001
MSG_CLOSE_DONE = 0x80000002
MSG_COMMAND_DONE = 0x80000003
MSG_FUNCTION_ERROR = 0x80000004
MSG_INDICATE_STATUS = 0x80000007

CMD_QUERY = 0
CMD_SET = 1

# MBIM_PROTOCOL_ERROR (FUNCTION_ERROR / HOST_ERROR payload)
PERR_TIMEOUT_FRAGMENT = 1
PERR_FRAGMENT_OUT_OF_SEQUENCE = 2
PERR_LENGTH_MISMATCH = 3
PERR_DUPLICATED_TID = 4
PERR_NOT_OPENED = 5
PERR_UNKNOWN = 6
PERR_CANCEL = 7
PERR_MAX_TRANSFER = 8

# MBIM_STATUS (COMMAND_DONE status)
ST_NONE = 0
ST_BUSY = 1
ST_FAILURE = 2
ST_SIM_NOT_INSERTED = 3
ST_BAD_SIM = 4
ST_PIN_REQUIRED = 5
ST_NOT_REGISTERED = 7
ST_NO_DEVICE_SUPPORT = 9
ST_MAX_ACTIVATED_CONTEXTS = 13
ST_NOT_INITIALIZED = 14
ST_CONTEXT_NOT_ACTIVATED = 16
ST_INVALID_PARAMETERS = 21
ST_INVALID_MEMORY_INDEX = 30
ST_SMS_FORMAT_NOT_SUPPORTED = 104

STATUS_NAMES = {
    0: "NONE", 1: "BUSY", 2: "FAILURE", 3: "SIM_NOT_INSERTED", 4: "BAD_SIM",
    5: "PIN_REQUIRED", 7: "NOT_REGISTERED", 9: "NO_DEVICE_SUPPORT",
    13: "MAX_ACTIVATED_CONTEXTS", 14: "NOT_INITIALIZED", 16: "CONTEXT_NOT_ACTIVATED",
    21: "INVALID_PARAMETERS", 30: "INVALID_MEMORY_INDEX", 104: "SMS_FORMAT_NOT_SUPPORTED",
}


def _uuid(s):
    return bytes.fromhex(s.replace("-", ""))


UUID_BASIC_CONNECT = _uuid("a289cc33-bcbb-8b4f-b6b0-133ec2aae6df")
UUID_SMS = _uuid("533fbeeb-14fe-4467-9f90-33a223e56c3f")
UUID_CONTEXT_INTERNET = _uuid("7e5e2a7e-4e6f-7272-736b-656e7e5e2a7e")

SERVICE_NAMES = {
    UUID_BASIC_CONNECT: "BASIC_CONNECT",
    UUID_SMS: "SMS",
    _uuid("e550a0c85e82479e82f710abf4c3351f"): "USSD",
    _uuid("4bf384761e6a41dbb1d8bed289c25bdb"): "PHONEBOOK",
    _uuid("d8f20131fcb54e178602d6ed3816164c"): "STK",
    _uuid("1d2b5ff70aa148b2aa5250f15767174e"): "AUTH",
    _uuid("c08a26dd7718438284826e0d583c4d0e"): "DSS",
    _uuid("e9f7dea2feaf400993ce90a3694103b6"): "MS_FIRMWARE_ID",
    _uuid("883b7c26985f43fa980427d7fb80959c"): "MS_HOST_SHUTDOWN",
    _uuid("68223d049f6c4e0f822d28441fb72340"): "MS_SAR",
    _uuid("838cf7fb8d0d4d7f871ed71dbefbb39b"): "PROXY_CONTROL",
    _uuid("d1a30bc2f97a6e43bf65c7e24fb0f0d3"): "QMI",
    _uuid("5967bdcc7fd249a29f5cb2e70e527db3"): "ATDS",
    _uuid("0ed374cbf8354474bc113b3fd76f5641"): "INTEL_FIRMWARE_UPDATE",
    _uuid("6427015f579d48f58c54f43ed1e76f83"): "QDU",
    _uuid("3d01dcc5fef54d050d3abef7058e9aaf"): "MS_BASIC_CONNECT_EXTENSIONS",
    _uuid("c2f6588ef0374bc98665f4d44bd09367"): "MS_UICC_LOW_LEVEL_ACCESS",
    _uuid("112233445566778899aabbccddeeff11"): "QUECTEL",
    _uuid("fdc22af2f4414d46af8d259fcdde4635"): "INTEL_THERMAL_RF",
    _uuid("8d8b9eba37be449b8f1e61cb034a702e"): "MS_VOICE_EXTENSIONS",
    _uuid("f85d46efab26408198684d183c0a3aec"): "INTEL_MUTUAL_AUTHENTICATION",
    _uuid("4ada4962b98846c387a797f20f994abb"): "INTEL_TOOLS",
    _uuid("3e1e92cfc53d4f1485d0a86ad9e12245"): "GOOGLE",
    _uuid("ffffffffabca4b11a4e2f2fc87f94488"): "FIBOCOM",
    _uuid("a2a32a97cab14f579ae1451c74dda957"): "COMPAL",
    _uuid("da138c646515489392b2a1e1ca7c81ca"): "INTEL_AT_TUNNEL",
}

# BASIC_CONNECT CIDs
BC_DEVICE_CAPS = 1
BC_SUBSCRIBER_READY_STATUS = 2
BC_RADIO_STATE = 3
BC_PIN = 4
BC_PIN_LIST = 5
BC_HOME_PROVIDER = 6
BC_PREFERRED_PROVIDERS = 7
BC_VISIBLE_PROVIDERS = 8
BC_REGISTER_STATE = 9
BC_PACKET_SERVICE = 10
BC_SIGNAL_STATE = 11
BC_CONNECT = 12
BC_PROVISIONED_CONTEXTS = 13
BC_SERVICE_ACTIVATION = 14
BC_IP_CONFIGURATION = 15
BC_DEVICE_SERVICES = 16
BC_DEVICE_SERVICE_SUBSCRIBE_LIST = 19
BC_PACKET_STATISTICS = 20
BC_NETWORK_IDLE_HINT = 21
BC_EMERGENCY_MODE = 22
BC_IP_PACKET_FILTERS = 23
BC_MULTICARRIER_PROVIDERS = 24

BC_NAMES = {
    1: "DEVICE_CAPS", 2: "SUBSCRIBER_READY_STATUS", 3: "RADIO_STATE", 4: "PIN", 5: "PIN_LIST",
    6: "HOME_PROVIDER", 7: "PREFERRED_PROVIDERS", 8: "VISIBLE_PROVIDERS", 9: "REGISTER_STATE",
    10: "PACKET_SERVICE", 11: "SIGNAL_STATE", 12: "CONNECT", 13: "PROVISIONED_CONTEXTS",
    14: "SERVICE_ACTIVATION", 15: "IP_CONFIGURATION", 16: "DEVICE_SERVICES",
    19: "DEVICE_SERVICE_SUBSCRIBE_LIST", 20: "PACKET_STATISTICS", 21: "NETWORK_IDLE_HINT",
    22: "EMERGENCY_MODE", 23: "IP_PACKET_FILTERS", 24: "MULTICARRIER_PROVIDERS",
}

# SMS CIDs
SMS_CONFIGURATION = 1
SMS_READ = 2
SMS_SEND = 3
SMS_DELETE = 4
SMS_MESSAGE_STORE_STATUS = 5
SMS_NAMES = {1: "CONFIGURATION", 2: "READ", 3: "SEND", 4: "DELETE", 5: "MESSAGE_STORE_STATUS"}

# enums
DEVICE_TYPE_EMBEDDED = 1
CELLULAR_CLASS_GSM = 1
VOICE_CLASS_NO_VOICE = 1
SIM_CLASS_REMOVABLE = 2
DC_GPRS, DC_EDGE, DC_UMTS, DC_HSDPA, DC_HSUPA, DC_LTE, DC_5G_NSA = 1, 2, 4, 8, 16, 32, 64
DATA_CLASS_CAPS = DC_GPRS | DC_EDGE | DC_UMTS | DC_HSDPA | DC_HSUPA | DC_LTE
SMS_CAPS_PDU_RECEIVE = 1
SMS_CAPS_PDU_SEND = 2

READY_NOT_INITIALIZED = 0
READY_INITIALIZED = 1
READY_SIM_NOT_INSERTED = 2
READY_BAD_SIM = 3
READY_FAILURE = 4
READY_DEVICE_LOCKED = 6

PIN_TYPE_PIN1 = 2
PIN_STATE_UNLOCKED = 0
PIN_STATE_LOCKED = 1
PIN_MODE_NOT_SUPPORTED = 0
PIN_MODE_ENABLED = 1
PIN_MODE_DISABLED = 2
PIN_FORMAT_UNKNOWN = 0
PIN_FORMAT_NUMERIC = 1

PROVIDER_HOME = 1
PROVIDER_VISIBLE = 8
PROVIDER_REGISTERED = 16

REG_UNKNOWN, REG_DEREGISTERED, REG_SEARCHING, REG_HOME, REG_ROAMING, REG_PARTNER, REG_DENIED = range(7)
REGISTER_MODE_AUTOMATIC = 1
REGISTER_ACTION_AUTOMATIC = 0
REGFLAG_MANUAL_SELECTION_NOT_AVAILABLE = 1
REGFLAG_PACKET_SERVICE_AUTOMATIC_ATTACH = 2

PS_ATTACHED = 2
PS_DETACHED = 4
PS_ACTION_ATTACH = 0
PS_ACTION_DETACH = 1

ACT_STATE = {"activated": 1, "activating": 2, "deactivated": 3, "deactivating": 4}
ACT_STATE_DEACTIVATED = 3
ACTIVATION_DEACTIVATE = 0
ACTIVATION_ACTIVATE = 1
IP_TYPE_TO_MBIM = {"default": 0, "ipv4": 1, "ipv6": 2, "ipv4v6": 3}
IP_TYPE_FROM_MBIM = {0: "default", 1: "ipv4", 2: "ipv6", 3: "ipv4v6", 4: "ipv4v6"}
AUTH_FROM_MBIM = {0: "none", 1: "pap", 2: "chap", 3: "chap"}

IPCFG_ADDRESS, IPCFG_GATEWAY, IPCFG_DNS, IPCFG_MTU = 1, 2, 4, 8

SMS_STORAGE_NOT_INITIALIZED = 0
SMS_STORAGE_INITIALIZED = 1
SMS_FORMAT_PDU = 0
SMS_FLAG_ALL, SMS_FLAG_INDEX, SMS_FLAG_NEW, SMS_FLAG_OLD, SMS_FLAG_SENT, SMS_FLAG_DRAFT = range(6)
SMS_STATUS = {"new": 0, "old": 1, "draft": 2, "sent": 3}
SMS_FLAG_TO_STATUS = {SMS_FLAG_NEW: "new", SMS_FLAG_OLD: "old", SMS_FLAG_SENT: "sent",
                      SMS_FLAG_DRAFT: "draft"}
SMS_STATUS_FLAG_STORE_FULL = 1
SMS_STATUS_FLAG_NEW_MESSAGE = 2

PROVISIONED_CONTEXT_ID_APPEND = 0xFFFFFFFF

# What DEVICE_SERVICES reports.  Only these get handled; anything else is NO_DEVICE_SUPPORT.
SUPPORTED_CIDS = {
    UUID_BASIC_CONNECT: (
        BC_DEVICE_CAPS, BC_SUBSCRIBER_READY_STATUS, BC_RADIO_STATE, BC_PIN, BC_PIN_LIST,
        BC_HOME_PROVIDER, BC_PREFERRED_PROVIDERS, BC_VISIBLE_PROVIDERS, BC_REGISTER_STATE,
        BC_PACKET_SERVICE, BC_SIGNAL_STATE, BC_CONNECT, BC_PROVISIONED_CONTEXTS,
        BC_IP_CONFIGURATION, BC_DEVICE_SERVICES, BC_DEVICE_SERVICE_SUBSCRIBE_LIST,
        BC_PACKET_STATISTICS, BC_NETWORK_IDLE_HINT, BC_EMERGENCY_MODE),
    UUID_SMS: (SMS_CONFIGURATION, SMS_READ, SMS_SEND, SMS_DELETE, SMS_MESSAGE_STORE_STATUS),
}

HDR = struct.Struct("<III")          # MessageType, MessageLength, TransactionId
FRAG = struct.Struct("<II")          # TotalFragments, CurrentFragment
MIN_CTRL_TRANSFER = 64
MAX_MESSAGE = 0x10000                # refuse anything claiming to be longer (resync)


def _cid_name(service, cid):
    sname = SERVICE_NAMES.get(service, "UNKNOWN_SERVICE")
    if service == UUID_BASIC_CONNECT:
        cname = BC_NAMES.get(cid, str(cid))
    elif service == UUID_SMS:
        cname = SMS_NAMES.get(cid, str(cid))
    else:
        cname = str(cid)
    return f"{sname}.{cname}"


# --------------------------------------------------------------------------- encoding

class _Builder:
    """Mirror of libmbim's MbimStructBuilder: a fixed part with offset/size pairs pointing
    into a variable part.  Offsets are relative to the start of this structure; every
    variable data buffer is padded to 4 bytes."""

    def __init__(self):
        self.fixed = bytearray()
        self.var = bytearray()
        self.fixups = []

    def u32(self, v):
        self.fixed += struct.pack("<I", int(v) & 0xFFFFFFFF)
        return self

    def u64(self, v):
        self.fixed += struct.pack("<Q", int(v) & 0xFFFFFFFFFFFFFFFF)
        return self

    def raw(self, b):
        self.fixed += b
        return self

    def _ref(self, data, with_len=True):
        if data:
            self.fixups.append(len(self.fixed))
            self.fixed += struct.pack("<I", len(self.var))
            self.var += data
            self.var += b"\0" * (-len(data) % 4)
        else:
            self.fixed += struct.pack("<I", 0)
        if with_len:
            self.fixed += struct.pack("<I", len(data))
        return self

    def string(self, s):
        return self._ref(s.encode("utf-16-le") if s else b"")

    def bytes_ol(self, b):
        return self._ref(bytes(b or b""))

    def offset_only(self, data):
        """struct-array / ref-ipv4 / ipv4-array: just an offset, count elsewhere."""
        return self._ref(bytes(data or b""), with_len=False)

    def ref_array(self, blobs):
        """ref-struct-array / string-array: one offset/size pair per element."""
        for b in blobs:
            self._ref(b)
        return self

    def done(self):
        out = bytearray(self.fixed)
        n = len(self.fixed)
        for p in self.fixups:
            v = struct.unpack_from("<I", out, p)[0] + n
            struct.pack_into("<I", out, p, v)
        return bytes(out + self.var)


def _u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def _ol(b, off, base=0):
    """Read an offset/size pair at `off`; data lives at base+offset.  Returns bytes."""
    o, n = struct.unpack_from("<II", b, off)
    if n == 0:
        return b""
    if base + o + n > len(b) or o == 0 and n:
        raise ValueError("offset/size out of range")
    return bytes(b[base + o:base + o + n])


def _ol_str(b, off, base=0):
    data = _ol(b, off, base)
    return data.decode("utf-16-le", errors="replace") if data else ""


def _ipv4(s):
    try:
        return socket.inet_pton(socket.AF_INET, s)
    except (OSError, TypeError, ValueError):
        return None


def _ipv6(s):
    try:
        return socket.inet_pton(socket.AF_INET6, s)
    except (OSError, TypeError, ValueError):
        return None


def rssi_code(sig):
    """MBIM/3GPP 27.007 RSSI coding: 0 = -113 dBm or less, 31 = -51 dBm or more, 99 unknown."""
    sig = sig or {}
    dbm = sig.get("rssi_dbm")
    if dbm is not None:
        return max(0, min(31, (int(dbm) + 113) // 2))
    rsrp = sig.get("rsrp_dbm")
    if rsrp is not None:
        return max(0, min(31, round((int(rsrp) + 140) * 31 / 96)))
    bars = sig.get("bars")
    if bars is not None:
        return max(0, min(31, round(int(bars) * 31 / 5)))
    return 99


def _data_class(act):
    return {"lte": DC_LTE, "umts": DC_UMTS | DC_HSDPA | DC_HSUPA, "gsm": DC_GPRS | DC_EDGE,
            "nr": DC_LTE | DC_5G_NSA}.get(act or "", 0)


# --------------------------------------------------------------------------- function

class _Pending:
    __slots__ = ("tid", "gen", "activate", "started", "timer", "req_ip", "done")

    def __init__(self, tid, gen, activate, req_ip):
        self.tid, self.gen, self.activate, self.req_ip = tid, gen, activate, req_ip
        self.started = False
        self.done = False
        self.timer = None


class MbimFunction:
    """Device side of an MBIM 1.0 control channel.  See module docstring."""

    def __init__(self, backend, write, log=None, *, verbose=False, apn="",
                 netdev="wwan0", sysfs_net="/sys/class/net", sms_capacity=100,
                 connect_timeout=150.0, disconnect_timeout=30.0):
        self.backend = backend
        self._write = write
        self._logf = log
        self.verbose = verbose
        self.netdev = netdev
        self.sysfs_net = sysfs_net
        self.sms_capacity = sms_capacity
        self.connect_timeout = connect_timeout
        self.disconnect_timeout = disconnect_timeout
        self._lock = threading.RLock()       # state
        self._wlock = threading.Lock()       # keeps fragments of one message together
        self._rxlock = threading.Lock()
        self._rx = bytearray()
        self._frag = None                    # [tid, total, current, bytearray]
        self._open = False
        self._gen = 0
        self._max_ctrl = 4096
        self._subs = None                    # None = default (all of BASIC_CONNECT + SMS)
        self._signal_cfg = [0, 0, 0]
        self._last_rssi = None
        self._idle_hint = 0
        self._pending = None
        self._contexts = {1: dict(type=UUID_CONTEXT_INTERNET, apn=apn or "", user="",
                                  password="", compression=0, auth=0)}
        self._handlers = {
            (UUID_BASIC_CONNECT, BC_DEVICE_CAPS): self._h_device_caps,
            (UUID_BASIC_CONNECT, BC_SUBSCRIBER_READY_STATUS): self._h_subscriber,
            (UUID_BASIC_CONNECT, BC_RADIO_STATE): self._h_radio,
            (UUID_BASIC_CONNECT, BC_PIN): self._h_pin,
            (UUID_BASIC_CONNECT, BC_PIN_LIST): self._h_pin_list,
            (UUID_BASIC_CONNECT, BC_HOME_PROVIDER): self._h_home_provider,
            (UUID_BASIC_CONNECT, BC_PREFERRED_PROVIDERS): self._h_preferred_providers,
            (UUID_BASIC_CONNECT, BC_VISIBLE_PROVIDERS): self._h_visible_providers,
            (UUID_BASIC_CONNECT, BC_REGISTER_STATE): self._h_register_state,
            (UUID_BASIC_CONNECT, BC_PACKET_SERVICE): self._h_packet_service,
            (UUID_BASIC_CONNECT, BC_SIGNAL_STATE): self._h_signal_state,
            (UUID_BASIC_CONNECT, BC_CONNECT): self._h_connect,
            (UUID_BASIC_CONNECT, BC_PROVISIONED_CONTEXTS): self._h_provisioned_contexts,
            (UUID_BASIC_CONNECT, BC_IP_CONFIGURATION): self._h_ip_configuration,
            (UUID_BASIC_CONNECT, BC_DEVICE_SERVICES): self._h_device_services,
            (UUID_BASIC_CONNECT, BC_DEVICE_SERVICE_SUBSCRIBE_LIST): self._h_subscribe_list,
            (UUID_BASIC_CONNECT, BC_PACKET_STATISTICS): self._h_packet_statistics,
            (UUID_BASIC_CONNECT, BC_NETWORK_IDLE_HINT): self._h_network_idle_hint,
            (UUID_BASIC_CONNECT, BC_EMERGENCY_MODE): self._h_emergency_mode,
            (UUID_SMS, SMS_CONFIGURATION): self._h_sms_configuration,
            (UUID_SMS, SMS_READ): self._h_sms_read,
            (UUID_SMS, SMS_SEND): self._h_sms_send,
            (UUID_SMS, SMS_DELETE): self._h_sms_delete,
            (UUID_SMS, SMS_MESSAGE_STORE_STATUS): self._h_sms_store_status,
        }

    # ------------------------------------------------------------------ plumbing

    def _log(self, msg):
        if self._logf:
            try:
                self._logf("mbim: " + msg)
            except Exception:
                pass

    def _call(self, name, *args):
        """Backend call; exceptions are swallowed (logged by type only)."""
        try:
            return getattr(self.backend, name)(*args)
        except Exception as e:
            self._log(f"backend.{name} raised {type(e).__name__}")
            return None

    def _emit(self, data):
        try:
            self._write(bytes(data))
        except Exception as e:
            self._log(f"write failed: {type(e).__name__}")

    def _send_simple(self, mtype, tid, value):
        with self._wlock:
            self._emit(HDR.pack(mtype, 16, tid) + struct.pack("<I", value))

    def _send_fragmented(self, mtype, tid, payload):
        """payload = everything after the fragment header (service id onwards)."""
        hdr_len = HDR.size + FRAG.size
        chunk = max(MIN_CTRL_TRANSFER, self._max_ctrl) - hdr_len
        parts = [payload[i:i + chunk] for i in range(0, len(payload), chunk)] or [b""]
        with self._wlock:
            for i, p in enumerate(parts):
                self._emit(HDR.pack(mtype, hdr_len + len(p), tid) + FRAG.pack(len(parts), i) + p)

    def _command_done(self, tid, service, cid, status, info=b""):
        payload = service + struct.pack("<III", cid, status, len(info)) + info
        self._send_fragmented(MSG_COMMAND_DONE, tid, payload)

    def _subscribed(self, service, cid):
        with self._lock:
            if not self._open:
                return False
            if self._subs is None:
                return service in SUPPORTED_CIDS
            cids = self._subs.get(service)
            return cids is not None and (cids == "all" or cid in cids)

    def _indicate(self, service, cid, info):
        if not self._subscribed(service, cid):
            return False
        payload = service + struct.pack("<II", cid, len(info)) + info
        self._send_fragmented(MSG_INDICATE_STATUS, 0, payload)
        if self.verbose:
            self._log(f"indicate {_cid_name(service, cid)}")
        return True

    def reset(self):
        """Forget the session (e.g. the bridge was reopened).  Host must OPEN again."""
        with self._rxlock:
            self._rx.clear()
            self._frag = None
        with self._lock:
            self._open = False
            self._gen += 1
            self._drop_pending()

    def assume_open(self, max_ctrl=4096):
        """The host kept the port open across a restart of the function (daemon restart):
        continue the session as if OPEN had been received, with default subscriptions."""
        with self._lock:
            self._open = True
            self._subs = None
            self._max_ctrl = max(MIN_CTRL_TRANSFER, min(max_ctrl, MAX_MESSAGE))
            self._last_rssi = None

    def _drop_pending(self):
        p, self._pending = self._pending, None
        if p:
            p.done = True
            if p.timer:
                p.timer.cancel()

    # ------------------------------------------------------------------ input

    def feed(self, data):
        """Bytes from the bridge.  Never raises."""
        try:
            with self._rxlock:
                self._rx += data
                msgs = []
                while len(self._rx) >= HDR.size:
                    mtype, mlen, tid = HDR.unpack_from(self._rx, 0)
                    if mlen < HDR.size or mlen > MAX_MESSAGE:
                        self._log(f"bad MessageLength {mlen}, flushing {len(self._rx)} bytes")
                        self._rx.clear()
                        self._frag = None
                        msgs.append((None, tid))
                        break
                    if len(self._rx) < mlen:
                        break
                    msgs.append((bytes(self._rx[:mlen]), tid))
                    del self._rx[:mlen]
            for m, tid in msgs:
                if m is None:
                    self._send_simple(MSG_FUNCTION_ERROR, tid, PERR_LENGTH_MISMATCH)
                else:
                    self._process(m)
        except Exception as e:
            self._log(f"feed: internal error {type(e).__name__}")

    def _process(self, m):
        mtype, mlen, tid = HDR.unpack_from(m, 0)
        if mtype == MSG_OPEN:
            if mlen < 16:
                self._send_simple(MSG_FUNCTION_ERROR, tid, PERR_LENGTH_MISMATCH)
                return
            mct = _u32(m, 12)
            with self._lock:
                self._drop_pending()
                self._open = True
                self._gen += 1
                self._subs = None
                self._last_rssi = None
                self._max_ctrl = max(MIN_CTRL_TRANSFER, min(mct or 4096, MAX_MESSAGE))
            with self._rxlock:
                self._frag = None
            self._log(f"OPEN (max control transfer {mct})")
            self._send_simple(MSG_OPEN_DONE, tid, ST_NONE)
        elif mtype == MSG_CLOSE:
            with self._lock:
                self._drop_pending()
                self._open = False
                self._gen += 1
            self._log("CLOSE")
            self._send_simple(MSG_CLOSE_DONE, tid, ST_NONE)
        elif mtype == MSG_HOST_ERROR:
            code = _u32(m, 12) if mlen >= 16 else -1
            self._log(f"HOST_ERROR {code} tid={tid}")
            with self._rxlock:
                if self._frag and self._frag[0] == tid:
                    self._frag = None
        elif mtype == MSG_COMMAND:
            self._process_command_fragment(m, tid)
        else:
            self._log(f"unexpected message type 0x{mtype:08x}")
            self._send_simple(MSG_FUNCTION_ERROR, tid, PERR_UNKNOWN)

    def _process_command_fragment(self, m, tid):
        if not self._open:
            self._log(f"COMMAND before OPEN tid={tid}")
            self._send_simple(MSG_FUNCTION_ERROR, tid, PERR_NOT_OPENED)
            return
        if len(m) < HDR.size + FRAG.size:
            self._send_simple(MSG_FUNCTION_ERROR, tid, PERR_LENGTH_MISMATCH)
            return
        total, current = FRAG.unpack_from(m, HDR.size)
        body = m[HDR.size + FRAG.size:]
        complete = None
        err = None
        with self._rxlock:
            if total <= 1 and current == 0:
                if self._frag:
                    err = (self._frag[0], PERR_FRAGMENT_OUT_OF_SEQUENCE)
                    self._frag = None
                complete = body
            elif current == 0 and total > 1:
                if self._frag:
                    err = (self._frag[0], PERR_FRAGMENT_OUT_OF_SEQUENCE)
                self._frag = [tid, total, 0, bytearray(body)]
            elif (self._frag and self._frag[0] == tid and self._frag[1] == total
                  and current == self._frag[2] + 1):
                self._frag[2] = current
                self._frag[3] += body
                if current == total - 1:
                    complete = bytes(self._frag[3])
                    self._frag = None
            else:
                self._frag = None
                err = (tid, PERR_FRAGMENT_OUT_OF_SEQUENCE)
        if err:
            self._log(f"fragment out of sequence tid={err[0]}")
            self._send_simple(MSG_FUNCTION_ERROR, err[0], err[1])
        if complete is not None:
            self._command(tid, complete)

    def _command(self, tid, body):
        if len(body) < 28:
            self._send_simple(MSG_FUNCTION_ERROR, tid, PERR_LENGTH_MISMATCH)
            return
        service = bytes(body[:16])
        cid, ctype, ilen = struct.unpack_from("<III", body, 16)
        info = body[28:28 + ilen]
        if len(info) < ilen:
            self._send_simple(MSG_FUNCTION_ERROR, tid, PERR_LENGTH_MISMATCH)
            return
        name = _cid_name(service, cid)
        kind = "set" if ctype == CMD_SET else "query"
        handler = self._handlers.get((service, cid))
        if handler is None:
            status, out = ST_NO_DEVICE_SUPPORT, b""
        else:
            try:
                res = handler(tid, ctype == CMD_SET, bytes(info))
            except (struct.error, ValueError, IndexError):
                res = (ST_INVALID_PARAMETERS, b"")
            except Exception as e:
                self._log(f"{name} {kind}: handler error {type(e).__name__}")
                res = (ST_FAILURE, b"")
            if res is None:                  # answered later (CONNECT, SMS SEND)
                self._log(f"{name} {kind} tid={tid} -> deferred")
                return
            status, out = res
        self._log(f"{name} {kind} tid={tid} -> {STATUS_NAMES.get(status, status)}")
        self._command_done(tid, service, cid, status, out)

    # ------------------------------------------------------------------ builders

    def _b_subscriber(self):
        sim = self._call("sim") or {}
        st = sim.get("state")
        ready = {"ready": READY_INITIALIZED, "absent": READY_SIM_NOT_INSERTED,
                 "locked": READY_DEVICE_LOCKED, "error": READY_FAILURE,
                 "initializing": READY_NOT_INITIALIZED}.get(st, READY_NOT_INITIALIZED)
        ok = st == "ready"
        nums = [n for n in (sim.get("msisdn") or []) if n] if ok else []
        b = _Builder().u32(ready).string(sim.get("imsi") if ok else "")
        b.string(sim.get("iccid") if st in ("ready", "locked") else "")
        b.u32(0).u32(len(nums)).ref_array([n.encode("utf-16-le") for n in nums])
        return b.done()

    def _b_radio(self, sw=None):
        if sw is None:
            sw = bool(self._call("radio"))
        return _Builder().u32(1).u32(1 if sw else 0).done()

    def _provider_blob(self, plmn, name, state, rssi=99):
        return (_Builder().string(plmn or "").u32(state).string(name or "")
                .u32(CELLULAR_CLASS_GSM).u32(rssi).u32(99).done())

    def _b_register(self):
        reg = self._call("registration") or {}
        st = {"home": REG_HOME, "roaming": REG_ROAMING, "searching": REG_SEARCHING,
              "denied": REG_DENIED, "deregistered": REG_DEREGISTERED,
              "unknown": REG_UNKNOWN}.get(reg.get("state"), REG_UNKNOWN)
        registered = st in (REG_HOME, REG_ROAMING, REG_PARTNER)
        b = _Builder().u32(reg.get("nw_error") or 0).u32(st).u32(REGISTER_MODE_AUTOMATIC)
        b.u32(_data_class(reg.get("act")) if registered else 0).u32(CELLULAR_CLASS_GSM)
        b.string(reg.get("plmn") if registered else "")
        b.string(reg.get("provider") if registered else "")
        b.string("")
        b.u32(REGFLAG_MANUAL_SELECTION_NOT_AVAILABLE | REGFLAG_PACKET_SERVICE_AUTOMATIC_ATTACH)
        return b.done()

    def _b_packet_service(self):
        attached = bool(self._call("packet_attached"))
        dc = 0
        if attached:
            dc = _data_class((self._call("registration") or {}).get("act"))
        return (_Builder().u32(0).u32(PS_ATTACHED if attached else PS_DETACHED).u32(dc)
                .u64(0).u64(0).done())

    def _b_signal(self, code=None):
        if code is None:
            code = rssi_code(self._call("signal"))
        with self._lock:
            cfg = list(self._signal_cfg)
        return _Builder().u32(code).u32(99).u32(cfg[0]).u32(cfg[1]).u32(cfg[2]).done()

    def _b_connect(self, conn=None, req_ip=0):
        if conn is None:
            conn = self._call("connection") or {}
        state = ACT_STATE.get(conn.get("state"), 0)
        ip = IP_TYPE_TO_MBIM.get(conn.get("ip_type") or "", None)
        if ip is None or (ip == 0 and req_ip):
            ip = req_ip
        return (_Builder().u32(0).u32(state).u32(0).u32(ip).raw(UUID_CONTEXT_INTERNET)
                .u32(conn.get("nw_error") or 0).done())

    def _b_ip_config(self, cfg):
        cfg = cfg or {}
        v4 = _ipv4(cfg.get("ipv4"))
        v6 = _ipv6(cfg.get("ipv6"))
        gw4 = _ipv4(cfg.get("ipv4_gateway")) if v4 else None
        gw6 = _ipv6(cfg.get("ipv6_gateway")) if v6 else None
        dns4 = [a for a in (_ipv4(x) for x in cfg.get("dns4") or []) if a]
        dns6 = [a for a in (_ipv6(x) for x in cfg.get("dns6") or []) if a]
        mtu = int(cfg.get("mtu") or 0)
        f4 = f6 = 0
        if v4:
            f4 |= IPCFG_ADDRESS | (IPCFG_GATEWAY if gw4 else 0) | (IPCFG_DNS if dns4 else 0)
            f4 |= IPCFG_MTU if mtu else 0
        elif dns4:
            f4 |= IPCFG_DNS
        if v6:
            f6 |= IPCFG_ADDRESS | (IPCFG_GATEWAY if gw6 else 0) | (IPCFG_DNS if dns6 else 0)
            f6 |= IPCFG_MTU if mtu else 0
        elif dns6:
            f6 |= IPCFG_DNS
        p4 = int(cfg.get("ipv4_prefix") or 32)
        p6 = int(cfg.get("ipv6_prefix") or 64)
        b = _Builder().u32(0).u32(f4).u32(f6)
        b.u32(1 if v4 else 0).offset_only(struct.pack("<I", p4) + v4 if v4 else b"")
        b.u32(1 if v6 else 0).offset_only(struct.pack("<I", p6) + v6 if v6 else b"")
        b.offset_only(gw4 or b"").offset_only(gw6 or b"")
        b.u32(len(dns4)).offset_only(b"".join(dns4))
        b.u32(len(dns6)).offset_only(b"".join(dns6))
        b.u32(mtu if v4 else 0).u32(mtu if v6 else 0)
        return b.done()

    def _b_contexts(self):
        with self._lock:
            items = sorted(self._contexts.items())
        blobs = [(_Builder().u32(cid).raw(c["type"]).string(c["apn"]).string(c["user"])
                  .string(c["password"]).u32(c["compression"]).u32(c["auth"]).done())
                 for cid, c in items]
        return _Builder().u32(len(blobs)).ref_array(blobs).done()

    # ------------------------------------------------------------------ BASIC_CONNECT

    def _h_device_caps(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        ids = self._call("device_ids") or {}
        hw = ids.get("hardware") or ids.get("model") or ""
        b = _Builder().u32(DEVICE_TYPE_EMBEDDED).u32(CELLULAR_CLASS_GSM).u32(VOICE_CLASS_NO_VOICE)
        b.u32(SIM_CLASS_REMOVABLE).u32(DATA_CLASS_CAPS).u32(SMS_CAPS_PDU_RECEIVE | SMS_CAPS_PDU_SEND)
        b.u32(0).u32(1).string("").string(ids.get("imei") or "")
        b.string(ids.get("firmware") or "").string(hw)
        return ST_NONE, b.done()

    def _h_subscriber(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        return ST_NONE, self._b_subscriber()

    def _h_radio(self, tid, is_set, info):
        if not is_set:
            return ST_NONE, self._b_radio()
        on = _u32(info, 0) == 1
        self._call("set_radio", on)
        return ST_NONE, self._b_radio(sw=on)

    def _sim_status(self):
        st = (self._call("sim") or {}).get("state")
        if st == "absent":
            return st, ST_SIM_NOT_INSERTED
        if st == "error":
            return st, ST_BAD_SIM
        if st not in ("ready", "locked"):
            return st, ST_NOT_INITIALIZED
        return st, ST_NONE

    def _h_pin(self, tid, is_set, info):
        st, err = self._sim_status()
        if err:
            return err, b""
        if is_set:
            # PIN entry/change is not exposed by the daemon.
            return ST_FAILURE, b""
        locked = st == "locked"
        return ST_NONE, (_Builder().u32(PIN_TYPE_PIN1)
                         .u32(PIN_STATE_LOCKED if locked else PIN_STATE_UNLOCKED).u32(3).done())

    def _h_pin_list(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        st, err = self._sim_status()
        if err:
            return err, b""
        b = _Builder()
        b.u32(PIN_MODE_ENABLED if st == "locked" else PIN_MODE_DISABLED).u32(PIN_FORMAT_NUMERIC)
        b.u32(4).u32(8)
        for _ in range(9):
            b.u32(PIN_MODE_NOT_SUPPORTED).u32(PIN_FORMAT_UNKNOWN).u32(0).u32(0)
        return ST_NONE, b.done()

    def _h_home_provider(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        sim = self._call("sim") or {}
        if sim.get("state") != "ready":
            return self._sim_status()[1] or ST_NOT_INITIALIZED, b""
        reg = self._call("registration") or {}
        if reg.get("state") == "home" and reg.get("plmn"):
            plmn, name = reg.get("plmn"), reg.get("provider") or ""
        else:
            imsi = sim.get("imsi") or ""
            plmn = imsi[:5] if len(imsi) >= 5 else ""
            name = (self._call("provider_name", plmn) or "") if plmn else ""
        return ST_NONE, self._provider_blob(plmn, name, PROVIDER_HOME)

    def _h_preferred_providers(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        return ST_NONE, _Builder().u32(0).done()

    def _h_visible_providers(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        reg = self._call("registration") or {}
        blobs = []
        if reg.get("state") in ("home", "roaming") and reg.get("plmn"):
            state = PROVIDER_VISIBLE | PROVIDER_REGISTERED
            if reg.get("state") == "home":
                state |= PROVIDER_HOME
            blobs.append(self._provider_blob(reg.get("plmn"), reg.get("provider"), state,
                                             rssi_code(self._call("signal"))))
        return ST_NONE, _Builder().u32(len(blobs)).ref_array(blobs).done()

    def _h_register_state(self, tid, is_set, info):
        if is_set:
            action = _u32(info, 8)
            if action != REGISTER_ACTION_AUTOMATIC:
                return ST_NO_DEVICE_SUPPORT, b""      # manual selection not offered
        return ST_NONE, self._b_register()

    def _h_packet_service(self, tid, is_set, info):
        # Attach is automatic on LTE; the daemon has no attach/detach call, so a SET is
        # answered with the actual state (MM then compares it with what it asked for).
        if is_set:
            _u32(info, 0)
        return ST_NONE, self._b_packet_service()

    def _h_signal_state(self, tid, is_set, info):
        if is_set:
            vals = list(struct.unpack_from("<III", info, 0))
            with self._lock:
                self._signal_cfg = vals
        return ST_NONE, self._b_signal()

    def _h_device_services(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        blobs = []
        for svc, cids in SUPPORTED_CIDS.items():
            b = _Builder().raw(svc).u32(0).u32(0).u32(len(cids))
            for c in cids:
                b.u32(c)
            blobs.append(b.done())
        return ST_NONE, _Builder().u32(len(blobs)).u32(0).ref_array(blobs).done()

    def _h_subscribe_list(self, tid, is_set, info):
        if not is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        count = _u32(info, 0)
        if count > 64:
            return ST_INVALID_PARAMETERS, b""
        subs, blobs = {}, []
        for i in range(count):
            off, size = struct.unpack_from("<II", info, 4 + 8 * i)
            if off + 20 > len(info) or size < 20:
                return ST_INVALID_PARAMETERS, b""
            svc = bytes(info[off:off + 16])
            n = _u32(info, off + 16)
            if n > 256 or off + 20 + 4 * n > len(info):
                return ST_INVALID_PARAMETERS, b""
            cids = struct.unpack_from(f"<{n}I", info, off + 20)
            prev = subs.get(svc)
            subs[svc] = "all" if (n == 0 or prev == "all") else (prev or set()) | set(cids)
            b = _Builder().raw(svc).u32(n)
            for c in cids:
                b.u32(c)
            blobs.append(b.done())
        with self._lock:
            self._subs = subs
        if self.verbose:
            self._log("subscribe list: " + ", ".join(
                f"{SERVICE_NAMES.get(s, '?')}:{'all' if c == 'all' else sorted(c)}"
                for s, c in subs.items()))
        return ST_NONE, _Builder().u32(len(blobs)).ref_array(blobs).done()

    def _h_packet_statistics(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""

        def stat(name):
            try:
                with open(os.path.join(self.sysfs_net, self.netdev, "statistics", name)) as f:
                    return int(f.read().strip() or 0)
            except (OSError, ValueError):
                return 0
        b = _Builder().u32(stat("rx_dropped")).u32(stat("rx_errors"))
        b.u64(stat("rx_bytes")).u64(stat("rx_packets"))
        b.u64(stat("tx_bytes")).u64(stat("tx_packets"))
        b.u32(stat("tx_errors")).u32(stat("tx_dropped"))
        return ST_NONE, b.done()

    def _h_network_idle_hint(self, tid, is_set, info):
        if is_set:
            with self._lock:
                self._idle_hint = 1 if _u32(info, 0) else 0
        return ST_NONE, _Builder().u32(self._idle_hint).done()

    def _h_emergency_mode(self, tid, is_set, info):
        if is_set and _u32(info, 0) != 0:
            return ST_NO_DEVICE_SUPPORT, b""
        return ST_NONE, _Builder().u32(0).done()

    def _h_provisioned_contexts(self, tid, is_set, info):
        if is_set:
            cid = _u32(info, 0)
            ctype = bytes(info[4:20])
            if len(ctype) != 16:
                return ST_INVALID_PARAMETERS, b""
            ctx = dict(type=ctype, apn=_ol_str(info, 20), user=_ol_str(info, 28),
                       password=_ol_str(info, 36), compression=_u32(info, 44),
                       auth=_u32(info, 48))
            with self._lock:
                if cid == PROVISIONED_CONTEXT_ID_APPEND:
                    cid = max(self._contexts, default=0) + 1
                if cid == 0 or cid > 64:
                    return ST_INVALID_PARAMETERS, b""
                self._contexts[cid] = ctx
            out = self._b_contexts()
            self._indicate(UUID_BASIC_CONNECT, BC_PROVISIONED_CONTEXTS, out)
            return ST_NONE, out
        return ST_NONE, self._b_contexts()

    def _h_ip_configuration(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        session = _u32(info, 0) if len(info) >= 4 else 0
        if session != 0:
            return ST_INVALID_PARAMETERS, b""
        conn = self._call("connection") or {}
        cfg = self._call("ip_config")
        if conn.get("state") != "activated" and not cfg:
            return ST_CONTEXT_NOT_ACTIVATED, b""
        return ST_NONE, self._b_ip_config(cfg)

    # -- CONNECT (session 0).  A SET is answered once the activation finished.

    def _h_connect(self, tid, is_set, info):
        session = _u32(info, 0) if len(info) >= 4 else 0
        if not is_set:
            if session != 0:
                return ST_NONE, (_Builder().u32(session).u32(ACT_STATE_DEACTIVATED).u32(0)
                                 .u32(0).raw(UUID_CONTEXT_INTERNET).u32(0).done())
            return ST_NONE, self._b_connect()
        if session != 0:
            return ST_MAX_ACTIVATED_CONTEXTS, b""
        command = _u32(info, 4)
        apn, user, password = _ol_str(info, 8), _ol_str(info, 16), _ol_str(info, 24)
        auth = AUTH_FROM_MBIM.get(_u32(info, 36), "none")
        req_ip = _u32(info, 40)
        ip_type = IP_TYPE_FROM_MBIM.get(req_ip, "default")
        req_ip = IP_TYPE_TO_MBIM[ip_type]
        activate = command == ACTIVATION_ACTIVATE
        if command not in (ACTIVATION_ACTIVATE, ACTIVATION_DEACTIVATE):
            return ST_INVALID_PARAMETERS, b""

        state = (self._call("connection") or {}).get("state")
        with self._lock:
            old = self._pending
            if old and old.activate and activate:
                return ST_BUSY, b""
            gen = self._gen
        if old:
            # A deactivate overrides a pending activate (and vice versa): fail the old one.
            self._finish_pending(old, ST_FAILURE)
        if activate and state == "activated":
            return ST_NONE, self._b_connect(req_ip=req_ip)
        if not activate and state in ("deactivated", None):
            return ST_NONE, self._b_connect()

        p = _Pending(tid, gen, activate, req_ip)
        timeout = self.connect_timeout if activate else self.disconnect_timeout
        p.timer = threading.Timer(timeout, self._pending_timeout, (p,))
        p.timer.daemon = True
        with self._lock:
            self._pending = p
        p.timer.start()
        if activate:
            self._call("connect", apn, ip_type, user, password, auth)
        else:
            self._call("disconnect")
        with self._lock:
            p.started = True
        self._check_pending()
        return None

    def _finish_pending(self, p, status, conn=None):
        with self._lock:
            if p.done:
                return
            p.done = True
            if self._pending is p:
                self._pending = None
            if p.timer:
                p.timer.cancel()
            live = p.gen == self._gen and self._open
        if not live:
            return
        info = self._b_connect(conn, req_ip=p.req_ip)
        self._log(f"BASIC_CONNECT.CONNECT set tid={p.tid} -> {STATUS_NAMES.get(status, status)}")
        self._command_done(p.tid, UUID_BASIC_CONNECT, BC_CONNECT, status, info)

    def _pending_timeout(self, p):
        with self._lock:
            if self._pending is not p:
                return
        self._log("CONNECT set timed out")
        if p.activate:
            self._call("disconnect")
            self._finish_pending(p, ST_FAILURE, dict(state="deactivated"))
        else:
            self._finish_pending(p, ST_NONE, dict(state="deactivated"))

    def _check_pending(self, conn=None):
        with self._lock:
            p = self._pending
        if p is None:
            return
        if conn is None:
            conn = self._call("connection") or {}
        st = conn.get("state")
        with self._lock:
            if self._pending is not p:
                return
            started = p.started
            if p.activate:
                if st == "activated":
                    status = ST_NONE
                elif st == "deactivated" and started:
                    status = ST_FAILURE
                else:
                    return
            else:
                if st != "deactivated":
                    return
                status = ST_NONE
            self._pending = None
        self._finish_pending(p, status, conn)

    # ------------------------------------------------------------------ SMS

    def _sms_list(self):
        out = []
        for m in self._call("sms_list") or []:
            try:
                out.append((int(m["index"]), m.get("status", "old"), bytes(m["pdu"])))
            except (KeyError, TypeError, ValueError):
                continue
        return out

    def _h_sms_configuration(self, tid, is_set, info):
        if is_set:
            if _u32(info, 0) != SMS_FORMAT_PDU:
                return ST_SMS_FORMAT_NOT_SUPPORTED, b""
            _ol_str(info, 4)   # SC address: accepted, the daemon uses the SIM's SMSC
        ready = (self._call("sim") or {}).get("state") == "ready"
        b = _Builder().u32(SMS_STORAGE_INITIALIZED if ready else SMS_STORAGE_NOT_INITIALIZED)
        b.u32(SMS_FORMAT_PDU).u32(self.sms_capacity).u32(0)
        b.string((self._call("smsc") or "") if ready else "")
        return ST_NONE, b.done()

    def _h_sms_read(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        fmt, flag = struct.unpack_from("<II", info, 0)
        index = _u32(info, 8) if len(info) >= 12 else 0
        if fmt != SMS_FORMAT_PDU:
            return ST_SMS_FORMAT_NOT_SUPPORTED, b""
        msgs = self._sms_list()
        if flag == SMS_FLAG_ALL:
            sel = msgs
        elif flag == SMS_FLAG_INDEX:
            sel = [m for m in msgs if m[0] == index]
            if not sel:
                return ST_INVALID_MEMORY_INDEX, b""
        elif flag in SMS_FLAG_TO_STATUS:
            sel = [m for m in msgs if m[1] == SMS_FLAG_TO_STATUS[flag]]
        else:
            return ST_INVALID_PARAMETERS, b""
        blobs = [_Builder().u32(i).u32(SMS_STATUS.get(s, 1)).bytes_ol(pdu).done()
                 for i, s, pdu in sel]
        out = _Builder().u32(SMS_FORMAT_PDU).u32(len(blobs)).ref_array(blobs).done()
        for i, s, _ in sel:
            if s == "new":
                self._call("sms_mark_read", i)
        return ST_NONE, out

    def _h_sms_send(self, tid, is_set, info):
        if not is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        if _u32(info, 0) != SMS_FORMAT_PDU:
            return ST_SMS_FORMAT_NOT_SUPPORTED, b""
        # MbimSmsPduSendRecord is inline at offset 4; its offset is relative to itself.
        off, size = struct.unpack_from("<II", info, 4)
        if size == 0 or size > 255:
            return ST_INVALID_PARAMETERS, b""
        if 4 + off + size <= len(info) and off >= 8:
            pdu = bytes(info[4 + off:4 + off + size])
        elif off + size <= len(info) and off >= 12:          # lenient: info-relative
            pdu = bytes(info[off:off + size])
        else:
            return ST_INVALID_PARAMETERS, b""
        with self._lock:
            gen = self._gen

        def work():
            res = self._call("sms_send", pdu)
            ok, mr = (res if isinstance(res, tuple) and len(res) == 2 else (False, 0))
            with self._lock:
                live = gen == self._gen and self._open
            if not live:
                return
            status = ST_NONE if ok else ST_FAILURE
            self._log(f"SMS.SEND set tid={tid} -> {STATUS_NAMES.get(status, status)}")
            self._command_done(tid, UUID_SMS, SMS_SEND, status,
                               _Builder().u32(int(mr or 0)).done() if ok else b"")
        threading.Thread(target=work, name="mbim-sms-send", daemon=True).start()
        return None

    def _h_sms_delete(self, tid, is_set, info):
        if not is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        flag = _u32(info, 0)
        index = _u32(info, 4) if len(info) >= 8 else 0
        if flag == SMS_FLAG_ALL:
            self._call("sms_delete", None)
        elif flag == SMS_FLAG_INDEX:
            if not any(m[0] == index for m in self._sms_list()):
                return ST_INVALID_MEMORY_INDEX, b""
            self._call("sms_delete", index)
        elif flag in SMS_FLAG_TO_STATUS:
            for i, s, _ in self._sms_list():
                if s == SMS_FLAG_TO_STATUS[flag]:
                    self._call("sms_delete", i)
        else:
            return ST_INVALID_PARAMETERS, b""
        return ST_NONE, b""

    def _h_sms_store_status(self, tid, is_set, info):
        if is_set:
            return ST_NO_DEVICE_SUPPORT, b""
        msgs = self._sms_list()
        new = [m[0] for m in msgs if m[1] == "new"]
        flag = (SMS_STATUS_FLAG_NEW_MESSAGE if new else 0) | (
            SMS_STATUS_FLAG_STORE_FULL if len(msgs) >= self.sms_capacity else 0)
        return ST_NONE, _Builder().u32(flag).u32(new[0] if new else 0).done()

    # ------------------------------------------------------------------ notifications

    def _safe(fn):
        def wrapper(self, *a):
            try:
                return fn(self, *a)
            except Exception as e:
                self._log(f"{fn.__name__}: internal error {type(e).__name__}")
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    @_safe
    def notify_radio(self):
        """RADIO_STATE indication (current software radio state)."""
        if self._subscribed(UUID_BASIC_CONNECT, BC_RADIO_STATE):
            self._indicate(UUID_BASIC_CONNECT, BC_RADIO_STATE, self._b_radio())

    @_safe
    def notify_subscriber(self):
        """SUBSCRIBER_READY_STATUS indication."""
        if self._subscribed(UUID_BASIC_CONNECT, BC_SUBSCRIBER_READY_STATUS):
            self._indicate(UUID_BASIC_CONNECT, BC_SUBSCRIBER_READY_STATUS, self._b_subscriber())

    @_safe
    def notify_registration(self):
        """REGISTER_STATE indication."""
        if self._subscribed(UUID_BASIC_CONNECT, BC_REGISTER_STATE):
            self._indicate(UUID_BASIC_CONNECT, BC_REGISTER_STATE, self._b_register())

    @_safe
    def notify_packet_service(self):
        """PACKET_SERVICE indication."""
        if self._subscribed(UUID_BASIC_CONNECT, BC_PACKET_SERVICE):
            self._indicate(UUID_BASIC_CONNECT, BC_PACKET_SERVICE, self._b_packet_service())

    @_safe
    def notify_signal(self):
        """SIGNAL_STATE indication; suppressed if the coded RSSI did not change (or moved
        less than the host's RssiThreshold)."""
        if not self._subscribed(UUID_BASIC_CONNECT, BC_SIGNAL_STATE):
            return
        code = rssi_code(self._call("signal"))
        with self._lock:
            last, thr = self._last_rssi, self._signal_cfg[1]
            if last is not None:
                if code == last:
                    return
                if 0 < thr < 0xFFFFFFFF and code != 99 and last != 99 and abs(code - last) < thr:
                    return
            self._last_rssi = code
        self._indicate(UUID_BASIC_CONNECT, BC_SIGNAL_STATE, self._b_signal(code))

    @_safe
    def notify_connect(self):
        """Connection state of session 0 changed: completes a pending CONNECT set when the
        state is final, then sends the CONNECT indication."""
        conn = self._call("connection") or {}
        self._check_pending(conn)
        if self._subscribed(UUID_BASIC_CONNECT, BC_CONNECT):
            self._indicate(UUID_BASIC_CONNECT, BC_CONNECT, self._b_connect(conn))

    @_safe
    def notify_ip_configuration(self):
        """Optional: IP_CONFIGURATION indication (e.g. after a global IPv6 is known)."""
        if self._subscribed(UUID_BASIC_CONNECT, BC_IP_CONFIGURATION):
            cfg = self._call("ip_config")
            if cfg:
                self._indicate(UUID_BASIC_CONNECT, BC_IP_CONFIGURATION, self._b_ip_config(cfg))

    @_safe
    def notify_sms(self, index):
        """New message stored at `index`: SMS MESSAGE_STORE_STATUS indication with the
        NEW_MESSAGE flag; ModemManager then reads it with SMS READ (flag INDEX).  No SMS
        READ indication is sent (MM would treat it as an unstored flash message)."""
        if self._subscribed(UUID_SMS, SMS_MESSAGE_STORE_STATUS):
            self._indicate(UUID_SMS, SMS_MESSAGE_STORE_STATUS,
                           _Builder().u32(SMS_STATUS_FLAG_NEW_MESSAGE).u32(int(index)).done())

    del _safe
