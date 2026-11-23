"""VoLTE media on the AP for shannon_ims: RTP with AMR / AMR-WB (RFC 4867, octet-aligned
and bandwidth-efficient), RFC 4733 DTMF, a small jitter buffer, codecs through ctypes
(opencore-amr: libopencore-amrnb, libopencore-amrwb; vo-amrwbenc: libvo-amrwbenc) and
audio through pw-cat (PipeWire) or aplay/arecord (no session), set up by
`call-audio voip-start` (earpiece/speaker amp switches, node lookup).

Timing: the capture stream clocks everything.  Every 20 ms of captured audio one frame
is encoded and sent, and one frame is taken from the jitter buffer, decoded (or
concealed) and written to the playback stream.
"""

import array
import ctypes
import ctypes.util
import os
import random
import select
import socket
import struct
import subprocess
import threading
import time

AMR_BITS = {"AMR": [95, 103, 118, 134, 148, 159, 204, 244, 39],
            "AMR-WB": [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]}
RATE = {"AMR": 8000, "AMR-WB": 16000}
NO_DATA = 15


def frame_bits(name, ft):
    b = AMR_BITS[name]
    return b[ft] if ft < len(b) else 0


def frame_bytes(name, ft):
    return (frame_bits(name, ft) + 7) // 8


# ---------------------------------------------------------------------------- RFC 4867

class _BitWriter:
    def __init__(self):
        self.out, self.acc, self.n = bytearray(), 0, 0

    def put(self, value, bits):
        for k in range(bits - 1, -1, -1):
            self.acc = (self.acc << 1) | ((value >> k) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                self.acc = self.n = 0

    def put_bytes(self, data, bits):
        for k in range(bits):
            self.put((data[k >> 3] >> (7 - (k & 7))) & 1, 1)

    def get(self):
        if self.n:
            self.out.append(self.acc << (8 - self.n))
            self.acc = self.n = 0
        return bytes(self.out)


class _BitReader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def left(self):
        return len(self.data) * 8 - self.pos

    def get(self, bits):
        v = 0
        for _ in range(bits):
            if self.pos >= len(self.data) * 8:
                raise ValueError("payload too short")
            v = (v << 1) | ((self.data[self.pos >> 3] >> (7 - (self.pos & 7))) & 1)
            self.pos += 1
        return v

    def get_bytes(self, bits):
        w = _BitWriter()
        for _ in range(bits):
            w.put(self.get(1), 1)
        return w.get()


def amr_pack(name, frames, cmr=15, octet_align=False):
    """frames: [(ft, q, data)] with data in storage order (ceil(bits/8) bytes)."""
    if octet_align:
        out = bytearray([cmr << 4])
        for k, (ft, q, _) in enumerate(frames):
            out.append((0x80 if k < len(frames) - 1 else 0) | ft << 3 | (q & 1) << 2)
        for ft, q, data in frames:
            out += data[:frame_bytes(name, ft)].ljust(frame_bytes(name, ft), b"\0")
        return bytes(out)
    w = _BitWriter()
    w.put(cmr, 4)
    for k, (ft, q, _) in enumerate(frames):
        w.put(1 if k < len(frames) - 1 else 0, 1)
        w.put(ft, 4)
        w.put(q & 1, 1)
    for ft, q, data in frames:
        w.put_bytes(data.ljust(frame_bytes(name, ft), b"\0"), frame_bits(name, ft))
    return w.get()


def amr_unpack(name, payload, octet_align=False):
    """-> (cmr, [(ft, q, data)]).  Raises ValueError on malformed payloads."""
    toc = []
    if octet_align:
        if len(payload) < 2:
            raise ValueError("payload too short")
        cmr, k = payload[0] >> 4, 1
        while True:
            if k >= len(payload):
                raise ValueError("ToC runs past the payload")
            b = payload[k]
            k += 1
            toc.append(((b >> 3) & 0xF, (b >> 2) & 1))
            if not b & 0x80:
                break
        frames = []
        for ft, q in toc:
            n = frame_bytes(name, ft)
            if k + n > len(payload):
                raise ValueError("frame runs past the payload")
            frames.append((ft, q, bytes(payload[k:k + n])))
            k += n
        return cmr, frames
    r = _BitReader(payload)
    cmr = r.get(4)
    while True:
        f, ft, q = r.get(1), r.get(4), r.get(1)
        toc.append((ft, q))
        if not f:
            break
        if len(toc) > 32:
            raise ValueError("ToC too long")
    frames = []
    for ft, q in toc:
        nb = frame_bits(name, ft)
        frames.append((ft, q, r.get_bytes(nb)))
    return cmr, frames


def storage_to_frame(data):
    """Codec-library storage frame (ToC byte + data) -> (ft, q, data)."""
    if not data:
        return NO_DATA, 1, b""
    return (data[0] >> 3) & 0xF, (data[0] >> 2) & 1, bytes(data[1:])


def frame_to_storage(name, ft, q, data):
    return bytes([(ft << 3) | (q << 2)]) + data[:frame_bytes(name, ft)]


# ---------------------------------------------------------------------------- RTP

def rtp_header(pt, seq, ts, ssrc, marker=False):
    return struct.pack("!BBHII", 0x80, (0x80 if marker else 0) | pt, seq & 0xFFFF,
                       ts & 0xFFFFFFFF, ssrc)


def rtp_parse(pkt):
    """-> (pt, seq, ts, ssrc, marker, payload) or None."""
    if len(pkt) < 12 or pkt[0] >> 6 != 2:
        return None
    cc, ext, pad = pkt[0] & 0xF, pkt[0] & 0x10, pkt[0] & 0x20
    k = 12 + 4 * cc
    if ext:
        if len(pkt) < k + 4:
            return None
        k += 4 + 4 * struct.unpack_from("!H", pkt, k + 2)[0]
    end = len(pkt) - (pkt[-1] if pad else 0)
    if k > end:
        return None
    seq, ts, ssrc = struct.unpack_from("!HII", pkt, 2)
    return pkt[1] & 0x7F, seq, ts, ssrc, bool(pkt[1] & 0x80), pkt[k:end]


DTMF_EVENTS = {**{str(d): d for d in range(10)}, "*": 10, "#": 11, "A": 12, "B": 13,
               "C": 14, "D": 15}


def dtmf_payload(event, end, volume, duration):
    return struct.pack("!BBH", event, (0x80 if end else 0) | (volume & 0x3F), duration)


class JitterBuffer:
    """Frames keyed by RTP sequence number; playout one per 20 ms tick."""

    def __init__(self, prefill=3, max_frames=12):
        self.buf, self.next, self.prefill, self.max = {}, None, prefill, max_frames
        self.started = False
        self.lost = self.late = 0

    def put(self, seq, frame):
        if self.next is not None and ((seq - self.next) & 0xFFFF) > 0x8000:
            self.late += 1
            return
        self.buf[seq] = frame
        if self.next is None:
            self.next = seq
        if len(self.buf) > self.max:          # too far behind: skip ahead
            newest = max(self.buf, key=lambda s: (s - self.next) & 0xFFFF)
            target = (newest - self.prefill) & 0xFFFF
            for s in list(self.buf):
                if ((s - target) & 0xFFFF) > 0x8000:
                    del self.buf[s]
            self.next = target

    def pop(self):
        """-> frame, None (lost: conceal), or False (not started yet: silence)."""
        if not self.started:
            if len(self.buf) < self.prefill:
                return False
            self.started = True
        if self.next is None:
            return False
        f = self.buf.pop(self.next, None)
        self.next = (self.next + 1) & 0xFFFF
        if f is None:
            self.lost += 1
            if not self.buf:
                self.started = False         # underrun: prefill again
        return f


# ---------------------------------------------------------------------------- codecs

def _lib(names, what=None):
    for n in names:
        p = ctypes.util.find_library(n) or None
        for cand in ([p] if p else []) + [f"lib{n}.so.0", f"lib{n}.so.1", f"lib{n}.so"]:
            try:
                return ctypes.CDLL(cand)
            except OSError:
                continue
    if what:
        raise OSError(f"library not found: {names[0]} (install {what})")
    raise OSError(f"codec library not found: {names[0]} (install opencore-amr / vo-amrwbenc)")


class AmrCodec:
    """AMR-NB: opencore-amrnb (enc+dec).  AMR-WB: vo-amrwbenc (enc) + opencore-amrwb (dec).
    encode(pcm 20 ms s16le) -> storage frame; decode(storage frame or None) -> pcm."""

    def __init__(self, name, mode, dtx=False):
        self.name, self.mode = name, mode
        self.samples = 160 if name == "AMR" else 320
        self.pcm_t = ctypes.c_short * self.samples
        self.out = (ctypes.c_ubyte * 64)()
        vp = ctypes.c_void_p
        if name == "AMR":
            nb = _lib(["opencore-amrnb"])
            nb.Encoder_Interface_init.restype = vp
            nb.Decoder_Interface_init.restype = vp
            nb.Encoder_Interface_Encode.argtypes = [vp, ctypes.c_int, ctypes.c_void_p,
                                                    ctypes.c_void_p, ctypes.c_int]
            nb.Decoder_Interface_Decode.argtypes = [vp, ctypes.c_void_p, ctypes.c_void_p,
                                                    ctypes.c_int]
            nb.Encoder_Interface_exit.argtypes = nb.Decoder_Interface_exit.argtypes = [vp]
            self.enc = nb.Encoder_Interface_init(int(dtx))
            self.dec = nb.Decoder_Interface_init()
            self._e = lambda pcm: nb.Encoder_Interface_Encode(self.enc, self.mode, pcm, self.out, 0)
            self._d = lambda inp, pcm, bfi: nb.Decoder_Interface_Decode(self.dec, inp, pcm, bfi)
            self._exit = lambda: (nb.Encoder_Interface_exit(self.enc), nb.Decoder_Interface_exit(self.dec))
        else:
            we, wd = _lib(["vo-amrwbenc"]), _lib(["opencore-amrwb"])
            we.E_IF_init.restype = vp
            wd.D_IF_init.restype = vp
            we.E_IF_encode.argtypes = [vp, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_int]
            wd.D_IF_decode.argtypes = [vp, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
            we.E_IF_exit.argtypes = wd.D_IF_exit.argtypes = [vp]
            self.enc, self.dec = we.E_IF_init(), wd.D_IF_init()
            self._e = lambda pcm: we.E_IF_encode(self.enc, self.mode, pcm, self.out, int(dtx))
            self._d = lambda inp, pcm, bfi: wd.D_IF_decode(self.dec, inp, pcm, bfi)
            self._exit = lambda: (we.E_IF_exit(self.enc), wd.D_IF_exit(self.dec))

    def encode(self, pcm):
        buf = self.pcm_t.from_buffer_copy(pcm.ljust(self.samples * 2, b"\0")[:self.samples * 2])
        n = self._e(buf)
        return bytes(self.out[:max(0, n)])

    def decode(self, frame):
        pcm = self.pcm_t()
        if frame:
            inp = (ctypes.c_ubyte * 64).from_buffer_copy(frame.ljust(64, b"\0")[:64])
            self._d(inp, pcm, 0)
        else:
            inp = (ctypes.c_ubyte * 64)()
            inp[0] = (NO_DATA << 3) | 0x04
            self._d(inp, pcm, 1)
        return bytes(pcm)

    def close(self):
        self._exit()


class NullCodec:
    """Test codec: the 'frame' is the PCM's first frame_bytes() bytes."""

    def __init__(self, name, mode):
        self.name, self.mode = name, mode
        self.samples = 160 if name == "AMR" else 320

    def encode(self, pcm):
        return frame_to_storage(self.name, self.mode, 1, pcm[:frame_bytes(self.name, self.mode)]
                                .ljust(frame_bytes(self.name, self.mode), b"\0"))

    def decode(self, frame):
        if not frame:
            return b"\0" * self.samples * 2
        return frame[1:].ljust(self.samples * 2, b"\0")

    def close(self):
        pass


# ---------------------------------------------------------------------------- echo cancel

# speexdsp headers (speex_echo.h, speex_preprocess.h)
SPEEX_ECHO_SET_SAMPLING_RATE = 24
SPEEX_PREPROCESS_SET_ECHO_STATE = 24


class SpeexAec:
    """Acoustic echo canceller for the AP media path (IMS_AEC=speex, default off):
    speexdsp's MDF adaptive filter plus its preprocessor (residual echo suppression and
    noise suppression).  The reference is exactly the PCM we hand to the playback
    stream in the same 20 ms tick, so no clock drift between the two; the filter tail
    must cover the pw-cat/ALSA playback + capture latency and the acoustic path."""

    def __init__(self, samples, rate, tail_ms=300, lib=None):
        L = lib or _lib(["speexdsp"], "speexdsp")
        vp = ctypes.c_void_p
        L.speex_echo_state_init.restype = vp
        L.speex_echo_state_init.argtypes = [ctypes.c_int, ctypes.c_int]
        L.speex_echo_ctl.argtypes = [vp, ctypes.c_int, vp]
        L.speex_echo_cancellation.argtypes = [vp, vp, vp, vp]
        L.speex_echo_state_destroy.argtypes = [vp]
        L.speex_preprocess_state_init.restype = vp
        L.speex_preprocess_state_init.argtypes = [ctypes.c_int, ctypes.c_int]
        L.speex_preprocess_ctl.argtypes = [vp, ctypes.c_int, vp]
        L.speex_preprocess_run.argtypes = [vp, vp]
        L.speex_preprocess_state_destroy.argtypes = [vp]
        self.L, self.samples = L, samples
        self.pcm_t = ctypes.c_int16 * samples
        self.echo = L.speex_echo_state_init(samples, max(samples, rate * tail_ms // 1000))
        r = ctypes.c_int(rate)
        L.speex_echo_ctl(self.echo, SPEEX_ECHO_SET_SAMPLING_RATE, ctypes.byref(r))
        self.pre = L.speex_preprocess_state_init(samples, rate)
        L.speex_preprocess_ctl(self.pre, SPEEX_PREPROCESS_SET_ECHO_STATE,
                               ctypes.c_void_p(self.echo))

    def process(self, rec, play):
        n = self.samples * 2
        r = self.pcm_t.from_buffer_copy(rec.ljust(n, b"\0")[:n])
        p = self.pcm_t.from_buffer_copy(play.ljust(n, b"\0")[:n])
        out = self.pcm_t()
        self.L.speex_echo_cancellation(self.echo, r, p, out)
        self.L.speex_preprocess_run(self.pre, out)
        return bytes(out)

    def close(self):
        if self.echo:
            self.L.speex_preprocess_state_destroy(self.pre)
            self.L.speex_echo_state_destroy(self.echo)
            self.echo = self.pre = None


# ---------------------------------------------------------------------------- audio I/O

def voip_audio_setup(script, dev, log):
    """`call-audio voip-start DEV` -> dict(mode=pw|alsa, user, sink, source)."""
    try:
        r = subprocess.run([script, "voip-start", dev], capture_output=True, text=True,
                           timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        log(f"media: {script} voip-start failed: {e}")
        return dict(mode="pw", user=None, sink=None, source=None)
    for l in (r.stderr or "").splitlines():
        log(f"audio: {l}")
    out = dict(mode="pw", user=None, sink=None, source=None)
    for tok in r.stdout.split():
        k, _, v = tok.partition("=")
        if k in out and v:
            out[k] = v
    return out


def audio_commands(setup, rate):
    """-> (playback argv taking s16 4 ch, capture argv giving s16 (1 ch for PipeWire,
    2 ch for ALSA), capture channels)."""
    if setup.get("mode") == "alsa":
        return (["aplay", "-q", "-D", "plughw:0,1", "-t", "raw", "-f", "S16_LE", "-c", "4",
                 "-r", str(rate), "--buffer-time=80000"],
                ["arecord", "-q", "-D", "plughw:0,0", "-t", "raw", "-f", "S16_LE", "-c", "2",
                 "-r", str(rate), "--period-time=20000"], 2)
    pre = []
    u = setup.get("user")
    if u and os.geteuid() == 0:
        try:
            import pwd
            uid = pwd.getpwnam(u).pw_uid
            pre = ["runuser", "-u", u, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}"]
        except KeyError:
            pre = []
    common = ["--raw", "--format", "s16", "--rate", str(rate), "-P", "media.role=Phone",
              "--latency", "20ms"]
    play = pre + ["pw-cat", "--playback", *common, "--channels", "4"] + \
        (["--target", setup["sink"]] if setup.get("sink") else []) + ["-"]
    rec = pre + ["pw-cat", "--record", *common, "--channels", "1"] + \
        (["--target", setup["source"]] if setup.get("source") else []) + ["-"]
    return play, rec, 1


def upmix4(pcm):
    a = array.array("h")
    a.frombytes(pcm)
    out = array.array("h", bytes(len(pcm) * 4))
    for ch in range(4):
        out[ch::4] = a
    return out.tobytes()


def downmix_first(pcm, channels):
    if channels == 1:
        return pcm
    a = array.array("h")
    a.frombytes(pcm[:len(pcm) - len(pcm) % (2 * channels)])
    return a[0::channels].tobytes()


# ---------------------------------------------------------------------------- session

class RtpMedia:
    muted = False
    """One call's media.  call: shannon_ims.Call (rtp_sock bound by the UA)."""

    def __init__(self, sock, log, audio=None, codec_factory=None, rtcp=True, aec=None):
        self.sock, self.log = sock, log
        self.audio = audio or {}           # dict(play_cmd, rec_cmd, rec_channels), callable(rate) -> that, or None
        self.codec_factory = codec_factory or AmrCodec
        self.stop_ev = threading.Event()
        self.threads = []
        self.dtmf_q = []
        self.lock = threading.Lock()
        self.ssrc = random.getrandbits(32)
        self.seq = random.getrandbits(16)
        self.ts = random.getrandbits(32)
        self.remote = None
        self.rtcp_sock = None
        self.want_rtcp = rtcp
        self.stats = dict(tx=0, rx=0, bad=0, dtmf=0)
        self.procs = []
        self.pcm_in = None                 # test hook: callable() -> 20 ms PCM
        self.pcm_out = None                # test hook: callable(pcm)
        self.aec_factory = aec             # callable(samples, rate) -> SpeexAec-like, or None
        self.aec = None

    def start(self, remote_ip, remote_port, codec):
        self.codec_info = codec
        self.name = codec.name
        self.rate = RATE[self.name]
        modes = codec.mode_set or ([0, 1, 2, 3, 4, 5, 6, 7] if self.name == "AMR"
                                   else [0, 1, 2, 3, 4, 5, 6, 7, 8])
        # AMR-WB 12.65 (mode 2) is the IMS default rate; best NB mode 7 (12.2)
        self.mode = (2 if 2 in modes else max(modes)) if self.name == "AMR-WB" else max(modes)
        self.modes = modes
        self.codec = self.codec_factory(self.name, self.mode)
        if self.aec_factory:
            try:
                self.aec = self.aec_factory(self.codec.samples, self.rate)
                self.log("media: echo canceller on")
            except Exception as e:             # optional: the call works without it
                self.log(f"media: echo canceller unavailable: {e}")
                self.aec = None
        info = socket.getaddrinfo(remote_ip, remote_port, self.sock.family, socket.SOCK_DGRAM)
        self.remote = info[0][4]
        if self.want_rtcp:
            try:
                self.rtcp_sock = socket.socket(self.sock.family, socket.SOCK_DGRAM)
                self.rtcp_sock.bind((self.sock.getsockname()[0], self.sock.getsockname()[1] + 1))
            except OSError:
                self.rtcp_sock = None
        self.jb = JitterBuffer()
        if callable(self.audio):
            self.audio = self.audio(self.rate)        # dict(play_cmd, rec_cmd, rec_channels)
        if self.audio and self.pcm_in is None:
            self._start_audio()
        for fn in (self._rx_loop, self._tx_loop):
            t = threading.Thread(target=fn, daemon=True, name=fn.__name__)
            t.start()
            self.threads.append(t)

    def _start_audio(self):
        play, rec, self.rec_ch = self.audio["play_cmd"], self.audio["rec_cmd"], \
            self.audio.get("rec_channels", 1)
        self.play_p = subprocess.Popen(play, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
        self.rec_p = subprocess.Popen(rec, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, start_new_session=True)
        self.procs = [self.play_p, self.rec_p]
        n = self.codec.samples * 2 * self.rec_ch

        def pcm_in():
            buf = b""
            while len(buf) < n and not self.stop_ev.is_set():
                r, _, _ = select.select([self.rec_p.stdout], [], [], 0.5)
                if not r:
                    continue
                d = os.read(self.rec_p.stdout.fileno(), n - len(buf))
                if not d:
                    self.stop_ev.wait(0.02)
                    return None
                buf += d
            return downmix_first(buf, self.rec_ch)

        def pcm_out(pcm):
            try:
                self.play_p.stdin.write(upmix4(pcm))
                self.play_p.stdin.flush()
            except (OSError, ValueError):
                pass
        self.pcm_in, self.pcm_out = pcm_in, pcm_out

    def _rx_loop(self):
        cmr_seen = 15
        while not self.stop_ev.is_set():
            r, _, _ = select.select([self.sock], [], [], 0.3)
            if not r:
                continue
            try:
                pkt, src = self.sock.recvfrom(2048)
            except OSError:
                break
            p = rtp_parse(pkt)
            if not p:
                self.stats["bad"] += 1
                continue
            pt, seq, ts, ssrc, marker, payload = p
            if pt != self.codec_info.pt:
                continue                            # DTMF/comfort noise from the far end
            try:
                cmr, frames = amr_unpack(self.name, payload, self.codec_info.octet_align)
            except ValueError:
                self.stats["bad"] += 1
                continue
            self.stats["rx"] += 1
            if cmr != 15 and cmr != cmr_seen and cmr in self.modes:
                cmr_seen = cmr
                with self.lock:
                    self.mode = cmr
                    self.codec.mode = cmr
            for k, (ft, q, data) in enumerate(frames):
                self.jb.put((seq + k) & 0xFFFF if len(frames) > 1 else seq,
                            frame_to_storage(self.name, ft, q, data) if ft != NO_DATA else b"")

    def _tx_loop(self):
        first = True
        samples = self.codec.samples
        next_t = time.monotonic()
        while not self.stop_ev.is_set():
            if self.pcm_in:
                pcm = self.pcm_in()
                if pcm is None:
                    continue
            else:
                next_t += 0.02
                self.stop_ev.wait(max(0, next_t - time.monotonic()))
                pcm = b"\0" * samples * 2
            # downlink: one frame per tick
            f = self.jb.pop()
            out = None
            if self.pcm_out:
                if f is False:
                    out = b"\0" * samples * 2
                else:
                    try:
                        out = self.codec.decode(f or None)
                    except Exception:
                        out = b"\0" * samples * 2
                self.pcm_out(out)
            # uplink
            if self._send_dtmf_step():
                self.ts += samples
                continue
            if self.aec:
                try:
                    pcm = self.aec.process(pcm, out or b"\0" * samples * 2)
                except Exception as e:
                    self.log(f"media: echo canceller failed, off: {e!r}")
                    self.aec = None
            if self.muted:                   # GNOME Calls mute: send silence (DTX)
                pcm = b"\0" * samples * 2
            with self.lock:
                frame = self.codec.encode(pcm)
            ft, q, data = storage_to_frame(frame)
            payload = amr_pack(self.name, [(ft, q, data)], 15, self.codec_info.octet_align)
            self._send(self.codec_info.pt, payload, first)
            first = False
            self.ts += samples

    def _send(self, pt, payload, marker=False, ts=None):
        pkt = rtp_header(pt, self.seq, self.ts if ts is None else ts, self.ssrc, marker) + payload
        self.seq = (self.seq + 1) & 0xFFFF
        try:
            self.sock.sendto(pkt, self.remote)
            self.stats["tx"] += 1
        except OSError:
            pass

    def dtmf(self, digit):
        ev = DTMF_EVENTS.get(str(digit).upper())
        info = getattr(self, "codec_info", None)       # None: start() not reached yet
        if ev is None or info is None or info.te_pt is None:
            return False
        with self.lock:
            self.dtmf_q.append([ev, 0, None])
        return True

    def _send_dtmf_step(self):
        """RFC 4733: one event packet per 20 ms for 100 ms, then 3 end packets."""
        with self.lock:
            if not self.dtmf_q:
                return False
            d = self.dtmf_q[0]
        ev, n, start_ts = d
        if start_ts is None:
            d[2] = start_ts = self.ts
        step = self.codec.samples
        if n < 5:
            self._send(self.codec_info.te_pt, dtmf_payload(ev, False, 10, step * (n + 1)),
                       marker=n == 0, ts=start_ts)
        else:
            self._send(self.codec_info.te_pt, dtmf_payload(ev, True, 10, step * 5), ts=start_ts)
        d[1] += 1
        if d[1] >= 8:
            with self.lock:
                self.dtmf_q.pop(0)
            self.stats["dtmf"] += 1
        return True

    def stop(self):
        self.stop_ev.set()
        for p in self.procs:
            try:
                os.killpg(p.pid, 15)
            except OSError:
                pass
        for t in self.threads:
            t.join(1)
        for p in self.procs:
            try:
                p.wait(2)
            except subprocess.TimeoutExpired:
                p.kill()
        if self.rtcp_sock:
            self.rtcp_sock.close()
        self.sock.close()
        try:
            if self.aec:
                self.aec.close()
        except Exception:
            pass
        try:
            if getattr(self, "codec", None):
                self.codec.close()
        except Exception:
            pass
        jb = getattr(self, "jb", None)
        self.log(f"media: stopped: {self.stats['tx']} packets sent, {self.stats['rx']} received, "
                 f"{self.stats['bad']} bad, {jb.lost if jb else 0} lost/concealed, "
                 f"{self.stats['dtmf']} DTMF")
