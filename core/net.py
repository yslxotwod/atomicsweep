"""Transport probes: TCP, TLS, HTTP, UDP, SNMP.

Two rules decide the shape of everything here, and both come from measurements
made during this work rather than from taste:

1. **Silence is not closure.** ICMP port-unreachable never comes back on this
   egress — tested on ports 500/4500/2123/33445 against four hosts, zero
   unreachable messages, while UDP egress itself works. So a UDP probe that gets
   nothing returns `unproven`, never `closed`. TCP is different: a RST is real
   evidence and is reported as `refused`.

2. **A protocol must never be identified by its port.** Three separate times in
   one sweep a "clean miss" turned out to be an assumption about a port
   rather than evidence about a device. Every classifier here reads the payload
   and nothing else.

Every function returns a `Probe` with an explicit state, and there is no state
that means both "no" and "did not answer".
"""

from __future__ import annotations

import errno
import hashlib
import re
import socket
import ssl
import struct
import threading
import functools
from dataclasses import dataclass, field

OPEN = "open"
REFUSED = "refused"
UNPROVEN = "unproven"
ERROR = "error"

DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

@dataclass
class Probe:
    state: str = UNPROVEN
    detail: str = ""
    data: bytes = b""
    text: str = ""
    rtt: float | None = None
    extra: dict = field(default_factory=dict)

    def __bool__(self):
        return self.state == OPEN

def tcp_connect(ip, port, timeout=3.0):
    """Connect and close. Returns Probe(state=open|refused|unproven|error)."""
    import time
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
        return Probe(OPEN, "connected", rtt=time.time() - t0)
    except ConnectionRefusedError:
        return Probe(REFUSED, "RST", rtt=time.time() - t0)
    except socket.timeout:
        return Probe(UNPROVEN, "timeout", rtt=time.time() - t0)
    except OSError as e:
        if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return Probe(ERROR, f"unreachable:{e.errno}")
        if e.errno == errno.ECONNRESET:
            return Probe(REFUSED, "reset-on-connect", rtt=time.time() - t0)
        return Probe(ERROR, f"os:{e.errno}")
    finally:
        try:
            s.close()
        except OSError:
            pass

def tcp_banner(ip, port, timeout=3.0, send=None, settle=0.6, limit=8192):
    """Connect, optionally send `send`, read whatever arrives.

    A device that accepts and then says nothing is `open` with an empty banner —
    which is a fact about the device, and is reported as such rather than being
    folded into "no service".
    """
    import time
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    buf = b""
    try:
        s.connect((ip, port))
    except ConnectionRefusedError:
        return Probe(REFUSED, "RST")
    except socket.timeout:
        return Probe(UNPROVEN, "timeout")
    except OSError as e:
        return Probe(ERROR, f"os:{e.errno}")
    try:
        if send:
            s.sendall(send)
        s.settimeout(settle)
        deadline = time.time() + timeout
        while len(buf) < limit and time.time() < deadline:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) >= limit:
                break
    finally:
        try:
            s.close()
        except OSError:
            pass
    return Probe(OPEN, "banner" if buf else "silent", data=buf, rtt=time.time() - t0,
                 text=clean_bytes(buf))

def clean_bytes(b):
    """Printable ASCII only — banners carry telnet IAC negotiation and NULs that
    would otherwise wreck a table column and a log line."""
    out = []
    for ch in b[:8192]:
        if 32 <= ch < 127:
            out.append(chr(ch))
        elif ch in (9,):
            out.append(" ")
        elif ch in (10, 13):
            out.append(" ")
    return re.sub(r"\s{2,}", " ", "".join(out)).strip()

def _der_short(b, i, n):
    """Best-effort ASCII string run for certificate field extraction.

    Deliberately not a real DER parser: the fields needed (CN, O, serial) are
    printable runs next to known OIDs, and a full ASN.1 walk would be a lot of
    code for a fingerprint. Anything that cannot be read is left empty rather
    than guessed.
    """
    return b[i:i + n].decode("latin-1", "replace")

def tls_peer(ip, port=443, timeout=4.0, servername=None):
    """Complete a TLS handshake and return the peer certificate fields.

    A device certificate is a fingerprint that cannot be spoofed by a port
    forward: vendor CAs (Ruckus DeviceSubCA, Sercomm, Baicells) and CNs that
    carry a serial number identify model and fleet membership without
    authentication.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    raw = None
    info = {}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=servername or ip) as ss:
                raw = ss.getpeercert(binary_form=True)
                info["tls_version"] = ss.version()
                try:
                    info["cipher"] = ss.cipher()[0]
                except (IndexError, TypeError):
                    info["cipher"] = ""
    except ssl.SSLError as e:
        return Probe(ERROR, f"tls:{e.reason or e}", extra=info)
    except socket.timeout:
        return Probe(UNPROVEN, "timeout", extra=info)
    except ConnectionRefusedError:
        return Probe(REFUSED, "RST", extra=info)
    except OSError as e:
        return Probe(ERROR, f"os:{e.errno}", extra=info)

    if not raw:
        return Probe(OPEN, "no-cert", extra=info)
    info["sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(raw, default_backend())
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        info["serial"] = "%X" % cert.serial_number
        cn = ""
        for attr in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
            cn = attr.value
            break
        info["cn"] = cn
        org = ""
        for attr in cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME):
            org = attr.value
            break
        info["org"] = org
        icn = ""
        for attr in cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
            icn = attr.value
            break
        info["issuer_cn"] = icn
        try:
            info["not_before"] = cert.not_valid_before_utc.isoformat()[:10]
            info["not_after"] = cert.not_valid_after_utc.isoformat()[:10]
        except AttributeError:
            info["not_before"] = str(cert.not_valid_before)[:10]
            info["not_after"] = str(cert.not_valid_after)[:10]
    except Exception:
        info.setdefault("subject", _printable_runs(raw)[:3])
    return Probe(OPEN, "cert", data=raw, extra=info)

def _printable_runs(b, minlen=4):
    runs, cur = [], []
    for ch in b:
        if 32 <= ch < 127:
            cur.append(chr(ch))
        else:
            if len(cur) >= minlen:
                runs.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        runs.append("".join(cur))
    return runs

@dataclass
class HttpResult:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    text: str = ""
    state: str = UNPROVEN
    detail: str = ""
    url: str = ""

    @property
    def ok(self):
        return 200 <= self.status < 400

def http_request(ip, port, path="/", timeout=5.0, tls=False, method="GET",
                 headers=None, body=None, host=None, max_body=262144):
    """One HTTP request, raw sockets. No redirect following by default.

    Following a redirect is how a sweep reports the vendor's cloud portal as if
    it were the device — the TP-Link shells found during development answer `302 ->
    https://192.168.88.245`, a private address. The caller decides what a 302
    means.
    """
    hdrs = {
        "Host": host or ip,
        "User-Agent": DEFAULT_UA,
        "Accept": "*/*",
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)
    if body is not None and "Content-Length" not in hdrs:
        hdrs["Content-Length"] = str(len(body))

    req = [f"{method} {path} HTTP/1.1"]
    for k, v in hdrs.items():
        req.append(f"{k}: {v}")
    req.append("")
    req.append("")
    raw_req = "\r\n".join(req).encode() + (body or b"")

    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            sock = ctx.wrap_socket(sock, server_hostname=host or ip)
        sock.settimeout(timeout)
        sock.sendall(raw_req)
        buf = b""
        while len(buf) < max_body:
            try:
                chunk = sock.recv(16384)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                head, _, rest = buf.partition(b"\r\n\r\n")
                if b"content-length" in head.lower():
                    try:
                        want = int(re.search(rb"content-length:\s*(\d+)", head, re.I).group(1))
                    except (AttributeError, ValueError):
                        want = None
                    if want is not None and len(rest) >= want:
                        break
    except socket.timeout:
        return HttpResult(state=UNPROVEN, detail="timeout")
    except ConnectionRefusedError:
        return HttpResult(state=REFUSED, detail="RST")
    except ssl.SSLError as e:
        return HttpResult(state=ERROR, detail=f"tls:{e.reason or e}")
    except OSError as e:
        return HttpResult(state=ERROR, detail=f"os:{e.errno}")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if not buf:
        return HttpResult(state=OPEN, detail="empty")
    head, _, bodyb = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = 0
    m = re.match(rb"HTTP/\d\.\d\s+(\d+)", lines[0] if lines else b"")
    if m:
        status = int(m.group(1))
    h = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        if k:
            h[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return HttpResult(status=status, headers=h, body=bodyb,
                      text=bodyb.decode("utf-8", "replace"),
                      state=OPEN if status else UNPROVEN,
                      detail="" if status else "no-status-line")

def udp_exchange(ip, port, payload, timeout=3.0, tries=2):
    """Send and wait. Silence is UNPROVEN — see the module docstring."""
    import time
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        for _ in range(max(1, tries)):
            s.sendto(payload, (ip, port))
            try:
                data, _addr = s.recvfrom(65535)
                if data:
                    return Probe(OPEN, "answered", data=data, rtt=time.time() - t0,
                                 text=clean_bytes(data))
            except socket.timeout:
                continue
            except OSError as e:
                return Probe(ERROR, f"os:{e.errno}")
        return Probe(UNPROVEN, "silent")
    finally:
        try:
            s.close()
        except OSError:
            pass

def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out

def _ber(tag, val):
    return bytes([tag]) + _ber_len(len(val)) + val

def _ber_int(n):
    if n == 0:
        return b"\x02\x01\x00"
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    if out[0] & 0x80:
        out = b"\x00" + out
    return _ber(0x02, out)

def _oid(oid):
    parts = [int(p) for p in oid.strip(".").split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            chunk = [p & 0x7F]
            p >>= 7
            while p:
                chunk.insert(0, (p & 0x7F) | 0x80)
                p >>= 7
            body += bytes(chunk)
    return _ber(0x06, body)

def snmp_build_get(community, oid="1.3.6.1.2.1.1.1.0", version=1):
    """A minimal, byte-exact SNMPv1 GET.

    Exists because the earlier SNMP work went through one process per
    request, which made a 20k-host sweep cost ~100k process spawns and never
    finished. This is one datagram.
    """
    varbind = _ber(0x30, _oid(oid) + _ber(0x05, b""))
    vbl = _ber(0x30, varbind)
    pdu = _ber(0xA0, _ber_int(1) + _ber_int(0) + _ber_int(0) + vbl)
    msg = _ber(0x30, _ber_int(version) + _ber(0x04, community.encode()) + pdu)
    return msg

def snmp_get(ip, community="public", oid="1.3.6.1.2.1.1.1.0", timeout=2.0,
             port=161, version=1):
    pkt = snmp_build_get(community, oid, version)
    r = udp_exchange(ip, port, pkt, timeout=timeout, tries=1)
    if r.state == OPEN:
        r.text = snmp_extract_string(r.data) or clean_bytes(r.data)
    return r

def snmp_extract_string(data):
    """Pull the longest printable OCTET STRING out of a GetResponse.

    A sysDescr is the answer; picking the longest readable run is what makes this
    work across vendors without a full BER walk. The earlier decoder in this
    a peer mis-nested long-form lengths and returned EMPTY for a 151-byte
    reply, which turned every hit into "UNKNOWN-ANSWERS".
    """
    runs = _printable_runs(data, minlen=4)
    runs = [r for r in runs if not r.isdigit() and len(r) > 4]
    if not runs:
        return ""
    runs.sort(key=len, reverse=True)
    return runs[0]

_ev = threading.local()
EV_RING = 3
EV_TEXT = 400
EV_HEADERS = ("server", "x-jenkins", "x-influxdb-version", "www-authenticate",
              "genieacs-version", "location", "content-type", "x-powered-by",
              "realm", "x-frame-options")

def clear_evidence():
    """Forget the ring for this thread. The engine calls this before each probe."""
    _ev.ring = []

def take_evidence():
    """Return and clear the exchanges this thread recorded since the last clear."""
    ring = getattr(_ev, "ring", [])
    _ev.ring = []
    return ring

def _ev_text(t):
    if not t:
        return ""
    t = " ".join(str(t).split())
    return t[:EV_TEXT] + ("…" if len(t) > EV_TEXT else "")

def record(fn_name, ip, port, result, note=""):
    """Append one exchange to this thread's ring. Never raises."""
    try:
        ring = getattr(_ev, "ring", None)
        if ring is None:
            ring = _ev.ring = []
        if len(ring) >= EV_RING:
            return
        item = {"via": fn_name, "target": f"{ip}:{port}", "note": note,
                "state": getattr(result, "state", ""),
                "detail": getattr(result, "detail", ""),
                "rtt": getattr(result, "rtt", None)}
        status = getattr(result, "status", None)
        if status is not None:
            item["status"] = status
            hdrs = getattr(result, "headers", {}) or {}
            picked = {k: v for k, v in hdrs.items() if k in EV_HEADERS}
            if picked:
                item["headers"] = picked
        text = _ev_text(getattr(result, "text", ""))
        if text:
            item["text"] = text
        extra = getattr(result, "extra", None)
        if extra:
            item["extra"] = {k: _ev_text(v) for k, v in list(extra.items())[:8]}
        ring.append(item)
    except Exception:
        pass

def _recorded(fn):
    """Wrap a transport so its result lands in the ring without touching callers."""
    @functools.wraps(fn)
    def wrapper(ip, port, *a, **kw):
        r = fn(ip, port, *a, **kw)
        note = ""
        if kw.get("path"):
            note = kw["path"]
            if kw.get("method") and kw["method"] != "GET":
                note = f"{kw['method']} {note}"
        elif a and isinstance(a[0], str) and a[0].startswith("/"):
            note = a[0]
        record(fn.__name__, ip, port, r, note)
        return r
    return wrapper

tcp_connect = _recorded(tcp_connect)
tcp_banner = _recorded(tcp_banner)
tls_peer = _recorded(tls_peer)
http_request = _recorded(http_request)
udp_exchange = _recorded(udp_exchange)
snmp_get = _recorded(snmp_get)
