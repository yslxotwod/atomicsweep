"""A tiny resolver, for one address at a time.

Why not `socket.gethostbyaddr`: it goes through nsswitch, so it answers from
`/etc/hosts` and from whatever the local resolver believes, and it collapses
multiple PTR records into one name plus aliases. In one sweep the multiple
answers were the interesting case — one address returned
`host-198.51.100.92.example-isp.net;host-198.51.100.2.example-isp.net`, two
names for one address, which is a fact about the zone rather than about the
host. A resolver that cannot return two answers cannot see that.

So this speaks DNS over UDP directly and returns every PTR in the answer
section. It is deliberately not a general resolver: no recursion control, no
TCP fallback, no DNSSEC, no caching. One question, one answer set, bounded.

The `formulaic` helper is the other half of the honesty rule here. A reverse
zone may be a wildcard that spells the address back —
`198.51.100.77` → `host-198.51.100.77.isp.example` — which produces a 99.9%
"naming rate" that is 100% noise. A name that simply restates the address is
reported as such rather than counted as information.
"""

from __future__ import annotations

import random
import re
import socket
import struct

QTYPE_PTR = 12
QCLASS_IN = 1
STATE_ANSWERED = "answered"
STATE_NXDOMAIN = "nxdomain"
STATE_SILENT = "silent"
STATE_ERROR = "error"

DEFAULT_SERVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")

def _encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        if not label:
            continue
        b = label.encode("idna")
        if len(b) > 63:
            raise ValueError(f"label too long: {label!r}")
        out += bytes([len(b)]) + b
    return out + b"\x00"

def _read_name(msg, off, depth=0):
    """Decode a (possibly compressed) name. Returns (name, next_offset)."""
    if depth > 8:
        raise ValueError("compression loop")
    labels = []
    jumped = False
    start = off
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated pointer")
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                start = off + 2
                jumped = True
            sub, _ = _read_name(msg, ptr, depth + 1)
            labels.append(sub)
            off += 2
            break
        off += 1
        labels.append(msg[off:off + ln].decode("latin-1"))
        off += ln
    return ".".join(x for x in labels if x), (start if jumped else off)

def parse_ptr(msg):
    """Every PTR rdata in the answer section, in order. Raises on malformed input."""
    if len(msg) < 12:
        raise ValueError("short header")
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    names = []
    for _ in range(an):
        _, off = _read_name(msg, off)
        if off + 10 > len(msg):
            raise ValueError("truncated rr")
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rd = msg[off:off + rdlen]
        if rtype == QTYPE_PTR:
            try:
                nm, _ = _read_name(msg, off)
                if nm:
                    names.append(nm.rstrip("."))
            except ValueError:
                pass
        off += rdlen
    return names, rcode

def query_ptr(ip, server, timeout=3.0):
    """One PTR query. Returns (names, state)."""
    try:
        rev = ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
        qname = _encode_name(rev)
    except ValueError:
        return [], STATE_ERROR
    msg = struct.pack(">HHHHHH", random.randrange(0, 65536), 0x0100, 1, 0, 0, 0)
    msg += qname + struct.pack(">HH", QTYPE_PTR, QCLASS_IN)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (server, 53))
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        return [], STATE_SILENT
    except OSError:
        return [], STATE_ERROR
    finally:
        try:
            s.close()
        except OSError:
            pass
    try:
        names, rcode = parse_ptr(data)
    except (ValueError, struct.error):
        return [], STATE_ERROR
    if rcode == 3:
        return [], STATE_NXDOMAIN
    if rcode != 0:
        return [], STATE_ERROR
    return names, STATE_ANSWERED if names else STATE_NXDOMAIN

def ptr_lookup(ip, servers=None, timeout=3.0, tries=2):
    """Ask each server in turn until one answers. Returns (names, state).

    A silent server is not an NXDOMAIN: `STATE_SILENT` means this egress could
    not get an answer out of any resolver, which is a fact about us. Returning
    nxdomain there would turn our own filtering into "this address has no name".
    """
    servers = servers or DEFAULT_SERVERS
    last = STATE_SILENT
    for _ in range(max(1, tries)):
        for srv in servers:
            names, state = query_ptr(ip, srv, timeout)
            if state == STATE_ANSWERED:
                return names, state
            if state == STATE_NXDOMAIN:
                return names, state
            last = state
    return [], last

def formulaic(ip, name):
    """True when the name simply spells the address back.

    Covers `host-198.51.100.77.isp.net`, `77.100.51.198.rev.isp.net` and
    `147-91-130-1.isp.net`, plus the four-octets-in-sequence form. Such a name
    confirms a reverse zone exists and says nothing about the host.
    """
    if not name:
        return True
    low = name.lower().rstrip(".")
    octets = str(ip).split(".")
    if len(octets) != 4:
        return False
    dotted = ".".join(octets)
    rdots = ".".join(reversed(octets))
    if dotted in low or rdots in low:
        return True
    for sep in ("-", "_"):
        if sep.join(octets) in low or sep.join(reversed(octets)) in low:
            return True
    toks = re.findall(r"\d+", low)
    for i in range(len(toks) - 3):
        if toks[i:i + 4] == octets:
            return True
    return False

def selftest():
    """Assertions for the parsers. Returns list of (name, ok, detail)."""
    out = []

    def chk(name, got, want):
        out.append((name, got == want, f"got={got!r} want={want!r}"))

    enc = _encode_name("1.130.91.147.in-addr.arpa")
    chk("encode-starts-with-len", enc[0], 1)
    chk("encode-ends-root", enc[-1], 0)
    chk("encode-label-count", enc.count(b"\x00"), 1)

    qname = _encode_name("1.130.91.147.in-addr.arpa")
    ans_name = _encode_name("host1.example.net")
    rr = b"\xc0\x0c" + struct.pack(">HHIH", QTYPE_PTR, QCLASS_IN, 300, len(ans_name)) + ans_name
    msg = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
           + qname + struct.pack(">HH", QTYPE_PTR, QCLASS_IN) + rr)
    names, rcode = parse_ptr(msg)
    chk("parse-one-ptr", names, ["host1.example.net"])
    chk("parse-rcode", rcode, 0)

    rr2 = rr + (b"\xc0\x0c" + struct.pack(">HHIH", QTYPE_PTR, QCLASS_IN, 300, len(ans_name))
                + _encode_name("host2.example.net"))
    msg2 = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
            + qname + struct.pack(">HH", QTYPE_PTR, QCLASS_IN) + rr2)
    names2, _ = parse_ptr(msg2)
    chk("parse-two-ptrs", names2, ["host1.example.net", "host2.example.net"])

    msg3 = (struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0)
            + qname + struct.pack(">HH", QTYPE_PTR, QCLASS_IN))
    names3, rcode3 = parse_ptr(msg3)
    chk("parse-nxdomain-empty", names3, [])
    chk("parse-nxdomain-rcode", rcode3, 3)

    bad_cases = (
        ("empty", b""),
        ("short-header", b"\x00" * 8),
        ("qd-without-question", struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0)),
        ("truncated-rr", struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c"),
    )
    for label, bad in bad_cases:
        try:
            parse_ptr(bad)
            out.append((f"parse-rejects-{label}", False, "returned without raising"))
        except (ValueError, struct.error):
            out.append((f"parse-rejects-{label}", True, "raised"))
    chk("parse-empty-is-valid", parse_ptr(struct.pack(">HHHHHH", 1, 0x8180, 0, 0, 0, 0)),
        ([], 0))

    chk("form-dotted", formulaic("198.51.100.77", "host-198.51.100.77.isp.net"), True)
    chk("form-reversed", formulaic("198.51.100.77", "77.100.51.198.rev.isp.net"), True)
    chk("form-dashed", formulaic("198.51.100.77", "adsl-198-51-100-77.isp.net"), True)
    chk("form-sequence", formulaic("198.51.100.77", "dsl-198-51-100-77.isp.net"), True)
    chk("form-real-name", formulaic("198.51.100.77", "radiolink01.example-isp.net"), False)
    chk("form-cmts", formulaic("198.51.100.5", "ubr10k-c810-s1b.example-isp.net"), False)
    chk("form-empty", formulaic("198.51.100.77", ""), True)
    return out
