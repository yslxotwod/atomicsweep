"""Small shared helpers for the fingerprint classes.

Every class here answers one question — "what IS this box" — from content, never
from a port number. These helpers exist so the eight new tiers do not each grow
their own HTTP client, JSON reader and banner decoder, because when they do the
classes drift apart and a fix in one never reaches the others.

Two conventions the callers rely on:

  * `get()`/`post()` take an explicit `tls` flag rather than inferring it from the
    port. Port 443 is not TLS (one Ruckus box checked during development answered plain
    GoAhead on it) and port 8081 is TLS on a Cambium and plain on a Huawei.
  * `body_get` returns "" for a body it could not read, so a matcher can never
    mistake a transport failure for a negative answer.
"""

from __future__ import annotations

import json
import re

from core import net

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

def get(ip, port, path="/", timeout=4.0, tls=False, host=None, max_body=65536,
        headers=None):
    return net.http_request(ip, port, path, timeout=timeout, tls=tls,
                            host=host, max_body=max_body, headers=headers)

def post(ip, port, path="/", body=b"", timeout=4.0, tls=False, ctype=None,
         headers=None, host=None, max_body=65536):
    h = {"Content-Type": ctype} if ctype else {}
    if headers:
        h.update(headers)
    return net.http_request(ip, port, path, timeout=timeout, tls=tls, method="POST",
                            headers=h, body=body, host=host, max_body=max_body)

def title(text):
    m = TITLE_RE.search(text or "")
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""

def jbody(text):
    """Parsed JSON body, or None. Never raises on a truncated read."""
    t = (text or "").strip()
    if not t or t[0] not in "{[":
        return None
    try:
        return json.loads(t)
    except Exception:
        return None

def u16_le(b, i=0):
    return int.from_bytes(b[i:i + 2], "little") if len(b) >= i + 2 else 0

def u32_le(b, i=0):
    return int.from_bytes(b[i:i + 4], "little") if len(b) >= i + 4 else 0

def printable(b, minlen=5, limit=200):
    """Longest printable ASCII run, for protocol replies with a name inside."""
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % minlen, b or b"")
    if not runs:
        return ""
    runs.sort(key=len, reverse=True)
    return runs[0][:limit].decode("ascii", "replace")

def state_from(r):
    """Map an HttpResult/TCP outcome onto a sweep verdict, or None to continue.

    Returning None means "it answered, keep fingerprinting". Returning a string
    means the class is finished with this target.
    """
    if r.state == net.REFUSED:
        return "refused"
    if r.state == net.UNPROVEN:
        return "unproven"
    if r.state != net.OPEN:
        return "error"
    return None

def server_of(r):
    return (r.headers.get("server") or "").strip()

def looks_auth(r):
    """A challenge, not a finding. Kept in one place so no class forgets."""
    if r.status in (401, 407):
        return True
    w = (r.headers.get("www-authenticate") or "").lower()
    return bool(w)
