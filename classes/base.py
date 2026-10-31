"""The contract every sweep class implements.

A class is a fingerprint, not a port list. `probe()` must identify a device from
what it says, and the verdict vocabulary below is the whole point: it separates
"found it" from "did not answer" from "not there", because collapsing those three
is the exact failure that produced three false clean sweeps earlier.

    hit      a named device was identified. The only verdict that is a finding.
    open     something answered but was not identified. Evidence, not a result.
    unproven nothing came back and there is no evidence either way. NEVER closure.
    refused  an explicit RST. Real evidence the port is closed.
    error    a local failure (route, permission, timeout on a TLS handshake).
"""

from __future__ import annotations

import re as _re

VERDICTS = ("hit", "open", "unproven", "refused", "error")

def res(verdict, product="", detail="", rtt=None):
    assert verdict in VERDICTS, verdict
    return {"verdict": verdict, "product": product, "detail": detail, "rtt": rtt}

class SweepClass:
    id = "base"
    title = "base"
    tier = "?"
    proto = "tcp"
    ports = (22,)
    population = "operator-all"
    desc = ""
    CONTROLS = ()
    geo_hint = (0.0, 0.0)

    def targets(self, ips):
        """Yield (ip, port). A class can override to do something smarter, such as
        stopping at the first port that answers."""
        for ip in ips:
            for p in self.ports:
                yield ip, p

    def probe(self, ip, port, timeout=3.0, tls=None):
        """Identify the box, or say why you could not.

        `tls` is normally None and the class decides from the port. It is passed
        only when gating against a positive control that lives on a different
        port than the one the class sweeps.
        """
        raise NotImplementedError

    @staticmethod
    def match_any(text, table):
        """First product whose keyword appears in `text` as a word, else None.

        The haystack is a web page or a banner, so plain substring matching is
        wrong by default and the wrongness is invisible: it produces hits, not
        misses. Three real examples from this tree — a PTR classifier read
        `alterego` as LTE and `odorhei` as O-RAN, `canonical` in a <link> tag was
        reported as a Canon printer, and a Prometheus metrics endpoint was graded
        an IPTV encoder because `seconds` contains `nds `.

        So edges are guarded automatically:

          bare keyword      left guard if it begins with a letter, right guard if
                            it ends with one. A DIGIT is allowed after the right
                            guard, because `gxp` must still match `GXP1625` and
                            `scs` must still match `SCS3200` — model numbers are
                            exactly what these tables exist to catch.
          `!keyword`        both edges unconditionally (no digit may follow).
          `~keyword`        unguarded substring, for a fragment like `ds-2cd` that
                            is a product-code prefix rather than a word.

        A guard on an edge that is not alphanumeric is skipped, so `"nsg "` keeps
        its own trailing space as the boundary.
        """
        low = (text or "").lower()
        for product, keys in table:
            for k in keys:
                if k.startswith("~"):
                    if k[1:] in low:
                        return product
                    continue
                forced = k.startswith("!")
                tok = k[1:] if forced else k
                if not tok:
                    continue
                pat = ""
                if forced and tok[0].isalnum():
                    pat += r"(?<![a-z0-9])"
                elif not forced and tok[0].isalpha():
                    pat += r"(?<![a-z])"
                pat += _re.escape(tok)
                if forced and tok[-1].isalnum():
                    pat += r"(?![a-z0-9])"
                elif not forced and tok[-1].isalpha():
                    pat += r"(?![a-z])"
                if _re.search(pat, low):
                    return product
        return None
