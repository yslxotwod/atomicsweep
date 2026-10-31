"""Tier B — management planes.

The distinguishing lesson from this project's ACS work: a CWMP port is not an
ACS. Maroc Telecom answered 2,738 CWMP endpoints on 7547 with zero management
plane behind them; Truth Wireless left the NBI open on 7557 and handed over 122
devices. Same port family, opposite meaning. So every class here keys on the
PRODUCT that answers, and a CPE digest challenge is recorded as `open` — a
customer box — never as a finding.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

from core import net
from classes.base import SweepClass, res

ORACLE = os.path.expanduser("~/oracle/data")

ACS_TABLE = [
    ("GenieACS", ["genieacs", '"total"', '"devices"']),
    ("Axiros AXESS", ["axiros", "axess"]),
    ("LibreACS", ["libreacs"]),
    ("Friendly Tech", ["friendly-tech", "friendly tech"]),
    ("Incognito", ["incognito"]),
    ("Nokia Motive", ["nokia motive", "motive acs", "alcatel acs"]),
    ("Huawei iManager", ["imanager", "huawei acs"]),
    ("AVSystem", ["avsystem", "coap acs"]),
    ("cwmpd / open ACS", ["cwmpd"]),
]

class AcsProduct(SweepClass):
    id = "b1_acs"
    title = "ACS control planes"
    tier = "B"
    proto = "tr-069"
    ports = (7557, 7567, 3000, 7547)
    population = "operator-all"
    desc = ("Keyed on the product, not the port. A 200 with JSON on 7557/7567/3000 "
            "is the door; a 401 digest is a customer box and is NEVER reported as a "
            "finding. Controls: Truth Wireless GenieACS NBI, A1 Belarus.")
    geo_hint = (0.0, 20.0)
    CONTROLS = (("102.212.11.170", 7557, "hit"),)

    def targets(self, ips):
        for ip in ips:
            yield ip, 7557
            yield ip, 7567
            yield ip, 3000
            yield ip, 7547

    def probe(self, ip, port, timeout=3.0, tls=None):
        r = net.http_request(ip, port, "/", timeout=max(4.0, timeout), max_body=65536)
        if r.state == net.REFUSED:
            return res("refused", "", "RST")
        if r.state == net.UNPROVEN:
            return res("unproven", "", r.detail)
        if r.state != net.OPEN:
            return res("error", "", r.detail)

        ver = r.headers.get("genieacs-version") or r.headers.get("x-genieacs-version")
        body = r.text.strip()
        auth = r.headers.get("www-authenticate", "")
        server = r.headers.get("server", "")

        if ver:
            detail = f"GenieACS {ver}"
            total = re.search(r'"total"\s*:\s*(\d+)', body)
            if total:
                detail += f" total={total.group(1)}"
            return res("hit", "GenieACS NBI", detail)

        if r.status == 200 and body[:1] in "[{" and port in (7557, 7567, 3000):
            try:
                json.loads(body)
                n = "?"
                m = re.search(r'"total"\s*:\s*(\d+)', body)
                if m:
                    n = m.group(1)
                return res("hit", "ACS NBI (unnamed)", f"json collection total={n}")
            except json.JSONDecodeError:
                pass

        if r.status == 401:
            realm = ""
            m = re.search(r'realm="([^"]*)"', auth, re.I)
            if m:
                realm = m.group(1)
            scheme = auth.split()[0] if auth else "?"
            return res("open", f"CPE ({scheme})", f"401 realm={realm[:40]} {server}".strip())

        if "soap" in body.lower() or "gsoap" in server.lower() or r.status in (404, 405):
            fault = re.search(r"<faultstring>(.*?)</faultstring>", body, re.I | re.S)
            detail = f"http {r.status} {server}".strip()
            if fault:
                detail += " fault=" + re.sub(r"\s+", " ", fault.group(1))[:60]
            return res("open", "CWMP stack", detail)

        hit = self.match_any(f"{server} {body[:400]}", ACS_TABLE)
        if hit and r.status == 200:
            return res("hit", hit, f"http {r.status} {server}".strip())

        if r.status:
            return res("open", "", f"http {r.status} {server}".strip())
        return res("unproven", "", "no status line")

class ConnReqMap(SweepClass):
    id = "b2_connreq"
    title = "Connection-request map"
    tier = "B"
    proto = "tr-069"
    ports = (7547, 58000)
    population = "custom"
    desc = ("Every ConnectionRequestURL harvested from an ACS estate, probed for "
            "reachability from outside. The Telekabel addresses time out at TCP "
            "level — firewalled to the ACS's own source — and that is the finding: "
            "the wakeup path is one-directional.")
    geo_hint = (41.6, 21.7)
    CONTROLS = ()

    def targets(self, ips):
        for ip in ips:
            yield ip, 7547

    def probe(self, ip, port, timeout=4.0, tls=None):
        p = net.tcp_connect(ip, port, timeout)
        if p.state == net.OPEN:
            b = net.tcp_banner(ip, port, timeout, settle=min(1.0, timeout))
            return res("hit", "connection-request reachable",
                       (b.text[:80] or "accepts from outside"), p.rtt)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state == net.UNPROVEN:
            return res("unproven", "", "no SYN-ACK — filtered or absent")
        return res("error", "", p.detail)

WISP_TABLE = [
    ("Cambium cnMaestro", ["cnmaestro", "cambium networks", "cambium"]),
    ("Cambium cnPilot", ["cnpilot", "cnmatrix", 'ng-app="falcon"']),
    ("Cambium ePMP", ["epmp", "pmp450", "pmp1000"]),
    ("Baicells CloudCore", ["baicells", "cloudcore", "neutrino"]),
    ("Ruckus vSZ/SmartZone", ["ruckus", "smartzone", "vsz"]),
    ("Airspan", ["airspan", "airvelocity", "airharmony"]),
    ("Tarana", ["tarana", "gnucl"]),
    ("Mimosa", ["mimosa networks"]),
    ("Ubiquiti UISP", ["uisp", "unms", "ubiquiti"]),
    ("Sercomm", ["sercomm"]),
    ("Parallel Wireless", ["parallel wireless", "parallelwireless"]),
    ("Mavenir", ["mavenir"]),
]

class WispControllers(SweepClass):
    id = "b3_wisp"
    title = "WISP / small-cell controllers"
    tier = "B"
    proto = "https"
    ports = (443, 80, 8443, 8081)
    population = "operator-all"
    desc = ("Cloud controllers for CBRS and WISP small cells — internet-facing by "
            "design. cnMaestro and Cambium cnPilot are confirmed live in this "
            "earlier sweep data.")
    geo_hint = (38.0, -97.0)
    CONTROLS = (("cloud.cambiumnetworks.com", 443, "hit"),
                ("cloudcore.baicells.com", 443, "hit"))

    def targets(self, ips):
        for ip in ips:
            yield ip, 443
            yield ip, 80

    def probe(self, ip, port, timeout=3.0, tls=None):
        tls = port in (443, 8443)
        r = net.http_request(ip, port, "/", timeout=max(4.0, timeout), tls=tls,
                             max_body=131072)
        if r.state == net.REFUSED:
            return res("refused", "", "RST")
        if r.state == net.UNPROVEN:
            return res("unproven", "", r.detail)
        if r.state != net.OPEN:
            return res("error", "", r.detail)

        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
        blob = f"{title} {r.headers.get('server', '')} {r.text[:8000]}"
        hit = self.match_any(blob, WISP_TABLE)
        if hit:
            api = ""
            for probe_path in ("/api/v1/access_token", "/api/login"):
                ar = net.http_request(ip, port, probe_path, timeout=max(4.0, timeout),
                                      tls=tls, max_body=2048)
                if ar.status and ar.status != 404:
                    api = f"{probe_path}->{ar.status}"
                    break
            return res("hit", hit, f"{title} {api}".strip(), None)
        if r.status:
            return res("open", "", f"http {r.status} {title}".strip())
        return res("unproven", "", "no status line")

CPE_TABLE = [
    ("Huawei ONT/HG", ["huawei", "hg8", "hg6", "echoLife", "eg8"]),
    ("ZTE F670/ZXHN", ["zte", "zxhn", "f670", "f660"]),
    ("Nokia/Alcatel G-240W", ["alcatel", "g-240w", "nokia"]),
    ("Calix", ["calix", "844e", "844g"]),
    ("Sercomm", ["sercomm"]),
    ("TP-Link", ["tp-link", "tplink", "archer c", "archer ax", "archer mr", "archer tx"]),
    ("D-Link", ["d-link", "dlink", "dir-"]),
    ("MikroTik", ["mikrotik", "routeros"]),
    ("GoAhead-Webs embedded", ["goahead-webs", "goahead"]),
    ("Boa embedded server", ["boa/0.9"]),
    ("Ruckus", ["ruckus"]),
    ("Sagemcom", ["sagemcom", "fast3686"]),
    ("Zyxel", ["zyxel"]),
    ("Technicolor", ["technicolor", "tg789"]),
    ("Fiberhome", ["fiberhome"]),
]

KNOWN_SHELLS = {
    "e267705c5a20bb22349f1ab945c1b499": "TP-Link cloud UI shell (48,212 B, assets 406)",
}

class CpeWebUi(SweepClass):
    id = "b4_cpeweb"
    title = "CPE / ONT web interfaces"
    tier = "B"
    proto = "http"
    ports = (80, 443, 8080)
    population = "broadband"
    desc = ("Login page identified by body hash and title, not by port. Three "
            "byte-identical TP-Link shells (md5 e267705c…) and a Boa captive portal "
            "were found this way; the hash groups a fleet even with no vendor word "
            "in the page.")
    geo_hint = (0.0, 0.0)
    CONTROLS = (("188.117.236.109", 80, "hit"),)

    def targets(self, ips):
        for ip in ips:
            yield ip, 80
            yield ip, 443

    def probe(self, ip, port, timeout=3.0, tls=None):
        tls = port == 443
        r = net.http_request(ip, port, "/", timeout=max(4.0, timeout), tls=tls,
                             max_body=131072)
        if r.state == net.REFUSED:
            return res("refused", "", "RST")
        if r.state == net.UNPROVEN:
            return res("unproven", "", r.detail)
        if r.state != net.OPEN:
            return res("error", "", r.detail)

        digest = hashlib.md5(r.body).hexdigest()
        size = len(r.body)
        shell = KNOWN_SHELLS.get(digest)
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:60]
        blob = f"{title} {r.headers.get('server', '')} {r.text[:4000]}"
        hit = self.match_any(blob, CPE_TABLE)

        if shell:
            return res("hit", shell, f"md5 {digest[:12]} {size}B {title}".strip())
        if hit:
            return res("hit", hit, f"{title} {size}B md5 {digest[:10]}".strip(), None)
        if r.status == 302:
            loc = r.headers.get("location", "")
            return res("open", "", f"302 -> {loc[:60]}")
        if r.status:
            return res("open", "", f"http {r.status} {size}B {title}".strip())
        return res("unproven", "", "no status line")

class MassResolve:
    """Not a sweep class: the button that runs after a scan finishes.

    Resolves every hit's PTR with the delegation-aware path, and marks a name
    `formulaic` when it merely spells the address back (host-102.59.72.253.…).
    Without that filter a wildcard reverse zone reports a 99.9% naming rate that
    is 100% noise — the exact artifact this matcher already produced once.
    """

    id = "mass_resolve"
    title = "Mass resolver"
    tier = "-"
    proto = "dns"
    ports = ()
    population = "custom"
    desc = "PTR for every hit, with formulaic names flagged rather than counted."
    geo_hint = None
    CONTROLS = ()

    @staticmethod
    def formulaic(addr, name):
        low = name.lower()
        dotted = addr.replace(".", r"\.")
        if re.search(dotted, low):
            return True
        rev = ".".join(reversed(addr.split(".")))
        if rev in low:
            return True
        dashed = addr.replace(".", "-")
        if dashed in low:
            return True
        nums = addr.split(".")
        return all(n in low for n in nums)
