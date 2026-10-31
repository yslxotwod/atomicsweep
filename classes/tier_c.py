"""Tier C — the sleeper.

Tier C does not look for a login page. It reads the certificate the box presents
and asks who signed it.

A device certificate is the one thing a redirect, a captive portal or a port
forward cannot fake: to be trusted by the vendor's own management plane an ONT
or an eNB must present a cert chained to that vendor's device CA. A Ruckus
access point found during development is the proof: it presents a
`CN=SN-<serial>, O=Ruckus Wireless Inc.` certificate, issued by
`RuckusPKI-DeviceSubCA-1`, valid 2019-2044, with no authentication of any kind.
The serial number and model are simply published in the certificate.
"""

from __future__ import annotations

import re

from core import net
from classes.base import SweepClass, res

PKI_TABLE = [
    ("Ruckus device PKI", ["ruckuspk", "ruckus wireless", "ruckuspki-devicesubca"]),
    ("Sercomm device PKI", ["sercomm"]),
    ("Baicells device PKI", ["baicells"]),
    ("Cambium device PKI", ["cambium"]),
    ("Calix device PKI", ["calix"]),
    ("Adtran device PKI", ["adtran"]),
    ("Huawei device PKI", ["huawei", "hiSilicon"]),
    ("ZTE device PKI", ["zte"]),
    ("Nokia/Alcatel device PKI", ["nokia", "alcatel"]),
    ("Ubiquiti device PKI", ["ubiquiti", "ui.com"]),
    ("MikroTik device PKI", ["mikrotik"]),
    ("Airspan device PKI", ["airspan"]),
    ("Cisco device PKI", ["cisco"]),
    ("Sagemcom device PKI", ["sagemcom"]),
    ("Technicolor device PKI", ["technicolor"]),
    ("Fiberhome device PKI", ["fiberhome"]),
]

SERIAL_CN = re.compile(
    r"^(?:SN[-_]?|S/N[-_]?)?([A-Z0-9]{6,}(?:[-][A-Z0-9]{4,}){1,}|[A-Z]{2,}[0-9]{6,})$",
    re.I,
)

class DevicePki(SweepClass):
    id = "c1_pki"
    title = "Device PKI harvest"
    tier = "C"
    proto = "tls"
    ports = (443, 8443, 8081)
    population = "operator-all"
    desc = ("Reads the certificate and asks who signed it. A vendor device CA names "
            "the model and the serial with no authentication — Ruckus "
            "DeviceSubCA-1 on 85.255.110.5 is the confirmed example. Builds a "
            "model-and-firmware inventory without touching a login.")
    geo_hint = (40.0, 20.0)
    CONTROLS = (("85.255.110.5", 443, "hit"),)

    def targets(self, ips):
        for ip in ips:
            yield ip, 443

    def probe(self, ip, port, timeout=4.0, tls=None):
        p = net.tls_peer(ip, port, max(4.0, timeout))
        if p.state == net.UNPROVEN:
            return res("unproven", "", p.detail)
        if p.state != net.OPEN:
            return res("refused" if p.state == net.REFUSED else "error", "", p.detail)

        ex = p.extra or {}
        issuer = f"{ex.get('issuer_cn', '')} {ex.get('issuer', '')}".strip()
        subject = f"{ex.get('cn', '')} {ex.get('subject', '')} {ex.get('org', '')}".strip()
        blob = f"{issuer} {subject}"

        hit = self.match_any(blob, PKI_TABLE)
        cn = ex.get("cn", "") or ""
        serial_like = bool(SERIAL_CN.match(cn)) or cn.upper().startswith("SN")

        if hit:
            detail = f"CN={cn[:40]} issuer={ex.get('issuer_cn', '')[:36]}"
            if serial_like:
                detail += " [device serial in CN]"
            nb, na = ex.get("not_before", ""), ex.get("not_after", "")
            if nb and na:
                detail += f" {nb}..{na}"
            return res("hit", hit, detail, p.rtt)

        if serial_like:
            return res("hit", "unnamed device PKI",
                       f"CN={cn[:40]} issuer={ex.get('issuer_cn', '')[:36]}", p.rtt)

        if ex.get("cn") or ex.get("subject"):
            return res("open", "", f"web cert CN={cn[:40]}", p.rtt)
        return res("open", "", "tls handshake without a readable certificate", p.rtt)
