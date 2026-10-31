"""Tier A — the shell on operator kit.

These are the boxes that, if reachable, are closer to the network than any
customer premises equipment: console servers with serial lines into routers and
basebands, OLT management planes that terminate every ONT behind them, NETCONF
daemons that intend to be configured, and router families with a policy banner.
"""

from __future__ import annotations

import re

from core import net
from classes.base import SweepClass, res

CONSOLE_TABLE = [
    ("Lantronix ETS/SCS", ["lantronix", "ets16", "ets32", "scs", "slc8", "slc16", "slc48"]),
    ("Avocent/Cyclades", ["avocent", "cyclades", "dsr102", "dsr2020", "alterpath", "acs6000"]),
    ("Digi PortServer", ["digi ", "portserver", "digi transport", "digi passport", "digi cm"]),
    ("Moxa NPort", ["moxa", "nport", "ioport"]),
    ("Perle IOLAN", ["perle", "iolan", "sds-"]),
    ("Opengear", ["opengear", "acm500", "console server"]),
    ("Raritan Dominion", ["raritan", "dominion", "kvm switch"]),
    ("Aten/Altusen", ["aten", "altusen"]),
    ("WTI / Baytech", ["western telematic", "wti-", "baytech", "rcp-"]),
    ("Terminal server (generic)", ["console server", "serial server", "terminal server",
                                   "rs232", "serial over ip"]),
]

CONSOLE_PORTS = (23, 22, 2001, 3001, 771, 4001, 7001, 5000)

class ConsoleServers(SweepClass):
    id = "a1_console"
    title = "Console / serial servers"
    tier = "A"
    proto = "tcp"
    ports = CONSOLE_PORTS
    population = "operator-all"
    desc = ("Serial lines into routers and basebands. Telnet/SSH banner plus the "
            "raw serial-over-TCP ports (2001, 3001, 771, 7001) that devices often "
            "leave open when the login is disabled.")
    geo_hint = (20.0, 10.0)
    CONTROLS = ()

    def targets(self, ips):
        for ip in ips:
            yield ip, 23
            yield ip, 22
            yield ip, 2001
            yield ip, 3001
            yield ip, 771
            yield ip, 7001

    def probe(self, ip, port, timeout=3.0, tls=None):
        p = net.tcp_banner(ip, port, timeout, settle=min(1.2, timeout))
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state != net.OPEN:
            return res("unproven", "", p.detail)
        text = p.text
        if port in (23, 22) and not text:
            p2 = net.tcp_banner(ip, port, timeout, send=b"\xff\xfb\x01\xff\xfb\x03",
                                settle=min(1.0, timeout))
            text = p2.text or text
        m = self.match_any(text, CONSOLE_TABLE)
        if m:
            return res("hit", m, text[:160], p.rtt)
        if port == 23 and text:
            return res("open", "", "telnet:" + text[:120], p.rtt)
        if text:
            return res("open", "", f"{port}:" + text[:120], p.rtt)
        return res("open", "", f"{port}: silent accept", p.rtt)

OLT_TABLE = [
    ("Huawei MA5600T/MA5800", ["huawei versatile routing platform", "ma5600", "ma5680",
                               "ma5800", "ea5800", "smartax", "quidway"]),
    ("ZTE ZXA10", ["zxA10", "zxa10", "c320", "c300", "c220", "zte olt", "zxan"]),
    ("Nokia/Alcatel ISAM", ["7360 isam", "7302 isam", "isam ", "alcatel-lucent",
                            "nokia isam", "7750"]),
    ("Calix E7/E9", ["calix", "e7-2", "e9-2", "c7-"]),
    ("Adtran TA/SDH", ["adtran", "total access", "ta5000", "ta1248"]),
    ("Fiberhome AN", ["fiberhome", "an5516", "an5116"]),
    ("DZS / Zhone", ["zhone", "dzs", "mxk-"]),
    ("Unnamed PON access node (vendor not identified)", ["olt", "xgs-pon"]),
]

ONT_TABLE = [
    ("Huawei ONT (HG/EG series)", ["hg8245", "hg8546", "hg8010", "eg8145", "eg8245",
                                   "echolife"]),
    ("ZTE ONT (ZXHN)", ["zxhn", "f660", "f670", "f601"]),
    ("Nokia/Alcatel ONT (G-240W)", ["g-240w", "g-140w", "g-010s"]),
    ("Fiberhome ONT", ["an5506", "hg6145"]),
    ("Generic GPON ONT / home gateway", ["gpon home gateway", "ont ", "onu "]),
]

OLT_PORTS = (22, 23, 80, 443, 8080, 8443)

class OltMgmt(SweepClass):
    id = "a2_olt"
    title = "OLT management planes"
    tier = "A"
    proto = "http/telnet"
    ports = OLT_PORTS
    population = "operator-all"
    desc = ("The box on the other end of every ONT already reached: Huawei MA5600T/"
            "MA5800, ZTE C320, Nokia 7360 ISAM, Calix E7. Identified from the HTTP "
            "title or the telnet/SSH banner, never from the port number.")
    geo_hint = (20.0, 10.0)
    CONTROLS = ()

    def targets(self, ips):
        for ip in ips:
            yield ip, 23
            yield ip, 22
            yield ip, 80
            yield ip, 443

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port in (80, 443, 8080, 8443):
            use_tls = (port in (443, 8443)) if tls is None else tls
            r = net.http_request(ip, port, "/", timeout=max(4.0, timeout),
                                 tls=use_tls)
            if r.state == net.REFUSED:
                return res("refused", "", "RST")
            if r.state != net.OPEN:
                return res("unproven", "", r.detail)
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            server = r.headers.get("server", "")
            blob = f"{title} {server} {r.text[:1500]}"

            ont = self.match_any(blob, ONT_TABLE)
            if ont:
                return res("open", f"{ont} — customer side, not an access node",
                           f"title={title!r}")
            hit = self.match_any(blob, OLT_TABLE)
            if hit:
                return res("hit", hit, f"{title} | {server}".strip(" |"))
            if r.status:
                return res("open", "", f"http {r.status} {title} {server}".strip())
            return res("unproven", "", "no status line")
        p = net.tcp_banner(ip, port, timeout, settle=min(1.2, timeout),
                           send=b"\xff\xfb\x01\xff\xfb\x03" if port == 23 else None)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state != net.OPEN:
            return res("unproven", "", p.detail)
        m = self.match_any(p.text, OLT_TABLE)
        if m:
            return res("hit", m, p.text[:160], p.rtt)
        return res("open", "", (p.text[:120] or "silent accept"), p.rtt)

NETCONF_HELLO = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
    b'<capabilities><capability>urn:ietf:params:netconf:base:1.0</capability>'
    b'</capabilities></hello>]]>]]>'
)

NETCONF_TABLE = [
    ("Tail-f ConfD", ["tail-f", "confd"]),
    ("Juniper Junos", ["juniper", "junos"]),
    ("Cisco IOS-XE/NX-OS", ["cisco", "ios-xe", "nx-os"]),
    ("Huawei VRP", ["huawei", "vrp"]),
    ("Nokia SR/ISAM", ["nokia", "alcatel", "srlinux", "isam"]),
    ("Ciena", ["ciena", "saos"]),
    ("ZTE", ["zte", "zxros"]),
    ("Arista EOS", ["arista", "eos"]),
    ("Adva / ADTRAN", ["adva", "adtran"]),
    ("NETCONF server (unnamed)", ["urn:ietf:params:netconf"]),
]

class NetconfYang(SweepClass):
    id = "a3_netconf"
    title = "NETCONF / YANG servers"
    tier = "A"
    proto = "netconf"
    ports = (830, 6513)
    population = "operator-all"
    desc = ("Port 830 is meaningless on its own — the discriminator is WHICH YANG "
            "server answers the hello and which capability set it declares. Live "
            "control: ConfD 6.4.4 at 176.29.176.230 (Zain Jordan).")
    geo_hint = (30.0, 35.0)
    CONTROLS = (("176.29.176.230", 830, "hit"),)

    def targets(self, ips):
        for ip in ips:
            yield ip, 830

    def probe(self, ip, port, timeout=4.0, tls=None):
        p = net.tcp_banner(ip, port, max(4.0, timeout), send=NETCONF_HELLO,
                           settle=min(3.0, max(2.0, timeout)))
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state != net.OPEN:
            return res("unproven", "", p.detail)
        text = p.text
        ssh = text[:120] if text.upper().startswith("SSH-") else ""
        if "hello" not in text.lower() and "capabilit" not in text.lower():
            if ssh:
                m = self.match_any(ssh, NETCONF_TABLE)
                if m:
                    return res("hit", m, "ssh banner: " + ssh.strip()[:70], p.rtt)
                return res("open", "", "ssh " + ssh.strip()[:80], p.rtt)
            return res("open", "", (text[:120] or "silent accept"), p.rtt)
        hit = self.match_any(text, NETCONF_TABLE)
        caps = len(re.findall(r"<capability>", text))
        detail = f"{caps} capabilities"
        mods = re.findall(r"module=([A-Za-z0-9_-]+)", text)
        if mods:
            detail += " | " + ",".join(sorted(set(mods))[:6])
        return res("hit", hit or "NETCONF server", detail, p.rtt)

ROUTER_TABLE = [
    ("Cisco IOS", ["cisco ios", "ios software", "cisco internetwork"]),
    ("Cisco IOS-XR", ["ios xr", "ios-xr"]),
    ("Juniper Junos", ["junos", "juniper"]),
    ("MikroTik RouterOS", ["routeros", "mikrotik"]),
    ("Huawei VRP", ["huawei versatile routing platform", "vrp ", "quidway"]),
    ("Nokia SR-OS", ["sr os", "sr-os", "timos", "alcatel"]),
    ("Arista EOS", ["arista", "eos version"]),
    ("VyOS / Vyatta", ["vyos", "vyatta"]),
    ("FortiOS", ["fortigate", "fortios"]),
    ("Zyxel", ["zyxel", "zywall"]),
    ("EdgeOS / Ubiquiti", ["edgeos", "ubiquiti", "edgerouter"]),
    ("RouterOS API greeting", ["!done", "login"]),
]

ROUTER_PORTS = (22, 23, 8728)

class RouterFamilies(SweepClass):
    id = "a4_router"
    title = "Router families"
    tier = "A"
    proto = "tcp"
    ports = ROUTER_PORTS
    population = "operator-all"
    desc = ("Cisco, Junos, RouterOS, VRP, SR-OS, EOS by policy banner on 22/23 and "
            "the RouterOS API on 8728 — the family that answers tells you which "
            "credential surface applies.")
    geo_hint = (45.0, 25.0)
    CONTROLS = (("82.115.58.79", 8291, "open"),)

    def targets(self, ips):
        for ip in ips:
            yield ip, 22
            yield ip, 23

    def probe(self, ip, port, timeout=3.0, tls=None):
        p = net.tcp_banner(ip, port, timeout, settle=min(1.5, timeout),
                           send=b"\r\n" if port == 23 else None)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state != net.OPEN:
            return res("unproven", "", p.detail)
        text = p.text
        hit = self.match_any(text, ROUTER_TABLE)
        if hit:
            return res("hit", hit, text[:160], p.rtt)
        if "ssh-2.0" in text.lower() or "ssh-1.99" in text.lower():
            banner = text.split("SSH-")[-1][:80]
            return res("open", "", "ssh:" + banner, p.rtt)
        if text:
            return res("open", "", text[:120], p.rtt)
        return res("open", "", f"{port}: silent accept", p.rtt)
