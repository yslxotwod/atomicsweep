"""Tier F — industrial control and energy.

Two families that share one property: the protocol has no authentication in it.
Modbus, DNP3, IEC-104 and S7 were all designed for a serial cable inside a fence,
and every one of them is now reachable over a routed network by accident.

Consequence recorded here so the tool cannot be misread later: a `hit` in this
tier is a statement about reachability, not an invitation. Nothing in these
classes writes a coil, sets a register, or changes a state. Register reads and
identity requests only.
"""

from __future__ import annotations

from core import net
from classes.base import SweepClass, res
from classes import netfp as fp

S7_COTP_CR = bytes.fromhex("0300001611e00000000100c1020100c2020102c0010a")

ENIP_LIST_IDENTITY = bytes.fromhex("63000000") + b"\x00" * 20

def _opcua_hel(url=b"opc.tcp://atomicsweep:4840"):
    body = (b"\x00\x00\x00\x00"
            + (65536).to_bytes(4, "little")
            + (65536).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + len(url).to_bytes(4, "little") + url)
    return b"HELF" + (8 + len(body)).to_bytes(4, "little") + body

OPCUA_HEL = _opcua_hel()
DNP3_RESET = bytes.fromhex("056405c001000004")
IEC104_STARTDT = bytes.fromhex("680407000000")

class Plcs(SweepClass):
    id = "f1_plc"
    title = "Siemens S7 / EtherNet-IP / OPC-UA"
    tier = "F"
    proto = "ot"
    ports = (102, 44818, 4840, 20000, 2404)
    population = "enterprise"
    desc = ("Programmable controllers and the gateways in front of them. EtherNet/IP "
            "ListIdentity names the vendor and model with no credential; OPC-UA "
            "answers an ACK to a HEL; S7 confirms a COTP connection. Identity "
            "requests only — no read or write of process data.")
    geo_hint = (50.0, 8.0)
    CONTROLS = ()

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 102:
            p = net.tcp_banner(ip, 102, timeout=timeout, send=S7_COTP_CR, settle=1.2)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            d = p.data or b""
            if len(d) >= 6 and d[0] == 0x03 and d[5] == 0xD0:
                return res("hit", "Siemens S7 / ISO-TSAP",
                           "COTP Connection Confirm", p.rtt)
            if len(d) >= 3 and d[0] == 0x03:
                return res("open", "ISO-TSAP (COTP reply)", f"{len(d)}B", p.rtt)
            return res("open", "", f"{len(d)}B on 102", p.rtt)

        if port == 44818:
            p = net.tcp_banner(ip, 44818, timeout=timeout,
                               send=ENIP_LIST_IDENTITY, settle=1.2)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            d = p.data or b""
            if len(d) >= 4 and d[:2] == b"\x63\x00":
                name = fp.printable(d[24:], 4, 80)
                return res("hit", "EtherNet/IP device",
                           f"ListIdentity reply name={name!r}", p.rtt)
            return res("open", "", f"{len(d)}B on 44818", p.rtt)

        if port == 4840:
            p = net.tcp_banner(ip, 4840, timeout=timeout, send=OPCUA_HEL, settle=1.2)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            d = p.data or b""
            if d[:4] == b"ACKF":
                return res("hit", "OPC-UA server", "HEL -> ACKF", p.rtt)
            if d[:4] == b"ERRF":
                return res("open", "OPC-UA server (rejected HEL)",
                           f"{len(d)}B", p.rtt)
            return res("open", "", f"{len(d)}B on 4840", p.rtt)

        if port == 20000:
            p = net.tcp_banner(ip, 20000, timeout=timeout, send=DNP3_RESET, settle=1.2)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            d = p.data or b""
            if len(d) >= 4 and d[:2] == b"\x05\x64":
                return res("hit", "DNP3 outstation", f"link reply {len(d)}B", p.rtt)
            return res("open", "", f"{len(d)}B on 20000", p.rtt)

        p = net.tcp_banner(ip, 2404, timeout=timeout, send=IEC104_STARTDT, settle=1.2)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state == net.UNPROVEN:
            return res("unproven", "", p.detail)
        d = p.data or b""
        if len(d) >= 2 and d[0] == 0x68:
            return res("hit", "IEC 60870-5-104", f"STARTDT reply {d[:6].hex()}", p.rtt)
        return res("open", "", f"{len(d)}B on 2404", p.rtt)

ENERGY_TABLE = [
    ("SolarEdge", ["solaredge"]),
    ("Fronius", ["fronius"]),
    ("SMA", ["sma solar", "sunny portal", "sunnyboy", "sma-"]),
    ("Huawei FusionSolar", ["fusion solar", "fusionsolar", "sun2000"]),
    ("Victron (Venus OS)", ["victron", "venus os", "cerbo"]),
    ("Enphase Envoy", ["enphase", "envoy"]),
    ("Solax", ["solax", "solaxcloud"]),
    ("GoodWe", ["goodwe", "sems portal"]),
    ("Growatt", ["growatt", "shinephone"]),
    ("Sungrow", ["sungrow", "isolarcloud"]),
    ("Tesla Energy Gateway", ["tesla energy", "powerwall"]),
    ("EV charger (OCPP)", ["ocpp", "open charge point"]),
    ("Fronius Symo / Datamanager", ["datamanager"]),
]

class EnergyDevices(SweepClass):
    id = "f2_energy"
    title = "Solar / battery / EV charging"
    tier = "F"
    proto = "http"
    ports = (80, 443, 502)
    population = "critical-infra"
    desc = ("Inverters, batteries and charge points. They publish a status web UI on "
            "purpose, which is why the fingerprint is the vendor's own API reply: "
            "Fronius answers /solar_api/GetAPIVersion.cgi with a version document "
            "and SolarEdge names itself in the page. Grid-connected kit with a "
            "default password is a physical risk, not just a data one.")
    geo_hint = (52.5, 13.4)
    CONTROLS = (("151.251.194.114", 80, "hit"),)

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 502:
            from classes.tier_e import MODBUS_READ
            p = net.tcp_banner(ip, 502, timeout=timeout, send=MODBUS_READ, settle=1.2)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            d = p.data or b""
            if len(d) >= 9 and d[7] == 0x03:
                return res("hit", "Modbus/TCP (energy endpoint candidate)",
                           f"func 3 answered {d[8]} bytes", p.rtt)
            return res("open", "", f"{len(d)}B on 502", p.rtt)

        tls = (port == 443) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)

        hit = self.match_any(body[:8000] + " " + t, ENERGY_TABLE)
        if hit:
            if fp.looks_auth(r):
                return res("open", hit, f"auth challenge, title={t!r}", None)
            return res("hit", hit, f"title={t!r}", None)

        f = fp.get(ip, port, "/solar_api/GetAPIVersion.cgi", timeout=timeout,
                   tls=tls, max_body=8192)
        if f.state == net.OPEN and "APIVersion" in (f.text or ""):
            j = fp.jbody(f.text) or {}
            return res("hit", "Fronius Datamanager",
                       f"APIVersion={j.get('APIVersion')}", None)

        return res("open", "", f"status={r.status} title={t!r}", None)

CLASSES = [Plcs(), EnergyDevices()]
