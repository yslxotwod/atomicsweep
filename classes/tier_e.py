"""Tier E — buildings and physical security.

This is the tier where a `hit` is uncomfortable: a camera is a lens in a room, an
intercom is a door release. Both of them are installed by a contractor, reached
from a phone app, and then forgotten.

The fingerprint discipline matters more here than anywhere else, because the
device population is enormous and the cheap signals are worthless. Thousands of
boxes answer on 554 with an RTSP banner; only the `Server:` line inside that
banner names the product, so the banner is read rather than counted.
"""

from __future__ import annotations

from core import net
from classes.base import SweepClass, res
from classes import netfp as fp

ONVIF_GET_TIME = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    b'<s:Body><GetSystemDateAndTime '
    b'xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
)

RTSP_OPTIONS = (b"OPTIONS rtsp://%s:554/ RTSP/1.0\r\n"
                b"CSeq: 1\r\n"
                b"User-Agent: atomicsweep\r\n\r\n")

CAMERA_TABLE = [
    ("Hikvision", ["hikvision", "hikvision digital", "ds-2cd", "ds-7600"]),
    ("Dahua", ["dahua", "general/netvideo", "netsurveillance"]),
    ("Axis", ["axis communications", "ax-", "axis "]),
    ("Reolink", ["reolink"]),
    ("Foscam", ["foscam"]),
    ("Amcrest", ["amcrest"]),
    ("Instar", ["instar"]),
    ("Vivotek", ["vivotek"]),
    ("Uniview", ["uniview", "unv "]),
    ("Hanwha / Wisenet", ["wisenet", "hanwha", "samsung techwin"]),
    ("Bosch", ["bosch security"]),
    ("Mobotix", ["mobotix"]),
    ("Geovision", ["geovision"]),
    ("Tiandy", ["tiandy"]),
    ("TVT", ["tvt digital", "tvt nvr"]),
    ("Avigilon", ["avigilon"]),
    ("Pelco", ["pelco"]),
    ("D-Link camera", ["d-link", "dcs-"]),
    ("TP-Link camera", ["tapo", "tplink cloud"]),
    ("XMEye / XVR", ["xmeye", "xvr"]),
    ("Zosi", ["zosi"]),
    ("Swann", ["swann"]),
    ("Lorex", ["lorex"]),
    ("Anpviz / OEM NVR", ["anpviz", "nvr", "dvr", "ip camera", "net camera"]),
    ("Webs / GoAhead embedded", ["goahead-webs", "webs/"]),
]

class Cameras(SweepClass):
    id = "e1_camera"
    title = "Cameras / NVR / DVR"
    tier = "E"
    proto = "http/rtsp"
    ports = (80, 443, 8000, 554)
    population = "enterprise"
    desc = ("The largest exposed device population there is. Identified by ONVIF "
            "GetSystemDateAndTime, which the specification makes unauthenticated, "
            "and by the product token inside the RTSP or HTTP banner. A 401 on the "
            "web UI means the box is a camera but is NOT reported as a finding.")
    geo_hint = (52.0, 20.0)
    CONTROLS = (("46.239.222.53", 80, "hit"),)

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 554:
            return self._rtsp(ip, timeout)
        tls = (port == 443) if tls is None else tls

        r = fp.get(ip, port, "/", timeout=timeout, tls=tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        server = fp.server_of(r)
        t = fp.title(body)

        hit = self.match_any(body[:6000] + " " + server + " " + t, CAMERA_TABLE)
        if hit:
            how = f"title={t!r}" if t else f"server={server!r}"
            if fp.looks_auth(r):
                return res("open", hit, f"auth challenge, {how}", None)
            return res("hit", hit, how, None)

        o = fp.post(ip, port, "/onvif/device_service", body=ONVIF_GET_TIME,
                    timeout=timeout, tls=tls,
                    ctype="application/soap+xml; charset=utf-8", max_body=16384)
        if o.state == net.OPEN and "GetSystemDateAndTimeResponse" in (o.text or ""):
            return res("hit", "ONVIF device",
                       f"unauthenticated GetSystemDateAndTime, title={t!r}", None)
        if o.state == net.OPEN and "onvif" in (o.text or "").lower():
            return res("open", "ONVIF device (auth required)",
                       f"status={o.status}", None)

        if fp.looks_auth(r):
            return res("open", "", f"auth challenge, title={t!r} server={server!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

    def _rtsp(self, ip, timeout):
        p = net.tcp_banner(ip, 554, timeout=timeout,
                           send=RTSP_OPTIONS % ip.encode(), settle=1.2)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state == net.UNPROVEN:
            return res("unproven", "", p.detail)
        b = (p.data or b"").decode("latin-1", "replace")
        if not b.startswith("RTSP/"):
            return res("open", "", f"{len(b)}B, not RTSP", p.rtt)
        server = ""
        for line in b.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
        hit = self.match_any(server + " " + b[:400], CAMERA_TABLE)
        if hit:
            return res("hit", hit, f"RTSP Server={server!r}", p.rtt)
        return res("open", "", f"RTSP, Server={server!r}", p.rtt)

BACNET_WHO_IS = b"\x81\x0a\x00\x08\x01\x00\x10\x08"

MODBUS_READ = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"

FOX_HELLO = b"fox a 1 -1 fox a 1\n"

class BuildingAutomation(SweepClass):
    id = "e2_bas"
    title = "BACnet / Modbus / Niagara (BAS)"
    tier = "E"
    proto = "bacnet"
    ports = (47808, 502, 1911, 4911)
    population = "enterprise"
    desc = ("Building controllers: HVAC, access, lighting. BACnet answers an "
            "unauthenticated Who-Is; Modbus has no authentication in the protocol "
            "at all; Niagara's Fox port greets with its own plaintext banner. These "
            "are the devices that keep a building habitable, so the response is "
            "report-and-stop.")
    geo_hint = (40.7, -74.0)
    CONTROLS = ()

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 47808:
            p = net.udp_exchange(ip, 47808, BACNET_WHO_IS, timeout=timeout, tries=2)
            if p.state == net.UNPROVEN:
                return res("unproven", "", "silent (UDP absence is not closure)")
            if p.state != net.OPEN:
                return res("error", "", p.detail)
            d = p.data or b""
            if d[:2] == b"\x81\x0a":
                kind = "I-Am" if d[6:8] == b"\x10\x00" else "BACnet reply"
                return res("hit", "BACnet device", f"{kind} {len(d)}B", p.rtt)
            return res("open", "", f"{len(d)}B, not BVLL", p.rtt)

        if port == 502:
            p = net.tcp_banner(ip, 502, timeout=timeout, send=MODBUS_READ, settle=1.2)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            d = p.data or b""
            if len(d) >= 9 and d[7] == 0x03:
                return res("hit", "Modbus/TCP",
                           f"func 3 answered {d[8]} bytes", p.rtt)
            if len(d) >= 9 and d[7] & 0x80:
                return res("open", "Modbus/TCP (exception reply)",
                           f"exception code {d[8]}", p.rtt)
            return res("open", "", f"{len(d)}B reply", p.rtt)

        p = net.tcp_banner(ip, port, timeout=timeout, send=FOX_HELLO, settle=1.2)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state == net.UNPROVEN:
            return res("unproven", "", p.detail)
        b = (p.data or b"").decode("latin-1", "replace")
        if "fox" in b.lower():
            return res("hit", "Tridium Niagara (Fox)", f"banner={b[:60]!r}", p.rtt)
        return res("open", "", f"reply={b[:60]!r}", p.rtt)

CLASSES = [Cameras(), BuildingAutomation()]
