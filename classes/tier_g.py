"""Tier G — the rest of the estate: satellite, radio, broadcast, voice, storage,
media, printers, telemetry, and doors.

Everything here shares one property: it was bought by a department, not by a
network team, and it announces itself on purpose. A Plex server publishes its
identity so clients can find it; a printer answers PJL on 9100 because that is
the protocol; a SIP gateway answers OPTIONS because that is how a peer checks
liveness. So the fingerprint is the device's own normal behaviour, not a bug in
it — which is exactly why these boxes stay reachable for years.

Same discipline as the other tiers: a login page that names the product is a
`hit` (it identified itself without a credential), but the detail always says
whether anything behind it was reachable.
"""

from __future__ import annotations

from core import net
from classes.base import SweepClass, res
from classes import netfp as fp

VSAT_TABLE = [
    ("iDirect (Evolution / Velocity)", ["idirect", "evolution x7", "vipersat"]),
    ("Hughes (HN / Jupiter)", ["hughes", "hn9", "hn7", "ht2000", "dw7000", "jupiter"]),
    ("Viasat / SurfBeam", ["viasat", "surfbeam", "exede", "wildblue"]),
    ("Comtech / Efdata", ["comtech", "efdata", "cdm-", "sdm-"]),
    ("Gilat SkyEdge", ["gilat", "skyedge", "skystar"]),
    ("Newtec / ST Engineering", ["newtec", "dialog ", "mdm3", "mdm2"]),
    ("Hylas / Avanti", ["hylas", "avanti"]),
    ("Generic VSAT terminal", ["vsat", "satellite terminal", "sat modem"]),
]

class VsatTerminals(SweepClass):
    id = "g1_vsat"
    title = "VSAT / satellite terminals"
    tier = "G"
    proto = "http"
    ports = (80, 443, 22)
    population = "operator-all"
    desc = ("Satellite modems and hubs. These are the backhaul for cellular sites in "
            "places with no fibre, so a terminal is often one hop from a base "
            "station's management network. Vendor web UIs name themselves in the "
            "title; the default credentials are the well-known one.")
    geo_hint = (0.0, 20.0)
    CONTROLS = ()

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 22:
            p = net.tcp_banner(ip, 22, timeout=timeout, settle=1.0)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            hit = self.match_any(p.text, VSAT_TABLE)
            if hit:
                return res("hit", hit, p.text[:80], p.rtt)
            return res("open", "", p.text[:80] or "silent accept", p.rtt)

        use_tls = (port == 443) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        blob = f"{t} {fp.server_of(r)} {body[:4000]}"
        hit = self.match_any(blob, VSAT_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

RADIO_TABLE = [
    ("Cambium ePMP", ["epmp"]),
    ("Cambium PTP (LINKPlanner / PTP 550)", ["ptp ", "ptp5", "ptp820", "linkplanner",
                                             "cnmediator", "cnpilot", "cambium"]),
    ("Ubiquiti airOS / airMAX", ["airos", "airmax", "airgrid", "nanostation",
                                 "litebeam", "powerbeam", "rocket m"]),
    ("Ubiquiti EdgeOS", ["edgeos", "edgemax", "unifi"]),
    ("Mimosa Networks", ["mimosa networks", "b5-lite", "b11"]),
    ("Aviat / Harris", ["aviat", "aviat eclipse", "truepoint", "!wmt"]),
    ("Ceragon", ["ceragon", "ip-20", "fibeair"]),
    ("Huawei RTN", ["rtn 9", "rtn 3", "rtn950", "optix rtn"]),
    ("Nokia/Infinera microwave", ["wavence", "9500 mpr", "infinera"]),
    ("DragonWave / Dragonwave Harmony", ["dragonwave", "horizon compact"]),
    ("Intracom / IntraLink", ["intracom", "intralink"]),
    ("Siklu / Etherhaul", ["siklu", "etherhaul"]),
    ("Generic wireless radio", ["wireless radio", "backhaul radio", "microwave link"]),
]

class PtpRadios(SweepClass):
    id = "g2_radio"
    title = "PTP / microwave / airMAX radios"
    tier = "G"
    proto = "http"
    ports = (80, 443, 22)
    population = "operator-all"
    desc = ("Point-to-point links. A microwave hop is literally part of a mobile "
            "backhaul path: find the radio and you have found a way onto the "
            "transport that carries the base station. airOS and ePMP ship with a "
            "default login and no source restriction.")
    geo_hint = (44.0, 21.0)
    CONTROLS = (("194.146.191.202", 80, "hit"),)

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 22:
            p = net.tcp_banner(ip, 22, timeout=timeout, settle=1.0)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            hit = self.match_any(p.text, RADIO_TABLE)
            if hit:
                return res("hit", hit, p.text[:80], p.rtt)
            return res("open", "", p.text[:80] or "silent accept", p.rtt)

        use_tls = (port == 443) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        blob = f"{t} {fp.server_of(r)} {body[:4000]}"
        hit = self.match_any(blob, RADIO_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

HEADEND_TABLE = [
    ("Harmonic (ProStream / NSG / Electra)", ["harmonic inc", "prostream", "nsg ", "electra",
                                              "spectrum x"]),
    ("Appear TV", ["appear tv", "appear x"]),
    ("AWS Elemental", ["elemental", "aws elemental"]),
    ("Ateme", ["ateme", "titan "]),
    ("Nevion / Grass Valley", ["nevion", "grass valley", "iqmix"]),
    ("Evertz", ["evertz", "magnum"]),
    ("Sencore", ["sencore"]),
    ("Dektec / DVEO", ["dektec", "dveo"]),
    ("Ericsson / MediaKind", ["mediakind", "ericsson ab", "avp "]),
    ("Generic streamer / encoder", ["streamer", "multiplexer", "headend", "nds ",
                                    "encoder configuration"]),
]

class BroadcastHeadend(SweepClass):
    id = "g3_iptv"
    title = "IPTV headend / broadcast encoders"
    tier = "G"
    proto = "http"
    ports = (80, 443, 8080)
    population = "operator-all"
    desc = ("Streaming headends and contribution encoders. Usually a management UI "
            "on a flat port with no source ACL because the vendor assumed a private "
            "VLAN. A headend hands over the whole channel line-up, and the encoder "
            "config frequently carries the origin credentials.")
    geo_hint = (51.5, -0.1)
    CONTROLS = ()

    def probe(self, ip, port, timeout=3.0, tls=None):
        use_tls = (port == 443) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        hit = self.match_any(f"{t} {fp.server_of(r)} {body[:4000]}", HEADEND_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

SIP_OPTIONS = (b"OPTIONS sip:probe@invalid SIP/2.0\r\n"
               b"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-atomicsweep\r\n"
               b"Max-Forwards: 70\r\n"
               b"From: <sip:probe@invalid>;tag=atomicsweep\r\n"
               b"To: <sip:probe@invalid>\r\n"
               b"Call-ID: atomicsweep@192.0.2.1\r\n"
               b"CSeq: 1 OPTIONS\r\n"
               b"User-Agent: atomicsweep\r\n"
               b"Content-Length: 0\r\n\r\n")

VOIP_TABLE = [
    ("Asterisk / FreePBX", ["asterisk", "freepbx", "asterisknow"]),
    ("Grandstream", ["grandstream", "gxp", "grp26", "ht8", "ucm6"]),
    ("Yealink", ["yealink", "sip-t", "sip-t5"]),
    ("Cisco Unified / SPA", ["cisco unified", "spa5", "spa1", "callmanager", "ucm "]),
    ("Avaya", ["avaya", "aura communication"]),
    ("Mitel / Aastra", ["mitel", "aastra", "mx-one"]),
    ("3CX", ["3cx"]),
    ("Kamailio / OpenSIPS", ["kamailio", "opensips", "openser"]),
    ("FreeSWITCH", ["freeswitch"]),
    ("Snom / Polycom", ["snom", "polycom", "soundpoint", "vvx"]),
    ("Alcatel / ALE", ["alcatel-lucent omnipcx", "ale-", "oxe"]),
    ("Generic SIP gateway / PBX", ["!pbx", "sip gateway", "voip gateway"]),
]

class VoipSystems(SweepClass):
    id = "g4_voip"
    title = "PBX / SIP gateways / IP phones"
    tier = "G"
    proto = "sip"
    ports = (80, 443, 5060, 5038)
    population = "enterprise"
    desc = ("Voice infrastructure. SIP answers an OPTIONS without any credential, "
            "which identifies a peer rather than a service; the Asterisk Manager "
            "Interface announces itself in a plaintext banner on 5038 because that "
            "is how its own clients find it. A PBX means call detail records, "
            "voicemail and often the trunk credentials.")
    geo_hint = (41.0, 29.0)
    CONTROLS = (("89.205.97.50", 80, "hit"),)

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 5060:
            p = net.udp_exchange(ip, 5060, SIP_OPTIONS, timeout=timeout, tries=2)
            if p.state == net.OPEN:
                b = (p.data or b"").decode("latin-1", "replace")
                if b.startswith("SIP/2.0"):
                    code = b.split(" ")[1] if len(b.split(" ")) > 1 else ""
                    srv = ""
                    for line in b.splitlines():
                        if line.lower().startswith("server:"):
                            srv = line.split(":", 1)[1].strip()
                    hit = self.match_any(srv + " " + b[:600], VOIP_TABLE)
                    if hit:
                        return res("hit", hit, f"SIP {code} Server={srv!r}", p.rtt)
                    return res("open", f"SIP peer ({code})",
                               f"Server={srv!r} — answered OPTIONS", p.rtt)
            q = net.tcp_banner(ip, 5060, timeout=timeout, send=SIP_OPTIONS, settle=1.2)
            if q.state == net.OPEN and (q.data or b"").startswith(b"SIP/2.0"):
                b = (q.data or b"").decode("latin-1", "replace")
                return res("open", "SIP peer (TCP)",
                           f"answered OPTIONS over TCP, {len(b)}B", q.rtt)
            if p.state == net.ERROR:
                return res("error", "", p.detail)
            return res("unproven", "", "UDP silent (absence is not closure)")

        if port == 5038:
            p = net.tcp_banner(ip, 5038, timeout=timeout, settle=1.0)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            b = (p.data or b"").decode("latin-1", "replace")
            if "asterisk call manager" in b.lower():
                ver = b.strip().split("/")[-1] if "/" in b else ""
                return res("hit", "Asterisk Manager Interface",
                           f"banner={b.strip()[:60]!r} version={ver}", p.rtt)
            return res("open", "", b[:60] or "silent accept", p.rtt)

        use_tls = (port == 443) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        hit = self.match_any(f"{t} {fp.server_of(r)} {body[:4000]}", VOIP_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

NAS_TABLE = [
    ("Synology DSM", ["synology", "diskstation", "dsm "]),
    ("QNAP QTS", ["qnap", "qts ", "quts"]),
    ("TrueNAS / FreeNAS", ["truenas", "freenas", "ixsystems"]),
    ("Western Digital My Cloud", ["my cloud", "wd my cloud"]),
    ("Drobo / Buffalo", ["drobo", "buffalotech", "terastation", "linkstation"]),
    ("Asustor / Thecus", ["asustor", "thecus"]),
    ("OpenMediaVault", ["openmediavault"]),
    ("Netgear ReadyNAS", ["readynas", "netgear"]),
    ("Generic NAS / file server", ["nas login", "network attached storage"]),
]

class NasDevices(SweepClass):
    id = "g5_nas"
    title = "NAS / file servers"
    tier = "G"
    proto = "http"
    ports = (80, 443, 5000, 5001)
    population = "broadband"
    desc = ("Network storage with a web admin UI. Routinely internet-facing in small "
            "operators because someone wanted remote access, and the backups of the "
            "billing or monitoring systems are frequently on it. Synology DSM listens "
            "on 5000/5001 by default, which is why the port belongs in the list.")
    geo_hint = (47.4, 8.5)
    CONTROLS = (("147.91.130.1", 80, "hit"),)

    def probe(self, ip, port, timeout=3.0, tls=None):
        use_tls = (port in (443, 5001)) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        hit = self.match_any(f"{t} {fp.server_of(r)} {body[:4000]}", NAS_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, port={port}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

MEDIA_TABLE = [
    ("Plex Media Server", ["plex media server", "plex media", "!plex"]),
    ("Jellyfin", ["jellyfin"]),
    ("Emby", ["emby"]),
    ("Home Assistant", ["home assistant"]),
    ("openHAB", ["openhab"]),
    ("HomeSeer / Hubitat", ["homeseer", "hubitat"]),
    ("Domoticz / ioBroker", ["domoticz", "iobroker"]),
    ("Kodi / XBMC", ["!kodi", "xbmc"]),
    ("Sonarr / Radarr / *arr", ["sonarr", "radarr", "lidarr", "prowlarr",
                                "bazarr", "sabnzbd"]),
    ("Tautulli / Ombi", ["tautulli", "ombi"]),
    ("Frigate / Shinobi (NVR)", ["frigate", "shinobi"]),
    ("Generic media server", ["media server", "!dlna"]),
]

class MediaServers(SweepClass):
    id = "g6_media"
    title = "Media servers / smart-home hubs"
    tier = "G"
    proto = "http"
    ports = (80, 443, 32400, 8096, 8123)
    population = "broadband"
    desc = ("Plex, Jellyfin, Home Assistant. Two reasons they matter here: they are "
            "the most common way a home lab reaches the internet from an ISP's "
            "address space, and Home Assistant holds the credentials to the rest of "
            "the house. Plex answers /identity with its own machine identifier "
            "before any login.")
    geo_hint = (37.8, -122.4)
    CONTROLS = (("46.22.97.140", 80, "hit"),)

    def probe(self, ip, port, timeout=3.0, tls=None):
        use_tls = (port == 443) if tls is None else tls

        if port == 32400:
            r = fp.get(ip, port, "/identity", timeout=timeout, tls=use_tls,
                       max_body=8192)
            if r.state == net.OPEN and "MediaContainer" in (r.text or ""):
                mid = ""
                for tok in (r.text or "").replace(">", " ").split():
                    if tok.startswith("machineIdentifier="):
                        mid = tok.split("=", 1)[1].strip('"')
                return res("hit", "Plex Media Server",
                           f"/identity machineIdentifier={mid}", None)

        if port == 8096:
            r = fp.get(ip, port, "/System/Info/Public", timeout=timeout,
                       tls=use_tls, max_body=8192)
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and ("ProductName" in j or "ServerName" in j):
                return res("hit", "Jellyfin",
                           f"ServerName={j.get('ServerName', '')} "
                           f"version={j.get('Version', '')}", None)

        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        hit = self.match_any(f"{t} {fp.server_of(r)} {body[:4000]}", MEDIA_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

PJL_INFO_ID = b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n"

IPP_VERSION = b"\x02\x00"
IPP_OP_GET_ATTR = b"\x00\x0b"
IPP_ATTR_CHARSET = b"\x47"
IPP_ATTR_LANG = b"\x48"
IPP_ATTR_URI = b"\x45"
IPP_END = b"\x03"

def ipp_get_attributes(uri=b"ipp://192.0.2.1/ipp/print"):
    def a(tag, name, value):
        return (tag + len(name).to_bytes(2, "big") + name
                + len(value).to_bytes(2, "big") + value)

    return (IPP_VERSION + IPP_OP_GET_ATTR + b"\x00\x00\x00\x01"
            + b"\x01"
            + a(IPP_ATTR_CHARSET, b"attributes-charset", b"utf-8")
            + a(IPP_ATTR_LANG, b"attributes-natural-language", b"en")
            + a(IPP_ATTR_URI, b"printer-uri", uri)
            + IPP_END)

IPP_GET_ATTR = ipp_get_attributes()

PRINTER_TABLE = [
    ("HP LaserJet / OfficeJet", ["hewlett-packard", "hp laserjet", "hp officejet",
                                 "hp color laserjet", "hp designjet"]),
    ("Brother", ["brother industries", "brother mfc", "brother dcp", "brother hl-",
                 "brother ql-", "brother ads-"]),
    ("Xerox", ["xerox", "workcentre", "versalink"]),
    ("Kyocera", ["kyocera", "taskalfa", "ecosys"]),
    ("Ricoh / Savin", ["ricoh", "!savin", "aficio", "imagio"]),
    ("Canon", ["imagerunner", "i-sensys", "!canon"]),
    ("Epson", ["epson", "workforce", "surecolor"]),
    ("Konica Minolta", ["konica", "bizhub", "!minolta"]),
    ("Lexmark", ["lexmark"]),
    ("Zebra (label / industrial)", ["zebra", "zdesigner", "zt411", "gk420"]),
    ("Samsung / Dell printer", ["samsung", "!dell", "clp-", "clx-"]),
    ("Sharp / Toshiba", ["!sharp", "toshiba", "e-studio"]),
    ("Generic printer / MFP", ["!printer", "multifunction", "!mfp", "jetdirect"]),
]

class Printers(SweepClass):
    id = "g7_printer"
    title = "Printers / MFPs"
    tier = "G"
    proto = "pjl/ipp"
    ports = (80, 443, 9100, 631)
    population = "enterprise"
    desc = ("Printers on port 9100 answer PJL INFO ID with their model, no "
            "credential, by design. They are also the classic way into an office "
            "network, they store documents, and they hold the address book and the "
            "LDAP bind credentials. IPP on 631 is the same story for anything "
            "without a raw port.")
    geo_hint = (35.7, 139.7)
    CONTROLS = (("95.155.37.50", 80, "hit"),)

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 9100:
            p = net.tcp_banner(ip, 9100, timeout=timeout, send=PJL_INFO_ID, settle=1.5)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            b = (p.data or b"").decode("latin-1", "replace")
            if "@PJL" in b.upper():
                model = ""
                for line in b.splitlines():
                    s = line.strip()
                    if s.upper().startswith("@PJL INFO ID"):
                        continue
                    if s and not s.startswith("\x1b") and s.upper() != "\x1b%-12345X":
                        model = s[:60]
                        break
                hit = self.match_any(b, PRINTER_TABLE)
                return res("hit", hit or "Printer (PJL)",
                           f"PJL reply model={model!r}", p.rtt)
            if b.strip():
                return res("open", "", f"reply={b[:60]!r}", p.rtt)
            return res("open", "", "accepts 9100, no PJL reply", p.rtt)

        if port == 631:
            p = net.tcp_banner(ip, 631, timeout=timeout, send=IPP_GET_ATTR, settle=1.5)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            d = p.data or b""
            if len(d) >= 8 and d[:2] in (b"\x01\x01", b"\x02\x00", b"\x01\x00"):
                status = int.from_bytes(d[2:4], "big")
                if status == 0:
                    return res("hit", "IPP printer",
                               "Get-Printer-Attributes successful-ok", p.rtt)
                return res("open", "IPP service",
                           f"status=0x{status:04x}", p.rtt)
            if d.startswith(b"HTTP/"):
                return res("open", "IPP over HTTP",
                           "631 speaks HTTP, not raw IPP", p.rtt)
            return res("open", "", f"{len(d)}B on 631", p.rtt)

        use_tls = (port == 443) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        hit = self.match_any(f"{t} {fp.server_of(r)} {body[:4000]}", PRINTER_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

RTU_TABLE = [
    ("Sierra Wireless AirLink", ["airlink", "acemanager", "es450", "rv50", "lx60",
                                 "mp70", "gx450"]),
    ("CalAmp / Fusion", ["calamp", "fusion2", "lm1190", "he910"]),
    ("Digi (Transport / IX / WR)", ["digi international", "transport wr", "digi ix",
                                    "connectport", "digi transpor"]),
    ("Teltonika RUT / TRB", ["teltonika", "rut2", "rut9", "trb1", "trb2"]),
    ("Cradlepoint", ["cradlepoint", "ibr6", "ibr9", "e3000"]),
    ("Peplink / Pepwave", ["peplink", "pepwave", "max br1", "balance 20"]),
    ("Moxa / Advantech IIoT", ["moxa", "advantech", "unigate"]),
    ("Robustel / Telit", ["robustel", "telit", "fn980"]),
    ("Huawei AR / industrial router", ["huawei ar", "ar1220", "ar651"]),
    ("Generic cellular router / RTU", ["cellular router", "4g router", "lte router",
                                       "rtu ", "telemetry"]),
]

class CellularRtus(SweepClass):
    id = "g8_rtu"
    title = "Cellular routers / RTUs / telematics"
    tier = "G"
    proto = "http"
    ports = (80, 443, 9191)
    population = "cellular-flat"
    desc = ("The cellular-attached boxes that are not phones and not base stations: "
            "utility meters, ATM backhaul, SCADA outstations, fleet telematics. "
            "Sierra Wireless ACEmanager listens on 9191 with a default password and "
            "no source ACL. A compromised RTU sits inside the operator's own data "
            "APN, which is the one place a public scan cannot otherwise reach.")
    geo_hint = (43.0, -79.0)
    CONTROLS = (("145.249.186.39", 80, "hit"),)

    def probe(self, ip, port, timeout=3.0, tls=None):
        use_tls = (port == 443) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        hit = self.match_any(f"{t} {fp.server_of(r)} {body[:4000]}", RTU_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, port={port}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

DOOR_TABLE = [
    ("2N (Access Unit / Intercom)", ["2n ", "2n access", "2n ip", "axis 2n"]),
    ("Akuvox", ["akuvox", "r29", "e16"]),
    ("Comelit", ["comelit"]),
    ("Fermax", ["fermax"]),
    ("Doorbird", ["doorbird"]),
    ("ButterflyMX / Swiftlane", ["butterflymx", "swiftlane"]),
    ("Hikvision intercom / door station", ["door station", "villa station",
                                           "ds-kd", "ds-kv"]),
    ("Dahua intercom / VTO", ["vto2", "vto6", "dahua intercom"]),
    ("Axis intercom / door controller", ["axis a8", "axis a1", "axis door"]),
    ("Paxton / Salto access control", ["paxton", "net2", "salto"]),
    ("Generic access control", ["access control", "door entry", "!intercom"]),
]

class DoorSystems(SweepClass):
    id = "g9_door"
    title = "Door entry / intercom / access control"
    tier = "G"
    proto = "http"
    ports = (80, 443)
    population = "enterprise"
    desc = ("Door stations and access controllers. Installed by a facilities "
            "contractor, given a public address so the app works off-site, and "
            "never patched. A door controller is a physical security system with a "
            "web form: the response is report-only and the finding never includes "
            "an attempt to operate the lock.")
    geo_hint = (50.1, 14.4)
    CONTROLS = ()

    def probe(self, ip, port, timeout=3.0, tls=None):
        use_tls = (port == 443) if tls is None else tls
        r = fp.get(ip, port, "/", timeout=timeout, tls=use_tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        body = r.text or ""
        t = fp.title(body)
        hit = self.match_any(f"{t} {fp.server_of(r)} {body[:4000]}", DOOR_TABLE)
        if hit:
            kind = "login page" if fp.looks_auth(r) else "unauthenticated UI"
            return res("hit", hit, f"{kind}, title={t!r}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

CLASSES = [VsatTerminals(), PtpRadios(), BroadcastHeadend(), VoipSystems(),
           NasDevices(), MediaServers(), Printers(), CellularRtus(), DoorSystems()]
