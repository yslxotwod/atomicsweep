# atomicsweep

**Bulk sweeps for specific device classes, with a bench.** One engine, one
honesty rule: *a negative is not a result unless a positive control answered
first.*

```
▄▀█ ▀█▀ █▀█ █▀▄▀█ █ █▀▀   █▀ █ █ █▀▀ █▀▀ █▀█
█▀█  █  █▄█ █ ▀ █ █▄▄   ▄█ █▄█ ██▄ ██▄ █▀▀
```

```
╔═ ATOMIC SWEEP ════════════════════════════════════════════════════════════════╗
║ DEVICE CLASSES · 28                                                          ║
║ ID            CLASS                                    TIER PROTO      GATE  ║
║>g7_printer    Printers / MFPs                          G    pjl/ipp    PASS  ║
║ g5_nas        NAS / file servers                       G    http       PASS  ║
║ g4_voip       PBX / SIP gateways / IP phones           G    sip        PASS  ║
║ d3_ops        Jenkins / Grafana / Prometheus / Kibana  D    http       PASS  ║
║ a1_console    Console / serial servers                 A    tcp        UNGATED║
╚═══════════════════════════════════════════════════════════════════════════════╝
 enter configure · g gate · q quit
```

A curses bench that sweeps 28 device classes across populations built from
registry data, streams what it finds into a live panel beside a spinning globe,
and refuses to report a zero it cannot justify.

---

## Why this exists

Three separate sweeps during this tool's own development reported **zero** and
were **wrong**:

| what it reported | what was actually true |
|---|---|
| "no GTP nodes in this block" | **our own throttle** — 10 hits at 48 workers, 138 when the same /24 was re-run alone. A **13.8x undercount**. |
| "2,738 clean misses" | **our own parsing bug** — an `awk` expression left `host:port` as a single token, so every probe dialled a host literally named that. |
| "no SNMP anywhere in 22,502 hosts" | **a port assumption** — the scanner underneath was TCP-only and never sent a UDP datagram. |

All three look identical in a results file. So this tool is built around three
rules:

1. **A class cannot report "none found" until a positive control answered.** Every
   class carries `CONTROLS` — real public boxes it must be able to see. A class
   with no control is displayed `UNGATED` and never green, and `--run` refuses it
   without `--ungated`.
2. **Silence is a verdict of its own.** `unproven`, never "closed". ICMP
   port-unreachable does not return on most egress, so a silent UDP port is
   *unprovable*, not closed.
3. **A population is never allowed to look empty.** Populations resolve
   incrementally, and every surface prints how much of one is actually resolved.

---

## Quick start

Requirements: **Python 3.10+**, a **256-colour terminal** with a UTF-8 locale.
No third-party packages — the bench is stdlib only. Optional: `pyte` for the
headless renderer in `tools/tui_shot.py`.

```sh
git clone <this repo> atomicsweep
cd atomicsweep

./atomicsweep                         # the bench
./atomicsweep --list                  # the 28 classes, one per line
./atomicsweep --selftest              # 320 offline assertions, no network
./atomicsweep --gate                  # run every live positive control
./atomicsweep --dry-run g7_printer    # count the probes, transmit nothing
./atomicsweep --run g7_printer        # actually sweep
./atomicsweep --runs                  # past runs and their counters
```

Everything the bench does is also a flag, so a scan can run in a loop over ssh and
still take the same code path.

### First run, in this order

`--selftest` first (proves the parsers and the wire encoders with no network),
`--gate` second (proves the classes can see known targets **from your egress** —
a control that answers from one network and not another is how you discover you
are the one being filtered), then a `--dry-run` to see the probe count before you
commit to it.

---

## The bench

The dashboard replaces "processes" with the classes. `enter` opens the filters,
`enter` again launches, and the filter panel gets out of the way so the addresses
have the room.

While a sweep is running the panel keeps seven controls, because a stop is the one
thing you cannot undo:

| key | what it does |
|---|---|
| `p` / space | **pause / resume** — holds the sweep without ending it. Workers finish what they already sent, nothing new goes out; the position and the counters survive. |
| `+` / `-` | **retune the rate live**, ±50% per press. The right answer to a peer that is throttling you is usually *slower*, not stopped. |
| `s` | stop, and keep the results |
| `r` | restart the same class and filters from zero, in a fresh run directory |
| `e` | export the hits and opens of this run to `hits.txt` beside its `results.tsv` |
| `f` | toggle the view between every row and hits-and-open only |
| `m` | mass-resolve the hits — with the formulaic-PTR filter, so a wildcard reverse zone that spells the address back is not counted as a name |
| `esc` | back to the dashboard |

The panel head reads `running`, `PAUSED` or `stopped`, so a held sweep never looks
like a finished one.

The globe spins because it is a lookup table, not a renderer: rotation about the
polar axis only adds a constant to every cell's longitude, so a frame costs one
grid lookup per cell and no trigonometry. The land mask is 4.5 KB of RLE in
`data/land.rle`. It does not compete with the scanner.

---

## Classes

Twenty-eight, in seven tiers. **Tiers are the ladder**: the box closest to the
network first, the sleeper last, because a certificate is the one thing a port
forward cannot fake.

### Tier A — shell on operator kit

| id | what it finds | control |
|---|---|---|
| `a1_console` | Console / serial servers (Lantronix, Avocent, Digi, Moxa, Perle, Opengear) — serial lines into routers and basebands | — ungated |
| `a2_olt` | OLT management planes (Huawei MA5600T/MA5800, ZTE C320, Nokia 7360, Calix E7, Fiberhome) — the box on the other end of every ONT | — ungated |
| `a3_netconf` | NETCONF / YANG servers by capability set, not by port | ConfD 6.4.4 |
| `a4_router` | Router families by banner (Cisco, Junos, RouterOS, VRP, SR-OS, EOS) | RouterOS |

### Tier B — management planes

| id | what it finds | control |
|---|---|---|
| `b1_acs` | ACS control planes keyed on **product** — a `401 digest` is a customer box and is never a finding | GenieACS NBI |
| `b2_connreq` | Connection-request reachability, i.e. whether the wake-up path is one-directional | — ungated |
| `b3_wisp` | WISP / CBRS cloud controllers (cnMaestro, CloudCore, UISP, Airspan, Tarana, Mimosa) | cnMaestro, CloudCore |
| `b4_cpeweb` | CPE / ONT web interfaces by body hash and title | — ungated |

### Tier C — device PKI

| id | what it finds | control |
|---|---|---|
| `c1_pki` | Device certificate harvest — reads the cert and asks which vendor CA signed it, which names model and serial with no login at all | Ruckus DeviceSubCA |

### Tier D — self-hosted software

The rule throughout: **a challenge is not a breach.** A Redis `-NOAUTH`, an
Elasticsearch `SecurityException` or a Redfish root behind a login is `open` with
the product named, never `hit`.

| id | what it finds | control |
|---|---|---|
| `d1_hypervisor` | ESXi / Proxmox / Nutanix / XenServer | XenServer |
| `d2_container` | Docker API, kubelet, etcd, Nomad, Portainer | — ungated |
| `d3_ops` | Jenkins, Grafana, Prometheus, Kibana, RabbitMQ, node_exporter, Zabbix agent | Prometheus, Grafana, Jenkins |
| `d4_datastore` | Elasticsearch / OpenSearch, Redis, MongoDB, CouchDB, ClickHouse, InfluxDB, memcached | — ungated |
| `d5_objectstore` | MinIO, Vault, SeaweedFS, any S3-compatible error document | MinIO |
| `d6_bmc` | BMC by Redfish root, iDRAC / iLO / Supermicro / XCC titles, RMCP+ reachable | — ungated |

### Tier E — buildings

`e1_camera` uses **ONVIF**, which the specification makes unauthenticated, plus
the `Server:` line inside an RTSP banner — thousands of boxes answer 554 and only
that line names the product.

| id | what it finds | control |
|---|---|---|
| `e1_camera` | Cameras / NVR / DVR | Dahua, Reolink |
| `e2_bas` | BACnet Who-Is, Modbus read, Tridium Niagara Fox | — ungated |

### Tier F — industrial and energy

Modbus, DNP3, IEC-104 and S7 have **no authentication in the protocol**. A `hit`
here is a statement about reachability, not an invitation: nothing is ever
written — identity and register reads only.

| id | what it finds | control |
|---|---|---|
| `f1_plc` | Siemens S7 COTP, EtherNet/IP ListIdentity, OPC-UA HEL, DNP3, IEC-104 | — ungated |
| `f2_energy` | Inverters, batteries, EV charge points (SolarEdge, Fronius, Victron, Enphase, OCPP) | Fronius |

### Tier G — the rest of the estate

The common property: each of these **announces itself on purpose**, because that
is its protocol. Plex publishes an identity so clients can find it, a printer
answers PJL on 9100 because that is the protocol, a SIP peer answers OPTIONS
because that is how liveness is checked. The fingerprint is the device's own
normal behaviour rather than a flaw in it, which is why these stay reachable for
years.

| id | what it finds | control |
|---|---|---|
| `g1_vsat` | VSAT / satellite terminals (iDirect, Hughes, Viasat, Comtech, Gilat) | — ungated |
| `g2_radio` | PTP / microwave / airMAX radios (Cambium, airOS, Mimosa, Aviat, Ceragon, RTN) | Cambium PTP |
| `g3_iptv` | IPTV headend / broadcast encoders (Harmonic, Appear, Elemental, Ateme, Nevion) | — ungated |
| `g4_voip` | PBX / SIP gateways / IP phones — SIP OPTIONS on 5060, AMI banner on 5038 | Grandstream |
| `g5_nas` | NAS / file servers (Synology, QNAP, TrueNAS, My Cloud) | Synology DSM |
| `g6_media` | Media servers and smart-home hubs (Plex `/identity`, Jellyfin, Home Assistant) | Home Assistant |
| `g7_printer` | Printers by **PJL INFO ID** on 9100 and raw **IPP** on 631 | HP LaserJet |
| `g8_rtu` | Cellular routers / RTUs / telematics (AirLink ACEmanager, Teltonika, CalAmp, Digi) | Teltonika RUT |
| `g9_door` | Door entry / intercom / access control (2N, Akuvox, Doorbird, Hikvision station) | — ungated |

Two worth calling out. `g8_rtu` is the only class pointed at cellular data space:
an RTU sits inside the operator's own data APN, which is the one place a scan from
the public internet cannot otherwise reach. And `g4_voip` refuses to call a silent
UDP 5060 closed even when TCP resets — SIP is a UDP protocol first, so a TCP reset
says nothing about it.

---

## Verdicts

Five, and the difference between them is the whole point.

| verdict | meaning |
|---|---|
| `hit` | a named device was identified. **The only verdict that is a finding.** |
| `open` | something answered and was not identified. Evidence, not a result. |
| `unproven` | nothing came back. **Never closure** — see rule 2 above. |
| `refused` | an explicit TCP RST. Real evidence. |
| `error` | local failure. Says nothing about the target. |

A class returning `open` for a login page is telling you the page named its own
product without a credential. A class returning `open` for a `401` is telling you
it found a customer box, not an access-control server.

---

## Populations

**A class declares the population it belongs in**, and `--population` overrides
it. This matters more than it sounds: the first populations were built for the
telecom ladder, and they are the wrong address space for everything that came
after. A hypervisor, a NAS, a printer and a Plex server are not in an operator's
transport network — sweeping mobile-carrier space for printers would not be a
negative result about printers, it would be a result about where we looked.

Populations come from `tools/build_popdb.py`, which buckets the PeeringDB dump by
the type each network **declares for itself** rather than by what its name looks
like:

| population | ASNs | used by |
|---|---|---|
| `pdb-isp` | 16,788 | ISPs and carriers that declare an access or transit role. The widest attributed population |
| `hosting-cloud` | 3,640 | tier D — content, CDN, VPS and hosting. Where an exposed Docker API, Elasticsearch, MinIO or Jenkins actually lives |
| `enterprise` | 2,040 | enterprise and government — printers, PBX, cameras, NAS, hypervisors, doors, building automation |
| `broadband` | 2,000 | consumer broadband — domestic cameras, NAS, media servers, home routers |
| `education` | 1,593 | universities and research networks: the largest mixed estates nobody counts as CPE |
| `peeringdb-isp` | 707 | the older, fully-resolved attributed set — small enough to use as a reference |
| `small-org` | 635 | non-profits, clinics, co-ops — the segment that keeps a device public because it works |
| `mobile-mno` | 81 | mobile carriers with real spectrum roles |
| `critical-infra` | 69 | utilities, energy, water, hospitals, transport — tier F's only honest starting point |
| `cellular-flat` | flat, 3.0M | cellular target space (`g8_rtu`) |
| `observed-open` | flat, 120k | addresses this toolkit has already seen answering a probe, with accept-all ranges removed. Use this one to *find a device*; coverage estimates need attributed prefixes instead |
| `omni-targets` | flat | every address any earlier sweep touched, with no provenance |
| `small-mno` | flat, 66k | small mobile operators |
| `operator-all` | all attributed | every ASN with per-prefix data. Tiers A–C default here, because transport gear is in transport networks |

Run `python3 tools/fetch_popdb.py --status` for the live figure. Resolution is
complete for `critical-infra` and `small-org`, past 60% for `education`,
`broadband` and `enterprise`, and still climbing for `hosting-cloud` and
`pdb-isp`. The numbers only go up.

`critical-infra` exists because **no registry field records "this is a water
utility"**. It is the one place a name is trusted, matched against
utility / energy / water / hospital / airport / rail / SCADA vocabulary on the
network's own name and its organisation's name.

**Route Server and Route Collector ASNs are deliberately excluded** from every
population. Those are IX fabric, not operators, and their addresses are peering
LANs that are not globally routed — all 262 probed came back dead. Including them
would manufacture an absence.

### Resolution is incremental, and it says so

Prefixes are fetched from RIPEstat by `tools/fetch_popdb.py` into
`~/oracle/data/popdb_pfx.json`, in the background, resumably, round-robin across
populations so no population sits at 0% while another drains. Every surface then
reports how much is resolved:

```
$ ./atomicsweep --dry-run d3_ops
class       d3_ops · Jenkins / Grafana / Prometheus / Kibana (tier D)
population  hosting-cloud · 94715 prefixes (whole population)
coverage    1,082/3,640 ASNs resolved to prefixes (30%) — the missing part is
            NOT empty, it is unfetched; run tools/fetch_popdb.py
```

That line is rule 3. A population that has not finished resolving would otherwise
report zero addresses, and a zero in this bench is never allowed to mean "nothing
is there".

An ASN that answers with no prefixes is cached as an empty list, because **"we
asked and it announces nothing" and "we have not asked" are different facts** and
must never collapse into one. A failed lookup is not cached, so it is retried.

### Geography

Attributed populations know a country and an operator for every prefix, so the
country and operator filters are *exact*. Flat populations are earlier target
files with no provenance, and the geo filter is reported as **unavailable** rather
than silently switched off.

Country attribution comes from `tools/build_geo.py`, which joins PeeringDB's `net`
table to `org` (the `net` table itself has no country) and writes
`~/oracle/data/asn_cc.json` for 23,123 ASNs. Without it a country filter knows
five countries and answers "no prefixes for ZA", which reads exactly like "South
Africa has no operator kit".

A filter that cannot be honoured is an error naming the reason, **never an empty
list**:

```
filters not honoured: no attributed prefixes for country ZA
  countries with attributed prefixes: AL, AM, AZ, BA, BG, BY, DZ, EG, FR, GB, ...
```

Host sampling inside a block is biased on purpose: `.1` and `.254` are where a
gateway or management interface sits, the network and broadcast pair catches
misconfigured kit, and the rest is sampled uniformly — because a /16 of consumer
CPE is not worth 65,536 probes to find one router.

---

## Guards

Four, and every one exists because of a specific failure this tool made itself.

**Fingerprint keywords are word-guarded automatically.** A table is matched
against a whole web page, so plain substring matching is wrong by default and the
wrongness is invisible — it produces hits, not misses. Three real examples, all
from this tree: a PTR classifier read `alterego` as LTE and `odorhei` as O-RAN;
`<link rel="canonical">` was reported as a **Canon printer**; a Prometheus scrape
line `process_cpu_seconds_total` was reported as an **IPTV headend** because
`seconds` contains `nds `. The third one produced 11 confident "hits" against
Brazilian CDN edges before anyone looked at the evidence column.

So `match_any` guards both edges of every keyword: a left guard if the token
begins with a letter (so `ont` does not match `font`) and a right guard if it ends
with one (so `nds ` does not match inside `seconds`). **A digit may follow the
right guard**, because `gxp` must still match `GXP1625` and `scs` must still match
`SCS3200` — model numbers are exactly what these tables exist to catch. An escape
hatch remains: `!token` forces both edges, `~token` opts out entirely for a
product-code prefix like `~ds-2cd`.

The selftest asserts this as a **policy, not a case**: every one of the 21
fingerprint tables is matched against ordinary prose, a metrics scrape and a
WordPress page, and not one of them may name a device (`kw-none-innocuous`). A
single-case assertion would have passed while `seconds` still matched `nds `.

**`--run` refuses a class with no positive control** unless `--ungated` is given,
because a class that has never been shown to see a known target cannot report
"nothing found" — only "nothing found by *this matcher*". The bench asks for a
second deliberate press on the launch key instead.

**Every run is followed by a silence rescan**: a 1% sample of the `unproven` rows,
re-probed at a tenth of the rate. A throttled first pass and a correct first pass
are indistinguishable in a results file — both are mostly silence — and asking the
same hosts again *slowly* is the only measurement that separates them. This is the
check that caught the 13.8x undercount. When it gets answers it says so in
capitals and tells you to lower `--rate`:

```
rescan      !! 2/20 answered on the second attempt (10.0%) — THE FIRST PASS WAS
            THROTTLED. Its zeroes are our own rate limit, not absence.
            Re-run the class at a lower --rate.
```

When it gets none, the silence is at least consistent with a miss. `--no-rescan`
skips it.

**Every run is followed by an intermediary check**, the mirror image of the
rescan: a *positive* can be an artifact too, and it is easier to believe. A host
that answered on two or more ports without being identified is re-probed on one
high port derived from its address. A connect there proves a proxy answering for
everything, and the opens are relabelled as the middlebox rather than a device.

Its limits are measured, not assumed. Some hosting ranges answer 80 and 443 with
a catch-all page (`Not Found on Accelerator`, `Error 404 (Not Found)!!1`) and
**time out on every other port**, so they are
wildcard-vhost accelerators rather than accept-all listeners and this check
cannot see them — for those, the evidence that nothing is there is the page, not
the port. A canary that times out is reported as **undecided**, never as proof:
a filtered port and a closed port are the same silence. `--no-intermediary`
skips the check.

---

## Pacing

The token bucket has **no burst allowance**, deliberately: a burst is what
produces the remote throttle that then looks like absence. The default 40 pps with
64 workers is conservative on purpose.

The panel shows the **achieved** rate, which is usually lower than the configured
one, because concurrency and timeout set the ceiling: 64 workers at a 3 s timeout
cannot exceed ~21 probes/s no matter what the bucket allows. If you need more,
raise `--conc`; if a peer is dropping you, the rescan will tell you and `-` will
slow it down without losing your position.

---

## Sampling

Addresses come from the population's prefixes by a seeded sample: the `.1`,
`.254`, network and broadcast addresses of every prefix (that is where management
interfaces actually live) plus a few interior addresses drawn from a PRNG.

The seed is **derived from the class name**, and this is load-bearing in both
directions. A rerun of a class must repeat it exactly, or a second pass at a lower
rate cannot be compared with the first. A *different* class must not repeat it, or
every class reports the same hosts and the population is 1,200 addresses wide no
matter how many times it is swept — which is what happened: `d6_bmc`,
`d2_container` and `d4_datastore` all probed an identical set, so the third hunt
learned nothing from the first two. `--seed N` overrides it, and the header prints
the seed actually in use.

---

## Resume

A run directory holds `results.tsv`, `done.tsv` and `meta.json`. `done_set()` is
seeded from **both** the results file and the done file, because a kill loses the
last done lines — so re-running the same command picks up where it stopped instead
of re-probing from zero.

---

## Tests

`./atomicsweep --selftest` runs **320 assertions with no network**. Four groups:

- **geometry** — the land mask against 12 known land/sea coordinates, the
  projection, and that a frame actually rotates.
- **contract** — the verdict vocabulary (including that `res()` *refuses* a
  verdict outside it), the formulaic-PTR filter, the guard logic (`rescan_note`,
  `Bucket.set_rate`, paused buckets not banking tokens), the population coverage
  shape, and that every class names a population that exists and accepts the
  `tls` override `gate()` passes.
- **fixtures** — every matcher in tiers D–G exercised against recorded reply bytes
  with a monkeypatched transport, including the boundary-token cases
  (`rel="canonical"` must not match a Canon printer; `complex` must not match
  Plex).
- **wire encoders** — every hand-built protocol constant checked for *declared
  length equals actual length*. This assertion class has caught more real bugs in
  this codebase than any other: a header that lies about its own length is dropped
  by a strict peer, and the drop reads exactly like "the target is not there".

`./atomicsweep --gate` runs the live positive controls — real boxes on the public
internet, each probed read-only, never with a credential and never with a write.
**17 of 28 classes are gated** as of writing:

| class | control | verdict |
|---|---|---|
| `a3_netconf` | Tail-f ConfD 6.4.4 on 830 | hit |
| `a4_router` | RouterOS on 8291 | open |
| `b1_acs` | GenieACS NBI on 7557 | hit |
| `b3_wisp` | `cloud.cambiumnetworks.com:443`, `cloudcore.baicells.com:443` | hit x2 |
| `b4_cpeweb` | TP-Link cloud UI shell on 80 | hit |
| `c1_pki` | Ruckus device CA on 443 | hit |
| `d1_hypervisor` | Citrix XenServer 6.2.0 on 80 | hit |
| `d3_ops` | `demo.promlabs.com:9090`, `play.grafana.org:443`, `ci.jenkins.io:443` | hit x3 |
| `d5_objectstore` | `play.min.io:443` MinIO | hit |
| `e1_camera` | Dahua on 80, Reolink on 80 | hit x2 |
| `f2_energy` | Fronius on 80 | hit |
| `g2_radio` | Cambium PTP on 80 | hit |
| `g4_voip` | Grandstream on 80 | hit |
| `g5_nas` | Synology DSM on 80 | hit |
| `g6_media` | Home Assistant on 80 | hit |
| `g7_printer` | HP LaserJet M127fn on 80 | hit |
| `g8_rtu` | Teltonika RUT on 80 | hit |

The other eleven report `UNGATED`, which is true and is the point of showing it.
They have no control this project can point at, so their matchers rest on the
fixture assertions and their sweeps say so on screen. Where a control exists it is
a host the author had already observed answering on that protocol, re-probed
read-only: one request, no credential, no write. When a control goes dark the gate
turns red rather than being quietly dropped; that is how `b3_wisp`'s previous
control was caught disappearing.

---

## Layout

```
atomicsweep               launcher
cli.py                    flag interface: dry-run, run, gate, selftest
tui.py                    the bench
core/globe.py             land mask decode + orthographic projection
core/geo.py               populations, country/operator filter, coverage, sampling
core/engine.py            token bucket, bounded dispatch, stats, pause, gate
core/net.py               tcp / tls / http / udp / snmp transports
core/store.py             resumable runs (results.tsv, done.tsv, meta.json)
core/ui.py                curses colours and box drawing
core/classes.py           the registry
classes/base.py           verdict vocabulary and the class contract
classes/netfp.py          shared HTTP/JSON helpers for the fingerprint matchers
classes/tier_a.py         console servers, OLT, NETCONF, routers
classes/tier_b.py         ACS, connection-request, WISP controllers, CPE UI, resolver
classes/tier_c.py         device PKI
classes/tier_d.py         hypervisors, containers, ops, datastores, object stores, BMC
classes/tier_e.py         cameras, building automation
classes/tier_f.py         PLCs, energy devices
classes/tier_g.py         VSAT, radios, broadcast, VoIP, NAS, media, printers, RTUs, doors
data/land.rle             the world map, 4.5 KB, RLE
data/runs/                every run, resumable (gitignored)
tools/build_popdb.py      PeeringDB dump -> population DB
tools/fetch_popdb.py      resumable RIPEstat prefix fetch for the populations
tools/build_geo.py        ASN -> country/name index from the PeeringDB dump
tools/build_observed_pop.py  observed-answering addresses -> the `observed-open` population
tools/hunt_from_opens.py  re-probe hosts a sweep already reached, for an ungated class
tools/tui_shot.py         render the interface headlessly and dump it (needs pyte)
```

Runtime data lives outside the tree in `~/oracle/data/` (`popdb.json`,
`popdb_pfx.json`, `asn_cc.json`, `asn_name.json`) because it is fetched, not
source. Point `ORACLE` in `core/geo.py` elsewhere if you keep it somewhere else.

---

## Scope

This sweeps **public address space** for device classes that answer to anyone who
asks. It is built for inventory, and for the argument that "we found nothing" is a
claim requiring evidence — the guard rails exist to stop *this tool* lying, and
they cut both ways.

What it deliberately does **not** do:

- **no credential attempts.** No default-password list lives here. A `401` is
  `open` with the product named; it is never attacked.
- **no writes to any device.** Modbus, DNP3, IEC-104 and S7 are read-only —
  identity and register reads. No coil write, no register write, no task pushed
  through a management API.
- **no exploitation.** Fingerprinting only. Where a class could be extended into a
  takeover, that extension is not here.
- **no scanning of IX peering LANs** (see the Route Server note above) and no
  vendor multi-tenant SaaS.

Use it on networks you are responsible for, or where you have permission. The
`CONTROLS` design means it will tell you when it cannot see — which is the only
way to trust it when it says it can.

---

## License

MIT. See `LICENSE`.
