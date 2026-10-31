#!/usr/bin/env python3
"""atomicsweep CLI — everything the TUI does, without a terminal.

    atomicsweep --list
    atomicsweep --gate [a3_netconf]
    atomicsweep --dry-run a1_console --population mobile-mno --country ZA
    atomicsweep --run a1_console --population mobile-mno --country ZA --rate 40
    atomicsweep --runs
    atomicsweep --selftest

`--dry-run` is the default for anything that would transmit: an accidental
`--run` on the wrong population is 3 million probes at somebody's operators.
"""

from __future__ import annotations

import argparse
import os
import queue
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from core import engine, geo as geolib, store
from core.classes import SWEEP_CLASSES, by_id
from classes.base import SweepClass

def fmt(n):
    return f"{n:,}" if isinstance(n, int) else str(n)

def cmd_list(_a):
    print(f"{'ID':<15}{'TIER':<6}{'PROTO':<13}{'POPULATION':<18}CONTROLS  TITLE")
    for k in SWEEP_CLASSES:
        c = "yes" if k.CONTROLS else "NONE"
        print(f"{k.id:<15}{k.tier:<6}{k.proto:<13}{k.population:<18}{c:<10}{k.title}")
    return 0

def cmd_gate(a):
    targets = SWEEP_CLASSES if not a.gate else [by_id(a.gate)]
    if not targets or targets == [None]:
        print(f"unknown class: {a.gate}", file=sys.stderr)
        return 2
    bad = 0
    for k in targets:
        ok, rows = engine.gate(k)
        if ok is None:
            print(f"UNGATED  {k.id:<13} no positive control — a negative from this "
                  f"class cannot be trusted")
            bad += 1
            continue
        for r in rows:
            want, got = r.get("want"), r.get("got")
            mark = "ok  " if got == want else "FAIL"
            rtt = r.get("rtt")
            rtt_s = f" {rtt * 1000:.0f}ms" if isinstance(rtt, (int, float)) else ""
            print(f"{mark}     {k.id:<13} control {r.get('target'):<22} "
                  f"wanted {want:<6} got {got:<6} {r.get('detail', '')}{rtt_s}")
        print(f"{'PASS' if ok else 'FAIL'}     {k.id}")
        if not ok:
            bad += 1
    return 0 if bad == 0 else 1

def resolve_targets(a):
    """Resolve the filter set to addresses, or explain exactly why not.

    A filter that cannot be honoured must never come back as an empty list: an
    empty list reads as "nothing there", which is the one answer this tool is not
    allowed to guess.
    """
    try:
        return _resolve_targets(a)
    except ValueError as e:
        geo = geolib.Geo().load()
        have = ", ".join(geo.countries())
        raise SystemExit(
            f"filters not honoured: {e}\n"
            f"  countries with attributed prefixes: {have}")

def _class_population(a):
    """The class's declared population, unless the caller overrode it."""
    if a.population:
        return a.population
    k = by_id(getattr(a, "klass", "")) if getattr(a, "klass", None) else None
    return (k.population if k and getattr(k, "population", None) else "peeringdb-isp")

def _resolve_targets(a):
    geo = geolib.Geo().load()
    seed_name = getattr(a, "klass", None) or _class_population(a)
    if a.cidr:
        addrs = geolib.expand(a.cidr, per_net=a.per_net, limit=a.limit,
                              seed=geolib.seed_for(seed_name, a.seed))
        return addrs, f"{len(a.cidr)} CIDR(s) given, population ignored"
    pop = a.population = _class_population(a)
    spec = geolib.POPULATIONS.get(pop)
    if not spec:
        raise SystemExit(f"unknown population {pop!r}; try: "
                         + ", ".join(geolib.POPULATIONS))
    if spec["kind"] == "custom":
        raise ValueError("custom population needs --cidr (repeatable)")
    if spec["kind"] == "attributed":
        country = None if a.country in (None, "", "*") else a.country
        op = a.operator or None
        if country or op:
            pfx = geo.prefixes(country=country, operator=op)
            note = f"{len(pfx)} prefixes (country={country} operator={op})"
        else:
            pfx = geolib.population_prefixes(pop, geo)
            note = f"{len(pfx)} prefixes (whole population)"
        addrs = geolib.expand(pfx, per_net=a.per_net, limit=a.limit,
                              seed=geolib.seed_for(seed_name, a.seed))
        return addrs, note
    addrs, prov = geolib.population_targets(
        pop, geo, per_net=a.per_net, limit=a.limit,
        seed=geolib.seed_for(seed_name, a.seed))
    return addrs, prov.get("note", "flat population")

def cmd_dry(a):
    k = by_id(a.klass)
    if not k:
        print(f"unknown class: {a.klass}", file=sys.stderr)
        return 2
    addrs, note = resolve_targets(a)
    ports = k.ports
    print(f"class       {k.id} · {k.title} (tier {k.tier})")
    print(f"population  {a.population} · {note}")
    cov = geolib.population_coverage(a.population)
    if cov and cov["share"] < 0.999:
        print(f"coverage    {cov['resolved']:,}/{cov['asns']:,} ASNs resolved to "
              f"prefixes ({cov['share']:.0%}) — the missing part is NOT empty, it "
              f"is unfetched; run tools/fetch_popdb.py")
    print(f"addresses   {len(addrs):,}")
    print(f"per host    ports {','.join(str(p) for p in ports)}"
          f" → about {len(addrs) * len(ports):,} probes")
    print(f"at {a.rate} pps that is about {len(addrs) * len(ports) / max(1, a.rate) / 60:.1f} min")
    if not k.CONTROLS:
        print("WARNING     this class has no positive control: a zero result from it "
              "is not evidence of absence")
        if not getattr(a, "ungated", False):
            print("NOTE        --run will refuse this class without --ungated")
    print("            (pass --run to actually transmit)")
    return 0

def silence_rescan(k, run, a):
    """Re-probe a sample of the `unproven` rows at a tenth of the rate.

    A first pass that was throttled and a first pass that was correct look
    identical in the results file: both are mostly silence. The one measurement
    that separates them is asking the same hosts again, slowly. That is how the
    earlier work found a 13.8x undercount on one /24 — 10 hits at 48
    workers, 138 when the same block was re-run alone.

    So this is not a second sweep, it is a check on the first one, and its output
    is a statement about the run rather than about the targets.
    """
    import random
    rows = [r for r in run.rows() if r.get("verdict") == "unproven"]
    if len(rows) < 20:
        print("rescan      skipped: too few unproven rows to say anything")
        return
    n = min(len(rows), max(20, len(rows) // 100))
    sample = random.Random(0x5EED).sample(rows, n)
    slow = max(1.0, a.rate / 10.0)
    print(f"rescan      {n} of {len(rows):,} unproven rows at {slow:.0f} pps "
          f"(asking again slowly — a throttle and a correct miss look the same)")
    sys.stdout.flush()

    from core.engine import Bucket
    bucket = Bucket(slow)
    changed = 0
    for r in sample:
        bucket.take()
        try:
            out = k.probe(r["ip"], int(r["port"]), timeout=a.timeout)
        except Exception:
            continue
        if out.get("verdict") not in ("unproven", "error"):
            changed += 1
            print(f"AGAIN {r['ip']:<16}{r['port']:<7}{out.get('verdict'):<8}"
                  f"{(out.get('product') or '')[:26]:<28}{(out.get('detail') or '')[:60]}")
            sys.stdout.flush()
    print(rescan_note(changed, n))
    sys.stdout.flush()

CANARY_PORTS = (16999, 23456, 34567, 45678, 56789, 61001, 62002, 63003)

def canary_for(ip):
    """A high port derived from the address, so the test repeats exactly."""
    import zlib
    return CANARY_PORTS[zlib.crc32(str(ip).encode("utf-8")) % len(CANARY_PORTS)]

def suspicious_hosts(rows, min_ports=2):
    """Hosts that answered on >= min_ports distinct ports without being named.

    One unidentified open port is ordinary: a web server with a page no table
    recognises. Several is a question — either a multi-service host, or a
    middlebox answering for everything.
    """
    ports = {}
    for r in rows:
        if r.get("verdict") != "open":
            continue
        ports.setdefault(r["ip"], set()).add(int(r["port"]))
    return sorted(ip for ip, p in ports.items() if len(p) >= min_ports)

def intermediary_note(confirmed, tried, refused=0):
    """What the canary result means. Pure, so it can be asserted.

    Three outcomes, and they are not interchangeable. A canary that CONNECTS
    proves a middlebox. A canary that is REFUSED proves the host itself closed a
    port, so the ports it did answer are its own. A canary that TIMES OUT proves
    nothing: a filtered port and a closed port are the same silence, and reading
    that silence as "the opens are real" is exactly the overclaim this project
    exists to prevent. The first draft of this function made that mistake on a
    live run and reported three accelerator-fronted hosts as genuine.
    """
    if tried == 0:
        return "intermediary  no host answered on enough ports for the test to apply"
    if confirmed:
        pct = 100.0 * confirmed / tried
        return (f"intermediary  {confirmed}/{tried} ({pct:.0f}%) answered on an "
                f"arbitrary high port: an accelerator or proxy front-ends those "
                f"addresses, so their `open` rows are the middlebox, not a device")
    if refused == tried:
        return (f"intermediary  all {tried} suspicious host(s) refused an arbitrary "
                f"high port — their opens are real")
    undecided = tried - refused
    return (f"intermediary  {undecided}/{tried} could not be decided: the canary port "
            f"timed out, which is what a FILTERED port and a CLOSED port both look "
            f"like. This test cannot separate them; their opens stand as evidence, "
            f"not as proof")

def intermediary_rescan(k, run, a, cap=40):
    """Connect to a canary port on hosts that answered on several ports.

    Only ever runs over rows the sweep already produced, and only over hosts
    that gave it several `open` rows to be suspicious about, so it costs a
    handful of probes rather than a second pass.
    """
    rows = run.rows()
    hosts = suspicious_hosts(rows)[:cap]
    if not hosts:
        print("intermediary  no host answered on 2+ ports; nothing to check")
        return
    import random
    random.Random(0xCA7A1).shuffle(hosts)
    print(f"intermediary  checking {len(hosts)} host(s) that answered on several ports "
          f"(one probe each, on a port derived from the address)")
    sys.stdout.flush()

    from core.engine import Bucket
    from core import net as netlib
    bucket = Bucket(max(1.0, a.rate / 4.0))
    confirmed = 0
    refused = 0
    evidence = []
    for ip in hosts:
        port = canary_for(ip)
        bucket.take()
        try:
            pr = netlib.tcp_connect(ip, port, timeout=a.timeout)
        except Exception:
            continue
        if pr.state == netlib.OPEN:
            confirmed += 1
            print(f"INTERM {ip:<16}{port:<7}open — every port answers here")
            sys.stdout.flush()
        elif pr.state == netlib.REFUSED:
            refused += 1
        evidence.append((ip, port, pr.state))
    import os as _os
    out = _os.path.join(str(run.dir), "intermediary.tsv")
    try:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("ip\tcanary_port\tstate\n")
            for row in evidence:
                fh.write("\t".join(str(x) for x in row) + "\n")
    except OSError:
        pass
    print(intermediary_note(confirmed, len(hosts), refused))
    sys.stdout.flush()

def rescan_note(changed, n):
    """What a re-probe result means. Kept pure so it can be asserted.

    The threshold is 2%: re-asking a host that is genuinely silent almost never
    makes it answer, so any appreciable second-attempt hit rate is evidence about
    our own pacing rather than about the network.
    """
    if not n:
        return "rescan      no sample taken"
    share = changed / n
    if changed == 0:
        return (f"rescan      none of {n} answered on a second, slower attempt — "
                f"the silence is consistent with a real miss")
    if share < 0.02:
        return (f"rescan      {changed}/{n} answered on the second attempt "
                f"({share:.1%}) — the first pass may have been paced too fast")
    return (f"rescan      !! {changed}/{n} answered on the second attempt "
            f"({share:.1%}) — THE FIRST PASS WAS THROTTLED. Its zeroes are our own "
            f"rate limit, not absence. Re-run the class at a lower --rate.")

def cmd_run(a):
    k = by_id(a.klass)
    if not k:
        print(f"unknown class: {a.klass}", file=sys.stderr)
        return 2
    addrs, note = resolve_targets(a)
    if not addrs:
        print("no addresses after filtering — nothing launched", file=sys.stderr)
        return 1
    if not k.CONTROLS and not getattr(a, "ungated", False):
        print("REFUSED     ungated class: no positive control exists, so a zero "
              "result cannot be told apart from a broken matcher.", file=sys.stderr)
        print("            Re-run with --ungated to sweep it anyway, and read the "
              "result as 'nothing found in this population', never as 'nothing "
              "there'.", file=sys.stderr)
        return 3
    run = store.Run(k.id, a.population, a.rate, a.timeout, a.conc)
    q = queue.Queue()
    import threading
    stop = threading.Event()

    print(f"run         {run.id}")
    print(f"class       {k.id} · {k.title}")
    print(f"population  {a.population} · {note} · {len(addrs):,} addresses")
    cov = geolib.population_coverage(a.population)
    if cov and cov["share"] < 0.999:
        print(f"coverage    {cov['resolved']:,}/{cov['asns']:,} ASNs resolved "
              f"({cov['share']:.0%}) — unfetched, not empty")
    print(f"pacing      {a.rate} pps · {a.conc} workers · {a.timeout}s timeout")
    print(f"sampling    seed {geolib.seed_for(getattr(a, 'klass', '') or a.population, a.seed)}"
          f" · {a.per_net} per net · " + ("all hosts" if getattr(a, "all_hosts", False)
                                          else "edge-biased"))
    if not k.CONTROLS:
        print("WARNING     ungated class (--ungated given): a zero result is not "
              "evidence of absence")
    sys.stdout.flush()

    def pump():
        while True:
            kind, payload = q.get()
            if kind == "result":
                ip, port, r = payload
                if r.get("verdict") == "hit":
                    print(f"HIT   {ip:<16}{port:<7}{(r.get('product') or '')[:24]:<26}"
                          f"{r.get('detail', '')[:90]}")
                    sys.stdout.flush()
                elif r.get("verdict") == "open" and a.show_open:
                    print(f"open  {ip:<16}{port:<7}{(r.get('product') or '')[:24]:<26}"
                          f"{r.get('detail', '')[:90]}")
                    sys.stdout.flush()
            elif kind == "done":
                s = payload
                print(f"done        probed {fmt(s.get('probed'))} · hits {fmt(s.get('hits'))}"
                      f" · open {fmt(s.get('open'))} · unproven {fmt(s.get('unproven'))}"
                      f" · refused {fmt(s.get('refused'))} · errors {fmt(s.get('errors'))}"
                      f" · {s.get('pps', 0):.1f} pps")
                print(f"results     {run.results_path}")
                return
            elif kind == "error":
                print(f"ERROR       {payload}", file=sys.stderr)
                return

    import threading as _t
    p = _t.Thread(target=pump, daemon=True)
    p.start()
    try:
        engine.run_sweep(k, k.targets(addrs), run, q, stop, rate=a.rate,
                         conc=a.conc, timeout=a.timeout)
    except KeyboardInterrupt:
        stop.set()
        print("\ninterrupted — run kept, resume with the same command")
        return 130
    p.join(timeout=5)
    if not getattr(a, "no_rescan", False):
        silence_rescan(k, run, a)
    if not getattr(a, "no_intermediary", False):
        intermediary_rescan(k, run, a)
    return 0

def cmd_runs(_a):
    runs = store.list_runs()
    if not runs:
        print("no runs yet")
        return 0
    print(f"{'ID':<34}{'PROBED':>9}{'HITS':>7}  STATUS")
    for r in runs[:40]:
        print(f"{r['id']:<34}{fmt(r.get('probed', 0)):>9}{fmt(r.get('hits', 0)):>7}"
              f"  {r.get('status', '?')}")
    return 0

cli_suspicious = suspicious_hosts

def cmd_selftest(_a):
    """Assertions that need no network: the globe, the geometry, the verdicts."""
    fails = 0
    n = 0

    def chk(name, got, want):
        nonlocal fails, n
        n += 1
        if got != want:
            fails += 1
            print(f"FAIL {name}: got {got!r} want {want!r}")

    from core.globe import Globe
    g = Globe(44, 22)
    chk("land-gulf-of-guinea", g._land(0, 0), 0)
    chk("land-sahara", g._land(20, 0), 1)
    chk("land-paris", g._land(49, 2), 1)
    chk("land-atlantic", g._land(0, -30), 0)
    chk("land-australia", g._land(-25, 135), 1)
    chk("land-pacific", g._land(0, -150), 0)
    frames = g.frame(0)
    chk("frame-rows", len(frames), 22)
    chk("frame-cols", len(frames[0]), 44)
    chk("frame-rotates", g.frame(0) != g.frame(90), True)

    from classes.base import res, VERDICTS
    chk("verdict-set", set(VERDICTS), {"hit", "open", "unproven", "refused", "error"})
    chk("res-hit", res("hit", "x")["verdict"], "hit")
    try:
        res("closed")
        chk("res-rejects-closed", "no error", "an exception")
    except AssertionError:
        chk("res-rejects-closed", "AssertionError", "AssertionError")
    except Exception as e:
        chk("res-rejects-closed", type(e).__name__, "AssertionError")

    from classes.tier_b import MassResolve
    chk("ptr-formulaic", MassResolve.formulaic("198.51.100.77", "host-198.51.100.77.example-isp.net"), True)
    chk("ptr-reversed", MassResolve.formulaic("10.1.2.3", "3.2.1.10.rev.example.net"), True)
    chk("ptr-dashed", MassResolve.formulaic("10.1.2.3", "adsl-10-1-2-3.isp.net"), True)
    chk("ptr-informative", MassResolve.formulaic("10.1.2.3", "gnb-brasov01.isp.net"), False)

    for k in SWEEP_CLASSES:
        chk(f"class-{k.id}-id", k.id.startswith(k.tier.lower()), True)
        chk(f"class-{k.id}-probe", callable(getattr(k, "probe", None)), True)
        chk(f"class-{k.id}-targets", callable(getattr(k, "targets", None)), True)
        chk(f"class-{k.id}-ports", isinstance(k.ports, tuple), True)

    from core import geo as _geo
    one = _geo.expand(["198.51.100.77/32"])
    chk("expand-single-address", one, ["198.51.100.77"])
    chk("expand-types", all(isinstance(x, str) for x in _geo.expand(["10.0.0.0/24"])), True)
    chk("expand-bias-edges", sorted(_geo.expand(["10.0.0.0/30"]))[0], "10.0.0.0")

    chk("seed-stable", _geo.seed_for("d6_bmc"), _geo.seed_for("d6_bmc"))
    chk("seed-differs-by-name",
        _geo.seed_for("d6_bmc") != _geo.seed_for("e1_camera"), True)
    chk("seed-override", _geo.seed_for("d6_bmc", 1234), 1234)
    _s1 = _geo.expand(["198.51.100.0/24"], per_net=8, seed=_geo.seed_for("a"))
    _s2 = _geo.expand(["198.51.100.0/24"], per_net=8, seed=_geo.seed_for("b"))
    chk("expand-same-seed-repeats", _s1, _geo.expand(["198.51.100.0/24"], per_net=8,
                                                    seed=_geo.seed_for("a")))
    chk("expand-seed-moves-interior", _s1 != _s2, True)

    st = engine.Stats()
    for v in ("hit", "open", "unproven", "refused", "error"):
        st.add(v)
    snap = st.snapshot()
    chk("stats-hits", snap["hits"], 1)
    chk("stats-open", snap["open"], 1)
    chk("stats-probed", snap["probed"], 5)

    from core import net as _net
    from classes import netfp as _fp

    def fixture(klass, port, http=None, banner=None, udp=None):
        http, banner, udp = http or {}, banner or {}, udp or {}
        saved = (_fp.get, _fp.post, _net.tcp_banner, _net.udp_exchange,
                 _net.tcp_connect)

        def mk(status, hdrs, body):
            if isinstance(body, str):
                body = body.encode()
            return _net.HttpResult(status=status, headers=dict(hdrs or {}),
                                   body=body,
                                   text=body.decode("utf-8", "replace"),
                                   state=_net.OPEN, detail="", url="")

        def fget(ip, p, path="/", timeout=4.0, tls=False, host=None,
                 max_body=65536, headers=None):
            r = http.get((p, path))
            return mk(404, {}, b"") if r is None else mk(*r)

        def fpost(ip, p, path="/", body=b"", timeout=4.0, tls=False, ctype=None,
                  headers=None, host=None, max_body=65536):
            r = http.get((p, path))
            return mk(404, {}, b"") if r is None else mk(*r)

        def fbanner(ip, p, timeout=3.0, send=None, settle=0.6, limit=8192):
            r = banner.get(p)
            if r is None:
                return _net.Probe(state=_net.REFUSED, detail="RST")
            return _net.Probe(state=_net.OPEN, detail="fixture",
                              data=r[0], rtt=r[1] if len(r) > 1 else 1.0)

        def fudp(ip, p, payload, timeout=3.0, tries=2):
            r = udp.get(p)
            if r is None:
                return _net.Probe(state=_net.UNPROVEN, detail="silent")
            return _net.Probe(state=_net.OPEN, detail="fixture", data=r, rtt=1.0)

        def fconnect(ip, p, timeout=3.0):
            return _net.Probe(state=_net.REFUSED, detail="RST")

        _fp.get, _fp.post = fget, fpost
        _net.tcp_banner, _net.udp_exchange, _net.tcp_connect = fbanner, fudp, fconnect
        try:
            return klass.probe("192.0.2.10", port, timeout=1.0)
        finally:
            (_fp.get, _fp.post, _net.tcp_banner, _net.udp_exchange,
             _net.tcp_connect) = saved

    from core.classes import by_id as _by_id

    r = fixture(_by_id("d1_hypervisor"), 443,
                http={(443, "/"): (200, {}, "<html><title>VMware ESXi</title>")})
    chk("fx-esxi", (r["verdict"], r["product"]), ("hit", "VMware ESXi"))

    r = fixture(_by_id("d2_container"), 2375,
                http={(2375, "/_ping"): (200, {}, "OK"),
                      (2375, "/version"): (200, {}, '{"Version":"24.0.7"}')})
    chk("fx-docker", (r["verdict"], r["product"]), ("hit", "Docker Engine API"))

    r = fixture(_by_id("d2_container"), 10250,
                http={(10250, "/healthz"): (200, {}, "ok"),
                      (10250, "/pods"): (403, {}, '{"kind":"Status"}')})
    chk("fx-kubelet-auth", (r["verdict"], r["product"]),
        ("open", "kubelet"))

    r = fixture(_by_id("d3_ops"), 9090,
                http={(9090, "/api/v1/status/buildinfo"):
                      (200, {}, '{"status":"success","data":{"version":"2.45.0"}}')})
    chk("fx-prometheus", (r["verdict"], r["product"]), ("hit", "Prometheus"))

    r = fixture(_by_id("d3_ops"), 443,
                http={(443, "/api/health"):
                      (200, {}, '{"database":"ok","version":"10.2.0"}')})
    chk("fx-grafana-offport", (r["verdict"], r["product"]), ("hit", "Grafana"))

    r = fixture(_by_id("d3_ops"), 443,
                http={(443, "/"): (403, {"X-Jenkins": "2.440.2"}, "<html>jenkins</html>")})
    chk("fx-jenkins-header", (r["verdict"], r["product"]), ("hit", "Jenkins"))

    r = fixture(_by_id("d4_datastore"), 9200,
                http={(9200, "/"): (200, {},
                      '{"cluster_name":"prod","version":{"number":"8.11.1"}}')})
    chk("fx-elastic", (r["verdict"], r["product"]), ("hit", "Elasticsearch"))

    r = fixture(_by_id("d4_datastore"), 6379, banner={6379: (b"-NOAUTH Authentication required.\r\n", 1.0)})
    chk("fx-redis-auth", (r["verdict"], r["product"]),
        ("open", "Redis (auth required)"))

    r = fixture(_by_id("d4_datastore"), 6379, banner={6379: (b"+PONG\r\n", 1.0)})
    chk("fx-redis-open", (r["verdict"], r["product"]), ("hit", "Redis"))

    r = fixture(_by_id("d5_objectstore"), 9000,
                http={(9000, "/minio/health/live"): (200, {"x-minio-server": "aistor"}, ""),
                      (9000, "/"): (403, {}, "<Error><Code>AccessDenied</Code></Error>")})
    chk("fx-minio", (r["verdict"], r["product"]), ("hit", "MinIO"))

    r = fixture(_by_id("d5_objectstore"), 9000,
                http={(9000, "/minio/health/live"): (200, {}, ""),
                      (9000, "/"): (404, {}, "<title>nginx</title>")})
    chk("fx-minio-not-200-alone", r["verdict"], "open")

    r = fixture(_by_id("d6_bmc"), 443,
                http={(443, "/redfish/v1"):
                      (200, {}, '{"RedfishVersion":"1.15.0","Vendor":"Dell","Product":"iDRAC"}')})
    chk("fx-redfish", r["verdict"], "hit")

    r = fixture(_by_id("d6_bmc"), 623,
                udp={623: b"\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"})
    chk("fx-ipmi", r["verdict"], "hit")

    r = fixture(_by_id("e1_camera"), 80,
                http={(80, "/"): (200, {}, "<html><title>Hikvision</title>")})
    chk("fx-hikvision", (r["verdict"], r["product"]), ("hit", "Hikvision"))

    r = fixture(_by_id("e1_camera"), 80,
                http={(80, "/"): (200, {}, "<html><body>login</body></html>"),
                      (80, "/onvif/device_service"):
                      (200, {}, '<s:Envelope><GetSystemDateAndTimeResponse/></s:Envelope>')})
    chk("fx-onvif", (r["verdict"], r["product"]), ("hit", "ONVIF device"))

    r = fixture(_by_id("e1_camera"), 80,
                http={(80, "/"): (401, {"WWW-Authenticate": 'Digest realm="IPCamera"'},
                                  "<html><title>Dahua</title>")})
    chk("fx-camera-auth", (r["verdict"], r["product"]), ("open", "Dahua"))

    r = fixture(_by_id("e1_camera"), 554,
                banner={554: (b"RTSP/1.0 200 OK\r\nServer: Hikvision RTSP Server\r\n\r\n", 1.0)})
    chk("fx-rtsp", (r["verdict"], r["product"]), ("hit", "Hikvision"))

    r = fixture(_by_id("e2_bas"), 47808,
                udp={47808: b"\x81\x0a\x00\x0e\x01\x00\x10\x00\xc4\x02\x00\x00\x01\x22"})
    chk("fx-bacnet", (r["verdict"], r["product"]), ("hit", "BACnet device"))

    r = fixture(_by_id("e2_bas"), 502,
                banner={502: (bytes.fromhex("0001000000050103020011"), 1.0)})
    chk("fx-modbus", (r["verdict"], r["product"]), ("hit", "Modbus/TCP"))

    r = fixture(_by_id("e2_bas"), 502,
                banner={502: (bytes.fromhex("000100000003018302"), 1.0)})
    chk("fx-modbus-exception", r["verdict"], "open")

    r = fixture(_by_id("f1_plc"), 102,
                banner={102: (bytes.fromhex("0300001611d000010000000100c0010ac1020100c2020102c2020100"), 1.0)})
    chk("fx-s7", (r["verdict"], r["product"]), ("hit", "Siemens S7 / ISO-TSAP"))

    r = fixture(_by_id("f1_plc"), 44818,
                banner={44818: (bytes.fromhex("63000000") + b"\x00" * 20 + b"1756-L71/B", 1.0)})
    chk("fx-enip", r["verdict"], "hit")

    r = fixture(_by_id("f1_plc"), 4840,
                banner={4840: (b"ACKF" + b"\x00" * 24, 1.0)})
    chk("fx-opcua", (r["verdict"], r["product"]), ("hit", "OPC-UA server"))

    r = fixture(_by_id("f2_energy"), 80,
                http={(80, "/"): (200, {}, "<html><title>SolarEdge Monitoring</title>")})
    chk("fx-solaredge", (r["verdict"], r["product"]), ("hit", "SolarEdge"))

    r = fixture(_by_id("f2_energy"), 80,
                http={(80, "/"): (200, {}, "<html></html>"),
                      (80, "/solar_api/GetAPIVersion.cgi"):
                      (200, {}, '{"APIVersion":1}')})
    chk("fx-fronius", (r["verdict"], r["product"]), ("hit", "Fronius Datamanager"))

    from classes.tier_g import PRINTER_TABLE as _PT, MEDIA_TABLE as _MT
    _printer_table = lambda: _PT
    _media_table = lambda: _MT

    r = fixture(_by_id("g5_nas"), 80,
                http={(80, "/"): (200, {}, "<html><title>Hello! Welcome to Synology Web Station</title>")})
    chk("fx-synology", (r["verdict"], r["product"]), ("hit", "Synology DSM"))

    r = fixture(_by_id("g6_media"), 32400,
                http={(32400, "/identity"):
                      (200, {}, '<MediaContainer size="0" machineIdentifier="abc123"/>')})
    chk("fx-plex", (r["verdict"], r["product"]), ("hit", "Plex Media Server"))
    chk("fx-plex-machine", "machineIdentifier=abc123" in r["detail"], True)

    r = fixture(_by_id("g6_media"), 8096,
                http={(8096, "/System/Info/Public"):
                      (200, {}, '{"ServerName":"kodi-box","Version":"10.8.0"}')})
    chk("fx-jellyfin", (r["verdict"], r["product"]), ("hit", "Jellyfin"))

    r = fixture(_by_id("g7_printer"), 9100,
                banner={9100: (b"@PJL INFO ID\r\nHP LaserJet Pro MFP M127fn\r\n\x0c", 1.0)})
    chk("fx-pjl", (r["verdict"], r["product"]), ("hit", "HP LaserJet / OfficeJet"))
    chk("fx-pjl-model", "M127fn" in r["detail"], True)

    r = fixture(_by_id("g7_printer"), 631,
                banner={631: (b"\x02\x00\x00\x00\x00\x00\x00\x01", 1.0)})
    chk("fx-ipp", (r["verdict"], r["product"]), ("hit", "IPP printer"))

    r = fixture(_by_id("g7_printer"), 631,
                banner={631: (b"HTTP/1.1 200 OK\r\n\r\n", 1.0)})
    chk("fx-ipp-http", (r["verdict"], r["product"]), ("open", "IPP over HTTP"))

    r = fixture(_by_id("g4_voip"), 5038,
                banner={5038: (b"Asterisk Call Manager/5.0.3\r\n", 1.0)})
    chk("fx-ami", (r["verdict"], r["product"]), ("hit", "Asterisk Manager Interface"))

    r = fixture(_by_id("g4_voip"), 5060,
                udp={5060: b"SIP/2.0 200 OK\r\nServer: Grandstream UCM6202\r\n\r\n"})
    chk("fx-sip", (r["verdict"], r["product"]), ("hit", "Grandstream"))

    r = fixture(_by_id("g4_voip"), 5060)
    chk("fx-sip-silent", r["verdict"], "unproven")
    chk("fx-sip-tcp-rst-is-not-closure", "UDP silent" in r["detail"], True)
    chk("fx-sip-not-closed", r["verdict"] != "refused", True)

    r = fixture(_by_id("g8_rtu"), 80,
                http={(80, "/"): (200, {}, "<html><title>Teltonika Networks</title>")})
    chk("fx-teltonika", (r["verdict"], r["product"]), ("hit", "Teltonika RUT / TRB"))

    r = fixture(_by_id("g2_radio"), 80,
                http={(80, "/"): (200, {}, "<html><title>Cambium ePMP</title>")})
    chk("fx-epmp", (r["verdict"], r["product"]), ("hit", "Cambium ePMP"))

    chk("fx-canonical-not-canon",
        SweepClass.match_any('<link rel="canonical" href="/x">', _printer_table()), None)
    chk("fx-canon-real", SweepClass.match_any("<title>Canon iR-ADV C5535</title>",
                                              _printer_table()), "Canon")
    chk("fx-complex-not-plex",
        SweepClass.match_any("this is a complex form", _media_table()), None)

    import classes.tier_a as _ta
    import classes.tier_b as _tb
    import classes.tier_c as _tc
    import classes.tier_d as _td
    import classes.tier_e as _te
    import classes.tier_f as _tf
    import classes.tier_g as _tg

    innocuous = (
        "process_cpu_seconds_total 2.87e+04\n"
        "process_resident_memory_bytes 1.9e+08\n"
        'python_gc_objects_collected_total{generation="0"} 1.7e+06\n'
        "python_gc_objects_uncollectable_total 0.0\n"
        "# HELP number of open file descriptors\n"
        "statement of work and advance notice for the meeting\n"
        "the font family and the line height of this paragraph\n"
        "boxes shipped, zombies processed, examples given\n"
        "you must be 18 or older to enter, take care\n"
        "we use cookies to improve your experience, sign in to continue\n"
        '<title>Welcome</title><link rel="canonical" href="/">\n'
        "powered by WordPress, hosted on shared infrastructure\n"
        "our mission is to enable growth across the region\n"
        "communication manager for the document workflow\n"
    ).lower()
    every_table = []
    for _m in (_ta, _tb, _tc, _td, _te, _tf, _tg):
        for _n, _v in vars(_m).items():
            if _n.endswith("TABLE") and isinstance(_v, list):
                every_table.append((_n, _v))
    chk("kw-tables-found", len(every_table) >= 21, True)
    chk("kw-none-innocuous",
        [f"{n}->{SweepClass.match_any(innocuous, t)}"
         for n, t in every_table if SweepClass.match_any(innocuous, t)], [])

    from classes.tier_a import CONSOLE_TABLE as _console, ONT_TABLE as _ont, \
        OLT_TABLE as _olt
    from classes.tier_e import CAMERA_TABLE as _cam
    from classes.tier_g import (VOIP_TABLE as _voip, HEADEND_TABLE as _head,
                                MEDIA_TABLE as _med, NAS_TABLE as _nas)

    chk("kw-digit-suffix-gxp", SweepClass.match_any("GXP1625", _voip), "Grandstream")
    chk("kw-digit-suffix-scs", SweepClass.match_any("SCS3200", _console),
        "Lantronix ETS/SCS")
    chk("kw-model-nport", SweepClass.match_any("NPort 5650", _console), "Moxa NPort")
    chk("kw-model-axis", SweepClass.match_any("<title>AXIS P3245-LVE</title>", _cam),
        "Axis")
    chk("kw-model-ds2cd", SweepClass.match_any("DS-2CD2143G2-I", _cam), "Hikvision")
    chk("kw-seconds-not-nds", SweepClass.match_any("seconds elapsed", _head), None)
    chk("kw-statement-not-ateme", SweepClass.match_any("statement of work", _head), None)
    chk("kw-advance-not-adva", SweepClass.match_any("advance notice", _ta.OLT_TABLE
                                                    if False else _olt), None)
    chk("kw-font-not-ont", SweepClass.match_any("font family", _ont), None)
    chk("kw-boxes-not-oxe", SweepClass.match_any("boxes shipped", _voip), None)
    chk("kw-zombie-not-ombi", SweepClass.match_any("zombie process", _med), None)
    chk("kw-example-not-exa", SweepClass.match_any("for example", _olt), None)
    chk("kw-buffalo-word", SweepClass.match_any("a herd of buffalo", _nas), None)
    chk("kw-harmonic-word", SweepClass.match_any("harmonic distortion", _head), None)
    chk("kw-tilde-prefix", SweepClass.match_any("DS-2CD2143", [("Code", ["~ds-2cd"])]),
        "Code")

    from classes.tier_e import BACNET_WHO_IS, MODBUS_READ, FOX_HELLO
    from classes.tier_f import (S7_COTP_CR, ENIP_LIST_IDENTITY, OPCUA_HEL,
                                DNP3_RESET, IEC104_STARTDT)
    from classes.tier_d import IPMI_AUTH_CAPS, MONGO_HELLO

    chk("enc-s7-len", len(S7_COTP_CR), 22)
    chk("enc-s7-tpkt", int.from_bytes(S7_COTP_CR[2:4], "big"), len(S7_COTP_CR))
    chk("enc-s7-cr", (S7_COTP_CR[5], S7_COTP_CR[4]), (0xE0, 0x11))

    chk("enc-enip-len", len(ENIP_LIST_IDENTITY), 24)
    chk("enc-enip-cmd", ENIP_LIST_IDENTITY[:2], b"\x63\x00")
    chk("enc-enip-paylen", int.from_bytes(ENIP_LIST_IDENTITY[2:4], "big"), 0)

    chk("enc-opcua-magic", OPCUA_HEL[:4], b"HELF")
    chk("enc-opcua-len", int.from_bytes(OPCUA_HEL[4:8], "little"), len(OPCUA_HEL))

    chk("enc-dnp3-len", len(DNP3_RESET), 8)
    chk("enc-dnp3-sync", DNP3_RESET[:2], b"\x05\x64")

    chk("enc-iec104-len", len(IEC104_STARTDT), 6)
    chk("enc-iec104-hdr", int.from_bytes(IEC104_STARTDT[1:2], "big"), len(IEC104_STARTDT) - 2)

    chk("enc-bacnet-len", len(BACNET_WHO_IS), 8)
    chk("enc-bacnet-bvll", int.from_bytes(BACNET_WHO_IS[2:4], "big"), len(BACNET_WHO_IS))
    chk("enc-bacnet-whois", BACNET_WHO_IS[6:], b"\x10\x08")

    chk("enc-modbus-mbap", int.from_bytes(MODBUS_READ[4:6], "big"), len(MODBUS_READ) - 6)
    chk("enc-modbus-func", MODBUS_READ[7], 3)

    chk("enc-ipmi-rmcp", IPMI_AUTH_CAPS[:4], b"\x06\x00\xff\x07")
    chk("enc-ipmi-len", len(IPMI_AUTH_CAPS), 24)
    chk("enc-ipmi-authtype", IPMI_AUTH_CAPS[14], 0x20)

    chk("enc-mongo-len", int.from_bytes(MONGO_HELLO[:4], "little"), len(MONGO_HELLO))
    chk("enc-mongo-opquery", int.from_bytes(MONGO_HELLO[12:16], "little"), 2004)
    chk("enc-fox-name", b"fox" in FOX_HELLO, True)

    from classes.tier_g import (SIP_OPTIONS, IPP_GET_ATTR, IPP_VERSION,
                                IPP_OP_GET_ATTR, IPP_END, PJL_INFO_ID)
    chk("enc-sip-crlf", SIP_OPTIONS.endswith(b"\r\n\r\n"), True)
    chk("enc-sip-cseq", b"CSeq: 1 OPTIONS" in SIP_OPTIONS, True)
    chk("enc-sip-via", b"Via: SIP/2.0/UDP" in SIP_OPTIONS, True)
    chk("enc-sip-clen", b"Content-Length: 0" in SIP_OPTIONS, True)
    chk("enc-sip-starts", SIP_OPTIONS.startswith(b"OPTIONS sip:"), True)

    chk("enc-ipp-version", IPP_GET_ATTR[:2], IPP_VERSION)
    chk("enc-ipp-op", IPP_GET_ATTR[2:4], IPP_OP_GET_ATTR)
    chk("enc-ipp-reqid", IPP_GET_ATTR[4:8], b"\x00\x00\x00\x01")
    chk("enc-ipp-group", IPP_GET_ATTR[8:9], b"\x01")
    chk("enc-ipp-end", IPP_GET_ATTR[-1:], IPP_END)
    off, ok = 9, True
    while off < len(IPP_GET_ATTR) - 1:
        off += 1
        nlen = int.from_bytes(IPP_GET_ATTR[off:off + 2], "big")
        name = IPP_GET_ATTR[off + 2:off + 2 + nlen]
        off += 2 + nlen
        vlen = int.from_bytes(IPP_GET_ATTR[off:off + 2], "big")
        val = IPP_GET_ATTR[off + 2:off + 2 + vlen]
        off += 2 + vlen
        if nlen != len(name) or vlen != len(val) or off > len(IPP_GET_ATTR) - 1:
            ok = False
            break
    chk("enc-ipp-lengths", ok, True)
    chk("enc-ipp-charset", b"utf-8" in IPP_GET_ATTR, True)
    chk("enc-pjl-uel", PJL_INFO_ID.startswith(b"\x1b%-12345X"), True)
    chk("enc-pjl-info", b"@PJL INFO ID" in PJL_INFO_ID, True)
    chk("enc-pjl-tail", PJL_INFO_ID.count(b"\x1b%-12345X"), 2)

    import threading as _th
    from core.engine import Bucket
    b = Bucket(50)
    chk("bucket-initial", b.rate, 50.0)
    b.set_rate(7)
    chk("bucket-retuned", b.rate, 7.0)
    before = b.sent
    paused = _th.Event()
    paused.set()
    b.take(paused)
    chk("bucket-paused-no-send", b.sent, before)
    paused.clear()
    b.take(None)
    chk("bucket-resumed-sends", b.sent, before + 1)

    from core import geo as _geo
    cov = _geo.population_coverage("enterprise")
    chk("coverage-has-asns", bool(cov and cov["asns"] > 0), True)
    chk("coverage-shape", set(cov or {}), {"asns", "resolved", "share"})
    chk("coverage-flat-is-none", _geo.population_coverage("cellular-flat"), None)
    missing = [k.id for k in SWEEP_CLASSES
               if getattr(k, "population", None) not in _geo.POPULATIONS]
    chk("every-class-population-exists", missing, [])

    chk("rescan-zero-is-miss", "consistent with a real miss" in rescan_note(0, 100), True)
    chk("rescan-small-is-pacing", "may have been paced too fast" in rescan_note(1, 100), True)
    chk("rescan-throttled", "FIRST PASS WAS THROTTLED" in rescan_note(10, 100), True)
    chk("rescan-empty", rescan_note(0, 0), "rescan      no sample taken")

    for k in SWEEP_CLASSES:
        try:
            k.probe("192.0.2.10", 1, timeout=0.05, tls=True)
            chk(f"tls-kw-{k.id}", "ok", "ok")
        except TypeError as e:
            chk(f"tls-kw-{k.id}", f"TypeError: {e}", "ok")
        except Exception:
            chk(f"tls-kw-{k.id}", "ok", "ok")

    from core import net as _net, dns as _dns
    _net.clear_evidence()
    _net.record("tcp_banner", "192.0.2.1", 23,
                type("R", (), {"state": "open", "detail": "banner", "text": "x" * 900,
                               "rtt": 0.01})())
    ring = _net.take_evidence()
    chk("evidence-recorded", len(ring), 1)
    chk("evidence-target", ring[0]["target"], "192.0.2.1:23")
    chk("evidence-truncated", len(ring[0]["text"]) <= _net.EV_TEXT + 1, True)
    chk("evidence-cleared", _net.take_evidence(), [])
    for i in range(_net.EV_RING + 3):
        _net.record("f", "192.0.2.2", i, type("R", (), {"state": "open"})())
    chk("evidence-ring-capped", len(_net.take_evidence()), _net.EV_RING)

    import threading as _th
    _out = {}

    def _ev_thread():
        _net.clear_evidence()
        _net.record("f", "192.0.2.3", 1, type("R", (), {"state": "open"})())
        _out["ring"] = _net.take_evidence()
    _t = _th.Thread(target=_ev_thread)
    _t.start()
    _t.join()
    chk("evidence-per-thread", len(_out.get("ring", [])), 1)

    for nm, ok, detail in _dns.selftest():
        chk(f"dns-{nm}", ok, True)

    chk("lookup-rejects-garbage", _geo.lookup("not-an-ip"), None)
    chk("lookup-rejects-octet", _geo.lookup("999.1.1.1"), None)
    chk("lookup-rejects-empty", _geo.lookup(""), None)

    _rows = [
        {"ip": "192.0.2.10", "port": 80, "verdict": "open"},
        {"ip": "192.0.2.10", "port": 443, "verdict": "open"},
        {"ip": "192.0.2.11", "port": 80, "verdict": "open"},
        {"ip": "192.0.2.12", "port": 80, "verdict": "hit"},
        {"ip": "192.0.2.12", "port": 443, "verdict": "hit"},
        {"ip": "192.0.2.13", "port": 80, "verdict": "refused"},
        {"ip": "192.0.2.13", "port": 443, "verdict": "refused"},
    ]
    chk("interm-selects-multi-port", cli_suspicious(_rows), ["192.0.2.10"])
    chk("interm-ignores-hits",
        cli_suspicious([r for r in _rows if r["ip"] == "192.0.2.12"]), [])
    chk("interm-ignores-refused",
        cli_suspicious([r for r in _rows if r["ip"] == "192.0.2.13"]), [])
    chk("interm-min-ports-3", cli_suspicious(_rows, min_ports=3), [])
    chk("interm-canary-stable", canary_for("192.0.2.10"), canary_for("192.0.2.10"))
    chk("interm-canary-is-high", canary_for("192.0.2.10") > 16000, True)
    chk("interm-canary-in-set", canary_for("192.0.2.10") in CANARY_PORTS, True)
    chk("interm-note-none", "no host answered" in intermediary_note(0, 0), True)
    chk("interm-note-confirmed",
        "middlebox, not a device" in intermediary_note(3, 5, 2), True)
    chk("interm-note-pct", "60%" in intermediary_note(3, 5, 2), True)
    chk("interm-note-all-refused",
        "their opens are real" in intermediary_note(0, 5, 5), True)
    chk("interm-note-timeout-undecided",
        "could not be decided" in intermediary_note(0, 5, 0), True)
    chk("interm-note-timeout-not-proof",
        "opens are real" in intermediary_note(0, 5, 0), False)
    chk("interm-note-mixed-undecided",
        "2/5 could not be decided" in intermediary_note(0, 5, 3), True)

    from core import ui as _ui
    _long = ("Serial lines into routers and basebands. Telnet/SSH banner plus the "
             "raw serial-over-TCP banner.")
    chk("mq-short-untouched", _ui.marquee("Short.", 40, 500), "Short.")
    chk("mq-empty-width", _ui.marquee(_long, 0, 500), "")
    chk("mq-frame0-is-head", _ui.marquee(_long, 20, 0), _long[:20])
    chk("mq-holds-at-first", _ui.marquee(_long, 20, 5), _long[:20])
    chk("mq-moves", _ui.marquee(_long, 20, 60) != _long[:20], True)
    chk("mq-width-exact",
        [len(_ui.marquee(_long, w, f)) for w in (1, 7, 20, 45) for f in (0, 30, 90)],
        [min(w, len(_long)) if f == 0 else w
         for w in (1, 7, 20, 45) for f in (0, 30, 90)])
    chk("mq-wraps-not-raises",
        len(_ui.marquee(_long, 20, 100000)), 20)

    print(f"RESULT assertions {n} / fail {fails}")
    return 0 if fails == 0 else 1

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    p = argparse.ArgumentParser(prog="atomicsweep", add_help=True)
    p.add_argument("--list", action="store_true", help="list the sweep classes")
    p.add_argument("--gate", nargs="?", const="", default=None,
                   help="run a class's positive controls (all when bare)")
    p.add_argument("--dry-run", dest="klass", metavar="CLASS",
                   help="count the probes without transmitting")
    p.add_argument("--run", dest="do_run", metavar="CLASS",
                   help="launch the sweep")
    p.add_argument("--runs", action="store_true", help="list past runs")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--population", default=None,
                   help="population to sweep (default: the class's own declared "
                        "population, because a printer is not in an operator's "
                        "transport network)")
    p.add_argument("--cidr", action="append", default=[],
                   help="with --population custom: a CIDR, repeatable")
    p.add_argument("--country", default="*")
    p.add_argument("--operator", default="")
    p.add_argument("--rate", type=int, default=40)
    p.add_argument("--conc", type=int, default=64)
    p.add_argument("--timeout", type=int, default=3)
    p.add_argument("--per-net", dest="per_net", type=int, default=6)
    p.add_argument("--seed", type=int, default=None,
                   help="address-sampling seed; default is derived from the "
                        "population name so a rerun repeats exactly and a "
                        "different population covers different addresses")
    p.add_argument("--limit", type=int, default=20000)
    p.add_argument("--ungated", action="store_true",
                   help="allow --run on a class with no positive control (default: refuse)")
    p.add_argument("--no-rescan", dest="no_rescan", action="store_true",
                   help="skip the slow re-probe of unproven rows after a run")
    p.add_argument("--no-intermediary", dest="no_intermediary",
                   action="store_true",
                   help="skip the canary check that detects a proxy answering "
                        "for every port (it labels opens that are not a device)")
    p.add_argument("--show-open", dest="show_open", action="store_true",
                   help="also print `open` rows (unidentified services)")
    a = p.parse_args(argv)

    if a.list:
        return cmd_list(a)
    if a.gate is not None:
        return cmd_gate(a)
    if a.runs:
        return cmd_runs(a)
    if a.selftest:
        return cmd_selftest(a)
    if a.do_run:
        a.klass = a.do_run
        return cmd_run(a)
    if a.klass:
        return cmd_dry(a)
    p.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
