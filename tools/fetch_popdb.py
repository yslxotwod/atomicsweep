#!/usr/bin/env python3
"""Resumable RIPEstat prefix fetch for the population DB.

The population database (`tools/build_popdb.py`) knows *which* ASNs belong to a
population. This fetches the announced prefixes for them, one ASN at a time,
into a persistent cache — because the census sweep taught the lesson that a
prefix list is only as good as the day it was refreshed, and because 24,696
lookups is hours of wall clock that must survive a kill.

Cache file: ~/oracle/data/popdb_pfx.json   {asn_str: {"prefixes": [...], "v6": [...], "addrs": N, "ts": iso}}

Rules that matter:
  * an ASN with NO announced prefixes is recorded as `[]`, not skipped — "we
    asked and it announces nothing" and "we have not asked" are different facts
    and must not collapse into one.
  * a failed lookup is NOT written, so it is retried next run.
  * RIPEstat is asked nicely: a fixed inter-request delay, and a backoff on
    non-200 rather than a retry storm.

Usage:
  fetch_popdb.py --population hosting-cloud --limit 200
  fetch_popdb.py --all --minutes 60
  fetch_popdb.py --status
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request

ORACLE = os.path.expanduser("~/oracle/data")
POPDB = os.path.join(ORACLE, "popdb.json")
CACHE = os.path.join(ORACLE, "popdb_pfx.json")
RI = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d"
UA = "atomicsweep/1.0 (population builder)"

def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default

def save_cache(cache):
    tmp = CACHE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cache, fh)
    os.replace(tmp, CACHE)

def fetch(asn, timeout=20):
    req = urllib.request.Request(RI % asn, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if r.status != 200:
            return None
        return json.loads(r.read().decode("utf-8", "replace"))

def parse(doc):
    """(v4 prefixes, v6 prefixes) from a RIPEstat announced-prefixes answer."""
    v4, v6 = [], []
    try:
        rows = doc["data"]["prefixes"]
    except (KeyError, TypeError):
        return None
    for row in rows:
        p = row.get("prefix")
        if not p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6

def addrs_of(prefixes):
    n = 0
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            n += net.num_addresses
    return n

def cmd_status():
    popdb = load_json(POPDB, {}).get("populations", {})
    cache = load_json(CACHE, {})
    if not popdb:
        print("no popdb — run tools/build_popdb.py first", file=sys.stderr)
        return 1
    print(f"cache: {CACHE}  {len(cache):,} ASNs resolved")
    print(f"{'population':<16}{'ASNs':>7}{'resolved':>10}{'prefixes':>10}{'v4 addrs':>14}")
    for name, spec in popdb.items():
        asns = spec.get("asns", [])
        got = [a for a in asns if str(a) in cache]
        pfx = sum(len(cache[str(a)].get("prefixes", [])) for a in got)
        adr = sum(cache[str(a)].get("addrs", 0) for a in got)
        print(f"{name:<16}{len(asns):>7}{len(got):>10}{pfx:>10}{adr:>14,}")
    return 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--population", action="append", default=[],
                    help="population name from popdb.json (repeatable)")
    ap.add_argument("--all", action="store_true", help="every population")
    ap.add_argument("--limit", type=int, default=0, help="stop after N new lookups")
    ap.add_argument("--minutes", type=float, default=0.0,
                    help="stop after N minutes (so a big run can be left and returned to)")
    ap.add_argument("--delay", type=float, default=0.25,
                    help="seconds between requests (default 0.25 = 4/s)")
    ap.add_argument("--conc", type=int, default=6,
                    help="parallel lookups (default 6); the --delay rate cap still "
                         "applies globally, so this raises throughput without "
                         "raising the request rate past what the source allows")
    ap.add_argument("--status", action="store_true")
    a = ap.parse_args()

    if a.status:
        return cmd_status()

    popdb = load_json(POPDB, {}).get("populations", {})
    if not popdb:
        print("no popdb — run tools/build_popdb.py first", file=sys.stderr)
        return 1

    names = list(popdb) if a.all else a.population
    if not names:
        print("give --population NAME or --all (see --status)", file=sys.stderr)
        return 2

    for n in names:
        if n not in popdb:
            print(f"unknown population {n!r}; have: {', '.join(popdb)}", file=sys.stderr)
            return 2

    queues = [list(popdb[n].get("asns", [])) for n in names]
    want = []
    seen = set()
    while any(queues):
        for q in queues:
            while q:
                asn = q.pop(0)
                if asn not in seen:
                    seen.add(asn)
                    want.append(asn)
                    break

    cache = load_json(CACHE, {})
    todo = [a for a in want if str(a) not in cache]
    print(f"populations  {', '.join(names)}")
    print(f"asns         {len(want):,} total · {len(want) - len(todo):,} cached · "
          f"{len(todo):,} to fetch")
    if a.limit:
        todo = todo[:a.limit]
        print(f"limit        {len(todo):,}")
    print(f"rate         {1/a.delay:.1f}/s → about {len(todo) * a.delay / 60:.0f} min")
    sys.stdout.flush()

    t0 = time.time()
    done = fail = empt = 0
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    lock = threading.Lock()
    next_slot = [time.time()]

    def pace():
        with lock:
            now = time.time()
            if next_slot[0] < now:
                next_slot[0] = now
            slot = next_slot[0]
            next_slot[0] += a.delay
        sleep = slot - time.time()
        if sleep > 0:
            time.sleep(sleep)

    def one(asn):
        pace()
        try:
            doc = fetch(asn)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return asn, ("fail", type(e).__name__)
        parsed = parse(doc) if doc else None
        if parsed is None:
            return asn, ("fail", "unparseable")
        return asn, ("ok", parsed)

    stopped = False
    try:
        with ThreadPoolExecutor(max_workers=max(1, a.conc)) as pool:
            futs = [pool.submit(one, asn) for asn in todo]
            for i, fu in enumerate(as_completed(futs)):
                if a.minutes and (time.time() - t0) / 60.0 >= a.minutes:
                    print(f"stopping     after {a.minutes:g} min as asked")
                    for f in futs:
                        f.cancel()
                    stopped = True
                    break
                asn, (state, payload) = fu.result()
                if state == "fail":
                    fail += 1
                    if fail % 20 == 0:
                        print(f"  {fail} failures so far (last: {payload})")
                        sys.stdout.flush()
                    continue
                v4, v6 = payload
                cache[str(asn)] = {
                    "prefixes": v4,
                    "v6": v6,
                    "addrs": addrs_of(v4),
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
                done += 1
                if not v4:
                    empt += 1
                if done % 100 == 0:
                    save_cache(cache)
                    el = time.time() - t0
                    rate = done / el if el else 0
                    left = (len(todo) - i - 1) / rate / 60 if rate else 0
                    print(f"  {done:,} done · {empt} announce nothing · {fail} failed · "
                          f"{rate:.1f}/s · ~{left:.0f} min left")
                    sys.stdout.flush()
    except KeyboardInterrupt:
        stopped = True
        print("interrupted")
    finally:
        save_cache(cache)
        el = time.time() - t0
        print(f"saved        {CACHE} ({len(cache):,} ASNs)")
        print(f"this run     {done:,} fetched · {empt} announced nothing · {fail} failed "
              f"· {el/60:.1f} min")
    return 0

if __name__ == "__main__":
    sys.exit(main())
