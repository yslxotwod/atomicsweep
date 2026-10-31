#!/usr/bin/env python3
"""Build the population database from the PeeringDB dump.

Why this exists: the first populations were built for the telecom ladder and
they are the wrong address space for everything else. A hypervisor, a NAS, a
printer, a Docker API and a Plex server are not found in an operator's transport
network — they are found in hosting, enterprise and broadband-consumer space.
Sweeping `mobile-mno` for `g7_printer` is not a negative result about printers,
it is a result about where we looked.

So each class declares the population that suits it, and this script builds
those populations from a source that says what a network actually is rather than
what its name looks like.

Input : /home/ysl/peeringdb_2_dump_2026_10_26.json
Output: ~/oracle/data/popdb.json  — {population: {asns: [...], desc, source}}

Deliberate exclusions, recorded so nobody re-adds them as "coverage":
  * Route Server and Route Collector — those ASNs are IX fabric infrastructure,
    not operators. Their "addresses" are peering LANs that are not globally
    routed (every one of 262 probed came back dead), so including them would
    manufacture an absence.
  * AS0, ASNs with no prefixes declared, and the RFC 6996 private range.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import os
import re
import sys

DUMP = "/home/ysl/peeringdb_2_dump_2026_10_26.json"
OUT = os.path.expanduser("~/oracle/data/popdb.json")

INFRA_RE = re.compile(
    r"\b(utility|utilities|energy|electric|power|grid|water|gas|pipeline|"
    r"hospital|clinic|health|airport|seaport|rail|railway|metro|transit|"
    r"telemetry|scada|industrial)\b", re.I)

EXCLUDE_TYPES = {"Route Server", "Route Collector"}

def main():
    with open(DUMP, encoding="utf-8") as fh:
        dump = json.load(fh)
    nets = dump["net"]["data"]
    orgs = {o["id"]: o for o in dump["org"]["data"]}

    by_type = collections.defaultdict(list)
    infra = []
    excluded = collections.Counter()

    for n in nets:
        asn = n.get("asn")
        if not asn:
            excluded["no-asn"] += 1
            continue
        if asn == 0 or 64496 <= asn <= 64511 or 64512 <= asn <= 65534 or asn >= 4200000000:
            excluded["private-or-reserved"] += 1
            continue
        it = n.get("info_type") or ""
        if it in EXCLUDE_TYPES:
            excluded[it] += 1
            continue
        rec = {
            "asn": asn,
            "name": n.get("name") or "",
            "type": it,
            "pfx4": n.get("info_prefixes4") or 0,
            "ix": n.get("ix_count") or 0,
            "fac": n.get("fac_count") or 0,
            "org": (orgs.get(n.get("org_id")) or {}).get("name", ""),
        }
        by_type[it].append(rec)
        if it in ("Enterprise", "Government", "Educational/Research", "Non-Profit"):
            blob = f"{rec['name']} {rec['org']}"
            if INFRA_RE.search(blob):
                infra.append(rec)

    def sort_key(r):
        return (-r["pfx4"], -r["ix"], -r["fac"], r["asn"])

    def take(rows, cap=None):
        rows = sorted(rows, key=sort_key)
        return rows[:cap] if cap else rows

    pops = {}

    def add(name, rows, desc, source, cap=None):
        rows = take(rows, cap)
        pops[name] = {
            "asns": [r["asn"] for r in rows],
            "desc": desc,
            "source": source,
            "declared_prefixes4": sum(r["pfx4"] for r in rows),
        }

    add("pdb-isp", by_type["Cable/DSL/ISP"] + by_type["NSP"],
        "ISPs and carriers that declare an access or transit role",
        "peeringdb info_type in (Cable/DSL/ISP, NSP)")

    add("hosting-cloud", by_type["Content"] + by_type["Network Services"],
        "content networks, CDNs, VPS and hosting providers — the address space "
        "where an exposed Docker API, Elasticsearch, MinIO or Jenkins lives",
        "peeringdb info_type in (Content, Network Services)")

    add("enterprise", by_type["Enterprise"] + by_type["Government"],
        "enterprise and government networks — printers, PBX, cameras, NAS, "
        "hypervisors, door controllers, building automation",
        "peeringdb info_type in (Enterprise, Government)")

    add("education", by_type["Educational/Research"],
        "universities and research networks — big mixed estates with permissive "
        "management planes",
        "peeringdb info_type == Educational/Research")

    add("broadband", by_type["Cable/DSL/ISP"],
        "consumer broadband access networks — where domestic cameras, NAS, media "
        "servers and home routers live; capped to the largest declared networks",
        "peeringdb info_type == Cable/DSL/ISP, top 2000 by declared prefixes",
        cap=2000)

    add("small-org", by_type["Non-Profit"],
        "non-profits, clinics, co-ops and small institutions — the segment that "
        "keeps a device public because it works",
        "peeringdb info_type == Non-Profit")

    add("critical-infra", infra,
        "networks whose name or organisation says utility, energy, water, "
        "hospital, airport, rail or industrial — the population tier F needs and "
        "cannot get from any registry field",
        "peeringdb Enterprise/Government/Education/Non-Profit with an "
        "infrastructure name match")

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"generated_from": DUMP, "populations": pops}, fh, indent=1)

    print(f"wrote {OUT}")
    print(f"excluded: {dict(excluded)}")
    print(f"{'population':<16}{'ASNs':>7}{'declared /24s':>15}  description")
    for k, v in pops.items():
        print(f"{k:<16}{len(v['asns']):>7}{v['declared_prefixes4']:>15}  {v['desc'][:60]}")
    allasn = set()
    for v in pops.values():
        allasn.update(v["asns"])
    print(f"\nunion: {len(allasn):,} distinct ASNs across {len(pops)} populations")

if __name__ == "__main__":
    sys.exit(main())
