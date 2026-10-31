#!/usr/bin/env python3
"""Build the ASN -> country / name index the geo filter needs.

Why this exists: `census_holders.json` carries a country code for 2,953 ASNs, but
those ASNs are an Africa-weighted census and overlap the 707 PeeringDB-qualified
ISPs by only 27. So a country filter built on the census alone knows five
countries and silently reports "no prefixes for country ZA" — which reads exactly
like "South Africa has no operator kit", the failure mode this project exists to
avoid.

PeeringDB's `net` table has no country field, but every net carries `org_id` and
the `org` table carries `country`. Joining those two gives a country for ~35,752
ASNs, which is the whole registry rather than one continent.

Writes:
    ~/oracle/data/asn_cc.json     {"<asn>": "<cc>"}      35k ASNs
    ~/oracle/data/asn_name.json   {"<asn>": "<name>"}    35k ASNs
"""

from __future__ import annotations

import json
import os
import sys

ORACLE = os.path.expanduser("~/oracle/data")
DUMP = os.path.expanduser("~/peeringdb_2_dump_2026_10_26.json")

def main(argv):
    dump = argv[0] if argv else DUMP
    if not os.path.exists(dump):
        print(f"dump not found: {dump}", file=sys.stderr)
        return 2
    with open(dump, encoding="utf-8") as fh:
        d = json.load(fh)

    org = {}
    for o in d.get("org", {}).get("data", []):
        if o.get("country"):
            org[o["id"]] = o["country"].strip().upper()

    cc, name = {}, {}
    for n in d.get("net", {}).get("data", []):
        try:
            asn = int(n["asn"])
        except (KeyError, TypeError, ValueError):
            continue
        c = org.get(n.get("org_id"))
        if c:
            cc[str(asn)] = c
        nm = (n.get("name_long") or n.get("name") or "").strip()
        if nm:
            name[str(asn)] = nm

    for fname, data in (("asn_cc.json", cc), ("asn_name.json", name)):
        path = os.path.join(ORACLE, fname)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, separators=(",", ":"))
        print(f"{fname}: {len(data)} entries -> {path}")

    for pop in ("pdb_pfx.json", "mno2_prefixes.json"):
        p = os.path.join(ORACLE, pop)
        if not os.path.exists(p):
            continue
        src = json.load(open(p, encoding="utf-8"))
        keys = {str(k).lstrip("AS") for k in src}
        hit = keys & set(cc)
        print(f"{pop}: {len(keys)} ASNs, {len(hit)} with a country")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
