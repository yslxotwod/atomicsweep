#!/usr/bin/env python3
"""Hunt a positive control by sweeping hosts that have already answered.

Blind sampling of a population spends almost all of its probes on addresses that
say nothing, so a class with no control can be swept for an hour and produce no
candidate to look at. Every earlier run in `data/runs/` already recorded which
hosts answered at all: `open` means something replied without being identified,
`hit` means a device was named. Those addresses are the only ones worth
re-probing with a new fingerprint, because reachability is the expensive part and
it has already been measured.

    tools/hunt_from_opens.py --class g3_iptv
    tools/hunt_from_opens.py --class g3_iptv --verdicts open,hit --limit 200 --run

Without `--run` it prints the addresses it would use and the command it would
issue; nothing is transmitted.

The addresses come from THIS tree's own results, so the pool is whatever the
earlier sweeps have already touched — it is a second pass over discovered hosts, never
a discovery step of its own. A class that finds nothing here has not been proven
blind, it has been proven blind *on the hosts something else already answered*,
which is the narrower and more useful statement.
"""

from __future__ import annotations

import argparse
import collections
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RUNS = os.path.join(ROOT, "data", "runs")
FIELDS = ["ip", "port", "verdict", "product", "detail", "rtt", "ts"]

def collect(verdicts=("open", "hit"), exclude_classes=()):
    """{ip: {verdict: count}} across every run recorded in this tree."""
    seen = collections.defaultdict(collections.Counter)
    files = glob.glob(os.path.join(RUNS, "*", "results.tsv"))
    for path in files:
        cls = os.path.basename(os.path.dirname(path)).rsplit("-", 2)[0]
        if cls in exclude_classes:
            continue
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            head = fh.readline().rstrip("\n").split("\t")
            if head[:3] != FIELDS[:3]:
                print(f"[!] skipping {path}: header {head[:3]} is not {FIELDS[:3]}",
                      file=sys.stderr)
                continue
            for ln in fh:
                p = ln.rstrip("\n").split("\t")
                if len(p) < 3:
                    continue
                if p[2] in verdicts:
                    seen[p[0]][p[2]] += 1
    return seen, len(files)

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--class", dest="klass", required=True,
                    help="the class to probe the discovered hosts with")
    ap.add_argument("--verdicts", default="open,hit",
                    help="which earlier verdicts count as 'answered' (default open,hit)")
    ap.add_argument("--limit", type=int, default=0, help="cap the address count")
    ap.add_argument("--rate", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=3)
    ap.add_argument("--conc", type=int, default=48)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--run", action="store_true", help="actually transmit")
    a = ap.parse_args(argv)

    verdicts = tuple(v.strip() for v in a.verdicts.split(",") if v.strip())
    seen, nfiles = collect(verdicts)
    if not seen:
        print(f"no reachable hosts recorded across {nfiles} results files — "
              f"nothing to hunt with", file=sys.stderr)
        return 1

    def key(ip):
        return (-seen[ip]["hit"], -sum(seen[ip].values()), ip)

    ips = sorted(seen, key=key)
    if a.limit:
        ips = ips[:a.limit]

    print(f"pool        {len(seen):,} address(es) that answered, from {nfiles} run(s)")
    print(f"using       {len(ips):,} after the limit")
    print(f"class       {a.klass}")
    print(f"verdicts    {', '.join(verdicts)}")
    for ip in ips[:8]:
        print(f"            {ip:<16} {dict(seen[ip])}")
    if len(ips) > 8:
        print(f"            ... {len(ips) - 8:,} more")

    cmd = [sys.executable, os.path.join(ROOT, "cli.py"), "--run", a.klass,
           "--population", "custom", "--rate", str(a.rate),
           "--timeout", str(a.timeout), "--conc", str(a.conc), "--ungated"]
    if a.seed is not None:
        cmd += ["--seed", str(a.seed)]
    for ip in ips:
        cmd += ["--cidr", f"{ip}/32"]

    if not a.run:
        print("\ntransmit    no (add --run)")
        return 0

    print(f"\ntransmit    yes · {len(ips):,} addresses", flush=True)
    return subprocess.call(cmd)

if __name__ == "__main__":
    sys.exit(main())
