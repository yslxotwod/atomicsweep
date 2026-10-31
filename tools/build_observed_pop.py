#!/usr/bin/env python3
"""Turn a toolkit's own sweep output into a population of KNOWN-REACHABLE hosts.

Blind sampling of a carrier's address space spends almost every probe on silence.
Measured in this tree: sweeping `d2_container` across 1,200 sampled addresses in
`hosting-cloud` cost 9,600 probes and produced 10 `open` rows and no hits. The
addresses were not empty, they were filtered — which is a fact about where the
sweep looked, not about Docker.

Earlier sweeps have already paid for that measurement. `~/oracle/data/*.out`
holds ~175,000 probe records of which ~124,000 are distinct addresses that
answered. A sweep aimed at those costs one probe per port per host and lands on
something that has already proven it will talk.

    tools/build_observed_pop.py                 # report only
    tools/build_observed_pop.py --write         # write ~/oracle/data/observed_open.txt

The output is a flat, one-address-per-line list, which is the format the existing
`cellular-flat` population uses, so it drops into `--population` unchanged.

Deliberate omissions:

  * `state` must be `open`. A row that timed out is not evidence of a host.
  * Rows flagged `tarpit` are EXCLUDED. A tarpit accepts a connection and never
    speaks; including it would put addresses in the population that answer every
    probe and identify nothing, which is the exact noise that makes a sweep look
    busy and find nothing.
  * Private, loopback, link-local, multicast and documentation ranges are
    dropped: they cannot be swept and would only inflate the count.
  * With `--verify`, `/24`s whose hosts each answered on many ports are tested
    on arbitrary high ports and, if one connects, the whole `/24` is excluded.

That last one is not hypothetical. Six `/24`s in one sample all accepted a TCP
connect on 12345, 33333 and 45678 as readily as on
80. Nothing is listening there; a middlebox answers for every address in the
range. Those hosts look maximally alive and contain no device, so putting them in
a population poisons every sweep that uses it. The signature is visible without
touching the network — essentially EVERY host in the `/24` answered on five or
more ports — and `--verify` confirms it with three probes.
"""

from __future__ import annotations

import argparse
import collections
import glob
import ipaddress
import json
import os
import sys

ORACLE = os.environ.get("ORACLE", os.path.expanduser("~/oracle"))
DATA = os.path.join(ORACLE, "data")
OUT = os.path.join(DATA, "observed_open.txt")

def load_rows(pattern=os.path.join(DATA, "*.out")):
    """Every probe record across the earlier sweep files."""
    files = sorted(glob.glob(pattern))
    bad = 0
    for path in files:
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for ln in fh:
                ln = ln.strip()
                if not ln.startswith("{"):
                    continue
                try:
                    yield json.loads(ln)
                except ValueError:
                    bad += 1
    if bad:
        print(f"[!] {bad} line(s) were not valid JSON and were skipped", file=sys.stderr)

def usable(rec):
    """A record worth sweeping again."""
    if rec.get("state") != "open":
        return False
    if rec.get("tarpit"):
        return False
    ip = rec.get("ip") or ""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast

ACCEPTALL_PORTS = (12345, 33333, 45678)

def net24(ip):
    return ip.rsplit(".", 1)[0] + ".0/24"

def suspicious_nets(per_ip, min_multi=8, min_ports=5):
    """`/24`s where many hosts answered on many ports — the accept-all signature.

    The reason this is a NETWORK test rather than a host test: a single host with
    six open ports is a busy server, and accusing it proves nothing. A whole /24
    where almost every host has five is an accelerator, and one probe settles it.
    """
    seen = collections.defaultdict(lambda: [0, 0])
    for ip, ports in per_ip.items():
        n = net24(ip)
        seen[n][0] += 1
        if len(ports) >= min_ports:
            seen[n][1] += 1
    return sorted(n for n, (hosts, multi) in seen.items()
                  if multi >= min_multi and hosts > 0)

def verify_net(net, hosts, per_net=3, timeout=2.0):
    """Probe arbitrary high ports on up to `per_net` hosts. Returns a state.

    confirmed  a host answered on two or more ports nothing listens on
    refused    every probe was refused — the hosts really do close ports
    undecided  silence, which is a filtered port and a closed port alike
    """
    import socket
    count = 0
    for ip in hosts[:per_net]:
        hits = 0
        for port in ACCEPTALL_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((ip, port))
                hits += 1
            except ConnectionRefusedError:
                pass
            except OSError:
                pass
            finally:
                s.close()
        if hits >= 2:
            return "confirmed"
        count += 1
    return "undecided"

def verify_host(ip, ports=ACCEPTALL_PORTS[:2], timeout=2.0):
    """Two arbitrary high ports. Both open means the host is answered for."""
    import socket
    hits = 0
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            hits += 1
        except OSError:
            pass
        finally:
            s.close()
    return hits >= len(ports)

def verify_multi_port_hosts(per_ip, min_ports=5, workers=24, timeout=2.0):
    """Host-level check for hosts that answered on many ports.

    The /24 test only catches ranges that were sampled densely. A single
    accept-all host inside a /24 where a sweep happened to probe one address
    is invisible to it — one host answered on ten ports including Docker,
    Postgres, Mongo, RabbitMQ and NETCONF, which no real machine runs together,
    and it is answered for by a middlebox. So the hosts with the most ports are
    tested individually.
    """
    import concurrent.futures
    cand = [ip for ip, c in per_ip.items() if len(c) >= min_ports]
    if not cand:
        return set(), 0
    bad = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(verify_host, ip, ACCEPTALL_PORTS[:2], timeout): ip
                for ip in cand}
        for f in concurrent.futures.as_completed(futs):
            try:
                if f.result():
                    bad.add(futs[f])
            except Exception:
                pass
    return bad, len(cand)

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="write the population file")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--pattern", default=os.path.join(DATA, "*.out"))
    ap.add_argument("--verify", action="store_true",
                    help="probe suspicious /24s on arbitrary high ports and "
                         "exclude the ones that answer")
    ap.add_argument("--verify-timeout", type=float, default=2.0)
    ap.add_argument("--verify-hosts", action="store_true",
                    help="also test individual hosts that answered on 5+ ports; "
                         "the /24 test cannot see one accept-all host in a "
                         "sparsely sampled range")
    ap.add_argument("--host-min-ports", type=int, default=5)
    a = ap.parse_args(argv)

    per_ip = collections.defaultdict(collections.Counter)
    total = 0
    for rec in load_rows(a.pattern):
        total += 1
        if usable(rec):
            per_ip[rec["ip"]][int(rec.get("port") or 0)] += 1

    if not per_ip:
        print("no usable records — nothing written", file=sys.stderr)
        return 1

    ips = sorted(per_ip, key=lambda i: (-len(per_ip[i]), -sum(per_ip[i].values()), i))

    print(f"records     {total:,} across {len(glob.glob(a.pattern))} file(s)")
    print(f"usable      {len(ips):,} distinct address(es) that answered")
    ports = collections.Counter()
    for c in per_ip.values():
        ports.update(c.keys())
    print("top ports   " + ", ".join(f"{p}:{n:,}" for p, n in ports.most_common(8)))
    multi = sum(1 for c in per_ip.values() if len(c) > 1)
    print(f"multi-port  {multi:,} host(s) answered on more than one port")
    for ip in ips[:5]:
        print(f"            {ip:<16} {dict(per_ip[ip])}")

    excluded = {}
    if a.verify:
        nets = suspicious_nets(per_ip)
        by_net = collections.defaultdict(list)
        for ip in ips:
            by_net[net24(ip)] = by_net[net24(ip)] if False else by_net[net24(ip)]
        hosts_in = collections.defaultdict(list)
        for ip in ips:
            hosts_in[net24(ip)].append(ip)
        print(f"\nverify      {len(nets)} /24(s) show the accept-all signature "
              f"(almost every host answered on 5+ ports)")
        for n in nets:
            st = verify_net(n, hosts_in[n], timeout=a.verify_timeout)
            n_hosts = len(hosts_in[n])
            if st == "confirmed":
                excluded[n] = n_hosts
                print(f"  ACCEPT-ALL {n:<20} {n_hosts:3} host(s) excluded — "
                      f"nothing is listening on the ports tested")
            else:
                print(f"  {st:<10} {n:<20} {n_hosts:3} host(s) kept")
        if excluded:
            keep = [ip for ip in ips if net24(ip) not in excluded]
            print(f"\nexcluded    {len(excluded)} /24(s), "
                  f"{sum(excluded.values()):,} address(es)")
            print(f"population  {len(keep):,} address(es) after exclusion")
            ips = keep

    if a.verify_hosts:
        bad, tried = verify_multi_port_hosts(per_ip, min_ports=a.host_min_ports,
                                             timeout=a.verify_timeout)
        print(f"\nverify      {len(bad):,} of {tried:,} host(s) with "
              f">= {a.host_min_ports} ports answered on two arbitrary high ports "
              f"— excluded")
        if bad:
            ips = [ip for ip in ips if ip not in bad]
            print(f"population  {len(ips):,} address(es) after host exclusion")

    if not a.write:
        print("\nwrite       no (add --write)")
        return 0

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("# addresses already observed answering a probe, from earlier sweeps\n")
        fh.write("# own sweep output. Excludes tarpits and non-global space.\n")
        for ip in ips:
            fh.write(ip + "\n")
    os.replace(tmp, a.out)
    print(f"\nwrote       {a.out} ({len(ips):,} addresses)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
