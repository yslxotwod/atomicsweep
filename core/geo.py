"""Populations and the geography filter.

"Where in the world exactly" is the filter the user asked for, and it is the one
thing a flat IP list cannot answer. So populations come in two kinds and the UI
must never blur them:

* **attributed** populations are built from per-ASN prefix data, so every
  address knows its ASN, operator name and country. The country and operator
  filters work here and are exact.
* **flat** populations are existing target files — a list of
  addresses with no provenance. Geo filters are *unavailable* on them, and the
  UI says so rather than silently switching the filter off.

Sample selection is biased on purpose: `.1` and `.254` are where a gateway or a
management interface sits, and the network/broadcast pair catches misconfigured
kit. The rest of a block is sampled uniformly, because a /16 of consumer CPE is
not worth 65,536 probes to find one router.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import os
import random
import zlib

ORACLE = os.path.expanduser("~/oracle/data")

ATTR_SOURCES = [
    ("pdb_pfx.json", "plain"),
    ("mno2_prefixes.json", "wrapped"),
    ("mno_prefixes.json", "plain"),
    ("hp_pfx.json", "country"),
    ("popdb_pfx.json", "wrapped"),
]

CC_SOURCE = "asn_cc.json"
NAME_SOURCE = "asn_name.json"

def _load_json(name):
    path = os.path.join(ORACLE, name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None

class Geo:
    """Prefix -> (asn, country, operator) index."""

    def __init__(self):
        self.by_country = {}
        self.by_asn = {}
        self.by_operator = {}
        self.by_cc_only = {}
        self.names = {}
        self.cc = {}
        self.loaded = False
        self.sources = []

    def load(self):
        if self.loaded:
            return self
        for fname, key_cc in (("census_holders.json", "cc"),):
            d = _load_json(fname)
            if isinstance(d, list):
                for row in d:
                    try:
                        asn = int(row.get("asn"))
                    except (TypeError, ValueError):
                        continue
                    if row.get("cc"):
                        self.cc[asn] = row["cc"]
                    h = (row.get("holder") or "").strip()
                    if h:
                        self.names[asn] = h
        ranked = _load_json("census_ranked.json")
        if isinstance(ranked, list):
            for row in ranked:
                try:
                    asn = int(row.get("asn"))
                except (TypeError, ValueError):
                    continue
                if row.get("cc"):
                    self.cc.setdefault(asn, row["cc"])
                h = (row.get("holder") or row.get("name") or "").strip()
                if h:
                    self.names.setdefault(asn, h)
        cc_file = _load_json(CC_SOURCE)
        if isinstance(cc_file, dict):
            for k, v in cc_file.items():
                try:
                    self.cc[int(k)] = str(v).strip().upper()[:2]
                except (TypeError, ValueError):
                    continue
        name_file = _load_json(NAME_SOURCE)
        if isinstance(name_file, dict):
            for k, v in name_file.items():
                try:
                    self.names.setdefault(int(k), str(v).strip())
                except (TypeError, ValueError):
                    continue

        hp = _load_json("hp_holders.json")
        if isinstance(hp, dict):
            for k, v in hp.items():
                try:
                    asn = int(k)
                except (TypeError, ValueError):
                    continue
                if isinstance(v, dict):
                    h = (v.get("holder") or "").strip()
                    if v.get("country"):
                        self.cc.setdefault(asn, v["country"])
                else:
                    h = str(v).strip()
                if h:
                    self.names.setdefault(asn, h)

        for fname, shape in ATTR_SOURCES:
            d = _load_json(fname)
            if not d:
                continue
            self.sources.append(fname)
            if shape == "country":
                for k, v in d.items():
                    pfx = [x for x in (v if isinstance(v, list) else []) if ":" not in x]
                    if not pfx:
                        continue
                    cc_key = str(k).strip().upper()[:2]
                    self.by_country.setdefault(cc_key, []).extend(pfx)
                    self.by_cc_only.setdefault(cc_key, []).extend(pfx)
                continue
            for k, v in d.items():
                try:
                    asn = int(str(k).strip().lstrip("AS"))
                except (TypeError, ValueError):
                    continue
                if shape == "wrapped":
                    pfx = v.get("prefixes") or [] if isinstance(v, dict) else []
                elif isinstance(v, list):
                    pfx = v
                elif isinstance(v, dict):
                    pfx = v.get("prefixes") or []
                else:
                    pfx = []
                pfx = [p for p in pfx if ":" not in p][:2000]
                if not pfx:
                    continue
                self.by_asn.setdefault(asn, []).extend(pfx)
                c = self.cc.get(asn)
                if c:
                    self.by_country.setdefault(c, []).extend(pfx)
                nm = self.names.get(asn) or ""
                if nm:
                    self.by_operator.setdefault(nm.lower(), []).extend(pfx)
        self.loaded = True
        return self

    def countries(self):
        self.load()
        return sorted(set(self.by_country) | set(self.by_cc_only))

    def operators(self, country=None, limit=400):
        self.load()
        if country:
            out = []
            for asn, c in self.cc.items():
                if c == country and asn in self.by_asn:
                    out.append((asn, self.names.get(asn, "?"), len(self.by_asn[asn])))
        else:
            out = [(a, self.names.get(a, "?"), len(p)) for a, p in self.by_asn.items()]
        out.sort(key=lambda r: r[2], reverse=True)
        return out[:limit]

    def prefixes(self, country=None, operator=None, asn=None):
        """Resolve a filter set to prefixes. Raises ValueError with a reason when
        the filter cannot be honoured — never silently ignores a constraint."""
        self.load()
        found = None
        if asn:
            try:
                a = int(str(asn).strip().lstrip("AS"))
            except ValueError:
                raise ValueError(f"not an ASN: {asn}")
            if a not in self.by_asn:
                raise ValueError(f"AS{a} has no prefix data in "
                                 f"{', '.join(self.sources) or 'any source'}")
            found = list(self.by_asn[a])
        if operator:
            frag = operator.lower()
            hits = []
            for name, pfx in self.by_operator.items():
                if frag in name:
                    if country:
                        keep = [p for a, p in self.by_asn.items()
                                if self.names.get(a, "").lower() == name
                                and self.cc.get(a) == country for p in p]
                        hits.extend(keep)
                    else:
                        hits.extend(pfx)
            if not hits:
                raise ValueError(f"no operator matching {operator!r}"
                                 + (f" in {country}" if country else ""))
            found = hits if found is None else [p for p in found if p in set(hits)]
            if not found:
                raise ValueError(f"{operator!r} and AS{asn} do not overlap")
        if country and found is None:
            if country not in self.by_country:
                raise ValueError(f"no attributed prefixes for country {country}")
            found = list(self.by_country[country])
        if found is None:
            raise ValueError("no filter given")
        return found

    def describe(self, prefixes):
        """Which countries and operators a prefix set actually covers."""
        self.load()
        pset = set(prefixes)
        ccs, ops = set(), {}
        for asn, pfx in self.by_asn.items():
            if any(p in pset for p in pfx):
                c = self.cc.get(asn)
                if c:
                    ccs.add(c)
                nm = self.names.get(asn)
                if nm:
                    ops[asn] = nm
        return sorted(ccs), ops

def host_bias(net, rng):
    """Addresses worth trying inside one network: the edges, then random.

    .1/.254 are gateway and management positions; the network and broadcast
    addresses catch kit that answers where it should not. The random interior
    keeps a /16 from being 65,536 sequential probes.
    """
    if net.prefixlen >= 31:
        return [str(net.network_address)]
    first = int(net.network_address)
    last = int(net.broadcast_address)
    picks = [first + 1, last - 1, first, last]
    if last - first > 8:
        for _ in range(2):
            picks.append(rng.randint(first + 2, last - 2))
    seen, out = set(), []
    for p in picks:
        if first <= p <= last and p not in seen:
            seen.add(p)
            out.append(str(ipaddress.IPv4Address(p)))
    return out

def seed_for(name, override=None):
    """A stable seed per class or population name.

    Two properties are wanted at once and they pull in opposite directions.
    Repeating a sweep must repeat it exactly, or a second pass at a lower rate
    cannot be compared with the first. Different sweeps must cover different
    ground, or every class reports the same hosts and the population is 20,000
    addresses wide no matter how many times it is swept. A number derived from
    the name gives both: same name, same addresses; new name, new addresses.
    """
    if override is not None:
        return int(override)
    crc = zlib.crc32(str(name).encode("utf-8")) & 0xFFFFFFFF
    return crc or 0x5EED

def expand(prefixes, per_net=6, limit=None, seed=0x5EED, all_hosts=False):
    """Turn prefixes into addresses.

    Deterministic for the same seed, so a rerun of a class sweeps the same set —
    a random population makes two runs incomparable, and "we already looked
    there" would stop being a statement anyone could check.

    The seed is per CLASS, not global (see `seed_for`): a single constant meant
    every class looked at the same 20,000 addresses, so hunting a control for a
    BMC re-probed exactly the hosts a camera hunt had already answered.
    """
    rng = random.Random(seed)
    out = []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        if all_hosts:
            hosts = (str(h) for h in net.hosts())
            for h in hosts:
                out.append(h)
                if limit and len(out) >= limit:
                    return out
        else:
            for h in host_bias(net, rng)[:per_net]:
                out.append(h)
                if limit and len(out) >= limit:
                    return out
    return out

POPDB = "popdb.json"

POPDB_LABELS = {
    "pdb-isp": "ISP / carrier access networks",
    "hosting-cloud": "hosting, CDN, VPS — self-hosted software lives here",
    "enterprise": "enterprise + government — printers, PBX, cameras, NAS",
    "education": "universities and research networks",
    "broadband": "consumer broadband — domestic cameras, NAS, media, routers",
    "small-org": "non-profits, clinics, co-ops",
    "critical-infra": "utilities, energy, water, hospitals, transport",
}

def popdb_populations():
    """{name: spec} from popdb.json, in a stable order."""
    d = _load_json(POPDB) or {}
    pops = d.get("populations") or {}
    out = {}
    for name, spec in pops.items():
        out[name] = {
            "kind": "attributed", "source": "popdb_pfx.json",
            "asns": spec.get("asns") or [],
            "desc": POPDB_LABELS.get(name, spec.get("desc", name)),
            "sub": spec.get("desc", ""),
        }
    return out

POPULATIONS = {
    "peeringdb-isp": {
        "kind": "attributed", "source": "pdb_pfx.json",
        "desc": "707 ASNs with declared ISP/NSP role (PeeringDB qualified)",
    },
    "mobile-mno": {
        "kind": "attributed", "source": "mno2_prefixes.json",
        "desc": "81 mobile carriers with real spectrum/network roles",
    },
    "operator-all": {
        "kind": "attributed", "source": "all",
        "desc": "every ASN with per-prefix data in the PeeringDB dump",
    },
    "cellular-flat": {
        "kind": "flat", "file": "cellular_targets.txt",
        "desc": "3.0M addresses already swept for cellular services",
    },
    "observed-open": {
        "kind": "flat", "file": "observed_open.txt",
        "desc": "120,516 addresses already seen answering; accept-all ranges removed",
    },
    "omni-targets": {
        "kind": "flat", "file": "all_targets.txt",
        "desc": "1.8 MB union of earlier sweeps",
    },
    "small-mno": {
        "kind": "flat", "file": "small_mno_scan.txt",
        "desc": "66k addresses across 26 small mobile operators",
    },
    "custom": {"kind": "custom", "desc": "CIDR list typed in the filter"},
}
POPULATIONS.update(popdb_populations())

def population_prefixes(name, geo=None):
    """Prefixes for a named population, or None for a flat file."""
    spec = POPULATIONS.get(name)
    if not spec or spec["kind"] != "attributed":
        return None
    geo = (geo or Geo()).load()
    if spec["source"] == "all":
        out = []
        for pfx in geo.by_asn.values():
            out.extend(pfx)
        return out
    if spec.get("asns"):
        cache = _load_json(spec["source"]) or {}
        rows = []
        for asn in spec["asns"]:
            v = cache.get(str(asn))
            if isinstance(v, dict):
                rows.extend(v.get("prefixes") or [])
        return rows
    rows = []
    if spec["source"] == "mno2_prefixes.json":
        d = _load_json("mno2_prefixes.json") or {}
        for v in d.values():
            rows.extend(v.get("prefixes", []) if isinstance(v, dict) else [])
        return rows
    d = _load_json(spec["source"]) or {}
    for v in d.values():
        if isinstance(v, list):
            rows.extend(v)
        elif isinstance(v, dict):
            rows.extend(v.get("prefixes", []))
    return rows

_ADDR_IX = None
_LOOKUP_GEO = None

def _lookup_geo():
    """One Geo for every lookup. `load()` reads several JSON files, so building a
    fresh instance per address would make a detail pane cost seconds."""
    global _LOOKUP_GEO
    if _LOOKUP_GEO is None:
        g = Geo()
        try:
            g.load()
        except Exception:
            pass
        _LOOKUP_GEO = g
    return _LOOKUP_GEO

def _ip_int(ip):
    """Dotted quad to integer, or None. Never raises — a hostname is not an error."""
    parts = str(ip).split(".")
    if len(parts) != 4:
        return None
    n = 0
    for part in parts:
        if not part.isdigit():
            return None
        v = int(part)
        if v > 255:
            return None
        n = (n << 8) | v
    return n

def _pfx_span(pf):
    """'a.b.c.d/len' -> (first, last) as integers, or None if it is not IPv4.

    Hand-rolled because ipaddress is the expensive part of building the index,
    and a v6 or malformed prefix is skipped rather than raised on — one bad
    entry in a fetched cache must not take out the whole lookup.
    """
    addr, _, plen = str(pf).partition("/")
    n = _ip_int(addr)
    if n is None:
        return None
    try:
        bits = int(plen) if plen else 32
    except ValueError:
        return None
    if not 0 <= bits <= 32:
        return None
    size = 1 << (32 - bits)
    n &= ~(size - 1) & 0xFFFFFFFF
    return n, n + size - 1

def addr_index():
    """Sorted (start, end, asn) intervals for every attributed prefix on disk."""
    global _ADDR_IX
    if _ADDR_IX is not None:
        return _ADDR_IX
    g = _lookup_geo()
    spans = []
    for asn, prefixes in g.by_asn.items():
        try:
            asn_i = int(asn)
        except (TypeError, ValueError):
            continue
        for pf in prefixes:
            span = _pfx_span(pf)
            if span is not None:
                spans.append((span[0], span[1], asn_i))
    spans.sort()
    _ADDR_IX = spans
    return _ADDR_IX

def lookup(ip):
    """(asn, name, country) for an address, or None when nothing on disk covers it.

    None means "no prefix in our data contains this address", which is a fact
    about our data, not about the address — the same distinction the populations
    make between "announces nothing" and "we have not asked".
    """
    n = _ip_int(ip)
    if n is None:
        return None
    spans = addr_index()
    if not spans:
        return None
    i = bisect.bisect_right(spans, (n, 1 << 32, 1 << 32)) - 1
    if i < 0:
        return None
    start, end, asn = spans[i]
    if not (start <= n <= end):
        return None
    g = _lookup_geo()
    return (asn, g.names.get(asn, "") or "", g.cc.get(asn, "") or "")

def population_coverage(name):
    """How much of a population has actually been resolved to prefixes.

    This exists because a population whose prefixes have not been fetched yet
    produces zero addresses, and zero addresses in this bench must never read as
    "nothing is there". The UI prints this beside the address count so a
    half-resolved population is visible as half-resolved.
    """
    spec = POPULATIONS.get(name) or {}
    asns = spec.get("asns") or []
    if not asns:
        return None
    cache = _load_json(spec.get("source", "popdb_pfx.json")) or {}
    resolved = sum(1 for a in asns if str(a) in cache)
    return {"asns": len(asns), "resolved": resolved,
            "share": (resolved / len(asns)) if asns else 0.0}

def population_targets(name, geo=None, per_net=6, limit=None, all_hosts=False,
                       seed=None):
    """Addresses for a named population plus a note about its provenance."""
    spec = POPULATIONS.get(name)
    if not spec:
        raise ValueError(f"unknown population {name!r}")
    if spec["kind"] == "flat":
        path = os.path.join(ORACLE, spec["file"])
        if not os.path.exists(path):
            raise ValueError(f"population file missing: {path}")
        out = []
        with open(path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip().split()[0] if ln.strip() else ""
                if not ln or ln.startswith("#"):
                    continue
                out.append(ln.split(":")[0])
                if limit and len(out) >= limit:
                    break
        return out, {"kind": "flat", "geo": False, "note":
                     "no ASN/operator attribution — country filter unavailable"}
    if spec["kind"] == "custom":
        raise ValueError("custom population needs explicit CIDRs")
    pfx = population_prefixes(name, geo)
    if not pfx:
        raise ValueError(f"{name} resolved to no prefixes")
    addrs = expand(pfx, per_net=per_net, limit=limit, all_hosts=all_hosts,
                   seed=seed if seed is not None else seed_for(name))
    return addrs, {"kind": "attributed", "geo": True, "prefixes": len(pfx),
                   "note": f"{len(pfx)} prefixes from {spec['source']}"}
