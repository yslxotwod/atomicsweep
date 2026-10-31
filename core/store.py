"""Resumable run store.

A sweep of a few hundred thousand addresses will be interrupted — the terminal
closes, the link drops, the operator rate-limits us. Losing the work is bad; the
worse failure is *believing* work is lost and re-sweeping, or worse, believing a
partial file is complete. So:

* results are appended as they arrive, never buffered to the end;
* a `.done` set is written per completion so a restart skips finished targets;
* the header carries the class, population and rate, so a file can never be
  mistaken for a run it is not.
"""

from __future__ import annotations

import json
import os
import time

RUNS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "runs")

FIELDS = ["ip", "port", "verdict", "product", "detail", "rtt", "ts"]

class Run:
    def __init__(self, class_id, population, rate, timeout, conc, custom=None):
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.id = f"{class_id}-{stamp}"
        self.dir = os.path.join(RUNS, self.id)
        os.makedirs(self.dir, exist_ok=True)
        self.results_path = os.path.join(self.dir, "results.tsv")
        self.done_path = os.path.join(self.dir, "done.tsv")
        self.meta_path = os.path.join(self.dir, "meta.json")
        self.evidence_path = os.path.join(self.dir, "evidence.jsonl")
        self.meta = {
            "id": self.id,
            "class": class_id,
            "population": population,
            "rate": rate,
            "timeout": timeout,
            "concurrency": conc,
            "custom": custom or {},
            "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with open(self.meta_path, "w", encoding="utf-8") as fh:
            json.dump(self.meta, fh, indent=2)
        if not os.path.exists(self.results_path):
            with open(self.results_path, "w", encoding="utf-8") as fh:
                fh.write("\t".join(FIELDS) + "\n")
        if not os.path.exists(self.done_path):
            open(self.done_path, "w", encoding="utf-8").close()
        self._done = None
        self._ev = None
        self._rl = open(self.results_path, "a", encoding="utf-8", buffering=1)
        self._dl = open(self.done_path, "a", encoding="utf-8", buffering=1)

    def done_set(self):
        """Targets already finished in this run, so a restart does not re-probe
        them. Seeded from the results file as well, because a kill can lose the
        last few `.done` lines and re-probing them is waste."""
        if self._done is not None:
            return self._done
        seen = set()
        if os.path.exists(self.done_path):
            with open(self.done_path, encoding="utf-8") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln:
                        seen.add(ln)
        with open(self.results_path, encoding="utf-8") as fh:
            next(fh, None)
            for ln in fh:
                parts = ln.split("\t")
                if len(parts) >= 2 and parts[0]:
                    seen.add(f"{parts[0]}:{parts[1]}")
        self._done = seen
        return seen

    def add(self, ip, port, verdict, product="", detail="", rtt=None, evidence=None):
        rtt_s = "" if rtt is None else f"{rtt:.3f}"
        safe = lambda s: str(s).replace("\t", " ").replace("\n", " ")[:300]
        self._rl.write("\t".join([str(ip), str(port), verdict, safe(product), safe(detail),
                                  rtt_s, time.strftime("%Y-%m-%dT%H:%M:%S")]) + "\n")
        self._dl.write(f"{ip}:{port}\n")
        if self._done is not None:
            self._done.add(f"{ip}:{port}")
        if evidence and verdict in ("hit", "open"):
            self._write_evidence(ip, port, verdict, product, evidence)

    def _write_evidence(self, ip, port, verdict, product, evidence):
        try:
            if self._ev is None:
                self._ev = open(self.evidence_path, "a", encoding="utf-8", buffering=1)
            self._ev.write(json.dumps({"ip": str(ip), "port": port, "verdict": verdict,
                                       "product": product, "exchanges": evidence},
                                      ensure_ascii=False) + "\n")
        except OSError:
            pass

    def mark_done(self, ip, port):
        self._dl.write(f"{ip}:{port}\n")

    def close(self, status="finished"):
        self.meta["status"] = status
        self.meta["ended"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            with open(self.meta_path, "w", encoding="utf-8") as fh:
                json.dump(self.meta, fh, indent=2)
        except OSError:
            pass
        for h in (self._rl, self._dl, self._ev):
            try:
                if h is not None:
                    h.close()
            except OSError:
                pass

    def rows(self):
        if not os.path.exists(self.results_path):
            return []
        out = []
        with open(self.results_path, encoding="utf-8") as fh:
            next(fh, None)
            for ln in fh:
                p = ln.rstrip("\n").split("\t")
                if len(p) >= len(FIELDS):
                    out.append(dict(zip(FIELDS, p)))
        return out

    def hits(self):
        return [r for r in self.rows() if r["verdict"] == "hit"]

def list_runs():
    """Every run on disk, newest first, with its counters."""
    if not os.path.isdir(RUNS):
        return []
    out = []
    for name in sorted(os.listdir(RUNS), reverse=True):
        d = os.path.join(RUNS, name)
        meta_p = os.path.join(d, "meta.json")
        res_p = os.path.join(d, "results.tsv")
        if not os.path.isdir(d):
            continue
        meta = {}
        if os.path.exists(meta_p):
            try:
                with open(meta_p, encoding="utf-8") as fh:
                    meta = json.load(fh)
            except (OSError, json.JSONDecodeError):
                meta = {}
        total = hits = 0
        if os.path.exists(res_p):
            with open(res_p, encoding="utf-8") as fh:
                next(fh, None)
                for ln in fh:
                    if not ln.strip():
                        continue
                    total += 1
                    if "\thit\t" in ln:
                        hits += 1
        meta.update({"id": name, "dir": d, "probed": total, "hits": hits})
        out.append(meta)
    return out

def active_run():
    """The most recent run that never closed — offer to resume it."""
    for m in list_runs():
        if m.get("status") not in ("finished", "stopped"):
            return m
    return None
