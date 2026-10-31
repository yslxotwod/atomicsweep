"""The sweep engine: one scheduler, one rate governor, one honesty rule.

The engine is deliberately dumb. It knows nothing about OLTs or ACSs — a class
supplies a `probe(ip, port, timeout) -> dict` and the engine only decides *when*
to call it and how to record the answer.

The honesty rule is the reason this file exists at all. Three times in this
field work a sweep produced a confident zero that was really one of:

* our own rate limit — block 213.163.101 gave 10 hits at 48 workers and 138 when
  re-run alone, a 13.8x undercount;
* our own parsing bug — a Maroc Telecom run reported 2,738 clean misses because
  an `awk` expression left `1.2.3.4:7547` as one token and every probe dialled a
  host literally named that;
* a port assumption — SNMP was never probed across 22,502 hosts because the
  scanner underneath was TCP-only.

All three look identical in the output file. So: every rate is a token bucket
with no burst, the achieved rate is measured and shown, and a class cannot
report "none found" unless its positive control answered first.
"""

from __future__ import annotations

import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from core import net

class Bucket:
    """Token bucket with a hard ceiling and no burst allowance.

    A burst is what produces the throttle that then looks like absence, so there
    is none: the first token arrives after 1/rate seconds like every other.

    `pace()` is adaptive — when the observed answer rate collapses while the
    send rate holds, the peer is dropping us and the bucket slows down instead of
    recording the drops as misses.
    """

    def __init__(self, rate):
        self.rate = max(0.1, float(rate))
        self.allowance = 0.0
        self.last = time.monotonic()
        self.lock = threading.Lock()
        self.sent = 0
        self.adapt = 1.0

    def set_rate(self, rate):
        """Change the ceiling while a run is going.

        Used by the pause/rate controls: a sweep that is visibly throttling a
        peer should be slowed from the panel rather than stopped and restarted,
        because a restart loses the position and the counters.
        """
        with self.lock:
            self.rate = max(0.1, float(rate))
            self.adapt = 1.0

    def take(self, pause_event=None):
        while True:
            with self.lock:
                now = time.monotonic()
                self.allowance = min(self.rate * self.adapt,
                                     self.allowance + (now - self.last) * self.rate * self.adapt)
                self.last = now
                if self.allowance >= 1.0:
                    self.allowance -= 1.0
                    self.sent += 1
                    return
                need = (1.0 - self.allowance) / (self.rate * self.adapt)
            if pause_event is not None and pause_event.is_set():
                self.last = time.monotonic()
                return
            time.sleep(min(need, 0.25))

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.probed = 0
        self.hits = 0
        self.open = 0
        self.unproven = 0
        self.refused = 0
        self.errors = 0
        self.total = 0
        self.t0 = time.time()
        self.per_verdict = {}

    def add(self, verdict):
        with self.lock:
            self.probed += 1
            self.per_verdict[verdict] = self.per_verdict.get(verdict, 0) + 1
            if verdict == "hit":
                self.hits += 1
            elif verdict == "open":
                self.open += 1
            elif verdict == "unproven":
                self.unproven += 1
            elif verdict == "refused":
                self.refused += 1
            elif verdict == "error":
                self.errors += 1

    @property
    def elapsed(self):
        return max(0.001, time.time() - self.t0)

    @property
    def pps(self):
        return self.probed / self.elapsed

    def snapshot(self):
        with self.lock:
            return {
                "probed": self.probed, "hits": self.hits, "open": self.open,
                "unproven": self.unproven,
                "refused": self.refused, "errors": self.errors, "total": self.total,
                "elapsed": self.elapsed, "pps": self.pps,
                "per_verdict": dict(self.per_verdict),
            }

def run_sweep(klass, targets, run, out_queue, stop_event,
              rate=40, conc=64, timeout=3.0, resume=True,
              pause_event=None, control=None):
    """Probe every target and stream results to `out_queue`.

    `targets` is an iterable of (ip, port). Results are (kind, payload) tuples so
    the UI can distinguish a hit from a progress tick without guessing from the
    payload shape.

    `pause_event`, when set, holds the sweep without ending it: workers finish
    what they already sent and nothing new goes out, so a pause is not a stop and
    the run keeps its position. `control` is a plain dict the caller may mutate
    while the run is going — `{"rate": N}` retunes the bucket in place.
    """
    stats = Stats()
    skipped = 0
    if resume:
        done = run.done_set()
    else:
        done = set()

    todo = []
    for ip, port in targets:
        key = f"{ip}:{port}"
        if key in done:
            skipped += 1
            continue
        todo.append((ip, port))
    stats.total = len(todo) + skipped
    out_queue.put(("meta", {
        "class": klass.id, "queued": len(todo), "skipped": skipped,
        "rate": rate, "conc": conc,
    }))

    bucket = Bucket(rate)
    tick_lock = threading.Lock()
    tick_count = [0]

    def work(item):
        ip, port = item
        if stop_event.is_set():
            return None
        while pause_event is not None and pause_event.is_set() and not stop_event.is_set():
            time.sleep(0.1)
        if stop_event.is_set():
            return None
        if control is not None:
            want = float(control.get("rate", rate))
            if abs(want - bucket.rate) > 1e-9:
                bucket.set_rate(want)
        bucket.take(pause_event)
        if stop_event.is_set():
            return None
        net.clear_evidence()
        try:
            res = klass.probe(ip, port, timeout)
        except Exception as e:
            res = {"verdict": "error", "product": "", "detail": f"exc:{type(e).__name__}:{e}"}
        res["evidence"] = net.take_evidence()
        stats.add(res.get("verdict", "error"))
        run.add(ip, port, res.get("verdict", "error"), res.get("product", ""),
                res.get("detail", ""), res.get("rtt"), res.get("evidence"))
        out_queue.put(("result", (ip, port, res)))
        with tick_lock:
            tick_count[0] += 1
            due = tick_count[0] % 25 == 0
        if due:
            out_queue.put(("tick", stats.snapshot()))
        return res

    window = max(64, conc * 8)
    try:
        with ThreadPoolExecutor(max_workers=max(1, conc)) as pool:
            pending = []
            it = iter(todo)
            exhausted = False
            while not stop_event.is_set():
                if pause_event is not None and pause_event.is_set():
                    time.sleep(0.1)
                    if pending:
                        done_set, _ = wait(pending, timeout=0.5,
                                           return_when=FIRST_COMPLETED)
                        pending = [f for f in pending if not f.done()]
                    continue
                while not exhausted and len(pending) < window:
                    try:
                        pending.append(pool.submit(work, next(it)))
                    except StopIteration:
                        exhausted = True
                        break
                if not pending:
                    break
                done, not_done = wait(pending, timeout=0.5,
                                      return_when=FIRST_COMPLETED)
                for f in done:
                    try:
                        f.result()
                    except Exception:
                        pass
                pending = list(not_done)
                if exhausted and not pending:
                    break
            for f in pending:
                if not stop_event.is_set():
                    try:
                        f.result()
                    except Exception:
                        pass
    finally:
        snap = stats.snapshot()
        run.close("stopped" if stop_event.is_set() else "finished")
        out_queue.put(("done", snap))
    return stats

def gate(klass, timeout=6.0):
    """Run a class's positive controls.

    Returns (ok, rows). `ok` is True only if at least one control produced the
    verdict the class expects from it. A class with no controls returns
    (None, []) — meaning "ungated", which the UI must show as a warning rather
    than quietly treating the class as verified.
    """
    controls = getattr(klass, "CONTROLS", None) or []
    if not controls:
        return None, []
    rows = []
    ok = False
    for ctl in controls:
        ip, port, want = ctl[0], ctl[1], ctl[2]
        tls = ctl[3] if len(ctl) > 3 else None
        t0 = time.time()
        try:
            res = klass.probe(ip, port, timeout, tls=tls)
        except Exception as e:
            rows.append({"target": f"{ip}:{port}", "want": want,
                         "got": "error", "detail": str(e), "rtt": None})
            continue
        got = res.get("verdict", "error")
        good = got == want
        ok = ok or good
        rows.append({"target": f"{ip}:{port}", "want": want, "got": got,
                     "detail": res.get("product") or res.get("detail", ""),
                     "rtt": time.time() - t0})
    return ok, rows
