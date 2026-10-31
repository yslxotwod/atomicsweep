#!/usr/bin/env python3
"""atomicsweep — one bench for every device class worth finding.

The dashboard replaces "processes" with the thing you actually want: the
classes. Pick one, set where in the world to look, launch, and the filter panel
gets out of the way so the addresses have the space.

Design rules that come from the sweep work this was built alongside:

  * a negative needs a positive control. Every class carries CONTROLS; a class
    with none is shown UNGATED and never green.
  * silence is not closure. `unproven` is a verdict, not an absence.
  * the globe is a lookup table, not a renderer: spinning it costs no budget
    that the scanner needs.
"""

from __future__ import annotations

import curses
import os
import queue
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from core import dns as nslib, engine, geo as geolib, store, ui
from core.classes import SWEEP_CLASSES, MASS_RESOLVE, by_id
from core.globe import BrailleGlobe

VERSION = "1.0.0"

BANNER_BIG = [
    "  \u2584  \u2597\u2584\u2584\u2584\u2596 \u2597\u2584\u2596 \u2597\u2584 \u2584\u2596 \u2584\u2584\u2584   \u2584\u2584       \u2597\u2584\u2596 \u2584   \u2584\u2597\u2584\u2584\u2584\u2596\u2597\u2584\u2584\u2584\u2596\u2597\u2584\u2584\u2596",
    " \u2590\u2588\u258c \u259d\u2580\u2588\u2580\u2598 \u2588\u2580\u2588 \u2590\u2588 \u2588\u258c \u2580\u2588\u2580  \u2588\u2580\u2580\u258c     \u2597\u259b\u2580\u259c \u2588   \u2588\u2590\u259b\u2580\u2580\u2598\u2590\u259b\u2580\u2580\u2598\u2590\u259b\u2580\u259c\u2596",
    " \u2590\u2588\u258c   \u2588  \u2590\u258c \u2590\u258c\u2590\u2588\u2588\u2588\u258c  \u2588  \u2590\u259b        \u2590\u2599   \u259c\u2596\u2588\u2597\u259b\u2590\u258c   \u2590\u258c   \u2590\u258c \u2590\u258c",
    " \u2588 \u2588   \u2588  \u2590\u258c \u2590\u258c\u2590\u258c\u2588\u2590\u258c  \u2588  \u2590\u258c         \u259c\u2588\u2599 \u2590\u258c\u2588\u2590\u258c\u2590\u2588\u2588\u2588 \u2590\u2588\u2588\u2588 \u2590\u2588\u2588\u259b",
    " \u2588\u2588\u2588   \u2588  \u2590\u258c \u2590\u258c\u2590\u258c\u2580\u2590\u258c  \u2588  \u2590\u2599           \u259c\u258c\u2590\u2588\u2580\u2588\u258c\u2590\u258c   \u2590\u258c   \u2590\u258c",
    "\u2597\u2588 \u2588\u2596  \u2588   \u2588\u2584\u2588 \u2590\u258c \u2590\u258c \u2584\u2588\u2584  \u2588\u2584\u2584\u2599     \u2590\u2584\u2584\u259f\u2598\u2590\u2588 \u2588\u258c\u2590\u2599\u2584\u2584\u2596\u2590\u2599\u2584\u2584\u2596\u2590\u258c",
    "\u259d\u2598 \u259d\u2598  \u2580   \u259d\u2580\u2598 \u259d\u2598 \u259d\u2598 \u2580\u2580\u2580   \u2580\u2580       \u2580\u2580\u2598 \u259d\u2580 \u2580\u2598\u259d\u2580\u2580\u2580\u2598\u259d\u2580\u2580\u2580\u2598\u259d\u2598",
]

BANNER_SMALL = [
    "\u2584\u2580\u2588 \u2580\u2588\u2580 \u2588\u2580\u2588 \u2588\u2580\u2584\u2580\u2588 \u2588 \u2588\u2580\u2580   \u2588\u2580 \u2588 \u2588 \u2588\u2580\u2580 \u2588\u2580\u2580 \u2588\u2580\u2588",
    "\u2588\u2580\u2588  \u2588  \u2588\u2584\u2588 \u2588 \u2580 \u2588 \u2588\u2584\u2584   \u2584\u2588 \u2588\u2584\u2588 \u2588\u2588\u2584 \u2588\u2588\u2584 \u2588\u2580\u2580",
]

VERDICT_ATTR = {
    "hit": "green",
    "open": "cyan",
    "unproven": "dim",
    "refused": "amber",
    "error": "red",
}

def _fmt_int(n):
    return f"{n:,}" if isinstance(n, int) else str(n)

class App:
    def __init__(self, scr):
        self.scr = scr
        self.view = "dash"
        self.sel = 0
        self.cfg_sel = 0
        self.rot = 0.0
        self.globe = None
        self.geo = geolib.Geo()
        self.pop_name = "peeringdb-isp"
        self.country = "*"
        self.operator = ""
        self.rate = 40
        self.timeout = 3
        self.per_net = 6
        self.limit = 20000
        self.results = []
        self.stats = {}
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.control = {}
        self.worker = None
        self.run = None
        self.klass = None
        self.scroll = 0
        self.status = "ready"
        self.preview = ""
        self.gate_state = {}
        self.resolve_rows = []
        self.last_tick = 0.0
        self.frame_no = 0
        self.desc_sel = -1
        self.desc_base = 0
        self.allow_ungated = False
        self.hits_only = False
        self.pinned = None
        self.follow = True
        self.detail_full = False
        self.stars = set()
        self.deep = {}
        self.deep_busy = set()
        self._addr_ready = False
        threading.Thread(target=self._warm_addr_index, daemon=True).start()

    def filters(self):
        pop = geolib.POPULATIONS[self.pop_name]
        cov = geolib.population_coverage(self.pop_name)
        pop_label = self.pop_name
        if cov and cov["share"] < 0.999:
            pop_label = f"{self.pop_name} ({cov['share']:.0%} resolved)"
        rows = [("POPULATION", pop_label, "cycle", list(geolib.POPULATIONS))]
        if pop["kind"] == "attributed":
            ccs = ["*"] + self.geo.countries()
            rows.append(("COUNTRY", self.country, "cycle", ccs))
            rows.append(("OPERATOR", self.operator or "(any)", "text", None))
            rows.append(("HOSTS / NET", self.per_net, "int", (1, 64)))
        rows += [
            ("RATE", self.rate, "int", (1, 2000)),
            ("TIMEOUT", self.timeout, "int", (1, 30)),
            ("LIMIT", self.limit, "int", (100, 3000000)),
        ]
        return rows

    def n_filters(self):
        return len(self.filters())

    def targets_preview(self):
        """How many addresses the current filters would probe, or why not."""
        try:
            pop = geolib.POPULATIONS[self.pop_name]
            if pop["kind"] == "attributed":
                country = None if self.country == "*" else self.country
                op = self.operator or None
                pfx = self.geo.prefixes(country=country, operator=op) if (country or op) \
                    else geolib.population_prefixes(self.pop_name, self.geo)
                if not pfx:
                    cov = geolib.population_coverage(self.pop_name)
                    if cov and cov["resolved"] < cov["asns"]:
                        return None, (f"no prefixes yet — {cov['resolved']}/"
                                      f"{cov['asns']} ASNs resolved, the rest are "
                                      f"unfetched, not empty")
                    return None, "no prefixes"
                addrs = geolib.expand(pfx, per_net=self.per_net, limit=self.limit)
                return addrs, f"{len(pfx)} prefixes"
            addrs, prov = geolib.population_targets(
                self.pop_name, self.geo, per_net=self.per_net, limit=self.limit)
            return addrs, prov.get("note", "")
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"

    def build_targets(self):
        addrs, note = self.targets_preview()
        if addrs is None:
            raise ValueError(note)
        return addrs, note

    def run_gate(self, klass):
        self.status = f"gating {klass.id} against its positive control…"
        self.draw()

        def work():
            ok, rows = engine.gate(klass)
            self.gate_state[klass.id] = ok
            self.status = (
                "ungated — no positive control, negatives cannot be trusted"
                if ok is None else
                ("gate PASS" if ok else "gate FAIL — the class cannot see a known target")
            )
            self.draw()

        threading.Thread(target=work, daemon=True).start()

    def launch(self):
        klass = SWEEP_CLASSES[self.sel]
        if not klass.CONTROLS and not self.allow_ungated:
            self.allow_ungated = True
            self.status = ("ungated class — press enter again to sweep anyway; "
                           "a zero result will not be evidence of absence")
            self.draw()
            return
        self.allow_ungated = False
        try:
            addrs, note = self.build_targets()
        except Exception as e:
            self.status = f"cannot launch: {e}"
            self.draw()
            return
        if not addrs:
            self.status = "cannot launch: the filters produced no addresses"
            self.draw()
            return

        self.klass = klass
        self.results = []
        self.stats = {}
        self.scroll = 0
        self.pinned = None
        self.follow = True
        self.detail_full = False
        self.stars = set()
        self.deep = {}
        self.stop_event.clear()
        self.pause_event.clear()
        self.control = {"rate": self.rate}
        self.run = store.Run(klass.id, self.pop_name, self.rate, self.timeout, 64)
        self.view = "scan"
        self.status = f"launched {klass.id} over {_fmt_int(len(addrs))} addresses ({note})"

        def work():
            try:
                engine.run_sweep(
                    klass, klass.targets(addrs), self.run, self.q, self.stop_event,
                    rate=self.rate, conc=64, timeout=self.timeout, resume=True,
                    pause_event=self.pause_event, control=self.control)
            except Exception as e:
                self.q.put(("error", f"{type(e).__name__}: {e}"))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.draw()

    def drain(self):
        changed = False
        while True:
            try:
                kind, payload = self.q.get_nowait()
            except queue.Empty:
                return changed
            changed = True
            if kind == "result":
                ip, port, r = payload
                if r.get("verdict") in ("hit", "open"):
                    self.results.append((ip, port, r))
            elif kind == "tick":
                self.stats = payload
            elif kind == "done":
                self.stats = payload
                self.status = ("stopped" if self.stop_event.is_set() else "finished") + \
                    f" — {payload.get('hits', 0)} hit / {payload.get('open', 0)} open" \
                    f" / {payload.get('probed', 0)} probed"
                if self.results:
                    self.status += "   [m] resolve hits"
            elif kind == "error":
                self.status = "scan failed: " + str(payload)
        return changed

    def put(self, y, x, s, attr=0):
        ui.safe(self.scr, y, x, s, attr)

    def draw(self):
        self.frame_no += 1
        H, W = self.scr.getmaxyx()
        if H < 18 or W < 60:
            ui.safe(self.scr, 0, 0, "terminal too small — need 60x18", ui.a("red"))
            return
        try:
            self.scr.erase()
        except curses.error:
            pass
        gw = max(26, min(50, W // 3))
        lw = W - gw - 1
        main_h = H - 1

        if self.view == "dash":
            self.draw_dash(0, 0, main_h, lw)
        elif self.view == "config":
            self.draw_config(0, 0, main_h, lw)
        else:
            self.draw_scan(0, 0, main_h, lw)

        self.draw_globe(0, lw, main_h, gw)

        self.draw_footer(H - 1, W)
        self.scr.noutrefresh()
        curses.doupdate()

    def banner(self, w, h):
        """Pick the largest banner that fits both the width and the height.

        The seven-row version needs 62 columns and about a third of the screen;
        below that the two-row one keeps the class table usable, which matters
        more than the logo.
        """
        if w >= len(BANNER_BIG[0]) + 6 and h >= len(BANNER_BIG) + 12:
            return BANNER_BIG
        return BANNER_SMALL

    def draw_dash(self, y, x, h, w):
        lines = self.banner(w, h)
        bh = len(lines) + 2
        ui.frame(self.scr, y, x, bh, w, "ATOMIC SWEEP", ui.a("amber", curses.A_BOLD),
                 heavy=True)
        for i, line in enumerate(lines):
            self.put(y + 1 + i, x + 2, line[:w - 4], ui.a("green", curses.A_BOLD))
        tag = "v" + VERSION + " · one bench "
        tag_x = x + w - len(tag) - 2
        if tag_x > x + 3 + len(lines[0]):
            self.put(y + 1, tag_x, tag, ui.a("dim"))

        ty = y + bh
        th = h - bh
        ui.frame(self.scr, ty, x, th, w,
                        f"DEVICE CLASSES · {len(SWEEP_CLASSES)}", ui.a("amber"))
        idw, tierw, gatew = 14, 5, 8
        protow = max(7, min(11, (w - 2) // 7))
        titlew = max(8, (w - 2) - (1 + idw + tierw + gatew + protow) - 5)
        hdr = (f" {'ID':<{idw}}{'CLASS':<{titlew}} {'TIER':<{tierw}}"
               f"{'PROTO':<{protow}}GATE")
        self.put(ty + 1, x + 1, hdr[:w - 2], ui.a("dim", curses.A_BOLD))
        maxrows = max(1, th - 3)
        total = len(SWEEP_CLASSES)
        top = 0
        if total > maxrows and self.sel >= maxrows:
            top = min(self.sel - maxrows + 1, total - maxrows)
        for i, k in enumerate(SWEEP_CLASSES[top:top + maxrows]):
            row = ty + 2 + i
            sel = (i + top == self.sel)
            attr = ui.a("bright", curses.A_REVERSE) if sel else ui.a("text")
            g = self.gate_state.get(k.id, "?")
            gate = "..." if g == "?" else ("PASS" if g else "FAIL") if g is not None else "UNGATED"
            gattr = ui.a("dim") if g == "?" else \
                ui.a("green") if g is True else ui.a("amber") if g is None else ui.a("red")
            line = (f"{'>' if sel else ' '}{k.id:<{idw}}{ui.fit(k.title, titlew):<{titlew}}"
                    f" {k.tier:<{tierw}}{ui.fit(k.proto, protow):<{protow}} ")
            self.put(row, x + 1, line[:w - 2], attr)
            self.put(row, x + 1 + len(line[:w - 2]), gate[:gatew], gattr)

        if total > maxrows:
            self.put(ty, x + w - 14, f" {top + 1:>2}-{min(top + maxrows, total):<2}/{total} ",
                     ui.a("dim"))

        dy = ty + th - 2
        if 0 <= self.sel < len(SWEEP_CLASSES):
            desc = SWEEP_CLASSES[self.sel].desc
            if self.desc_sel != self.sel:
                self.desc_sel = self.sel
                self.desc_base = self.frame_no
            self.put(dy, x + 2,
                     ui.marquee(desc, max(0, w - 4), self.frame_no - self.desc_base),
                     ui.a("dim"))

    def draw_config(self, y, x, h, w):
        k = SWEEP_CLASSES[self.sel]
        fh = min(h - 5, self.n_filters() + 3)
        ui.frame(self.scr, y, x, fh, w, f"FILTERS · {k.id} · {k.title}",
                 ui.a("amber", curses.A_BOLD), heavy=True)
        rows = self.filters()
        for i, (name, val, kind, extra) in enumerate(rows):
            row = y + 1 + i
            sel = (i == self.cfg_sel)
            attr = ui.a("bright", curses.A_REVERSE) if sel else ui.a("text")
            mark = {"cycle": "\u25c4\u25ba", "int": "+-", "text": ".."}.get(kind, "")
            line = f"{name:<14}{str(val):<40}{mark}"
            self.put(row, x + 2, line[:w - 4], attr)
        by = y + fh
        bh = 3
        ui.frame(self.scr, by, x, bh, w, "", ui.a("green"))
        label = "  [ LAUNCH SWEEP ]  "
        self.put(by + 1, x + max(1, (w - len(label)) // 2), label,
                 ui.a("green", curses.A_BOLD | curses.A_REVERSE))
        if by + bh < y + h:
            addrs, note = self.targets_preview()
            if addrs is None:
                self.put(by + bh, x + 2, ("unavailable: " + note)[:w - 4], ui.a("red"))
            else:
                self.put(by + bh, x + 2,
                         (f"{_fmt_int(len(addrs))} addresses · {note} · "
                          f"{k.id} on ports {','.join(str(p) for p in k.ports[:5])}")[:w - 4],
                         ui.a("dim"))

    def _warm_addr_index(self):
        """Build the address->operator index off the UI thread.

        It is one sort over ~437k prefixes, about four seconds. Paid at startup
        in the background rather than on the first keypress, because a detail
        pane that freezes the panel for four seconds is worse than a pane that
        says "indexing" for four seconds.
        """
        try:
            geolib.addr_index()
        except Exception:
            pass
        self._addr_ready = True

    def visible_rows(self):
        rows = self.results
        if getattr(self, "hits_only", False):
            rows = [r for r in rows if r[2].get("verdict") in ("hit", "open")]
        return rows

    def pinned_row(self):
        if not self.pinned:
            return None
        for ip, port, r in self.results:
            if (ip, port) == self.pinned:
                return (ip, port, r)
        return None

    def move_sel(self, delta):
        rows = self.visible_rows()
        if not rows:
            self.status = "nothing to select yet"
            return
        if self.pinned is None:
            idx = 0 if delta > 0 else len(rows) - 1
        else:
            keys = [(ip, port) for ip, port, _ in rows]
            try:
                idx = keys.index(self.pinned) + delta
            except ValueError:
                idx = 0
        idx = max(0, min(len(rows) - 1, idx))
        self.pinned = (rows[idx][0], rows[idx][1])
        self.follow = False
        maxrows = max(1, self._list_rows() - 1)
        if idx < self.scroll:
            self.scroll = idx
        elif idx >= self.scroll + maxrows:
            self.scroll = idx - maxrows + 1

    def _list_rows(self):
        h = self.scr.getmaxyx()[0]
        avail = h - 7
        if self.pinned_row() and not self.detail_full:
            return max(3, avail * 55 // 100)
        return max(3, avail)

    def star_toggle(self):
        if not self.pinned:
            self.status = "move onto a row first"
            return
        if self.pinned in self.stars:
            self.stars.discard(self.pinned)
            self.status = f"unmarked {self.pinned[0]}:{self.pinned[1]}"
        else:
            self.stars.add(self.pinned)
            self.status = f"marked {self.pinned[0]}:{self.pinned[1]} ({len(self.stars)} in shortlist)"

    def deep_probe(self, all_classes=False):
        """Re-probe the pinned host, slowly, from this panel.

        One host, one probe per class, no pacing pressure — which makes it the
        only view in the tool where a `refused` or an answered port is not
        competing with 64 workers for the truth. It is the same measurement the
        silence rescan makes, aimed by hand at a row the operator chose.
        """
        row = self.pinned_row()
        if not row:
            self.status = "move onto a row first"
            return
        ip, port, _r = row
        if all_classes:
            klasses = SWEEP_CLASSES
        else:
            k = self.klass
            if k is None:
                k = [c for c in SWEEP_CLASSES
                     if (ip, port) in set(c.targets([ip]))] or []
                k = k[0] if k else None
            klasses = [k] if k else []
        if not klasses:
            self.status = "no class to re-probe with"
            return
        key = (ip, port)
        if key in self.deep_busy:
            self.status = "already probing"
            return
        self.deep_busy.add(key)
        self.status = f"re-probing {ip}:{port} (slow)…"
        self.draw()

        def work():
            found = []
            for k in klasses:
                try:
                    r = k.probe(ip, port, max(4.0, self.timeout))
                except Exception as e:
                    r = {"verdict": "error", "product": "",
                         "detail": f"exc:{type(e).__name__}:{e}"}
                r["evidence"] = net.take_evidence()
                if r.get("verdict") in ("hit", "open"):
                    found.append((k.id, r))
            self.deep[key] = found
            self.deep_busy.discard(key)
            if found:
                self.status = f"{ip}:{port} — " + ", ".join(
                    f"{cid}:{r['product'] or r['verdict']}" for cid, r in found[:2])
            else:
                self.status = f"{ip}:{port} — nothing answered on a slow single probe"

        threading.Thread(target=work, daemon=True).start()

    def resolve_one(self):
        row = self.pinned_row()
        if not row:
            self.status = "move onto a row first"
            return
        ip = row[0]
        key = (ip, row[1])
        if key in self.deep_busy:
            self.status = "already looking"
            return
        self.deep_busy.add(key)
        self.status = f"resolving {ip}…"

        def work():
            try:
                names, state = nslib.ptr_lookup(ip, None, 3.0, 2)
            except Exception as e:
                names, state = [], f"error:{e}"
            notable = [n for n in names if not nslib.formulaic(ip, n)]
            self.deep[key + ("ptr",)] = (state, names, notable)
            self.deep_busy.discard(key)
            if notable:
                self.status = f"{ip} → {notable[0]}"
            elif names:
                self.status = (f"{ip} → {names[0]} (formulaic: spells the address "
                               f"back, no information)")
            else:
                self.status = f"{ip} → no PTR ({state})"

        threading.Thread(target=work, daemon=True).start()

    def draw_scan(self, y, x, h, w):
        k = self.klass
        s = self.stats or {}
        state = ""
        if self.worker and self.worker.is_alive():
            state = " · PAUSED" if self.pause_event.is_set() else " · running"
        elif self.stop_event.is_set():
            state = " · stopped"
        if not self.follow and self.pinned:
            state += " · SELECTED"
        head = (f"{k.id} · probe {_fmt_int(s.get('probed', 0))}/{_fmt_int(s.get('total', 0))}"
                f"{state}" if k else "no run")
        ui.frame(self.scr, y, x, h, w, head, ui.a("amber", curses.A_BOLD), heavy=True)

        row = self.pinned_row()
        detail_h = 0
        list_h = h - 4
        if row and not self.detail_full:
            detail_h = max(6, (h - 4) * 45 // 100)
            list_h = max(3, h - 4 - detail_h - 1)
        elif row and self.detail_full:
            list_h = 0

        if list_h:
            hdr = f"{'':1}{'IP':<17}{'PORT':<7}{'VERDICT':<10}{'PRODUCT':<26}DETAIL"
            self.put(y + 1, x + 2, hdr[:w - 4], ui.a("dim", curses.A_BOLD))
            rows = self.visible_rows()
            maxrows = max(1, list_h - 1)
            if self.follow:
                self.scroll = max(0, len(rows) - maxrows)
            elif len(rows) > maxrows:
                self.scroll = max(0, min(self.scroll, len(rows) - maxrows))
            for i, (ip, port, r) in enumerate(rows[self.scroll:self.scroll + maxrows]):
                attr = ui.a(VERDICT_ATTR.get(r.get("verdict"), "text"))
                here = (ip, port) == self.pinned
                if here:
                    attr |= curses.A_REVERSE
                mark = "*" if (ip, port) in self.stars else " "
                line = (f"{mark}{ip:<17}{port:<7}{r.get('verdict', ''):<10}"
                        f"{(r.get('product') or '')[:25]:<26}{r.get('detail', '')}")
                self.put(y + 2 + i, x + 2, line[:w - 4], attr)
            if not self.results:
                self.put(y + 2, x + 2, self.status[:w - 4], ui.a("dim"))
        if row:
            dy = y + 2 + (list_h if list_h else 0)
            self.draw_detail(dy, x + 1, (detail_h if not self.detail_full else h - 4), w - 2)

        tot = s.get("total") or 0
        frac = (s.get("probed", 0) / tot) if tot else 0.0
        ui.bar(self.scr, y + h - 2, x + 2, max(10, w - 4), frac,
               ui.a("green"), ui.a("dim"))
        self.put(y + h - 2, x + 3, f" {frac * 100:5.1f}% ", ui.a("bright"))

    def draw_detail(self, y, x, h, w):
        """Everything known about the selected row, including WHY.

        The evidence block is the reason this pane exists. A verdict is a
        summary the matcher wrote about itself; the bytes underneath it are the
        only way an operator can catch a matcher that is confidently wrong, and
        this bench has been confidently wrong before — `<link rel="canonical">`
        once came back as a Canon printer.
        """
        row = self.pinned_row()
        if not row:
            return
        ip, port, r = row
        key = (ip, port)
        ui.frame(self.scr, y, x, h, w, f"{ip}:{port}", ui.a("cyan"), heavy=False)
        lines = []

        res_lbl = geolib.lookup(ip) if self._addr_ready else None
        if not self._addr_ready:
            lines.append(("operator", "building address index…", ui.a("dim")))
        elif res_lbl:
            asn, name, cc = res_lbl
            lines.append(("operator", f"AS{asn} {name}" + (f" · {cc}" if cc else ""),
                          ui.a("bright")))
        else:
            lines.append(("operator",
                          "no prefix in local data covers this address "
                          "(that is a fact about our data, not about the host)",
                          ui.a("dim")))

        lines.append(("verdict", f"{r.get('verdict')} · {r.get('product') or '—'}", 
                      ui.a(VERDICT_ATTR.get(r.get("verdict"), "text"))))
        rtt = r.get("rtt")
        lines.append(("detail", r.get("detail") or "—", ui.a("text")))
        if rtt:
            lines.append(("rtt", f"{rtt * 1000:.0f} ms", ui.a("dim")))

        deep = self.deep.get(key)
        if key in self.deep_busy:
            lines.append(("re-probe", "probing slowly…", ui.a("amber")))
        elif deep:
            body = ", ".join(f"{cid}:{d.get('product') or d.get('verdict')}"
                             for cid, d in deep[:4]) or "nothing answered"
            lines.append(("re-probe", body, ui.a("green2")))
        ptr = self.deep.get(key + ("ptr",))
        if ptr:
            state, names, notable = ptr
            if notable:
                lines.append(("ptrs", "; ".join(notable[:3]), ui.a("green2")))
            elif names:
                lines.append(("ptrs", f"{names[0]} (formulaic — spells the address back)",
                              ui.a("dim")))
            else:
                lines.append(("ptrs", f"no name ({state})", ui.a("dim")))

        ev = r.get("evidence") or []
        hdr_room = 2
        used = len(lines) + hdr_room
        if not ev:
            lines.append(("evidence", "none recorded for this row "
                                      "(a resumed run or a row from disk)", ui.a("dim")))
        else:
            for e in ev:
                bits = [e.get("via", "?")]
                if e.get("note"):
                    bits.append(e["note"])
                if e.get("status"):
                    bits.append(f"→ {e['status']}")
                if e.get("state") and e["state"] != "open":
                    bits.append(f"[{e['state']}]")
                if e.get("detail"):
                    bits.append(e["detail"])
                lines.append(("", " ".join(bits), ui.a("dim")))
                hdrs = e.get("headers") or {}
                if hdrs:
                    used += 1
                    if used < h - 2:
                        lines.append(("", "   " + " · ".join(f"{k}={v}" for k, v in hdrs.items()),
                                      ui.a("dim")))
                for k2, v2 in (e.get("extra") or {}).items():
                    used += 1
                    if used < h - 2:
                        lines.append(("", f"   {k2}={v2}", ui.a("dim")))
                if e.get("text"):
                    used += 1
                    if used < h - 2:
                        lines.append(("", "   " + e["text"], ui.a("text")))

        room = max(1, h - 2)
        for i, (label, text, attr) in enumerate(lines[:room]):
            if label:
                self.put(y + 1 + i, x + 2, f"{label:<9}"[:11], ui.a("magenta"))
                self.put(y + 1 + i, x + 12, text[:w - 14], attr)
            else:
                self.put(y + 1 + i, x + 2, text[:w - 4], attr)

    def draw_globe(self, y, x, h, w):
        ui.frame(self.scr, y, x, h, w, "WORLD", ui.a("amber"))
        COUNTER_ROWS = 8
        gw = w - 2
        gh = max(6, min(max(6, h - 2 - COUNTER_ROWS), (gw // 2) + 2))
        if self.globe is None or self.globe.width != gw or self.globe.height != gh:
            try:
                mode = "halftone" if gw >= 30 else "solid"
                self.globe = BrailleGlobe(gw, gh, mode=mode)
            except Exception as e:
                self.put(y + 2, x + 2, f"globe: {e}", ui.a("red"))
                return
        lat_shift = 0.0
        k = self.klass if self.view == "scan" else SWEEP_CLASSES[self.sel]
        if k is not None and getattr(k, "geo_hint", None):
            lat_shift = -k.geo_hint[0] * 0.5
        try:
            rows = self.globe.frame(self.rot, lat_shift=lat_shift)
        except Exception as e:
            self.put(y + 2, x + 2, f"globe: {e}", ui.a("red"))
            return
        for i, line in enumerate(rows[:gh]):
            self.put(y + 1 + i, x + 1, line, ui.a("blue"))

        s = self.stats or {}
        cy = y + h - 7
        lines = [
            ("probed", _fmt_int(s.get("probed", 0))),
            ("hits", _fmt_int(s.get("hits", 0))),
            ("open", _fmt_int(s.get("open", 0))),
            ("unproven", _fmt_int(s.get("unproven", 0))),
            ("rate", f"{s.get('pps', 0.0):.1f}/s"),
        ]
        for i, (nm, val) in enumerate(lines):
            self.put(cy + i, x + 2, f"{nm:<10}{val:>8}"[:w - 4],
                     ui.a("green") if nm == "hits" else ui.a("dim"))

    def draw_footer(self, y, w):
        keys = {
            "dash": "enter configure · g gate · q quit",
            "config": "enter launch · esc back · q quit",
            "scan": "↑↓ select · enter detail · d re-probe · a all classes · t ptr · y mark",
        }.get(self.view, "")
        if self.view == "scan" and self.results:
            keys = ("↑↓ select · enter detail · d re-probe · a all classes · t ptr · y mark"
                    " · p pause · s stop · e export · esc")
        left = " " + keys
        right = self.status
        try:
            self.scr.move(y, 0)
            self.scr.clrtoeol()
        except curses.error:
            pass
        room = max(0, w - len(right) - 2)
        if room < 20:
            self.put(y, w - min(len(right), w - 2) - 1,
                     right[-min(len(right), w - 2):], ui.a("dim"))
            return
        self.put(y, 0, left[:room], ui.a("bright", curses.A_REVERSE))
        self.put(y, w - min(len(right), room) - 1,
                 right[-min(len(right), room):], ui.a("dim"))

    def mass_resolve(self):
        if not self.results:
            self.status = "nothing to resolve"
            self.draw()
            return
        self.status = f"resolving {len(self.results)} hits…"
        self.draw()
        addrs = [ip for ip, _p, _r in self.results]

        def work():
            import socket
            rows = []
            for ip in addrs:
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except Exception:
                    name = ""
                kind = ""
                if name:
                    kind = "formulaic" if MASS_RESOLVE.formulaic(ip, name) else "informative"
                rows.append((ip, name, kind))
            self.resolve_rows = rows
            inf = sum(1 for _i, _n, kd in rows if kd == "informative")
            self.status = (f"resolved {len(rows)} — {inf} informative, "
                           f"{sum(1 for _i,_n,kd in rows if kd=='formulaic')} formulaic, "
                           f"{sum(1 for _i,_n,kd in rows if not kd)} none")
            self.draw()

        threading.Thread(target=work, daemon=True).start()

    def edit_config(self, key):
        rows = self.filters()
        if not rows:
            return
        name, val, kind, extra = rows[self.cfg_sel]
        delta = 1 if key in (curses.KEY_RIGHT, ord("+"), ord("=")) else -1
        if kind == "cycle":
            opts = extra
            if name == "POPULATION":
                val = self.pop_name
            try:
                i = opts.index(val)
            except ValueError:
                i = 0
            nv = opts[(i + delta) % len(opts)]
            if name == "POPULATION":
                self.pop_name = nv
                self.country = "*"
                self.operator = ""
                self.cfg_sel = 0
            elif name == "COUNTRY":
                self.country = nv
                self.operator = ""
            return
        if kind == "int":
            lo, hi = extra
            cur = int(val)
            step = max(1, int(cur * 0.25)) if abs(cur) > 20 else 1
            nv = max(lo, min(hi, cur + delta * step))
            if name == "RATE":
                self.rate = nv
            elif name == "TIMEOUT":
                self.timeout = nv
            elif name == "LIMIT":
                self.limit = nv
            elif name == "HOSTS / NET":
                self.per_net = nv
            return
        if kind == "text":
            ops = ["(any)"] + [n for _a, n, _c in self.geo.operators(
                None if self.country == "*" else self.country, limit=120)]
            cur = val
            try:
                i = ops.index(cur)
            except ValueError:
                i = 0
            self.operator = "" if ops[(i + delta) % len(ops)] == "(any)" \
                else ops[(i + delta) % len(ops)]

    def key(self, ch):
        if ch == ord("q"):
            if self.view == "scan" and self.worker and self.worker.is_alive():
                self.stop_event.set()
                self.status = "stopping…"
                self.draw()
                return
            return False

        if self.view == "dash":
            if ch in (curses.KEY_UP, ord("k")):
                self.sel = (self.sel - 1) % len(SWEEP_CLASSES)
                self.allow_ungated = False
            elif ch in (curses.KEY_DOWN, ord("j")):
                self.sel = (self.sel + 1) % len(SWEEP_CLASSES)
                self.allow_ungated = False
            elif ch in (curses.KEY_ENTER, 10, 13):
                self.view = "config"
                self.cfg_sel = 0
                wanted = getattr(SWEEP_CLASSES[self.sel], "population", None)
                if wanted and wanted in geolib.POPULATIONS:
                    self.pop_name = wanted
            elif ch == ord("g"):
                self.run_gate(SWEEP_CLASSES[self.sel])
            elif ch == ord("l"):
                self.view = "config"
                self.launch()
            self.draw()
            return True

        if self.view == "config":
            if ch == 27:
                self.view = "dash"
                self.allow_ungated = False
            elif ch in (curses.KEY_UP, ord("k")):
                self.cfg_sel = (self.cfg_sel - 1) % max(1, self.n_filters())
            elif ch in (curses.KEY_DOWN, ord("j")):
                self.cfg_sel = (self.cfg_sel + 1) % max(1, self.n_filters())
            elif ch in (curses.KEY_LEFT, curses.KEY_RIGHT, ord("+"), ord("="), ord("-")):
                self.edit_config(ch)
            elif ch in (curses.KEY_ENTER, 10, 13):
                self.launch()
                return True
            self.draw()
            return True

        if ch in (ord("p"), ord(" ")):
            self.toggle_pause()
        elif ch == ord("s"):
            self.stop_event.set()
            self.status = "stopping…"
        elif ch in (ord("+"), ord("=")):
            self.bump_rate(1.5)
        elif ch == ord("-"):
            self.bump_rate(1 / 1.5)
        elif ch == ord("r"):
            self.restart()
        elif ch == ord("e"):
            self.export_hits()
        elif ch == ord("f"):
            self.toggle_hits_only()
        elif ch == ord("m"):
            self.mass_resolve()
        elif ch == ord("y"):
            self.star_toggle()
        elif ch == ord("d"):
            self.deep_probe(all_classes=False)
        elif ch == ord("a"):
            self.deep_probe(all_classes=True)
        elif ch == ord("t"):
            self.resolve_one()
        elif ch == 27:
            if self.detail_full:
                self.detail_full = False
            elif not self.follow:
                self.follow = True
                self.pinned = None
                self.status = "following new results"
            else:
                if self.worker and self.worker.is_alive():
                    self.stop_event.set()
                self.view = "dash"
        elif ch in (curses.KEY_UP, ord("k")):
            self.move_sel(-1)
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.move_sel(1)
        elif ch in (curses.KEY_ENTER, 10, 13):
            if self.pinned_row():
                self.detail_full = not self.detail_full
                self.status = ("detail full height — enter to restore, esc to step back"
                               if self.detail_full else "selection kept")
            else:
                self.status = "move onto a row first"
        self.draw()
        return True

    def toggle_pause(self):
        """Pause holds the sweep; it does not end it.

        A stop loses the position and the counters, which is why stop is the only
        control worth having unless pause exists: a run that looks like it is
        annoying a peer should be held, looked at, and then either slowed with
        `+`/`-` or stopped on purpose.
        """
        if not (self.worker and self.worker.is_alive()):
            self.status = "nothing running to pause"
            self.draw()
            return
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.status = f"resumed at {self.control.get('rate', self.rate):g} pps"
        else:
            self.pause_event.set()
            self.status = "PAUSED — nothing is being sent; p resumes, s stops"
        self.draw()

    def restart(self):
        """Stop the current run and start the same filters again from zero."""
        if self.worker and self.worker.is_alive():
            self.stop_event.set()
            self.worker.join(timeout=6)
        if not self.klass:
            self.status = "nothing to restart"
            self.draw()
            return
        self.results = []
        self.stats = {}
        self.launch()

    def export_hits(self):
        """Write this run's findings next to its results.

        If the operator has marked rows, the shortlist is what gets written —
        marking exists precisely because the interesting subset is usually much
        smaller than "everything that answered", and exporting all 900 opens
        when you marked four is not an export, it is a dump.
        """
        if not self.run:
            self.status = "no run to export"
            self.draw()
            return
        if self.stars:
            rows = [(ip, port, r) for ip, port, r in self.results
                    if (ip, port) in self.stars]
            name, what = "shortlist.txt", "marked"
        else:
            rows = [(ip, port, r) for ip, port, r in self.results
                    if r.get("verdict") in ("hit", "open")]
            name, what = "hits.txt", "hit/open"
        path = os.path.join(self.run.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            for ip, port, r in rows:
                fh.write(f"{ip}\t{port}\t{r.get('verdict')}\t"
                         f"{r.get('product', '')}\t{r.get('detail', '')}\n")
        self.status = f"wrote {len(rows)} {what} row(s) to {path}"
        self.draw()

    def toggle_hits_only(self):
        self.hits_only = not getattr(self, "hits_only", False)
        self.status = ("showing hits and open only" if self.hits_only
                       else "showing every row the run has produced")
        self.draw()

    def bump_rate(self, factor):
        """Retune the ceiling while the run is going."""
        if not (self.worker and self.worker.is_alive()):
            self.status = "nothing running to retune"
            self.draw()
            return
        cur = float(self.control.get("rate", self.rate))
        new = max(1.0, min(2000.0, cur * factor))
        self.control["rate"] = new
        self.rate = int(round(new))
        self.status = f"rate now {new:.0f} pps" + (" (paused)" if self.pause_event.is_set() else "")
        self.draw()

    def auto_gate(self):
        """Gate every class that has a control, in the background.

        A class that is never gated shows `...` forever, and an ungated class is
        the state this bench exists to make visible rather than to hide.
        """
        def work():
            for k in SWEEP_CLASSES:
                if not k.CONTROLS:
                    self.gate_state[k.id] = None
                    continue
                try:
                    ok, _rows = engine.gate(k)
                except Exception:
                    ok = None
                self.gate_state[k.id] = ok
            self.draw()

        threading.Thread(target=work, daemon=True).start()

    def loop(self):
        self.scr.timeout(90)
        self.draw()
        self.auto_gate()
        running = True
        while running:
            if self.drain():
                self.draw()
            ch = self.scr.getch()
            if ch == -1:
                if self.view == "scan":
                    self.rot = (self.rot + 3.0) % 360.0
                else:
                    self.rot = (self.rot + 0.8) % 360.0
                self.draw()
                continue
            if ch == curses.KEY_RESIZE:
                self.globe = None
                self.draw()
                continue
            running = self.key(ch)
        if self.worker and self.worker.is_alive():
            self.stop_event.set()

def main(argv):
    os.environ.setdefault("ESCDELAY", "25")
    ap = App(None)

    def run(scr):
        ap.scr = scr
        curses.curs_set(0)
        scr.keypad(True)
        ui.init()
        try:
            if curses.has_colors():
                curses.start_color()
        except curses.error:
            pass
        try:
            ap.geo.load()
        except Exception:
            pass
        ap.loop()

    try:
        curses.wrapper(run)
    except KeyboardInterrupt:
        return 130
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
