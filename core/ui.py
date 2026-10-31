"""Colours, box drawing and the widgets the dashboard is assembled from.

Plain ANSI + `curses.color_pair`, no third-party dependency: the tool has to run
over a serial console and on a box where nothing is installed, which is the same
constraint that made the original console-world-map worth having.

The theme is a phosphor terminal: cold green for structure, amber for a selected
row, cyan for a live number, red for a failure that matters.
"""

from __future__ import annotations

import curses

C = {}

def init():
    """Build the colour pairs once, after initscr(). Falls back silently when
    the terminal cannot do colour, because a monochrome session is still usable."""
    if not curses.has_colors():
        return False
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK

    pairs = {
        "dim":     (240, bg),
        "text":    (252, bg),
        "bright":  (231, bg),
        "green":   (114, bg),
        "green2":  (77, bg),
        "cyan":    (80, bg),
        "amber":   (214, bg),
        "red":     (203, bg),
        "magenta": (176, bg),
        "blue":    (68, bg),
        "ocean":   (24, bg),
        "g1":      (236, bg),
        "g2":      (30, bg),
        "g3":      (80, bg),
        "g4":      (176, bg),
        "gblk":    (81, 17),
        "gblk2":   (213, 53),
    }
    for i, (name, (fg, b)) in enumerate(pairs.items(), start=1):
        try:
            curses.init_pair(i, fg, b)
        except curses.error:
            return False
        C[name] = i
    return True

def a(name, extra=0):
    pair = C.get(name)
    if pair is None:
        return extra
    return curses.color_pair(pair) | extra

HEAVY = {"tl": "╔", "tr": "╗", "bl": "╚", "br": "╝", "h": "═", "v": "║",
         "lt": "╠", "rt": "╣", "tt": "╦", "bt": "╩", "x": "╬"}
LIGHT = {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│",
         "lt": "├", "rt": "┤", "tt": "┬", "bt": "┴", "x": "┼"}

def safe(win, y, x, text, attr=0):
    """addstr that refuses to raise at the edge of the window.

    curses raises on writing the last cell of a window; every widget goes
    through here so a resize mid-draw degrades to a clipped line instead of
    killing the event loop.
    """
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w or x < 0:
        return
    try:
        win.addstr(y, x, text[: max(0, w - x - 1)], attr)
    except curses.error:
        pass

def frame(win, y, x, h, w, title="", attr=0, heavy=False, tattr=None):
    """Draw a box, optionally with a title set into the top edge.

    Returns the interior rect (y, x, h, w) so callers do not re-derive it and
    get the off-by-one that clips the last row.
    """
    if h < 2 or w < 2:
        return None
    cs = HEAVY if heavy else LIGHT
    ta = attr if tattr is None else tattr
    safe(win, y, x, cs["tl"] + cs["h"] * (w - 2) + cs["tr"], attr)
    for i in range(1, h - 1):
        safe(win, y + i, x, cs["v"], attr)
        safe(win, y + i, x + w - 1, cs["v"], attr)
    safe(win, y + h - 1, x, cs["bl"] + cs["h"] * (w - 2) + cs["br"], attr)
    if title:
        t = " " + title + " "
        safe(win, y, x + 2, t, ta)
    return (y + 1, x + 1, h - 2, w - 2)

def hline(win, y, x, w, attr=0, heavy=False, label=""):
    cs = HEAVY if heavy else LIGHT
    safe(win, y, x, cs["h"] * w, attr)
    if label:
        safe(win, y, x + 2, " " + label + " ", attr)

def bar(win, y, x, w, frac, attr=0, empty_attr=None, glyph="█"):
    """A solid fill bar. Used for sweep progress and the header gauges."""
    w = max(1, w)
    filled = int(round(max(0.0, min(1.0, frac)) * w))
    if empty_attr is None:
        empty_attr = a("dim")
    safe(win, y, x, glyph * filled, attr)
    safe(win, y, x + filled, "░" * (w - filled), empty_attr)

def clip(s, n):
    if len(s) <= n:
        return s
    return s[: n - 1] + "…" if n > 1 else s[:n]

def fit(s, n):
    """Pad or clip to exactly n columns so table columns stay aligned."""
    s = clip(s, n)
    return s + " " * (n - len(s))

def marquee(s, n, frame, hold=14, speed=2, gap="   \u00b7   "):
    """Scroll `s` right-to-left inside `n` columns.

    A clipped description is worse than a missing one: it ends mid-word, so the
    reader sees a sentence that looks finished and stops reading. The panel is
    the width it is for a reason (the globe needs the right column), so the text
    moves instead of the layout.

    `hold` frames show the beginning before anything shifts — movement from the
    first frame makes the first words unreadable, which defeats the purpose.
    `speed` is frames per character; at the panel's ~11 fps, 2 is ~5 chars/s.
    """
    if n <= 0:
        return ""
    s = s or ""
    if len(s) <= n:
        return s
    span = s + gap
    step = frame - hold
    if step <= 0:
        return s[:n]
    off = (step // max(1, speed)) % len(span)
    doubled = span + span
    return doubled[off:off + n]

GLITCH = ("\u2591\u2592\u2593\u2502\u2524\u2561\u2562\u2556\u2555\u2563\u2551"
          "\u2557\u255d\u2510\u2514\u2534\u252c\u251c\u2500\u253c\u255e\u255f"
          "\u255a\u2554\u2569\u2566\u2560\u2550\u256c\u2567\u2568\u2564\u2565"
          "\u2559\u2558\u2552\u2553\u256b\u256a\u2518\u250c\u2588\u2584\u258c\u2590")

def glitch(win, y, x, h, w, frame, density=70, attr=0, hot=None):
    """Scatter interference behind a panel's content.

    Deliberately drawn BEFORE the content so text always wins: noise you can
    still read through is decoration, noise that hides a class name is a bug.
    The pattern is a hash of (row, col, frame block) so it is stable for a few
    frames and then jumps, instead of flickering every redraw.
    """
    if h <= 0 or w <= 0:
        return
    block = frame // 4
    for r in range(h):
        base = (r * 73856093) ^ (block * 83492791)
        for c in range(w):
            k = (base ^ (c * 19349663)) % 1000
            if k >= density:
                continue
            g = GLITCH[(k * 31 + r * 7 + c) % len(GLITCH)]
            a = attr
            if hot is not None and k < max(1, density // 12):
                a = hot
            safe(win, y + r, x + c, g, a)

NOISE = "\u2591\u2592\u2593\u2588\u2584\u2580\u258c\u2590\u00b7\u2027"

def crt_noise(win, y, x, h, w, frame, density=110, attr=0):
    """Draw interference that looks like a signal fault rather than a pattern.

    Three layers, because one layer always reads as decoration:

      * an interlaced dot field — odd rows are skipped, so the texture has
        scanlines instead of uniform stipple;
      * sparks — a fraction of cells in cyan or magenta, which is what makes a
        glitch look like a broken channel instead of static;
      * tears — one or two horizontal runs per frame-block drawn in half blocks
        with a coloured background, which is the part that reads as *graphical*.

    Everything is drawn before the panel content, so text always wins.
    """
    if h <= 0 or w <= 0:
        return
    block = frame // 5
    for r in range(h):
        if r & 1:
            continue
        base = (r * 73856093) ^ (block * 83492791)
        for c in range(w):
            k = (base ^ (c * 19349663)) % 1000
            if k >= density:
                continue
            if k < 6:
                g, a = "\u2500", attr
            elif k < 12:
                g, a = "\u00b7", attr
            else:
                g, a = NOISE[(k * 7 + r) % len(NOISE)], attr
            if k % 23 == 0:
                a = C.get("g3") and curses.color_pair(C["g3"]) or attr
            elif k % 31 == 0:
                a = C.get("g4") and curses.color_pair(C["g4"]) or attr
            safe(win, y + r, x + c, g, a)

    for t in range(1 + (block % 2)):
        kk = (block * 2654435761 + t * 40503) & 0x7FFFFFFF
        tr = kk % max(1, h)
        if tr & 1:
            tr = min(h - 1, tr + 1)
        tl = 6 + (kk >> 7) % 14
        tc = (kk >> 11) % max(1, w - tl)
        use = C.get("gblk") if t == 0 else C.get("gblk2")
        at = curses.color_pair(use) if use else attr
        for c in range(tl):
            if ((c * 7 + kk) % 5) >= 3:
                continue
            g = "\u2580" if ((c + kk) & 3) else "\u2584"
            safe(win, y + tr, x + tc + c, g, at)
