"""Spinning globe of filled continents, for the right-hand panel.

The geometry is precomputed once per panel size. Rotation around the polar axis
is then just a constant added to every cell's longitude, which is why a frame
costs one array lookup per visible cell instead of a matrix multiply — the panel
redraws at 10 fps next to a live scan without touching the scanner's budget.

Projection is orthographic: a cell at screen (X, Y) inside the unit disc sits on
the near hemisphere at Z = sqrt(1 - X^2 - Y^2). Latitude is asin(Y) and the
longitude at rotation 0 is atan2(X, Z); rotating the globe by t adds t to that
longitude, so land never has to be re-projected.

Terminal cells are about twice as tall as they are wide, so the grid is sized
2R columns by R rows for the same visual circle. Getting that ratio wrong
produces an egg, not a planet.
"""

from __future__ import annotations

import math
import os

GLYPHS = {
    0.00: " ",
    0.20: ".",
    0.45: ":",
    0.75: "+",
    1.01: "#",
}

SHADE = "@%#*+=:."

def _decode_rle(path):
    """Expand the RLE land mask into a (180, 360) byte grid indexed [lat][lon]."""
    with open(path, encoding="utf-8") as fh:
        body = "".join(ln for ln in fh if not ln.startswith("#"))
    toks = body.split()
    grid = bytearray(180 * 360)

    def runs(s):
        j = 0
        on = True
        while j < len(s):
            c = s[j]
            if c == "S":
                n = int(s[j + 1:j + 4])
                j += 4
            elif c == "T":
                n = int(s[j + 1:j + 3])
                j += 3
            else:
                n = int(c)
                j += 1
            yield on, n
            on = not on

    i = 0
    while i + 2 < len(toks) + 1 and i + 2 <= len(toks):
        lat = int(toks[i])
        lon = int(toks[i + 1])
        s = toks[i + 2]
        i += 3
        row = (lat + 90) % 180
        x = lon
        for on, n in runs(s):
            if on:
                for xx in range(x, x + n):
                    grid[row * 360 + ((xx + 180) % 360)] = 1
            x += n
    return grid

_LAND = None

def land():
    """Load the mask once. Missing data raises rather than drawing an empty sea."""
    global _LAND
    if _LAND is None:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(here, "data", "land.rle")
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        _LAND = _decode_rle(path)
    return _LAND

class Globe:
    """Precomputed orthographic sphere for one panel size.

    Every visible cell's latitude and its longitude at rotation 0 are computed
    once in `_build`. A frame then only adds the rotation to the longitude
    index, so redrawing costs one array lookup per cell — cheap enough to run at
    10 fps beside a live scan without competing for the scanner's budget.
    """

    def __init__(self, width, height, supersample=2):
        self.width = max(8, width)
        self.height = max(4, height)
        self.ss = supersample
        self.cells = []
        self._build()

    def _build(self):
        """Precompute, for every terminal cell, the sample points inside the disc.

        Each sample stores its latitude and its longitude at rotation 0, because
        spinning the globe about the polar axis only ADDS to longitude. A frame
        is therefore one grid lookup per sample and no trigonometry, which is
        what lets this redraw beside a live 400 pps scan without stealing budget
        from it.
        """
        W, H, ss = self.width, self.height, self.ss
        R = min(W / 2.0, H)
        cx, cy = W / 2.0, H / 2.0

        for row in range(H):
            for col in range(W):
                samples = []
                for sy in range(ss):
                    for sx in range(ss):
                        px = col + (sx + 0.5) / ss
                        py = row + (sy + 0.5) / ss
                        X = (px - cx) / R
                        Y = (cy - py) / (R / 2.0)
                        d2 = X * X + Y * Y
                        if d2 > 1.0:
                            continue
                        Z = math.sqrt(max(0.0, 1.0 - d2))
                        lat = math.degrees(math.asin(max(-1.0, min(1.0, Y))))
                        lon = math.degrees(math.atan2(X, Z))
                        samples.append((lat, lon))
                if samples:
                    self.cells.append((row, col, samples))

    def _land(self, lat, lon):
        grid = land()
        li = int(round(lat)) + 90
        if not (0 <= li < 180):
            return 0
        return grid[li * 360 + (int(round(lon)) + 180) % 360]

    def frame(self, rot_deg, lat_shift=0.0, halftone=True):
        """Return `height` strings of `width` cells.

        rot_deg spins the globe eastward; lat_shift tilts the view toward the
        north pole (positive) so a run's geography can be brought to the middle
        of the panel instead of the equator.

        halftone=True draws the OCEAN as a dot screen and leaves the land dark,
        which is how a newsroom globe is printed. That inversion matters: with
        land drawn as glyphs the continents are the only thing visible and the
        sphere disappears; with the ocean screened, the planet is a solid ball
        and the landmasses read as holes in it.
        """
        W, H = self.width, self.height
        grid = land()
        canvas = [[" "] * W for _ in range(H)]
        full = self.ss * self.ss
        shift_i = int(round(lat_shift))
        rot_i = int(round(rot_deg))

        for row, col, samples in self.cells:
            cov = 0
            for lat, lon in samples:
                li = int(round(lat)) + 90 + shift_i
                if not (0 <= li < 180):
                    continue
                oi = (int(round(lon)) + rot_i + 180) % 360
                if grid[li * 360 + oi]:
                    cov += 1
            frac = cov / float(full)
            if halftone:
                if frac >= 0.5:
                    continue
                canvas[row][col] = "\u2591" if len(samples) == full else "\u00b7"
                continue
            if cov:
                idx = int(frac * (len(SHADE) - 1) + 0.5)
                canvas[row][col] = SHADE[min(idx, len(SHADE) - 1)]
            elif len(samples) < full:
                canvas[row][col] = "\u00b7"
        return ["".join(r) for r in canvas]
    def _land(self, lat, lon):
        grid = land()
        li = int(round(lat)) + 90
        if not (0 <= li < 180):
            return 0
        return grid[li * 360 + (int(round(lon)) + 180) % 360]

BRAILLE_BITS = (
    (0x01, 0x08),
    (0x02, 0x10),
    (0x04, 0x20),
    (0x40, 0x80),
)

BAYER4 = (
    (0, 8, 2, 10),
    (12, 4, 14, 6),
    (3, 11, 1, 9),
    (15, 7, 13, 5),
)

class BrailleGlobe:
    """Orthographic earth drawn with braille sub-cells.

    Same interface as `Globe` — `frame(rot_deg, lat_shift)` returns `height`
    strings of `width` cells — so the two are drop-in replacements.

    The ocean is a dithered dot screen and the land is left dark, which is how a
    newsroom globe is printed: the planet reads as a solid ball with the
    continents punched out of it, and the dither carries the curvature.
    """

    def __init__(self, width, height, mode="halftone"):
        self.width = max(4, width)
        self.height = max(2, height)
        self.mode = mode
        self.SW = self.width * 2
        self.SH = self.height * 4

    def frame(self, rot_deg, lat_shift=0.0):
        W, H = self.width, self.height
        SW, SH = self.SW, self.SH
        grid = land()
        R = min(SW / 2.0, SH / 2.0) - 2
        cx, cy = SW / 2.0, SH / 2.0
        rot = int(round(rot_deg)) + 180
        shift = int(round(lat_shift))

        mask = [[0] * W for _ in range(H)]
        inside = [[False] * W for _ in range(H)]

        for py in range(SH):
            Y = (cy - py - 0.5) / R
            row4 = py & 3
            yy = Y * Y
            for px in range(SW):
                X = (px - cx + 0.5) / R
                d2 = X * X + yy
                if d2 >= 1.0:
                    continue
                ci, cj = py >> 2, px >> 1
                inside[ci][cj] = True
                Z = math.sqrt(1.0 - d2)
                lat = math.degrees(math.asin(max(-1.0, min(1.0, Y)))) + shift
                li = int(round(lat)) + 90
                if not (0 <= li < 180):
                    continue
                lon = math.degrees(math.atan2(X, Z))
                oi = (int(round(lon)) + rot) % 360
                if grid[li * 360 + oi]:
                    continue
                if self.mode == "solid":
                    on = True
                elif self.mode == "dots":
                    on = ((px + py) & 1) == 0
                else:
                    on = ((px + py) & 1) == 0
                if on and Z <= 0.34:
                    light = 0.30 + Z * 2.05
                    on = (BAYER4[row4][px & 3] + 0.5) / 16.0 < light
                if on:
                    mask[ci][cj] |= BRAILLE_BITS[row4][px & 1]

        out = []
        for r in range(H):
            chars = []
            for c in range(W):
                m = mask[r][c]
                if m:
                    chars.append(chr(0x2800 + m))
                elif inside[r][c]:
                    chars.append(" ")
                else:
                    chars.append(" ")
            out.append("".join(chars))
        return out
