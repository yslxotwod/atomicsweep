#!/usr/bin/env python3
"""Render the TUI headlessly and dump its screen.

Why this exists: a curses interface is the easiest thing in a project to break
without noticing, because a broken one still exits 0 and prints nothing. This
runs the real `tui.py` under a real pty at a fixed size, feeds it keystrokes, and
paints the output through a terminal emulator so the result can be asserted on.

    tools/tui_shot.py                 # dashboard, 120x40
    tools/tui_shot.py --keys '\n'     # enter the filter panel
    tools/tui_shot.py --keys '\n\n'   # ... and launch
"""

from __future__ import annotations

import argparse
import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time

import pyte

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def render(keys=b"", cols=120, rows=40, settle=1.2, total=3.0, args=()):
    screen = pyte.Screen(cols, rows)
    stream = pyte.ByteStream(screen)
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.environ["LINES"] = str(rows)
        os.environ["COLUMNS"] = str(cols)
        os.environ["ESCDELAY"] = "25"
        os.chdir(HERE)
        try:
            os.execvp(sys.executable, [sys.executable, os.path.join(HERE, "tui.py"), *args])
        finally:
            os._exit(127)

    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    start = time.time()
    sent = False
    sent_at = 0.0
    while time.time() - start < total:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            stream.feed(data)
        if keys and not sent and time.time() - start > settle:
            os.write(fd, keys)
            sent = True
            sent_at = time.time()
        if sent and time.time() - sent_at > settle * 0.8:
            break
    try:
        os.write(fd, b"q")
        time.sleep(0.1)
        os.write(fd, b"q")
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass
    return screen.display

def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys", default="")
    ap.add_argument("--cols", type=int, default=120)
    ap.add_argument("--rows", type=int, default=40)
    ap.add_argument("--settle", type=float, default=1.2)
    ap.add_argument("--total", type=float, default=3.5)
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    keys = a.keys.encode().decode("unicode_escape").encode()
    for i, line in enumerate(render(keys, a.cols, a.rows, a.settle, a.total, a.args)):
        print(f"{i:02d}|{line.rstrip()}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
