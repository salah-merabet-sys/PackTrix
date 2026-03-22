"""
_display.py  –  Shared terminal display primitives
===================================================
Single source of truth for every ANSI code, colour helper, and
table-drawing function used across scanner, sniffer, analyzer, and
dashboard.

Design rules (developer notes)
-------------------------------
1. No third-party deps – stdlib only.
2. Every public function returns a plain str. Nothing prints itself.
3. ANSI width is always computed via `vlen()` so coloured strings
   align correctly in fixed-width columns.
4. The cursor-control helpers in the CursorUI class are the only place
   that issue escape sequences directly to stdout.
"""

import re
import shutil
import sys
import time
from datetime import datetime

# ── Raw codes ──────────────────────────────────────────────────────────────
RST   = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RED   = "\033[31m"
GREEN = "\033[32m"
YEL   = "\033[33m"
BLUE  = "\033[34m"
MAG   = "\033[35m"
CYN   = "\033[36m"
WHT   = "\033[97m"
GRY   = "\033[90m"
BRED  = "\033[91m"
BGRN  = "\033[92m"
BYEL  = "\033[93m"
BCYN  = "\033[96m"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def c(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes with a reset suffix."""
    return "".join(codes) + str(text) + RST


def vlen(text: str) -> int:
    """Visible character count – strips ANSI codes before measuring."""
    return len(_ANSI.sub("", text))


def pad(text: str, width: int, align: str = "<") -> str:
    """
    Pad *text* to *width* visible characters.
    align: '<' left  '>' right  '^' centre

    Truncation walks character-by-character, preserving ANSI codes so
    coloured strings keep their colour after being clipped.
    """
    v = vlen(text)
    if v > width:
        target  = max(0, width - 1)
        result  = []
        visible = 0
        i       = 0
        while i < len(text):
            m = _ANSI.match(text, i)
            if m:
                result.append(m.group())
                i += len(m.group())
            else:
                if visible >= target:
                    break
                result.append(text[i])
                visible += 1
                i += 1
        return "".join(result) + RST + "\u2026"
    spaces = width - v
    if align == ">":
        return " " * spaces + text
    if align == "^":
        l = spaces // 2
        return " " * l + text + " " * (spaces - l)
    return text + " " * spaces


def bar(filled: int, total: int, width: int = 20,
        fill_col: str = CYN, empty_col: str = GRY) -> str:
    """Horizontal progress bar: ████░░░░"""
    if total <= 0:
        f = 0
    else:
        f = min(width, int(filled / total * width))
    e = width - f
    return c("█" * f, fill_col) + c("░" * e, empty_col)


def sev_colour(sev: str) -> str:
    return {
        "CRITICAL": BOLD + BRED,
        "HIGH":     RED,
        "MEDIUM":   YEL,
        "LOW":      GREEN,
        "INFO":     GRY,
    }.get(sev.upper(), WHT)


def proto_colour(proto: str) -> str:
    return {
        "TCP":   CYN,
        "UDP":   GREEN,
        "ICMP":  YEL,
        "ARP":   MAG,
    }.get(proto.upper(), GRY)


def term_size() -> tuple[int, int]:
    """(cols, rows) of the current terminal."""
    s = shutil.get_terminal_size((120, 40))
    return s.columns, s.lines


# ── Simple table builder ───────────────────────────────────────────────────

def table(rows: list[list[str]],
          headers: list[str],
          widths: list[int],
          aligns: list[str] | None = None) -> str:
    """
    Build a plain box-drawing table from lists of strings.

    rows    – list of rows; each row is a list of pre-formatted strings
    headers – column header strings (plain text, will be bolded)
    widths  – visible column width for each column
    aligns  – '<' '>' '^' per column (defaults to all '<')
    """
    if aligns is None:
        aligns = ["<"] * len(headers)

    sep_segs  = ["─" * (w + 2) for w in widths]
    top       = c("┌" + "┬".join(sep_segs) + "┐", GRY)
    mid_sep   = c("├" + "┼".join(sep_segs) + "┤", GRY)
    bot       = c("└" + "┴".join(sep_segs) + "┘", GRY)

    vbar = c("│", GRY)

    def _row(cells: list[str], bold: bool = False) -> str:
        parts = []
        for cell, w, a in zip(cells, widths, aligns):
            styled = c(pad(cell, w, a), BOLD, WHT) if bold else pad(cell, w, a)
            parts.append(f" {styled} ")
        return vbar + vbar.join(parts) + vbar

    lines = [top, _row(headers, bold=True), mid_sep]
    for row in rows:
        lines.append(_row(row))
    lines.append(bot)
    return "\n".join(lines)


# ── In-place cursor UI (used by sniffer and dashboard) ────────────────────

class CursorUI:
    """
    Manages a fixed-height in-place drawing region.

    The screen is NOT cleared on each refresh – only changed lines are
    rewritten, which eliminates flicker completely.

    Usage::

        ui = CursorUI(height=30)
        ui.enter()
        while running:
            frame = build_frame_lines()   # list[str], len == height
            ui.draw(frame)
            time.sleep(0.5)
        ui.leave()
    """

    def __init__(self, height: int):
        self._h      = height
        self._prev   = [""] * height
        self._origin = 0           # row where our region starts (0-indexed)
        self._active = False

    def enter(self) -> None:
        """Reserve vertical space and hide the cursor."""
        sys.stdout.write("\033[?25l")          # hide cursor
        sys.stdout.write("\n" * self._h)       # push down to make room
        sys.stdout.flush()
        self._prev   = [""] * self._h
        self._active = True

    def draw(self, lines: list[str]) -> None:
        """
        Redraw only the lines that changed since the last call.

        lines – exactly self._h strings (will be padded/truncated to fit)
        """
        if not self._active:
            return

        cols, _ = term_size()
        out     = []

        for i, (new, old) in enumerate(zip(lines, self._prev)):
            if new == old:
                continue
            # Move up (self._h - i) lines from current position, then CR
            out.append(f"\033[{self._h - i}A\r")
            # Write line, pad/clip to terminal width, then erase rest of line
            visible = _ANSI.sub("", new)
            if len(visible) > cols:
                new = visible[:cols - 1] + "…"
            out.append(new)
            out.append("\033[K")               # erase to end of line
            # Move back down
            out.append(f"\033[{self._h - i}B\r")

        if out:
            sys.stdout.write("".join(out))
            sys.stdout.flush()

        self._prev = list(lines)

    def leave(self) -> None:
        """Restore cursor and leave a blank line."""
        sys.stdout.write("\033[?25h")          # show cursor
        sys.stdout.write("\n")
        sys.stdout.flush()
        self._active = False

    def print_below(self, text: str) -> None:
        """Print a line below the drawing region (for status messages)."""
        sys.stdout.write(f"\r{text}\n")
        sys.stdout.flush()
