"""
dashboard.py  –  Live terminal dashboard
=========================================
A flicker-free, keyboard-navigable dashboard built with the CursorUI
in-place renderer from _display.py.

How flicker is eliminated
--------------------------
We do NOT clear the screen.  CursorUI keeps track of what was drawn last
frame and only rewrites the lines that actually changed.  This means even
at a 0.5 s refresh the display is completely stable.

Layout (adapts to terminal width/height)
-----------------------------------------

  ┌──────────────────────────────────────────────────────────┐
  │  PACKTRIX  eth0  up 00:01:23  1,482 pkts  2.3 pkt/s     │  header
  ├───────────────────────────┬──────────────────────────────┤
  │  Protocol Distribution    │  Top Talkers                 │  row 1
  ├───────────────────────────┼──────────────────────────────┤
  │  Recent Packets  (scroll) │  Security Alerts             │  row 2
  ├───────────────────────────┴──────────────────────────────┤
  │  Active Connections                                       │  row 3
  └──────────────────────────────────────────────────────────┘
  [q] quit  [p] pause  [c] clear alerts  [r] reset  [↑↓] scroll feed

Keys
----
  q        quit
  p        pause / resume
  c        clear alerts
  r        reset all stats
  ↑ / k    scroll packet feed up
  ↓ / j    scroll packet feed down
"""

import os
import sys
import time
import threading
import select
import signal
from collections import Counter, deque
from datetime import datetime
from typing import Optional

from packtrix._display import (
    c, pad, vlen, bar, term_size, CursorUI,
    RST, BOLD, DIM, GRY, WHT, CYN, GREEN, YEL, MAG, RED, BRED,
    proto_colour, sev_colour,
)

# ── Shared state ───────────────────────────────────────────────────────────

def _make_state(interface: str = "eth0") -> dict:
    return {
        "proto_counts":   Counter(),
        "src_counts":     Counter(),
        "total_pkts":     0,
        "total_bytes":    0,
        "pkt_rate":       0.0,
        "byte_rate":      0.0,
        "interval_pkts":  0,
        "interval_bytes": 0,
        "interval_start": time.time(),
        "recent_pkts":    deque(maxlen=500),
        "alerts":         deque(maxlen=100),
        "connections":    {},
        "start_time":     time.time(),
        "paused":         False,
        "interface":      interface,
        "scroll":         0,      # packet feed scroll offset
    }


def _ingest_packet(state: dict, pkt: dict) -> None:
    """Update state with one new packet. Must be called under lock."""
    proto    = pkt.get("protocol", "OTHER")
    src_ip   = pkt.get("src_ip",  "?")
    src_port = pkt.get("src_port")
    dst_ip   = pkt.get("dst_ip",  "?")
    dst_port = pkt.get("dst_port")
    size     = int(pkt.get("size", 0))
    ts       = float(pkt.get("timestamp", time.time()))

    state["proto_counts"][proto] += 1
    state["src_counts"][src_ip]  += 1
    state["total_pkts"]          += 1
    state["total_bytes"]         += size
    state["interval_pkts"]       += 1
    state["interval_bytes"]      += size

    state["recent_pkts"].appendleft(pkt)

    key = (src_ip, src_port or 0, dst_ip, dst_port or 0)
    state["connections"][key] = ts

    cutoff = time.time() - 30.0
    state["connections"] = {
        k: v for k, v in state["connections"].items() if v >= cutoff
    }


def _tick_rates(state: dict) -> None:
    now     = time.time()
    elapsed = now - state["interval_start"]
    if elapsed > 0:
        state["pkt_rate"]  = state["interval_pkts"]  / elapsed
        state["byte_rate"] = state["interval_bytes"]  / elapsed
    state["interval_pkts"]  = 0
    state["interval_bytes"] = 0
    state["interval_start"] = now


# ── Background feed ────────────────────────────────────────────────────────

def _run_feed(state: dict, lock: threading.Lock, stop: threading.Event) -> None:
    """Background thread: ingest packets and run detection every 10 s."""
    from packtrix.sniffer  import _placeholder_stream
    from packtrix.analyzer import (
        _detect_brute_force, _detect_port_scan, _detect_traffic_spike,
    )

    window: list[dict] = []
    last_det = time.time()

    for pkt in _placeholder_stream():
        if stop.is_set():
            break
        with lock:
            if state["paused"]:
                time.sleep(0.1)
                continue
            _ingest_packet(state, pkt)
        window.append(pkt)

        now = time.time()
        if now - last_det >= 10.0:
            alerts = (
                _detect_brute_force(window) +
                _detect_port_scan(window)   +
                _detect_traffic_spike(window)
            )
            with lock:
                for a in alerts:
                    state["alerts"].appendleft(a)
            cutoff = now - 60.0
            window = [p for p in window if float(p.get("timestamp", 0)) >= cutoff]
            last_det = now

        time.sleep(0.05)   # keep lock free for render thread


# ── Frame builder ──────────────────────────────────────────────────────────

def _build_frame(snap: dict, cols: int, rows: int) -> list[str]:
    """
    Build a complete frame as a list of exactly *rows* strings.

    Each string is already formatted and will be written in-place.
    """
    lines: list[str] = []

    # ── Header ─────────────────────────────────────────────────────────
    uptime_s = int(time.time() - snap["start_time"])
    h, rem   = divmod(uptime_s, 3600)
    m, s     = divmod(rem, 60)
    uptime   = f"{h:02d}:{m:02d}:{s:02d}"
    total    = snap["total_pkts"]
    pkt_rate = snap["pkt_rate"]
    kb_rate  = snap["byte_rate"] / 1024
    iface    = snap["interface"]
    clock    = datetime.now().strftime("%H:%M:%S")
    paused   = "  ⏸ PAUSED" if snap["paused"] else ""

    hdr = (f"  {c('PACKTRIX', BOLD, CYN)}"
           f"  {c(iface, CYN)}"
           f"  {c('up', GRY)} {c(uptime, GREEN)}"
           f"  {c(f'{total:,}', WHT)} pkts"
           f"  {c(f'{pkt_rate:.1f}', CYN)} p/s"
           f"  {c(f'{kb_rate:.1f}', CYN)} KB/s"
           f"  {c(clock, GRY)}"
           f"{c(paused, YEL, BOLD)}")
    lines.append(hdr)
    lines.append(c("─" * cols, GRY))

    # ── Panel dimensions ────────────────────────────────────────────────
    body_rows = rows - 5   # header(2) + divider(1) + footer(2)
    half_cols = cols // 2 - 1
    left_w    = half_cols
    right_w   = cols - half_cols - 3

    row1_h    = max(6, body_rows // 3)
    row2_h    = max(6, body_rows // 3)
    row3_h    = max(3, body_rows - row1_h - row2_h)

    # ── Row 1: Protocols | Talkers ──────────────────────────────────────
    proto_lines   = _panel_proto(snap, left_w, row1_h)
    talkers_lines = _panel_talkers(snap, right_w, row1_h)
    for pl, tl in zip(proto_lines, talkers_lines):
        lines.append(
            c("│", GRY) + " " + pl + " " + c("│", GRY) + " " + tl + " " + c("│", GRY)
        )
    lines.append(c("─" * cols, GRY))

    # ── Row 2: Packet feed | Alerts ─────────────────────────────────────
    feed_lines   = _panel_feed(snap, left_w, row2_h)
    alerts_lines = _panel_alerts(snap, right_w, row2_h)
    for fl, al in zip(feed_lines, alerts_lines):
        lines.append(
            c("│", GRY) + " " + fl + " " + c("│", GRY) + " " + al + " " + c("│", GRY)
        )
    lines.append(c("─" * cols, GRY))

    # ── Row 3: Connections ──────────────────────────────────────────────
    conn_lines = _panel_connections(snap, cols - 2, row3_h)
    for cl in conn_lines:
        lines.append(c("│", GRY) + " " + cl + " " + c("│", GRY))
    lines.append(c("─" * cols, GRY))

    # ── Footer ──────────────────────────────────────────────────────────
    keys = [("[q]","quit"), ("[p]","pause"), ("[c]","clear"),
            ("[r]","reset"), ("[↑↓]","scroll")]
    footer = "  " + "   ".join(
        f"{c(k, BOLD, CYN)} {c(v, GRY)}" for k, v in keys
    )
    lines.append(footer)

    # Pad to exact height
    while len(lines) < rows:
        lines.append("")

    return lines[:rows]


# ── Panel helpers ──────────────────────────────────────────────────────────

def _fill(lines: list[str], height: int, width: int) -> list[str]:
    """Pad list to exactly *height* lines, each padded to *width* chars."""
    while len(lines) < height:
        lines.append(" " * width)
    return [pad(l, width) for l in lines[:height]]


def _panel_proto(snap: dict, width: int, height: int) -> list[str]:
    lines = [c(pad("Protocol Distribution", width, "<"), BOLD, WHT)]
    total = snap["total_pkts"] or 1
    for proto in ["TCP", "UDP", "ICMP", "ARP", "OTHER"]:
        cnt   = snap["proto_counts"].get(proto, 0)
        pct   = cnt / total * 100
        pc    = proto_colour(proto)
        b     = bar(cnt, total, width=12, fill_col=pc)
        row   = (f"{c(pad(proto, 5, '<'), BOLD, pc)}"
                 f" {b}"
                 f" {c(f'{pct:4.0f}%', DIM)}"
                 f" {c(str(cnt), WHT)}")
        lines.append(row)
    return _fill(lines, height, width)


def _panel_talkers(snap: dict, width: int, height: int) -> list[str]:
    lines = [c(pad("Top Talkers", width, "<"), BOLD, WHT)]
    top   = snap["src_counts"].most_common(height - 2)
    mx    = top[0][1] if top else 1
    for rank, (ip, cnt) in enumerate(top, 1):
        b   = bar(cnt, mx, width=10, fill_col=CYN)
        row = (f"{c(str(rank), GRY)}"
               f" {c(pad(ip, 15, '<'), WHT)}"
               f" {b}"
               f" {c(str(cnt), CYN)}")
        lines.append(row)
    if not top:
        lines.append(c("No traffic yet", GRY))
    return _fill(lines, height, width)


def _panel_feed(snap: dict, width: int, height: int) -> list[str]:
    scroll   = snap.get("scroll", 0)
    pkts     = list(snap["recent_pkts"])
    max_rows = height - 1
    window   = pkts[scroll: scroll + max_rows]

    scroll_ind = ""
    if len(pkts) > max_rows:
        pos = f"{scroll + 1}-{min(scroll + max_rows, len(pkts))}/{len(pkts)}"
        scroll_ind = f" {c(pos, GRY)}"

    title = c(pad("Recent Packets" + scroll_ind, width, "<"), BOLD, WHT)
    lines = [title]

    for pkt in window:
        proto = pkt.get("protocol", "?")
        pc    = proto_colour(proto)
        ts    = datetime.fromtimestamp(pkt.get("timestamp", time.time())).strftime("%H:%M:%S")
        src   = pkt.get("src_ip", "?")
        dst   = pkt.get("dst_ip", "?")
        dp    = pkt.get("dst_port")
        svc   = pkt.get("service", "")
        sz    = pkt.get("size", 0)
        dst_s = f"{dst}:{dp}" if dp else dst

        # Compact row that fits in half the terminal
        row = (f"{c(ts, GRY)} "
               f"{c(pad(src, 13, '<'), WHT)}"
               f"{c('>', GRY)}"
               f"{c(pad(dst_s, 18, '<'), DIM)}"
               f" {c(pad(proto, 5, '^'), BOLD, pc)}"
               f" {c(pad(svc, 8, '<'), pc)}"
               f" {c(str(sz) + 'B', DIM)}")
        lines.append(row)

    if not pkts:
        lines.append(c("Waiting for packets…", GRY))

    return _fill(lines, height, width)


def _panel_alerts(snap: dict, width: int, height: int) -> list[str]:
    alerts = list(snap["alerts"])
    count  = len(alerts)
    badge  = f" {c(str(count), BOLD, RED)}" if count else f" {c('clean', BOLD, GREEN)}"
    lines  = [c(pad(f"Alerts{badge}", width, "<"), BOLD, WHT)]

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_al = sorted(
        alerts[:height - 1],
        key=lambda a: sev_order.get(
            getattr(a, "severity", None) or
            (a.get("severity") if isinstance(a, dict) else "INFO"),
            9
        )
    )

    for alert in sorted_al:
        if isinstance(alert, dict):
            sev   = alert.get("severity",   "INFO")
            atype = alert.get("alert_type", "?")
            src   = alert.get("src_ip",     "?")
        else:
            sev   = getattr(alert, "severity",   "INFO")
            atype = getattr(alert, "alert_type", "?")
            src   = getattr(alert, "src_ip",     "?")

        sc  = sev_colour(sev)
        row = (f"{c(pad(f'[{sev[:4]}]', 7, '<'), BOLD, sc)}"
               f" {c(pad(atype, 14, '<'), sc)}"
               f" {c(pad(src, 15, '<'), WHT)}")
        lines.append(row)

    if not alerts:
        lines.append(c("No alerts", GRY))

    return _fill(lines, height, width)


def _panel_connections(snap: dict, width: int, height: int) -> list[str]:
    now   = time.time()
    conns = sorted(snap["connections"].items(), key=lambda x: -x[1])[:height - 1]
    lines = [c(pad("Active Connections", width, "<"), BOLD, WHT)]

    for (sip, sp, dip, dp), ts in conns:
        src   = f"{sip}:{sp}" if sp else sip
        dst   = f"{dip}:{dp}" if dp else dip
        age   = int(now - ts)
        age_c = GREEN if age < 10 else YEL
        row   = (f"{c(pad(src, 22, '<'), WHT)}"
                 f" {c('>', GRY)} "
                 f"{c(pad(dst, 22, '<'), DIM)}"
                 f"  {c(f'{age}s', age_c)}")
        lines.append(row)

    if not conns:
        lines.append(c("No active connections", GRY))

    return _fill(lines, height, width)


# ── Keyboard input (raw mode, non-blocking) ────────────────────────────────

class _RawTerm:
    """
    Context manager: puts stdin in raw mode for the duration of the dashboard.

    Raw mode means every keypress is delivered immediately without waiting
    for Enter, and without the terminal echoing it back.  We restore the
    original settings on exit, even on crash.

    This must be held for the *entire* dashboard session — toggling raw mode
    on and off per keypress (the old approach) causes keys to be swallowed
    by the cooked-mode line buffer while the terminal is in normal mode.
    """

    def __init__(self):
        self._fd  = None
        self._old = None
        self._ok  = False

    def __enter__(self):
        if not sys.stdin.isatty() or os.name == "nt":
            return self
        try:
            import tty, termios
            self._fd  = sys.stdin.fileno()
            self._old = termios.tcgetattr(self._fd)
            tty.setraw(self._fd)
            self._ok  = True
        except Exception:
            pass
        return self

    def __exit__(self, *_):
        if self._ok and self._old is not None:
            try:
                import termios
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
            except Exception:
                pass

    def read_key(self, timeout: float = 0.0) -> str | None:
        """
        Return one keypress (non-blocking) or None if nothing is ready.

        timeout — how many seconds to wait for a key (0 = pure non-blocking)

        Arrow keys send a 3-byte sequence: ESC [ A/B/C/D.
        We handle that by reading the follow-up bytes with a short timeout.
        """
        if not self._ok:
            return None
        try:
            r, _, _ = select.select([sys.stdin], [], [], timeout)
            if not r:
                return None
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                # Possible arrow key — read the next two bytes quickly
                r2, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r2:
                    ch2 = sys.stdin.read(1)
                    if ch2 == "[":
                        r3, _, _ = select.select([sys.stdin], [], [], 0.05)
                        if r3:
                            ch3 = sys.stdin.read(1)
                            return {"A": "UP", "B": "DOWN",
                                    "C": "RIGHT", "D": "LEFT"}.get(ch3, "ESC")
                return "ESC"
            return ch
        except Exception:
            return None


# ── Main entry point ───────────────────────────────────────────────────────

def show_dashboard(
    interface:    str   = "eth0",
    refresh_rate: float = 1.0,
) -> None:
    """
    Launch the live terminal dashboard.

    The display uses in-place line replacement so there is zero flicker —
    only changed lines are rewritten on each refresh.

    Keys: q quit  p pause  c clear alerts  r reset  ↑↓ scroll packet feed

    Args:
        interface:    NIC name shown in the header.
        refresh_rate: Seconds between redraws (min 0.2).
    """
    refresh_rate = max(0.2, float(refresh_rate))

    state = _make_state(interface=interface)
    lock  = threading.Lock()
    stop  = threading.Event()

    # Start background packet feed
    feed = threading.Thread(
        target=_run_feed, args=(state, lock, stop), daemon=True
    )
    feed.start()

    # Determine frame height
    _, rows = term_size()
    frame_h = max(20, rows - 2)

    ui = CursorUI(frame_h)
    ui.enter()

    # Intercept Ctrl+C to quit cleanly
    quit_flag = threading.Event()

    def _on_sigint(sig, frame):
        quit_flag.set()

    orig_handler = signal.signal(signal.SIGINT, _on_sigint)

    # ── Keep terminal in raw mode for the entire session ─────────────────
    # This is the critical fix for keys not working.
    # The old approach toggled raw mode on/off per keypress, meaning keys
    # pressed while the terminal was in cooked mode (during sleep) were
    # swallowed or delayed.  With _RawTerm held open for the full session,
    # every keypress reaches us immediately.
    #
    # read_key(timeout=refresh_rate) replaces the old sleep() + poll
    # pattern. It blocks for at most refresh_rate seconds waiting for a key,
    # then returns — so the loop wakes up either on a keypress or on the
    # refresh timer, whichever comes first.
    try:
        with _RawTerm() as term:
            while not quit_flag.is_set():
                cols, rows = term_size()
                frame_h    = max(20, rows - 2)

                # Snapshot state under lock
                with lock:
                    _tick_rates(state)
                    snap = {
                        **state,
                        "proto_counts": Counter(state["proto_counts"]),
                        "src_counts":   Counter(state["src_counts"]),
                        "recent_pkts":  list(state["recent_pkts"]),
                        "alerts":       list(state["alerts"]),
                        "connections":  dict(state["connections"]),
                    }

                frame  = _build_frame(snap, cols, frame_h)
                ui._h  = frame_h
                ui.draw(frame)

                # Wait up to refresh_rate seconds for a keypress.
                # Returns immediately if a key is ready.
                key = term.read_key(timeout=refresh_rate)

                if key is None:
                    continue

                k = key.lower()
                if k in ("q", "\x03", "\x04"):   # q, Ctrl+C, Ctrl+D
                    break
                elif k == "p":
                    with lock:
                        state["paused"] = not state["paused"]
                elif k == "c":
                    with lock:
                        state["alerts"].clear()
                elif k == "r":
                    with lock:
                        state["proto_counts"].clear()
                        state["src_counts"].clear()
                        state["total_pkts"]  = 0
                        state["total_bytes"] = 0
                        state["connections"] = {}
                        state["start_time"]  = time.time()
                        state["recent_pkts"].clear()
                        state["alerts"].clear()
                        state["scroll"]      = 0
                elif k in ("up", "k"):
                    with lock:
                        state["scroll"] = max(0, state["scroll"] - 1)
                elif k in ("down", "j"):
                    with lock:
                        pkts       = len(state["recent_pkts"])
                        max_scroll = max(0, pkts - 5)
                        state["scroll"] = min(max_scroll, state["scroll"] + 1)

    finally:
        stop.set()
        signal.signal(signal.SIGINT, orig_handler)
        ui.leave()
        feed.join(timeout=2.0)
        total   = state["total_pkts"]
        elapsed = int(time.time() - state["start_time"])
        print(f"  Dashboard closed. "
              f"{c(str(total), BOLD, WHT)} packets in {c(str(elapsed) + 's', CYN)}\n")
