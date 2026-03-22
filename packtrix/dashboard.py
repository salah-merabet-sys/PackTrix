"""
dashboard.py  –  Live terminal dashboard
=========================================
Flicker-free, keyboard-navigable dashboard built with CursorUI.

Layout
------

  ┌──────────────────────────────────────────────────────────────┐
  │  PACKTRIX  eth0  up 00:01:23  1,482 pkts  2.3 p/s  [DEMO]   │  header
  ├──────────────────────┬───────────────────────────────────────┤
  │  Protocol Chart      │  Top Talkers                          │  row 1
  ├──────────────────────┼───────────────────────────────────────┤
  │  Recent Packets ↕    │  Security Alerts  [LIVE]              │  row 2
  ├──────────────────────┴───────────────────────────────────────┤
  │  Active Connections                                           │  row 3
  ├──────────────────────────────────────────────────────────────┤
  │  Threat Timeline  (last 60 s)                                 │  row 4 NEW
  └──────────────────────────────────────────────────────────────┘
  [q] quit  [p] pause  [c] clear  [r] reset  [↑↓] scroll  [t] threats

Keys
----
  q / Ctrl+C   quit
  p            pause / resume packet feed
  c            clear alerts
  r            reset all stats and logs
  ↑ / k        scroll packet feed up
  ↓ / j        scroll packet feed down
  t            inject a simulated threat (demo mode)

Demo mode
---------
In demo mode the dashboard simulates realistic threat scenarios
automatically — a new attack pattern fires every 20-40 seconds:
    • SSH brute-force from a single IP
    • Port scan across many destinations
    • ICMP flood / ping sweep
    • ARP spoofing attempt
    • DNS tunneling (high query rate)
    • Traffic spike from a compromised host
    • Cleartext credentials on FTP/HTTP

Each scenario injects specially crafted packets into the packet
window so the detection rules fire naturally, then adds a formatted
alert to the alerts panel — exactly as real detection would work.
"""

import os
import sys
import time
import random
import threading
import select
import signal
from collections import Counter, deque
from datetime import datetime
from typing import Optional

from packtrix._display import (
    c, pad, bar, term_size, CursorUI,
    BOLD, DIM, GRY, WHT, CYN, GREEN, YEL, MAG, RED, BRED,
    proto_colour, sev_colour,
)

# ── Simulated attacker and victim IPs ─────────────────────────────────────
_NORMAL_IPS = [
    "192.168.1.1",  "192.168.1.10", "192.168.1.42",
    "192.168.1.99", "10.0.0.5",     "8.8.8.8",
]
_ATTACKER_IPS = [
    "10.10.10.99",  "172.16.0.200", "192.168.1.254",
    "185.220.101.5", "45.33.32.156",
]
_VICTIM_IPS = [
    "192.168.1.1", "192.168.1.10", "192.168.1.42",
]


# ═══════════════════════════════════════════════════════════════════════════
# SHARED STATE
# ═══════════════════════════════════════════════════════════════════════════

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
        "threat_timeline": deque(maxlen=30),  # last 30 threat events
        "start_time":     time.time(),
        "paused":         False,
        "interface":      interface,
        "scroll":         0,
        "demo_mode":      True,   # set False when Scapy live capture active
        "threat_stats":   Counter(),   # alert_type → count
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

    # Evict stale connections
    cutoff = time.time() - 30.0
    state["connections"] = {
        k: v for k, v in state["connections"].items() if v >= cutoff
    }


def _add_alert(state: dict, alert: dict) -> None:
    """Add an alert and record it in the threat timeline. Must be under lock."""
    state["alerts"].appendleft(alert)
    state["threat_stats"][alert.get("alert_type", "UNKNOWN")] += 1
    state["threat_timeline"].appendleft({
        "ts":    time.time(),
        "type":  alert.get("alert_type", "?"),
        "sev":   alert.get("severity", "INFO"),
        "src":   alert.get("src_ip", "?"),
        "count": alert.get("event_count", 1),
    })


def _tick_rates(state: dict) -> None:
    now     = time.time()
    elapsed = now - state["interval_start"]
    if elapsed > 0:
        state["pkt_rate"]  = state["interval_pkts"]  / elapsed
        state["byte_rate"] = state["interval_bytes"]  / elapsed
    state["interval_pkts"]  = 0
    state["interval_bytes"] = 0
    state["interval_start"] = now


# ═══════════════════════════════════════════════════════════════════════════
# THREAT SIMULATION  (demo mode)
# ═══════════════════════════════════════════════════════════════════════════

def _sim_ssh_brute(attacker: str, victim: str, count: int = 25) -> tuple[list, dict]:
    """
    Simulate an SSH brute-force attack.

    Generates a burst of TCP SYN packets from *attacker* to port 22 on
    *victim*, then adds a BRUTE_FORCE alert. The packet timestamps are
    compressed into a 30-second window so the detection rule fires.
    """
    now  = time.time()
    pkts = []
    for i in range(count):
        pkts.append({
            "timestamp": now - (30 - i * 1.2),
            "src_ip":    attacker,
            "dst_ip":    victim,
            "src_port":  random.randint(49152, 65535),
            "dst_port":  22,
            "protocol":  "TCP",
            "service":   "SSH",
            "size":      random.randint(54, 80),
            "flags":     "SYN",
            "info":      f"{attacker} -> {victim}:22 [SYN]",
        })
    alert = {
        "alert_type":  "BRUTE_FORCE",
        "severity":    "CRITICAL" if count >= 20 else "HIGH",
        "src_ip":      attacker,
        "dst_ip":      victim,
        "dst_port":    22,
        "event_count": count,
        "detail":      f"{count} SYN attempts to SSH port in 30s window",
        "rule":        "demo_simulation",
    }
    return pkts, alert


def _sim_port_scan(attacker: str, victim: str, num_ports: int = 30) -> tuple[list, dict]:
    """
    Simulate a port scan.

    Generates SYN packets to many different destination ports from a
    single source IP in a short time window.
    """
    now   = time.time()
    ports = random.sample(range(1, 65536), num_ports)
    pkts  = []
    for i, port in enumerate(ports):
        pkts.append({
            "timestamp": now - (10 - i * 0.3),
            "src_ip":    attacker,
            "dst_ip":    victim,
            "src_port":  random.randint(49152, 65535),
            "dst_port":  port,
            "protocol":  "TCP",
            "service":   "unknown",
            "size":      54,
            "flags":     "SYN",
            "info":      f"{attacker} -> {victim}:{port} [SYN]",
        })
    alert = {
        "alert_type":  "PORT_SCAN",
        "severity":    "HIGH" if num_ports >= 25 else "MEDIUM",
        "src_ip":      attacker,
        "dst_ip":      victim,
        "dst_port":    None,
        "event_count": num_ports,
        "detail":      f"{num_ports} unique ports probed in 10s — range {min(ports)}-{max(ports)}",
        "rule":        "demo_simulation",
    }
    return pkts, alert


def _sim_icmp_flood(attacker: str, target: str, count: int = 120) -> tuple[list, dict]:
    """
    Simulate an ICMP flood / ping sweep.

    Generates a high-rate burst of ICMP echo requests.
    """
    now  = time.time()
    pkts = []
    for i in range(count):
        pkts.append({
            "timestamp": now - (5.0 - i * (5.0 / count)),
            "src_ip":    attacker,
            "dst_ip":    target,
            "src_port":  None,
            "dst_port":  None,
            "protocol":  "ICMP",
            "service":   "ICMP",
            "size":      random.randint(28, 84),
            "flags":     "Echo Request",
            "info":      f"{attacker} -> {target}  ICMP Echo Request",
        })
    alert = {
        "alert_type":  "ICMP_FLOOD",
        "severity":    "HIGH",
        "src_ip":      attacker,
        "dst_ip":      target,
        "dst_port":    None,
        "event_count": count,
        "detail":      f"{count} ICMP echo requests in 5s — possible ping flood or DoS",
        "rule":        "demo_simulation",
    }
    return pkts, alert


def _sim_arp_spoof(attacker: str, victim: str) -> tuple[list, dict]:
    """
    Simulate ARP spoofing (gratuitous ARP / MAC flooding).

    Generates ARP reply packets claiming the attacker's MAC for the
    victim's IP — the signature of a man-in-the-middle attack.
    """
    now   = time.time()
    # Simulate multiple ARP replies for the same IP with different MACs
    macs  = ["de:ad:be:ef:00:01", "de:ad:be:ef:00:02", "de:ad:be:ef:00:03"]
    pkts  = []
    for i, mac in enumerate(macs):
        pkts.append({
            "timestamp": now - (3 - i),
            "src_ip":    attacker,
            "dst_ip":    victim,
            "src_port":  None,
            "dst_port":  None,
            "protocol":  "ARP",
            "service":   "ARP",
            "src_mac":   mac,
            "size":      42,
            "flags":     "reply",
            "info":      f"ARP reply: {victim} is at {mac}  [{attacker}]",
        })
    alert = {
        "alert_type":  "ARP_SPOOF",
        "severity":    "HIGH",
        "src_ip":      attacker,
        "dst_ip":      victim,
        "dst_port":    None,
        "event_count": len(macs),
        "detail":      f"MAC changed {len(macs)} times for {victim} — possible MITM attack",
        "rule":        "demo_simulation",
    }
    return pkts, alert


def _sim_dns_tunnel(attacker: str, count: int = 80) -> tuple[list, dict]:
    """
    Simulate DNS tunneling — abnormally high DNS query rate.

    DNS tunneling exfiltrates data by encoding it in DNS queries.
    The key indicator is a very high query rate from a single source.
    """
    now   = time.time()
    names = [
        f"{random.randbytes(8).hex()}.tunnel.evil.com",
        f"data-{random.randint(1000, 9999)}.c2.attacker.net",
        f"{random.randbytes(6).hex()}.exfil.badactor.org",
    ]
    pkts  = []
    for i in range(count):
        pkts.append({
            "timestamp": now - (60 - i * 0.75),
            "src_ip":    attacker,
            "dst_ip":    "8.8.8.8",
            "src_port":  random.randint(49152, 65535),
            "dst_port":  53,
            "protocol":  "UDP",
            "service":   "DNS",
            "size":      random.randint(60, 180),
            "flags":     "",
            "info":      f"DNS query: {random.choice(names)}",
        })
    alert = {
        "alert_type":  "DNS_TUNNELING",
        "severity":    "MEDIUM",
        "src_ip":      attacker,
        "dst_ip":      "8.8.8.8",
        "dst_port":    53,
        "event_count": count,
        "detail":      f"{count} DNS queries in 60s from same source — possible data exfil",
        "rule":        "demo_simulation",
    }
    return pkts, alert


def _sim_traffic_spike(attacker: str, count: int = 400) -> tuple[list, dict]:
    """
    Simulate a traffic spike from a compromised host.

    One IP sends far more traffic than all others combined —
    could indicate data exfiltration, botnet C2, or a UDP flood.
    """
    now  = time.time()
    pkts = []
    for i in range(count):
        pkts.append({
            "timestamp": now - random.uniform(0, 60),
            "src_ip":    attacker,
            "dst_ip":    random.choice(["8.8.8.8", "1.1.1.1", "93.184.216.34"]),
            "src_port":  random.randint(49152, 65535),
            "dst_port":  random.choice([80, 443, 53, 8080]),
            "protocol":  random.choice(["TCP", "UDP"]),
            "service":   "unknown",
            "size":      random.randint(100, 1400),
            "flags":     "PSH|ACK",
            "info":      f"{attacker} high-volume outbound",
        })
    alert = {
        "alert_type":  "TRAFFIC_SPIKE",
        "severity":    "HIGH",
        "src_ip":      attacker,
        "dst_ip":      "",
        "dst_port":    None,
        "event_count": count,
        "detail":      f"{count} packets — {count // 10}× above per-IP average (possible exfil)",
        "rule":        "demo_simulation",
    }
    return pkts, alert


def _sim_cleartext_creds(attacker: str, server: str) -> tuple[list, dict]:
    """
    Simulate cleartext credentials on FTP or HTTP.

    Generates TCP packets with payloads containing
    plaintext authentication data.
    """
    now    = time.time()
    creds  = [
        ("FTP", 21,  "USER admin\r\nPASS password123\r\n"),
        ("HTTP", 80, "GET /admin HTTP/1.1\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n"),
    ]
    choice = random.choice(creds)
    pkts   = [{
        "timestamp": now,
        "src_ip":    attacker,
        "dst_ip":    server,
        "src_port":  random.randint(49152, 65535),
        "dst_port":  choice[1],
        "protocol":  "TCP",
        "service":   choice[0],
        "size":      len(choice[2]) + 54,
        "flags":     "PSH|ACK",
        "info":      f"{attacker} -> {server}:{choice[1]} {choice[0]} credentials",
        "payload":   choice[2].encode(),
    }]
    alert = {
        "alert_type":  "CLEARTEXT_CREDS",
        "severity":    "HIGH",
        "src_ip":      attacker,
        "dst_ip":      server,
        "dst_port":    choice[1],
        "event_count": 1,
        "detail":      f"{choice[0]} credentials sent in plaintext to {server}:{choice[1]}",
        "rule":        "demo_simulation",
    }
    return pkts, alert


# All threat scenarios in one place
_THREAT_SCENARIOS = [
    ("SSH Brute-Force",      _sim_ssh_brute),
    ("Port Scan",            _sim_port_scan),
    ("ICMP Flood",           _sim_icmp_flood),
    ("ARP Spoofing",         _sim_arp_spoof),
    ("DNS Tunneling",        _sim_dns_tunnel),
    ("Traffic Spike",        _sim_traffic_spike),
    ("Cleartext Credentials",_sim_cleartext_creds),
]


def _inject_threat(state: dict, lock: threading.Lock,
                   scenario_name: str | None = None) -> str:
    """
    Inject a simulated threat scenario into the dashboard state.

    Picks a random (or named) scenario, generates the packets and alert,
    injects them into state under the lock, and returns the scenario name.

    Args:
        state:         shared dashboard state dict
        lock:          state mutex
        scenario_name: optional name to pick a specific scenario

    Returns:
        Name of the scenario that was injected.
    """
    attacker = random.choice(_ATTACKER_IPS)
    victim   = random.choice(_VICTIM_IPS)

    # Pick scenario
    if scenario_name:
        scenarios = [s for s in _THREAT_SCENARIOS if s[0] == scenario_name]
        if not scenarios:
            scenarios = _THREAT_SCENARIOS
    else:
        scenarios = _THREAT_SCENARIOS

    name, fn = random.choice(scenarios)

    try:
        pkts, alert = fn(attacker, victim)
    except TypeError:
        # Some scenarios take 2 args, some take 3 — handle both
        pkts, alert = fn(attacker)

    with lock:
        for pkt in pkts:
            _ingest_packet(state, pkt)
        _add_alert(state, alert)

    return name


# ═══════════════════════════════════════════════════════════════════════════
# BACKGROUND FEED THREAD
# ═══════════════════════════════════════════════════════════════════════════

def _run_feed(state: dict, lock: threading.Lock,
              stop: threading.Event) -> None:
    """
    Background daemon thread.

    In demo mode:
        - Streams simulated normal traffic via _placeholder_stream()
        - Injects a threat scenario every 20-40 seconds automatically
        - Runs detection rules every 10 seconds over the packet window

    In live mode (Scapy available + root):
        - Replaces placeholder stream with real Scapy sniff()
        - Threat injection is disabled (real threats detected instead)
    """
    from packtrix.sniffer import _placeholder_stream
    from packtrix.analyzer import (
        _detect_brute_force,
        _detect_port_scan,
        _detect_traffic_spike,
    )

    # Try real Scapy capture
    use_real    = False
    pkt_queue   = None
    stop_sniff  = threading.Event()

    try:
        import os as _os
        from scapy.all import sniff as _sniff, conf as _conf  # type: ignore
        if _os.geteuid() != 0:
            raise PermissionError("root required")
        import queue as _q
        _conf.verb = 0
        pkt_queue  = _q.Queue()
        use_real   = True

        def _cb(pkt):
            from packtrix.sniffer import parse_packet
            pkt_queue.put(parse_packet(pkt))

        threading.Thread(
            target=_sniff,
            kwargs={
                "iface":       state["interface"],
                "prn":         _cb,
                "store":       False,
                "stop_filter": lambda _: stop_sniff.is_set(),
            },
            daemon=True,
        ).start()

        with lock:
            state["demo_mode"] = False

    except (ImportError, PermissionError):
        pass   # fall through to demo mode
    except Exception:
        pass

    # Demo mode setup
    sim_gen          = None if use_real else _placeholder_stream()
    detection_window : list[dict] = []
    last_det         = time.time()
    last_threat      = time.time()
    threat_interval  = random.uniform(20, 40)   # first threat in 20-40 s

    import queue as _q2

    while not stop.is_set():
        # ── Get next packet ───────────────────────────────────────────
        if use_real:
            try:
                pkt = pkt_queue.get(timeout=0.15)
            except _q2.Empty:
                pkt = None
        else:
            result_q: _q2.Queue = _q2.Queue(1)

            def _advance():
                try:
                    result_q.put(("ok", next(sim_gen)))
                except StopIteration:
                    result_q.put(("stop", None))

            threading.Thread(target=_advance, daemon=True).start()
            pkt = None
            deadline = time.time() + 0.5
            while pkt is None and not stop.is_set() and time.time() < deadline:
                try:
                    status, val = result_q.get(timeout=0.1)
                    if status == "stop":
                        stop.set()
                    else:
                        pkt = val
                except _q2.Empty:
                    continue

        if pkt is None or stop.is_set():
            continue

        with lock:
            if state["paused"]:
                time.sleep(0.1)
                continue
            _ingest_packet(state, pkt)

        detection_window.append(pkt)

        now = time.time()

        # ── Run detection rules every 10 s ────────────────────────────
        if now - last_det >= 10.0:
            new_alerts = (
                _detect_brute_force(detection_window) +
                _detect_port_scan(detection_window)   +
                _detect_traffic_spike(detection_window)
            )
            with lock:
                for a in new_alerts:
                    alert_d = {
                        "alert_type":  getattr(a, "alert_type",  a.get("alert_type",  "?")),
                        "severity":    getattr(a, "severity",    a.get("severity",    "INFO")),
                        "src_ip":      getattr(a, "src_ip",      a.get("src_ip",      "?")),
                        "dst_ip":      getattr(a, "dst_ip",      a.get("dst_ip",      "")),
                        "dst_port":    getattr(a, "dst_port",    a.get("dst_port",    None)),
                        "event_count": getattr(a, "event_count", a.get("event_count", 1)),
                        "detail":      getattr(a, "detail",      a.get("detail",      "")),
                        "rule":        getattr(a, "rule",        a.get("rule",        "detector")),
                    }
                    _add_alert(state, alert_d)

            cutoff = now - 60.0
            detection_window = [
                p for p in detection_window
                if float(p.get("timestamp", 0)) >= cutoff
            ]
            last_det = now

        # ── Auto-inject threat in demo mode ───────────────────────────
        if state["demo_mode"] and (now - last_threat) >= threat_interval:
            _inject_threat(state, lock)
            last_threat     = now
            threat_interval = random.uniform(20, 40)   # next threat in 20-40 s

        time.sleep(0.05)

    if use_real:
        stop_sniff.set()


# ═══════════════════════════════════════════════════════════════════════════
# FRAME BUILDER
# ═══════════════════════════════════════════════════════════════════════════

def _build_frame(snap: dict, cols: int, rows: int) -> list[str]:
    """Build the complete display frame as a list of exactly *rows* strings."""
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
    demo_badge = f"  {c('[DEMO]', YEL, BOLD)}" if snap["demo_mode"] else \
                 f"  {c('[LIVE]', GREEN, BOLD)}"
    alert_ct = len(snap["alerts"])
    alert_badge = (f"  {c(f'⚠ {alert_ct}', RED, BOLD)}"
                   if alert_ct else "")

    hdr = (f"  {c('PACKTRIX', BOLD, CYN)}"
           f"  {c(iface, CYN)}"
           f"  {c('up', GRY)} {c(uptime, GREEN)}"
           f"  {c(f'{total:,}', WHT)} pkts"
           f"  {c(f'{pkt_rate:.1f}', CYN)} p/s"
           f"  {c(f'{kb_rate:.1f}', CYN)} KB/s"
           f"  {c(clock, GRY)}"
           f"{demo_badge}"
           f"{alert_badge}"
           f"{c(paused, YEL, BOLD)}")
    lines.append(hdr)
    lines.append(c("─" * cols, GRY))

    # ── Panel dimensions ────────────────────────────────────────────────
    body_rows = max(4, rows - 7)   # header(2) + 3 dividers + footer(2)
    half_cols = cols // 2 - 1
    left_w    = half_cols
    right_w   = cols - half_cols - 3

    # Distribute rows: proto+talkers 30%, feed+alerts 35%, conns 15%, timeline 20%
    row1_h    = max(5,  int(body_rows * 0.28))
    row2_h    = max(5,  int(body_rows * 0.35))
    row3_h    = max(3,  int(body_rows * 0.15))
    row4_h    = max(3,  body_rows - row1_h - row2_h - row3_h)

    # ── Row 1: Protocol chart | Top talkers ─────────────────────────────
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

    # ── Row 3: Active connections ────────────────────────────────────────
    conn_lines = _panel_connections(snap, cols - 2, row3_h)
    for cl in conn_lines:
        lines.append(c("│", GRY) + " " + cl + " " + c("│", GRY))
    lines.append(c("─" * cols, GRY))

    # ── Row 4: Threat timeline (new) ────────────────────────────────────
    tl_lines = _panel_timeline(snap, cols - 2, row4_h)
    for tl in tl_lines:
        lines.append(c("│", GRY) + " " + tl + " " + c("│", GRY))
    lines.append(c("─" * cols, GRY))

    # ── Footer ──────────────────────────────────────────────────────────
    keys = [("[q]","quit"), ("[p]","pause"), ("[c]","clear"),
            ("[r]","reset"), ("[↑↓]","scroll"), ("[t]","threat")]
    footer = "  " + "   ".join(
        f"{c(k, BOLD, CYN)} {c(v, GRY)}" for k, v in keys
    )
    lines.append(footer)

    # Pad to exact height
    while len(lines) < rows:
        lines.append("")

    return lines[:rows]


# ═══════════════════════════════════════════════════════════════════════════
# PANEL HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _fill(lines: list[str], height: int, width: int) -> list[str]:
    """Pad list to exactly *height* lines, each visible-padded to *width*."""
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
    lines    = [c(pad("Top Talkers", width, "<"), BOLD, WHT)]
    top      = snap["src_counts"].most_common(height - 2)
    mx       = top[0][1] if top else 1
    # Mark attacker IPs in red
    attacker_set = set(_ATTACKER_IPS)
    for rank, (ip, cnt) in enumerate(top, 1):
        b      = bar(cnt, mx, width=10, fill_col=CYN)
        ip_col = RED if ip in attacker_set else WHT
        threat = c(" ⚠", RED) if ip in attacker_set else ""
        row    = (f"{c(str(rank), GRY)}"
                  f" {c(pad(ip, 15, '<'), ip_col)}"
                  f" {b}"
                  f" {c(str(cnt), CYN)}"
                  f"{threat}")
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
        pos = f"{scroll+1}-{min(scroll+max_rows, len(pkts))}/{len(pkts)}"
        scroll_ind = f" {c(pos, GRY)}"

    title = c(pad("Recent Packets" + scroll_ind, width, "<"), BOLD, WHT)
    lines = [title]

    attacker_set = set(_ATTACKER_IPS)
    for pkt in window:
        proto = pkt.get("protocol", "?")
        pc    = proto_colour(proto)
        ts    = datetime.fromtimestamp(
            pkt.get("timestamp", time.time())
        ).strftime("%H:%M:%S")
        src   = pkt.get("src_ip", "?")
        dst   = pkt.get("dst_ip", "?")
        dp    = pkt.get("dst_port")
        svc   = pkt.get("service", "")
        sz    = pkt.get("size", 0)
        dst_s = f"{dst}:{dp}" if dp else dst

        # Highlight attack traffic in red
        src_col = RED if src in attacker_set else WHT
        row = (f"{c(ts, GRY)} "
               f"{c(pad(src, 13, '<'), src_col)}"
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
    source = c("[DEMO]", YEL) if snap["demo_mode"] else c("[LIVE]", GREEN)
    badge  = f" {c(str(count), BOLD, RED)}" if count else f" {c('clean', BOLD, GREEN)}"
    title  = c(pad(f"Alerts{badge}", width - 8, "<"), BOLD, WHT) + f" {source}"
    lines  = [title]

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_al = sorted(
        alerts[:height - 1],
        key=lambda a: sev_order.get(
            a.get("severity", "INFO") if isinstance(a, dict)
            else getattr(a, "severity", "INFO"),
            9
        )
    )

    for alert in sorted_al:
        if isinstance(alert, dict):
            sev    = alert.get("severity",   "INFO")
            atype  = alert.get("alert_type", "?")
            src    = alert.get("src_ip",     "?")
            detail = alert.get("detail",     "")
        else:
            sev    = getattr(alert, "severity",   "INFO")
            atype  = getattr(alert, "alert_type", "?")
            src    = getattr(alert, "src_ip",     "?")
            detail = getattr(alert, "detail",     "")

        sc  = sev_colour(sev)
        # Truncate detail to fit
        short_detail = detail[:max(0, width - 38)]
        row = (f"{c(pad(f'[{sev[:4]}]', 7, '<'), BOLD, sc)}"
               f" {c(pad(atype[:13], 13, '<'), sc)}"
               f" {c(pad(src, 14, '<'), WHT)}"
               f" {c(short_detail, DIM)}")
        lines.append(row)

    if not alerts:
        lines.append(c("No alerts  —  threats will appear here", GRY))

    return _fill(lines, height, width)


def _panel_connections(snap: dict, width: int, height: int) -> list[str]:
    now   = time.time()
    conns = sorted(snap["connections"].items(), key=lambda x: -x[1])[:height - 1]
    lines = [c(pad("Active Connections", width, "<"), BOLD, WHT)]

    attacker_set = set(_ATTACKER_IPS)
    for (sip, sp, dip, dp), ts in conns:
        src    = f"{sip}:{sp}" if sp else sip
        dst    = f"{dip}:{dp}" if dp else dip
        age    = int(now - ts)
        age_c  = GREEN if age < 10 else YEL
        src_c  = RED if sip in attacker_set else WHT
        row    = (f"{c(pad(src, 22, '<'), src_c)}"
                  f" {c('>', GRY)} "
                  f"{c(pad(dst, 22, '<'), DIM)}"
                  f"  {c(f'{age}s', age_c)}")
        lines.append(row)

    if not conns:
        lines.append(c("No active connections", GRY))

    return _fill(lines, height, width)


def _panel_timeline(snap: dict, width: int, height: int) -> list[str]:
    """
    Threat timeline panel — shows the last N threat events as a mini log.

    Each entry shows: time · severity colour dot · alert type · source IP · count.
    Also shows the threat type distribution as a compact summary line.
    """
    timeline = list(snap["threat_timeline"])
    stats    = snap["threat_stats"]

    # Title with summary counts
    if stats:
        top_types = stats.most_common(3)
        summary   = "  ".join(
            f"{c(t[:8], sev_colour('HIGH'))}:{c(str(n), WHT)}"
            for t, n in top_types
        )
        title = c(pad("Threat Timeline", 16, "<"), BOLD, WHT) + "  " + summary
    else:
        title = c(pad("Threat Timeline  (threats will auto-fire in demo mode)", width, "<"), GRY)

    lines = [title]

    max_events = height - 1
    for event in timeline[:max_events]:
        ts    = datetime.fromtimestamp(event["ts"]).strftime("%H:%M:%S")
        sev   = event["sev"]
        atype = event["type"]
        src   = event["src"]
        cnt   = event["count"]
        sc    = sev_colour(sev)

        dot   = c("●", sc)
        row   = (f"{c(ts, GRY)}"
                 f" {dot}"
                 f" {c(pad(atype[:14], 14, '<'), sc)}"
                 f"  {c(pad(src, 15, '<'), WHT)}"
                 f"  {c(f'×{cnt}', DIM)}")
        lines.append(row)

    if not timeline:
        lines.append(c("No threats recorded yet", GRY))

    return _fill(lines, height, width)


# ═══════════════════════════════════════════════════════════════════════════
# KEYBOARD INPUT
# ═══════════════════════════════════════════════════════════════════════════

class _RawTerm:
    """
    Context manager: holds stdin in raw mode for the full dashboard session.

    Raw mode delivers every keypress immediately without waiting for Enter.
    Toggling raw mode per keypress (old approach) caused keys to be
    swallowed while the terminal was briefly in cooked mode.
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
        """Block up to *timeout* seconds for a keypress, return None if none."""
        if not self._ok:
            return None
        try:
            r, _, _ = select.select([sys.stdin], [], [], timeout)
            if not r:
                return None
            ch = sys.stdin.read(1)
            if ch == "\x1b":
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


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

def show_dashboard(
    interface:    str   = "eth0",
    refresh_rate: float = 1.0,
) -> None:
    """
    Launch the live terminal dashboard.

    Flicker-free in-place rendering — only lines that changed are rewritten
    on each refresh cycle.

    In demo mode, threat scenarios fire automatically every 20-40 seconds
    so all panels fill with realistic data immediately. Press [t] to inject
    a threat manually at any time.

    Keys
    ----
    q / Ctrl+C   quit
    p            pause / resume
    c            clear alerts
    r            reset all stats
    ↑ / k        scroll packet feed up
    ↓ / j        scroll packet feed down
    t            inject a random threat scenario (demo mode)

    Args:
        interface:    NIC name shown in header.
        refresh_rate: Seconds between redraws (min 0.2).
    """
    refresh_rate = max(0.2, float(refresh_rate))

    state = _make_state(interface=interface)
    lock  = threading.Lock()
    stop  = threading.Event()

    feed = threading.Thread(
        target=_run_feed, args=(state, lock, stop), daemon=True
    )
    feed.start()

    _, rows = term_size()
    frame_h = max(24, rows - 2)

    ui = CursorUI(frame_h)
    ui.enter()

    quit_flag = threading.Event()

    def _on_sigint(sig, frame):
        quit_flag.set()

    orig_handler = signal.signal(signal.SIGINT, _on_sigint)

    try:
        with _RawTerm() as term:
            while not quit_flag.is_set():
                cols, rows = term_size()
                frame_h    = max(24, rows - 2)

                with lock:
                    _tick_rates(state)
                    snap = {
                        **state,
                        "proto_counts":    Counter(state["proto_counts"]),
                        "src_counts":      Counter(state["src_counts"]),
                        "recent_pkts":     list(state["recent_pkts"]),
                        "alerts":          list(state["alerts"]),
                        "connections":     dict(state["connections"]),
                        "threat_timeline": list(state["threat_timeline"]),
                        "threat_stats":    Counter(state["threat_stats"]),
                    }

                frame  = _build_frame(snap, cols, frame_h)
                ui._h  = frame_h
                ui.draw(frame)

                key = term.read_key(timeout=refresh_rate)

                if key is None:
                    continue

                k = key.lower()

                if k in ("q", "\x03", "\x04"):
                    break
                elif k == "p":
                    with lock:
                        state["paused"] = not state["paused"]
                elif k == "c":
                    with lock:
                        state["alerts"].clear()
                        state["threat_timeline"].clear()
                        state["threat_stats"].clear()
                elif k == "r":
                    with lock:
                        state["proto_counts"].clear()
                        state["src_counts"].clear()
                        state["total_pkts"]    = 0
                        state["total_bytes"]   = 0
                        state["connections"]   = {}
                        state["start_time"]    = time.time()
                        state["recent_pkts"].clear()
                        state["alerts"].clear()
                        state["threat_timeline"].clear()
                        state["threat_stats"].clear()
                        state["scroll"]        = 0
                elif k in ("up", "k"):
                    with lock:
                        state["scroll"] = max(0, state["scroll"] - 1)
                elif k in ("down", "j"):
                    with lock:
                        pkts       = len(state["recent_pkts"])
                        max_scroll = max(0, pkts - 5)
                        state["scroll"] = min(max_scroll, state["scroll"] + 1)
                elif k == "t":
                    # Manual threat injection
                    name = _inject_threat(state, lock)
                    # Brief visual feedback — next render will show the alert

    finally:
        stop.set()
        signal.signal(signal.SIGINT, orig_handler)
        ui.leave()
        feed.join(timeout=2.0)
        total   = state["total_pkts"]
        elapsed = int(time.time() - state["start_time"])
        alerts  = len(state["threat_stats"])
        print(f"  Dashboard closed. "
              f"{c(str(total), BOLD, WHT)} packets  "
              f"{c(str(sum(state['threat_stats'].values())), BOLD, RED)} threats  "
              f"in {c(str(elapsed) + 's', CYN)}\n")
