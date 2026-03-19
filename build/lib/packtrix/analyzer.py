"""
analyzer.py — Security Detection & Traffic Analysis
=====================================================
Parses packet log data (from a file path or live packet list), runs
multiple detection rules over the traffic, and prints a colour-coded
alert report to the terminal.  Alerts can optionally be exported to
JSON or CSV files for further investigation.

Detection rules implemented:
    1. Brute-force login   — Many failed auth attempts to SSH/FTP/RDP
                             from one source IP within a short window.
    2. Port scan           — One source IP probing many distinct destination
                             ports in rapid succession.
    3. Traffic spike       — Packet volume from a single source IP that
                             exceeds a rolling-average baseline by a
                             configurable multiplier.

Data flow:
    analyze_logs(logfile)
        └── _load_log(logfile)          parses file or returns placeholder
        └── _run_detections(packets)
                ├── _detect_brute_force(packets)
                ├── _detect_port_scan(packets)
                └── _detect_traffic_spike(packets)
        └── _render_alerts(alerts)      prints table to terminal
        └── _export_alerts(alerts, …)   optional CSV / JSON export

Usage (from cli.py):
    from packtrix.analyzer import analyze_logs
    alerts = analyze_logs("capture.log", export="json", export_path="out/")

Dependencies:
    dataclasses     — Alert dataclass (stdlib)
    collections     — defaultdict, Counter for per-IP aggregation (stdlib)
    csv             — CSV export (stdlib)
    json            — JSON export + log parsing (stdlib)
    pathlib         — File I/O path handling (stdlib)
    datetime        — Timestamp formatting (stdlib)
    re              — Payload pattern matching for brute-force (stdlib)
    packtrix.utils  — COMMON_PORTS, utc_now, port_service
"""

import csv
import json
import re
import sys
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from packtrix.utils import COMMON_PORTS, port_service, utc_now

# ---------------------------------------------------------------------------
# ANSI colour helpers  (stdlib only)
# ---------------------------------------------------------------------------

_RESET        = "\033[0m"
_BOLD         = "\033[1m"
_DIM          = "\033[2m"
_RED          = "\033[31m"
_GREEN        = "\033[32m"
_YELLOW       = "\033[33m"
_BLUE         = "\033[34m"
_MAGENTA      = "\033[35m"
_CYAN         = "\033[36m"
_WHITE        = "\033[97m"
_BRIGHT_BLACK = "\033[90m"
_BG_RED       = "\033[41m"
_BG_YELLOW    = "\033[43m"


def _c(text: str, *codes: str) -> str:
    """Wrap *text* with one or more ANSI escape codes and a reset suffix."""
    return "".join(codes) + str(text) + _RESET


# ---------------------------------------------------------------------------
# Severity constants & colour mapping
# ---------------------------------------------------------------------------

INFO     = "INFO"
LOW      = "LOW"
MEDIUM   = "MEDIUM"
HIGH     = "HIGH"
CRITICAL = "CRITICAL"

# Severity → (ANSI colour, sort priority where 0 is most urgent)
_SEV_META: dict[str, tuple[str, int]] = {
    CRITICAL: (_RED   + _BOLD,  0),
    HIGH:     (_RED,            1),
    MEDIUM:   (_YELLOW,         2),
    LOW:      (_GREEN,          3),
    INFO:     (_BRIGHT_BLACK,   4),
}


def _sev_colour(severity: str) -> str:
    """Return the ANSI colour string for a given severity level."""
    return _SEV_META.get(severity, (_WHITE, 99))[0]


def _sev_priority(severity: str) -> int:
    """Return the sort priority (0 = most critical) for a severity string."""
    return _SEV_META.get(severity, (_WHITE, 99))[1]


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """
    A structured security alert produced by a detection rule.

    Attributes:
        timestamp   Human-readable UTC timestamp string when the alert fired.
        alert_type  Short category label, e.g. "BRUTE_FORCE", "PORT_SCAN".
        severity    One of: INFO, LOW, MEDIUM, HIGH, CRITICAL.
        src_ip      Source IP address that triggered the alert.
        dst_ip      Destination IP, or "" when not applicable.
        dst_port    Destination port integer, or None when not applicable.
        event_count Number of matching events that triggered this alert.
        detail      Human-readable description with context.
        rule        Internal rule name that generated this alert.
    """
    timestamp:   str
    alert_type:  str
    severity:    str
    src_ip:      str
    dst_ip:      str
    dst_port:    Optional[int]
    event_count: int
    detail:      str
    rule:        str = field(default="", repr=False)

    def to_dict(self) -> dict:
        """Return alert fields as a plain dict (for JSON/CSV export)."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Detection thresholds
# (defined at module level so they are easy to tune without touching logic)
# ---------------------------------------------------------------------------

# Brute-force: minimum failed-auth events from one IP to trigger alert
BRUTE_FORCE_THRESHOLD: int = 5

# Brute-force: time window in seconds to count events within
BRUTE_FORCE_WINDOW_S: float = 60.0

# Port scan: minimum unique destination ports from one IP to trigger alert
PORT_SCAN_THRESHOLD: int = 10

# Port scan: time window in seconds for the unique-port count
PORT_SCAN_WINDOW_S: float = 10.0

# Traffic spike: minimum total packets per IP before spike detection kicks in
SPIKE_MIN_PACKETS: int = 20

# Traffic spike: multiplier above per-IP average to trigger a spike alert
SPIKE_MULTIPLIER: float = 3.0

# Ports considered high-value authentication targets for brute-force detection
BRUTE_FORCE_PORTS: set[int] = {22, 21, 23, 3389, 5900, 25, 110, 143, 3306}

# ---------------------------------------------------------------------------
# Placeholder packet generator
# ---------------------------------------------------------------------------

def _placeholder_packets() -> list[dict]:
    """
    Return a list of simulated packet dicts for testing and demonstration.

    The placeholder data deliberately contains traffic patterns that will
    trigger each detection rule:
        • Brute-force:    many SYN packets from 10.0.0.5 to port 22 (SSH)
        • Port scan:      packets from 10.0.0.99 hitting 15+ distinct ports
        • Traffic spike:  10.0.0.7 sending a burst of 60 packets

    Each dict mirrors the structure produced by sniffer.parse_packet() /
    sniffer._placeholder_stream(), so all detection logic works unchanged
    when real packet data is fed in.

    Returns:
        List of packet dicts ready to pass to _run_detections().
    """
    import random

    # Use a fixed seed for reproducible placeholder output
    random.seed(42)

    packets: list[dict] = []
    base_ts = 1_700_000_000.0   # arbitrary fixed epoch base

    def _pkt(src, dst, proto, sport, dport, flags="ACK", size=64, ts_offset=0.0):
        """Helper to construct a packet dict with all required fields."""
        return {
            "timestamp": base_ts + ts_offset,
            "src_ip":    src,
            "dst_ip":    dst,
            "protocol":  proto,
            "src_port":  sport,
            "dst_port":  dport,
            "flags":     flags,
            "size":      size,
            "service":   port_service(dport),
            "info":      f"{src}:{sport} → {dst}:{dport}  [{flags}]",
        }

    # ── Normal background traffic (mix of HTTP/HTTPS/DNS) ─────────────────
    # Provides a realistic baseline so spike detection has an average to
    # compare against.  Each of the three hosts sends ~10 packets, giving
    # a mean of ~10 pkt/IP — well below the spike host's 100 packets (10×).
    normal_hosts = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    for i in range(30):
        src  = normal_hosts[i % len(normal_hosts)]   # ~10 packets each
        dst  = random.choice(["8.8.8.8", "1.1.1.1", "151.101.1.1"])
        port = random.choice([80, 443, 53])
        packets.append(_pkt(src, dst, "TCP", 50000 + i, port,
                            flags="ACK", size=random.randint(60, 800),
                            ts_offset=random.uniform(0, 30)))

    # ── Pattern 1: Brute-force SSH (10.0.0.5 → 192.168.1.10:22) ──────────
    # 18 SYN packets to port 22 within 30 seconds simulates an attacker
    # hammering SSH credentials.  Threshold is 5 → this will fire CRITICAL.
    for i in range(18):
        packets.append(_pkt(
            src="10.0.0.5", dst="192.168.1.10",
            proto="TCP", sport=60000 + i, dport=22,
            flags="SYN", size=60,
            ts_offset=float(i * 1.5),   # one attempt every ~1.5s
        ))

    # ── Pattern 2: Port scan (10.0.0.99 → 192.168.1.1) ───────────────────
    # 20 SYN packets to 20 distinct ports within 5 seconds mirrors a fast
    # Nmap-style sweep.  Threshold is 10 unique ports → fires HIGH.
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                  443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    for i, dport in enumerate(scan_ports):
        packets.append(_pkt(
            src="10.0.0.99", dst="192.168.1.1",
            proto="TCP", sport=40000 + i, dport=dport,
            flags="SYN", size=60,
            ts_offset=float(i * 0.25),  # 4 ports/second
        ))

    # ── Pattern 3: Traffic spike (10.0.0.7) ───────────────────────────────
    # 100 packets in a short burst from one IP that otherwise sends nothing.
    # With ~10 background packets per normal host the mean sits around 15–20
    # pkt/IP, making 10.0.0.7's 100 packets ≥ 5× above mean → fires HIGH.
    for i in range(100):
        packets.append(_pkt(
            src="10.0.0.7", dst="192.168.1.50",
            proto="UDP", sport=53, dport=53,
            flags="", size=random.randint(28, 512),
            ts_offset=random.uniform(0, 3),  # 60 packets in 3 seconds
        ))

    # Sort chronologically so rolling-window logic gets events in order
    packets.sort(key=lambda p: p["timestamp"])
    return packets


# ---------------------------------------------------------------------------
# Log file parser
# ---------------------------------------------------------------------------

def _load_log(logfile: str) -> list[dict]:
    """
    Load packet data from a file path or return placeholder data.

    Supported file formats:
        .json   — array of packet dicts (as written by sniffer / logger)
        .log    — newline-delimited JSON (one packet dict per line)
        .csv    — CSV with header row matching packet dict keys
        other   — treated as newline-delimited JSON; falls back to placeholder

    If *logfile* is the special sentinel string ``"__placeholder__"`` or if
    the file is missing / unreadable, placeholder data is returned instead.

    Args:
        logfile: Path string to the log or pcap file to load.

    Returns:
        List of packet dicts ready for _run_detections().
    """
    # Special sentinel: caller explicitly requested placeholder data
    if logfile == "__placeholder__":
        print(f"{_c('[*]', _CYAN, _BOLD)} Using built-in placeholder packet data.\n")
        return _placeholder_packets()

    path = Path(logfile)

    # File existence check with a clear error message
    if not path.exists():
        print(f"{_c('[!]', _YELLOW)} File not found: {_c(logfile, _BOLD)}")
        print(f"{_c('[*]', _CYAN)} Falling back to placeholder packet data.\n")
        return _placeholder_packets()

    packets: list[dict] = []
    suffix = path.suffix.lower()

    try:
        if suffix == ".json":
            # Full JSON array: [{{...}}, {{...}}, ...]
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                packets = data
            else:
                raise ValueError("JSON file must contain a top-level array.")

        elif suffix in (".log", ".jsonl"):
            # Newline-delimited JSON: one dict per line
            with path.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        packets.append(json.loads(line))
                    except json.JSONDecodeError:
                        print(f"{_c('[!]', _YELLOW)} Skipping malformed JSON "
                              f"on line {lineno}.")

        elif suffix == ".csv":
            # CSV with a header row; numeric fields are auto-cast
            with path.open("r", newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    # Cast numeric fields that detection rules depend on
                    for key in ("timestamp", "size"):
                        if key in row:
                            try:
                                row[key] = float(row[key])
                            except (ValueError, TypeError):
                                pass
                    for key in ("src_port", "dst_port", "event_count"):
                        if key in row and row[key] not in ("", None):
                            try:
                                row[key] = int(row[key])
                            except (ValueError, TypeError):
                                pass
                    packets.append(dict(row))

        else:
            # Unknown extension — attempt newline-delimited JSON
            print(f"{_c('[!]', _YELLOW)} Unknown extension '{suffix}'; "
                  "attempting line-by-line JSON parse.")
            with path.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        packets.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass   # silently skip unparseable lines

        if not packets:
            print(f"{_c('[!]', _YELLOW)} File parsed but contained no packets. "
                  "Falling back to placeholder data.\n")
            return _placeholder_packets()

        print(f"{_c('[+]', _GREEN)} Loaded {_c(str(len(packets)), _BOLD, _GREEN)} "
              f"packets from {_c(str(path.name), _BOLD)}.\n")
        return packets

    except Exception as exc:
        print(f"{_c('[!]', _RED)} Failed to parse '{logfile}': {exc}")
        print(f"{_c('[*]', _CYAN)} Falling back to placeholder packet data.\n")
        return _placeholder_packets()


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

def _detect_brute_force(packets: list[dict]) -> list[Alert]:
    """
    Detect brute-force login attempts against authentication services.

    Strategy:
        Group SYN packets by (src_ip, dst_port) where dst_port is in the
        BRUTE_FORCE_PORTS set.  For each group, use a sliding time window of
        BRUTE_FORCE_WINDOW_S seconds: if more than BRUTE_FORCE_THRESHOLD SYN
        packets originate from the same source IP to the same auth port within
        that window, an alert is raised.

        Severity is scaled by attempt count:
            ≥ 50 → CRITICAL
            ≥ 20 → HIGH
            ≥  5 → MEDIUM

    Args:
        packets: Chronologically sorted list of packet dicts.

    Returns:
        List of Alert objects — one per (src_ip, dst_port) pair that
        exceeded the threshold.
    """
    alerts: list[Alert] = []

    # Bucket timestamps by (src_ip, dst_port) — only SYN packets on auth ports
    # {(src_ip, dst_port): [ts, ts, ...]}
    buckets: dict[tuple, list[float]] = defaultdict(list)

    for pkt in packets:
        if pkt.get("flags", "").upper() not in ("SYN", "SYN|ACK"):
            continue
        dport = pkt.get("dst_port")
        if dport not in BRUTE_FORCE_PORTS:
            continue
        src = pkt.get("src_ip", "")
        if not src:
            continue
        buckets[(src, dport)].append(float(pkt.get("timestamp", 0)))

    for (src_ip, dst_port), timestamps in buckets.items():
        timestamps.sort()

        # Sliding window: find the maximum number of events within any
        # BRUTE_FORCE_WINDOW_S-second span using a two-pointer approach.
        max_in_window = 0
        left = 0
        for right in range(len(timestamps)):
            # Advance left pointer until window fits within the threshold
            while timestamps[right] - timestamps[left] > BRUTE_FORCE_WINDOW_S:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window < BRUTE_FORCE_THRESHOLD:
            continue    # below threshold — not suspicious

        # Scale severity by how many attempts were seen
        if max_in_window >= 50:
            severity = CRITICAL
        elif max_in_window >= 20:
            severity = HIGH
        else:
            severity = MEDIUM

        service = port_service(dst_port)
        detail  = (
            f"{max_in_window} SYN attempts to {service} "
            f"(:{dst_port}) within {BRUTE_FORCE_WINDOW_S:.0f}s window"
        )

        alerts.append(Alert(
            timestamp   = utc_now(),
            alert_type  = "BRUTE_FORCE",
            severity    = severity,
            src_ip      = src_ip,
            dst_ip      = "",          # attacker may target any host on the port
            dst_port    = dst_port,
            event_count = max_in_window,
            detail      = detail,
            rule        = "detect_brute_force",
        ))

    return alerts


def _detect_port_scan(packets: list[dict]) -> list[Alert]:
    """
    Detect horizontal port scanning — one source probing many distinct ports.

    Strategy:
        For each source IP, collect (timestamp, dst_port) pairs from SYN
        packets.  Use a sliding window of PORT_SCAN_WINDOW_S seconds: if the
        number of *unique* destination ports within any window exceeds
        PORT_SCAN_THRESHOLD, a PORT_SCAN alert is raised.

        Severity is scaled by unique port count:
            ≥ 50 → CRITICAL
            ≥ 20 → HIGH
            ≥ 10 → MEDIUM

    Args:
        packets: Chronologically sorted list of packet dicts.

    Returns:
        List of Alert objects — one per source IP confirmed as a scanner.
    """
    alerts: list[Alert] = []

    # Collect (timestamp, dst_port) per source IP for SYN packets only
    # {src_ip: [(ts, port), ...]}
    syn_events: dict[str, list[tuple[float, int]]] = defaultdict(list)

    for pkt in packets:
        if pkt.get("flags", "").upper() != "SYN":
            continue
        src   = pkt.get("src_ip", "")
        dport = pkt.get("dst_port")
        ts    = float(pkt.get("timestamp", 0))
        if src and dport is not None:
            syn_events[src].append((ts, dport))

    for src_ip, events in syn_events.items():
        events.sort(key=lambda e: e[0])   # sort by timestamp

        # Sliding window: track unique ports in window using a deque
        from collections import deque
        window: deque[tuple[float, int]] = deque()
        port_set: Counter = Counter()
        max_unique = 0
        peak_dst   = None

        for ts, port in events:
            # Evict events that have fallen outside the time window
            while window and ts - window[0][0] > PORT_SCAN_WINDOW_S:
                old_ts, old_port = window.popleft()
                port_set[old_port] -= 1
                if port_set[old_port] == 0:
                    del port_set[old_port]

            window.append((ts, port))
            port_set[port] += 1

            unique_now = len(port_set)
            if unique_now > max_unique:
                max_unique = unique_now
                # Record which destination IP was being scanned at this peak
                peak_dst = None   # may be multiple targets; left blank

        if max_unique < PORT_SCAN_THRESHOLD:
            continue

        if max_unique >= 50:
            severity = CRITICAL
        elif max_unique >= 20:
            severity = HIGH
        else:
            severity = MEDIUM

        # List up to 8 of the probed ports for context in the detail string
        all_ports  = sorted({port for _, port in events})
        port_sample = ", ".join(str(p) for p in all_ports[:8])
        if len(all_ports) > 8:
            port_sample += f"… (+{len(all_ports) - 8} more)"

        detail = (
            f"{max_unique} unique ports probed within "
            f"{PORT_SCAN_WINDOW_S:.0f}s window — ports: {port_sample}"
        )

        alerts.append(Alert(
            timestamp   = utc_now(),
            alert_type  = "PORT_SCAN",
            severity    = severity,
            src_ip      = src_ip,
            dst_ip      = peak_dst or "",
            dst_port    = None,
            event_count = max_unique,
            detail      = detail,
            rule        = "detect_port_scan",
        ))

    return alerts


def _detect_traffic_spike(packets: list[dict]) -> list[Alert]:
    """
    Detect unusual per-source traffic volume spikes.

    Strategy:
        Count total packets per source IP.  Compute the mean packet count
        across all IPs (the baseline).  Flag any IP whose count exceeds
        baseline × SPIKE_MULTIPLIER, but only if it also exceeds
        SPIKE_MIN_PACKETS (to avoid false positives on small data sets).

        Additionally compute per-IP bytes to estimate bandwidth spikes.

        Severity is scaled by the spike ratio:
            ≥ 10× mean → CRITICAL
            ≥  5× mean → HIGH
            ≥  3× mean → MEDIUM

    Args:
        packets: List of packet dicts (order not important for this rule).

    Returns:
        List of Alert objects — one per source IP that exceeded the spike
        threshold.
    """
    alerts: list[Alert] = []

    # Aggregate per-IP packet count and total bytes
    pkt_count:  Counter = Counter()
    byte_count: Counter = Counter()

    for pkt in packets:
        src = pkt.get("src_ip", "")
        if not src:
            continue
        pkt_count[src]  += 1
        byte_count[src] += int(pkt.get("size", 0))

    if not pkt_count:
        return alerts

    # Baseline: mean packets per IP across all observed sources
    total_ips  = len(pkt_count)
    total_pkts = sum(pkt_count.values())
    mean_pkts  = total_pkts / total_ips

    # Need at least 3 sources to have a meaningful baseline
    if total_ips < 3:
        return alerts

    for src_ip, count in pkt_count.items():
        if count < SPIKE_MIN_PACKETS:
            continue   # too few packets for reliable detection

        ratio = count / mean_pkts if mean_pkts > 0 else 0
        if ratio < SPIKE_MULTIPLIER:
            continue   # within normal range

        if ratio >= 10:
            severity = CRITICAL
        elif ratio >= 5:
            severity = HIGH
        else:
            severity = MEDIUM

        kb     = byte_count[src_ip] / 1024
        detail = (
            f"{count} packets ({kb:.1f} KB) — "
            f"{ratio:.1f}× above per-IP average of {mean_pkts:.1f} pkts"
        )

        alerts.append(Alert(
            timestamp   = utc_now(),
            alert_type  = "TRAFFIC_SPIKE",
            severity    = severity,
            src_ip      = src_ip,
            dst_ip      = "",
            dst_port    = None,
            event_count = count,
            detail      = detail,
            rule        = "detect_traffic_spike",
        ))

    return alerts


def _run_detections(packets: list[dict]) -> list[Alert]:
    """
    Run all detection rules over *packets* and return aggregated alerts.

    Execution order
    ---------------
    1. Built-in rules always run first (brute_force, port_scan, traffic_spike).
    2. Plugin modules in ``packtrix/plugins/`` are auto-discovered and run next.
       A plugin that fails to import or raises during detection is skipped with
       a warning so one broken plugin never kills the whole analysis.

    Args:
        packets: Full list of packet dicts to analyse.

    Returns:
        Combined list of Alert objects, sorted most-critical first.
    """
    all_alerts: list[Alert] = []

    # ── 1. Built-in detection rules (always active) ───────────────────────
    _BUILTIN_RULES: list[tuple[str, callable]] = [
        ("Brute-force detection",   _detect_brute_force),
        ("Port scan detection",     _detect_port_scan),
        ("Traffic spike detection", _detect_traffic_spike),
    ]
    for label, rule_fn in _BUILTIN_RULES:
        print(f"  {_c('→', _BRIGHT_BLACK)} {label}…", end="", flush=True)
        found = rule_fn(packets)
        print(f"  {_c(str(len(found)), _BOLD, _YELLOW if found else _GREEN)} alert(s)")
        all_alerts.extend(found)

    # ── 2. Plugin discovery ───────────────────────────────────────────────
    # Scan packtrix/plugins/*.py for modules exposing detect(packets).
    # Files beginning with '_' are ignored.
    plugin_alerts = _run_plugins(packets)
    if plugin_alerts:
        all_alerts.extend(plugin_alerts)

    # Sort: most critical first; within same severity, by src_ip
    all_alerts.sort(key=lambda a: (_sev_priority(a.severity), a.src_ip))
    return all_alerts


def _run_plugins(packets: list[dict]) -> list[Alert]:
    """
    Auto-discover and execute all plugin detection modules.

    Scans the ``packtrix/plugins/`` directory for ``*.py`` files (excluding
    ``__init__.py`` and files beginning with ``_``), imports each as a module,
    and calls its ``detect(packets)`` function.

    Plugin ``detect()`` may return either:
        - A list of ``Alert`` dataclass instances, or
        - A list of plain dicts that are converted to ``Alert`` objects here.

    A plugin that raises ``ImportError`` is silently skipped (missing optional
    dependency).  Any other exception triggers a warning but does not abort the
    analysis.

    Args:
        packets: Packet list passed through to each plugin's ``detect()``.

    Returns:
        Merged list of ``Alert`` objects from all successfully-run plugins.
    """
    import importlib, pkgutil, pathlib

    alerts: list[Alert] = []
    plugins_dir = pathlib.Path(__file__).parent / "plugins"

    if not plugins_dir.is_dir():
        return alerts

    for mod_info in pkgutil.iter_modules([str(plugins_dir)]):
        name = mod_info.name
        if name.startswith("_"):
            continue   # skip __init__ and private helpers

        full_name = f"packtrix.plugins.{name}"
        try:
            mod = importlib.import_module(full_name)
        except ImportError as exc:
            # Missing optional dependency — silently skip
            print(f"  {_c('[skip]', _BRIGHT_BLACK)} plugin {name}: {exc}")
            continue
        except Exception as exc:
            print(f"  {_c('[!]', _YELLOW)} plugin {name} import error: {exc}")
            continue

        if not hasattr(mod, "detect"):
            continue  # not a valid plugin — no detect() callable

        print(f"  {_c('→', _BRIGHT_BLACK)} Plugin [{_c(name, _CYAN)}]…",
              end="", flush=True)
        try:
            raw_results = mod.detect(packets)
        except Exception as exc:
            print(f"  {_c('error', _RED)}: {exc}")
            continue

        # Normalise: accept both Alert objects and plain dicts
        plugin_alerts: list[Alert] = []
        for item in raw_results:
            if isinstance(item, Alert):
                plugin_alerts.append(item)
            elif isinstance(item, dict):
                try:
                    plugin_alerts.append(Alert(
                        timestamp   = item.get("timestamp", utc_now()),
                        alert_type  = item.get("alert_type", "UNKNOWN"),
                        severity    = item.get("severity",   "INFO"),
                        src_ip      = item.get("src_ip",     ""),
                        dst_ip      = item.get("dst_ip",     ""),
                        dst_port    = item.get("dst_port"),
                        event_count = int(item.get("event_count", 1)),
                        detail      = item.get("detail",     ""),
                        rule        = item.get("rule", name),
                    ))
                except Exception:
                    pass

        n = len(plugin_alerts)
        print(f"  {_c(str(n), _BOLD, _YELLOW if n else _GREEN)} alert(s)")
        alerts.extend(plugin_alerts)

    return alerts


# ---------------------------------------------------------------------------
# Terminal rendering
# ---------------------------------------------------------------------------

# Column widths for the alert table
_ACOL = {
    "idx":     4,
    "time":   22,
    "type":   16,
    "sev":    10,
    "src":    16,
    "port":    6,
    "count":   7,
    "detail": 55,
}


def _alert_top() -> str:
    segs = ["─" * (_ACOL[k] + 2) for k in _ACOL]
    return _c("╭" + "┬".join(segs) + "╮", _BRIGHT_BLACK)


def _alert_sep(left="├", mid="┼", right="┤") -> str:
    segs = ["─" * (_ACOL[k] + 2) for k in _ACOL]
    return _c(left + mid.join(segs) + right, _BRIGHT_BLACK)


def _alert_bot() -> str:
    segs = ["─" * (_ACOL[k] + 2) for k in _ACOL]
    return _c("╰" + "┴".join(segs) + "╯", _BRIGHT_BLACK)


def _alert_header() -> str:
    """Return the bold column-header row for the alert table."""
    sep   = _c("│", _BRIGHT_BLACK)
    cells = [
        _c(f"{'No.'    :>{_ACOL['idx']}}", _BOLD, _BRIGHT_BLACK),
        _c(f"{'Timestamp':<{_ACOL['time']}}", _BOLD, _WHITE),
        _c(f"{'Type'    :<{_ACOL['type']}}", _BOLD, _WHITE),
        _c(f"{'Severity':^{_ACOL['sev']}}", _BOLD, _WHITE),
        _c(f"{'Source IP':<{_ACOL['src']}}", _BOLD, _WHITE),
        _c(f"{'Port':>{_ACOL['port']}}", _BOLD, _WHITE),
        _c(f"{'Events':>{_ACOL['count']}}", _BOLD, _WHITE),
        _c(f"{'Detail':<{_ACOL['detail']}}", _BOLD, _WHITE),
    ]
    return sep + sep.join(f" {c} " for c in cells) + sep


def _alert_row(idx: int, alert: Alert) -> str:
    """Format a single Alert as a coloured table row string."""
    sep   = _c("│", _BRIGHT_BLACK)
    sc    = _sev_colour(alert.severity)

    # Truncate detail so the table never wraps
    detail = alert.detail
    if len(detail) > _ACOL["detail"]:
        detail = detail[:_ACOL["detail"] - 1] + "…"

    port_str = str(alert.dst_port) if alert.dst_port else "—"

    cells = [
        _c(f"{idx:>{_ACOL['idx']}}", _BRIGHT_BLACK),
        _c(f"{alert.timestamp:<{_ACOL['time']}}", _DIM),
        _c(f"{alert.alert_type:<{_ACOL['type']}}", _BOLD, sc),
        _c(f"{alert.severity:^{_ACOL['sev']}}", _BOLD, sc),
        _c(f"{alert.src_ip:<{_ACOL['src']}}", _WHITE),
        _c(f"{port_str:>{_ACOL['port']}}", _BRIGHT_BLACK),
        _c(f"{alert.event_count:>{_ACOL['count']}}", _YELLOW),
        _c(f"{detail:<{_ACOL['detail']}}", _DIM),
    ]
    return sep + sep.join(f" {c} " for c in cells) + sep


def _render_alerts(alerts: list[Alert], total_packets: int) -> None:
    """
    Print the full alert report table to stdout.

    Prints a summary line when there are no alerts so the user can confirm
    the analysis ran (it did not silently fail).

    Args:
        alerts:        Sorted list of Alert objects to display.
        total_packets: Number of packets that were analysed (for summary).
    """
    print()

    if not alerts:
        print(_c("  ✔ No security alerts detected across "
                 f"{total_packets} packets.", _BOLD, _GREEN))
        print()
        return

    title = _c(" Packtrix — Security Alert Report ", _BOLD, _WHITE)
    print(f"  {title}")
    print(_alert_top())
    print(_alert_header())
    print(_alert_sep())

    for idx, alert in enumerate(alerts, start=1):
        print(_alert_row(idx, alert))

    print(_alert_bot())

    # Per-severity count summary line below the table
    sev_counts: Counter = Counter(a.severity for a in alerts)
    parts = []
    for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
        count = sev_counts.get(sev, 0)
        if count:
            parts.append(_c(f"{count} {sev}", _BOLD, _sev_colour(sev)))
    print(f"\n  {_c('Total:', _BOLD)} {_c(str(len(alerts)), _BOLD, _WHITE)} alert(s)  "
          + "  ".join(parts))
    print()


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def _export_alerts(
    alerts:      list[Alert],
    export_fmt:  str,
    export_path: str = ".",
    filename_stem: str = "packtrix_alerts",
) -> str:
    """
    Write alert data to a JSON or CSV file.

    Args:
        alerts:       List of Alert objects to export.
        export_fmt:   "json" or "csv" (case-insensitive).
        export_path:  Directory to write the output file into.
                      Defaults to the current working directory.
        filename_stem: Base name (without extension) for the output file.

    Returns:
        Full path string of the file that was written.

    Raises:
        ValueError: If export_fmt is not "json" or "csv".
        IOError:    If the output file cannot be written.
    """
    fmt = export_fmt.lower().strip()
    if fmt not in ("json", "csv"):
        raise ValueError(f"Unsupported export format '{export_fmt}'. "
                         "Use 'json' or 'csv'.")

    out_dir  = Path(export_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{filename_stem}.{fmt}"

    alert_dicts = [a.to_dict() for a in alerts]

    if fmt == "json":
        # Write a human-readable JSON array
        with out_file.open("w", encoding="utf-8") as fh:
            json.dump(alert_dicts, fh, indent=2, default=str)

    else:
        # CSV: use Alert field names as header row
        if alert_dicts:
            fieldnames = list(alert_dicts[0].keys())
            with out_file.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(alert_dicts)
        else:
            # Write header-only CSV so the file is still valid
            with out_file.open("w", newline="", encoding="utf-8") as fh:
                fh.write("timestamp,alert_type,severity,src_ip,dst_ip,"
                         "dst_port,event_count,detail,rule\n")

    return str(out_file)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_logs(
    logfile:     str              = "__placeholder__",
    export:      Optional[str]   = None,
    export_path: str              = ".",
) -> list[Alert]:
    """
    Parse packet log data and run all security detection rules.

    This is the primary entry point called by cli.py.  It orchestrates
    four sequential phases:

        Phase 1 — Load:      read packets from *logfile* (or use placeholder).
        Phase 2 — Detect:    run brute-force, port-scan, and spike detections.
        Phase 3 — Render:    print a colour-coded alert table to the terminal.
        Phase 4 — Export:    optionally write alerts to a JSON or CSV file.

    Supported logfile formats:
        .json    — top-level array of packet dicts
        .log     — newline-delimited JSON (one packet dict per line)
        .csv     — CSV with field-name header row
        other    — attempted as newline-delimited JSON; falls back to placeholder
        (missing) — falls back to placeholder data

    Args:
        logfile:     Path to the packet log file to analyse.
                     Pass ``"__placeholder__"`` (the default) to use the
                     built-in simulated dataset.
        export:      Optional export format — ``"json"`` or ``"csv"``.
                     When None (default), no file is written.
        export_path: Directory to write the export file into.
                     Defaults to the current working directory.

    Returns:
        List of Alert objects for all detected threats, sorted most-critical
        first.  Empty list if no threats were detected.

    Raises:
        ValueError: If *export* is set to an unsupported format string.

    Example:
        >>> from packtrix.analyzer import analyze_logs
        >>> alerts = analyze_logs()                         # uses placeholder
        >>> alerts = analyze_logs("capture.log")            # real log file
        >>> alerts = analyze_logs("capture.log", export="json", export_path="reports/")
    """

    # ── Phase 1: Load packets ─────────────────────────────────────────────
    print(f"\n{_c('[*]', _CYAN, _BOLD)} Packtrix Analyzer\n")
    print(f"{_c('[*]', _CYAN)} Loading data from: "
          f"{_c(logfile if logfile != '__placeholder__' else '[placeholder]', _BOLD, _WHITE)}")

    packets = _load_log(logfile)
    print(f"{_c('[*]', _CYAN)} Packets loaded   : "
          f"{_c(str(len(packets)), _BOLD, _GREEN)}\n")

    # ── Phase 2: Run detection rules ──────────────────────────────────────
    print(f"{_c('[*]', _CYAN, _BOLD)} Running detections…")
    alerts = _run_detections(packets)

    # ── Phase 3: Render results ───────────────────────────────────────────
    _render_alerts(alerts, total_packets=len(packets))

    # ── Phase 4: Optional export ──────────────────────────────────────────
    if export:
        try:
            out_path = _export_alerts(
                alerts,
                export_fmt   = export,
                export_path  = export_path,
                filename_stem= "packtrix_alerts",
            )
            print(f"{_c('[+]', _GREEN)} Alerts exported → "
                  f"{_c(out_path, _BOLD, _CYAN)}\n")
        except (ValueError, IOError) as exc:
            print(f"{_c('[!]', _RED)} Export failed: {exc}\n")

    return alerts
