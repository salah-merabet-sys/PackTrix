"""
icmp_flood.py — ICMP Flood Detection Plugin
============================================
Detects ICMP echo (ping) floods — a common volumetric DoS technique where
an attacker sends a continuous stream of ICMP echo-request packets to exhaust
bandwidth or overwhelm a target's network stack.

Heuristic
---------
    • Filter all ICMP packets.
    • Group by source IP and count in a ICMP_WINDOW_S-second sliding window.
    • Exceeding ICMP_THRESHOLD in the window fires a HIGH alert.
    • Exceeding ICMP_CRITICAL fires CRITICAL.

Plugin contract: exposes ``detect(packets) -> list[dict]``.
"""

from collections import defaultdict
from datetime import datetime, timezone

# ── Tunable thresholds ────────────────────────────────────────────────────
ICMP_THRESHOLD: int   = 100   # ICMP packets / window → HIGH
ICMP_CRITICAL:  int   = 500   # ICMP packets / window → CRITICAL
ICMP_WINDOW_S:  float = 5.0   # sliding window width in seconds


def detect(packets: list[dict]) -> list[dict]:
    """
    Detect ICMP flood attacks from unusually high ICMP packet rates.

    Args:
        packets: List of packet dicts from the sniffer / analyzer.

    Returns:
        List of alert dicts for each source IP exceeding the threshold.
    """
    alerts: list[dict] = []

    icmp_events: dict[str, list[float]] = defaultdict(list)

    for pkt in packets:
        if pkt.get("protocol", "").upper() != "ICMP":
            continue
        src = pkt.get("src_ip", "")
        if not src:
            continue
        icmp_events[src].append(float(pkt.get("timestamp", 0)))

    now_str = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for src_ip, timestamps in icmp_events.items():
        timestamps.sort()

        max_in_window = 0
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > ICMP_WINDOW_S:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window < ICMP_THRESHOLD:
            continue

        severity = "CRITICAL" if max_in_window >= ICMP_CRITICAL else "HIGH"
        alerts.append({
            "timestamp":   now_str,
            "alert_type":  "ICMP_FLOOD",
            "severity":    severity,
            "src_ip":      src_ip,
            "dst_ip":      "",
            "dst_port":    None,
            "event_count": max_in_window,
            "detail": (
                f"{max_in_window} ICMP packets within {ICMP_WINDOW_S:.0f}s — "
                "possible ping flood / ICMP DoS attack"
            ),
            "rule": "icmp_flood",
        })

    return alerts
