"""
dns_tunneling.py — DNS Tunneling Detection Plugin
==================================================
Detects potential DNS tunneling by flagging source IPs that send an
unusually large number of DNS queries in a short window, which is the
hallmark of data-exfiltration tools that encode payloads in DNS labels
(e.g. iodine, dns2tcp, dnscat2).

Heuristic
---------
    • Filter all UDP packets on port 53 (DNS).
    • Group by source IP and count queries in a 60-second sliding window.
    • Any source exceeding DNS_QUERY_THRESHOLD queries in that window fires
      a MEDIUM alert; exceeding DNS_QUERY_CRITICAL fires HIGH.

Tuning
------
    Adjust DNS_QUERY_THRESHOLD and DNS_QUERY_CRITICAL at the top of this file.
    Legitimate resolvers (caching forwarders, stub resolvers with many clients)
    may generate high query rates — add known-good IPs to DNS_WHITELIST.

Plugin contract: exposes ``detect(packets) -> list[dict]``.
"""

from collections import defaultdict
from datetime import datetime, timezone

# ── Tunable thresholds ────────────────────────────────────────────────────
DNS_QUERY_THRESHOLD: int  = 50    # queries / 60 s → MEDIUM
DNS_QUERY_CRITICAL:  int  = 200   # queries / 60 s → HIGH
DNS_WINDOW_S:        float = 60.0  # sliding window width

# IPs that should never trigger this rule (e.g. your caching resolver)
DNS_WHITELIST: set[str] = set()


def detect(packets: list[dict]) -> list[dict]:
    """
    Detect potential DNS tunneling from unusually high DNS query rates.

    Args:
        packets: List of packet dicts from the sniffer / analyzer.

    Returns:
        List of alert dicts for each flagged source IP.
    """
    alerts: list[dict] = []

    # Collect (timestamp, src_ip) for every DNS query packet
    # DNS = UDP on port 53
    dns_events: dict[str, list[float]] = defaultdict(list)

    for pkt in packets:
        if pkt.get("protocol", "").upper() != "UDP":
            continue
        if int(pkt.get("dst_port") or 0) != 53:
            continue
        src = pkt.get("src_ip", "")
        if not src or src in DNS_WHITELIST:
            continue
        dns_events[src].append(float(pkt.get("timestamp", 0)))

    now_str = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for src_ip, timestamps in dns_events.items():
        timestamps.sort()

        # Sliding-window: find max queries in any DNS_WINDOW_S span
        max_in_window = 0
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > DNS_WINDOW_S:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window < DNS_QUERY_THRESHOLD:
            continue

        severity = "HIGH" if max_in_window >= DNS_QUERY_CRITICAL else "MEDIUM"
        alerts.append({
            "timestamp":   now_str,
            "alert_type":  "DNS_TUNNELING",
            "severity":    severity,
            "src_ip":      src_ip,
            "dst_ip":      "",
            "dst_port":    53,
            "event_count": max_in_window,
            "detail": (
                f"{max_in_window} DNS queries within {DNS_WINDOW_S:.0f}s — "
                "possible data exfiltration via DNS tunneling"
            ),
            "rule": "dns_tunneling",
        })

    return alerts
