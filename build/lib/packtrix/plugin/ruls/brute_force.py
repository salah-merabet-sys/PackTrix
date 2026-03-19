"""
rules/brute_force.py — Brute-Force Login Detection Plugin
===========================================================
Detects rapid repeated SYN connections to authentication services
(SSH, FTP, RDP, Telnet, VNC, IMAP, POP3) from a single source IP,
characteristic of automated credential-stuffing or dictionary attacks.

Algorithm:
    Two-pointer sliding window over SYN packets to auth ports.
    If ≥ THRESHOLD distinct attempts land within WINDOW_S seconds,
    an alert is raised.  Severity scales with attempt count.

Tuning knobs (override after import):
    BruteForceRule.THRESHOLD  — min attempts to trigger (default 5)
    BruteForceRule.WINDOW_S   — time window in seconds  (default 60)
    BruteForceRule.AUTH_PORTS — set of ports considered auth targets
"""

from __future__ import annotations
from collections import defaultdict
from packtrix.plugins.base import DetectionRule, AlertResult
from packtrix.utils import port_service


class BruteForceRule(DetectionRule):
    """Detect brute-force login attempts against authentication services."""

    name        = "BRUTE_FORCE"
    description = "Repeated SYN attempts to auth ports (SSH/FTP/RDP/…) from one IP."
    severity    = "HIGH"
    version     = "1.1.0"
    author      = "packtrix"

    # Tuning constants — override on the instance if needed
    THRESHOLD:  int   = 5
    WINDOW_S:   float = 60.0
    AUTH_PORTS: set   = {22, 21, 23, 3389, 5900, 25, 110, 143, 3306, 5432, 6379}

    def analyze(self, packets: list[dict]) -> list[AlertResult]:
        """
        Scan *packets* for brute-force patterns and return alerts.

        Args:
            packets: Chronologically sorted packet dicts.

        Returns:
            One AlertResult per (src_ip, dst_port) pair that exceeded the threshold.
        """
        # Bucket SYN timestamps by (src_ip, dst_port)
        buckets: dict[tuple, list[float]] = defaultdict(list)

        for pkt in packets:
            if pkt.get("flags", "").upper() not in ("SYN", "SYN|ACK"):
                continue
            dport = pkt.get("dst_port")
            if dport not in self.AUTH_PORTS:
                continue
            src = pkt.get("src_ip", "")
            if src:
                buckets[(src, dport)].append(float(pkt.get("timestamp", 0)))

        alerts: list[AlertResult] = []
        for (src_ip, dst_port), timestamps in buckets.items():
            timestamps.sort()
            max_in_window = _sliding_window_max(timestamps, self.WINDOW_S)
            if max_in_window < self.THRESHOLD:
                continue

            if max_in_window >= 50:
                sev = "CRITICAL"
            elif max_in_window >= 20:
                sev = "HIGH"
            else:
                sev = "MEDIUM"

            service = port_service(dst_port)
            alerts.append(self.make_alert(
                src_ip      = src_ip,
                event_count = max_in_window,
                detail      = (
                    f"{max_in_window} SYN attempts to {service} (:{dst_port}) "
                    f"within {self.WINDOW_S:.0f}s window"
                ),
                dst_port    = dst_port,
                severity    = sev,
            ))

        return alerts


def _sliding_window_max(timestamps: list[float], window: float) -> int:
    """Return the maximum count of timestamps within any *window*-second span."""
    if not timestamps:
        return 0
    left = 0
    max_count = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1
        max_count = max(max_count, right - left + 1)
    return max_count
