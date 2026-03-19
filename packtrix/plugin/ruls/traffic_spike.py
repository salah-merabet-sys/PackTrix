"""
rules/traffic_spike.py — Traffic Spike / Volume Anomaly Plugin
===============================================================
Detects unusual per-source traffic volume by comparing each IP's packet
count against the cross-IP mean.  IPs that send MULTIPLIER × mean packets
and exceed MIN_PACKETS are flagged as anomalous.

Tuning knobs:
    TrafficSpikeRule.MULTIPLIER  — ratio above mean to trigger (default 3.0)
    TrafficSpikeRule.MIN_PACKETS — minimum packets before detection (default 20)
"""

from __future__ import annotations
from collections import Counter
from packtrix.plugins.base import DetectionRule, AlertResult
from packtrix.utils import human_bytes


class TrafficSpikeRule(DetectionRule):
    """Detect traffic volume spikes — one IP generating far more than peers."""

    name        = "TRAFFIC_SPIKE"
    description = "Source IP packet volume significantly exceeds the per-IP average."
    severity    = "MEDIUM"
    version     = "1.1.0"
    author      = "packtrix"

    MULTIPLIER:  float = 3.0
    MIN_PACKETS: int   = 20

    def analyze(self, packets: list[dict]) -> list[AlertResult]:
        """
        Compare per-IP packet counts against the baseline mean.

        Returns:
            One AlertResult per IP whose count exceeds MULTIPLIER × mean.
        """
        pkt_count:  Counter = Counter()
        byte_count: Counter = Counter()
        for pkt in packets:
            src = pkt.get("src_ip", "")
            if src:
                pkt_count[src]  += 1
                byte_count[src] += int(pkt.get("size", 0))

        if len(pkt_count) < 3:
            return []

        mean_pkts = sum(pkt_count.values()) / len(pkt_count)
        alerts: list[AlertResult] = []

        for src_ip, count in pkt_count.items():
            if count < self.MIN_PACKETS:
                continue
            ratio = count / mean_pkts if mean_pkts > 0 else 0
            if ratio < self.MULTIPLIER:
                continue

            sev = "CRITICAL" if ratio >= 10 else ("HIGH" if ratio >= 5 else "MEDIUM")
            alerts.append(self.make_alert(
                src_ip      = src_ip,
                event_count = count,
                detail      = (
                    f"{count} pkts ({human_bytes(byte_count[src_ip])}) — "
                    f"{ratio:.1f}× above mean of {mean_pkts:.1f} pkts/IP"
                ),
                severity    = sev,
            ))
        return alerts
