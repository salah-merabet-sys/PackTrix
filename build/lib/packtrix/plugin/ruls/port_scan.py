"""
rules/port_scan.py — Port Scan Detection Plugin
=================================================
Detects horizontal port scanning — one source IP probing many distinct
destination ports in a short time window.

Algorithm:
    Sliding deque window over SYN packets per source IP.
    If unique destination port count within WINDOW_S seconds exceeds
    THRESHOLD, a PORT_SCAN alert is raised.

Tuning knobs:
    PortScanRule.THRESHOLD  — unique port count to trigger (default 10)
    PortScanRule.WINDOW_S   — time window in seconds       (default 10)
"""

from __future__ import annotations
from collections import defaultdict, deque, Counter
from packtrix.plugins.base import DetectionRule, AlertResult


class PortScanRule(DetectionRule):
    """Detect rapid horizontal port scanning from a single source IP."""

    name        = "PORT_SCAN"
    description = "One IP probing many distinct ports rapidly (Nmap-style sweep)."
    severity    = "HIGH"
    version     = "1.1.0"
    author      = "packtrix"

    THRESHOLD: int   = 10
    WINDOW_S:  float = 10.0

    def analyze(self, packets: list[dict]) -> list[AlertResult]:
        """
        Scan *packets* for port-scan patterns.

        Returns:
            One AlertResult per source IP confirmed as a scanner.
        """
        # Collect (timestamp, dst_port) per source IP for SYN packets
        events: dict[str, list[tuple]] = defaultdict(list)
        for pkt in packets:
            if pkt.get("flags", "").upper() != "SYN":
                continue
            src   = pkt.get("src_ip", "")
            dport = pkt.get("dst_port")
            ts    = float(pkt.get("timestamp", 0))
            if src and dport is not None:
                events[src].append((ts, dport))

        alerts: list[AlertResult] = []
        for src_ip, ev in events.items():
            ev.sort(key=lambda x: x[0])
            window: deque = deque()
            port_cnt: Counter = Counter()
            max_unique = 0

            for ts, port in ev:
                while window and ts - window[0][0] > self.WINDOW_S:
                    _, old_port = window.popleft()
                    port_cnt[old_port] -= 1
                    if port_cnt[old_port] == 0:
                        del port_cnt[old_port]
                window.append((ts, port))
                port_cnt[port] += 1
                max_unique = max(max_unique, len(port_cnt))

            if max_unique < self.THRESHOLD:
                continue

            sev = "CRITICAL" if max_unique >= 50 else ("HIGH" if max_unique >= 20 else "MEDIUM")
            all_ports  = sorted({port for _, port in ev})
            sample     = ", ".join(str(p) for p in all_ports[:8])
            if len(all_ports) > 8:
                sample += f" … (+{len(all_ports) - 8} more)"

            alerts.append(self.make_alert(
                src_ip      = src_ip,
                event_count = max_unique,
                detail      = (
                    f"{max_unique} unique ports in {self.WINDOW_S:.0f}s — "
                    f"ports: {sample}"
                ),
                severity    = sev,
            ))
        return alerts
