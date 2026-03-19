"""
rules/arp_spoof.py — ARP Spoofing / Cache Poisoning Plugin
============================================================
Detects ARP cache poisoning by tracking a trusted IP→MAC mapping table
and alerting when a new ARP reply assigns a different MAC to a known IP.

This is a stateful rule: the first ARP reply seen for each IP is trusted
and recorded.  Subsequent replies with a different source MAC are flagged.

Note: reset() clears the trusted table so repeated analyze() calls on
the same packet list produce the same result.
"""

from __future__ import annotations
from packtrix.plugins.base import DetectionRule, AlertResult


class ArpSpoofRule(DetectionRule):
    """Detect ARP cache poisoning by tracking IP→MAC binding conflicts."""

    name        = "ARP_SPOOF"
    description = "ARP reply assigns a different MAC to a previously known IP."
    severity    = "CRITICAL"
    version     = "1.0.0"
    author      = "packtrix"

    def reset(self) -> None:
        """Clear the trusted IP→MAC table."""
        self._arp_table: dict[str, str] = {}

    def analyze(self, packets: list[dict]) -> list[AlertResult]:
        """
        Scan *packets* for conflicting ARP replies.

        Returns:
            One AlertResult per detected MAC conflict.
        """
        if not hasattr(self, "_arp_table"):
            self._arp_table = {}

        alerts: list[AlertResult] = []
        for pkt in packets:
            if pkt.get("protocol", "").upper() != "ARP":
                continue
            # ARP reply info is often encoded in the info field
            # Real Scapy packets expose psrc/hwsrc; placeholder uses src_ip/info
            src_ip  = pkt.get("src_ip", "")
            src_mac = pkt.get("src_mac", "")   # populated by real Scapy parser

            if not src_ip or not src_mac:
                continue

            known_mac = self._arp_table.get(src_ip)
            if known_mac is None:
                self._arp_table[src_ip] = src_mac
            elif known_mac != src_mac:
                alerts.append(self.make_alert(
                    src_ip      = src_ip,
                    event_count = 1,
                    detail      = (
                        f"IP {src_ip} was {known_mac} — "
                        f"now claims MAC {src_mac}"
                    ),
                ))
                # Update table to track latest claim
                self._arp_table[src_ip] = src_mac
        return alerts
