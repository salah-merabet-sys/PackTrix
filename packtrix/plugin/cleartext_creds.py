"""
cleartext_creds.py — Cleartext Credential Detection Plugin
===========================================================
Identifies packets that carry authentication credentials in plaintext —
a serious security risk on any network where traffic can be intercepted.

Protocols monitored
-------------------
    HTTP  (port 80)  — "Authorization: Basic <base64>" header
    FTP   (port 21)  — "USER <name>" and "PASS <password>" commands
    Telnet(port 23)  — any packet on port 23 flagged (inherently insecure)
    SMTP  (port 25/587) — "AUTH LOGIN" / "AUTH PLAIN" base64 credentials
    POP3  (port 110) — "USER" / "PASS" commands
    IMAP  (port 143) — "LOGIN <user> <pass>" command

Note on payload availability
-----------------------------
In placeholder mode the packet dicts don't carry a raw payload field, so
this plugin inspects ``info``, ``service``, and ``dst_port`` as a proxy.
In real Scapy mode, extend ``parse_packet()`` in sniffer.py to include a
``payload`` key and update the regexes below accordingly.

Plugin contract: exposes ``detect(packets) -> list[dict]``.
"""

import re
from datetime import datetime, timezone

# Ports where cleartext credentials are a concern
CLEARTEXT_PORTS: dict[int, str] = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 587: "SMTP-ALT",
}

# Regex patterns matched against the ``info`` or ``payload`` field
_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Authorization:\s*Basic\s+\S+",  re.I), "HTTP Basic Auth"),
    (re.compile(r"\bUSER\s+\S+",                  re.I), "FTP/POP3 USER"),
    (re.compile(r"\bPASS\s+\S+",                  re.I), "FTP/POP3 PASS"),
    (re.compile(r"\bAUTH\s+(LOGIN|PLAIN)\b",      re.I), "SMTP AUTH"),
    (re.compile(r"\bLOGIN\s+\S+\s+\S+",           re.I), "IMAP LOGIN"),
]


def detect(packets: list[dict]) -> list[dict]:
    """
    Detect cleartext credentials transmitted over insecure protocols.

    Inspects the ``info`` and ``payload`` fields of each packet for patterns
    that indicate credential data is being sent in the clear.

    Args:
        packets: List of packet dicts from the sniffer / analyzer.

    Returns:
        List of alert dicts — one per packet containing credential patterns.
        In practice this is deduplicated to one alert per (src_ip, protocol).
    """
    alerts: list[dict] = []
    now_str = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Deduplicate: only one alert per (src_ip, dst_port) pair
    seen: set[tuple] = set()

    for pkt in packets:
        dst_port = pkt.get("dst_port")
        if dst_port not in CLEARTEXT_PORTS:
            continue

        src_ip  = pkt.get("src_ip", "")
        dst_ip  = pkt.get("dst_ip", "")
        proto_name = CLEARTEXT_PORTS[dst_port]

        # Telnet is always flagged — the protocol itself is the vulnerability
        if dst_port == 23:
            key = (src_ip, dst_port)
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "timestamp":   now_str,
                    "alert_type":  "CLEARTEXT_CREDS",
                    "severity":    "HIGH",
                    "src_ip":      src_ip,
                    "dst_ip":      dst_ip,
                    "dst_port":    dst_port,
                    "event_count": 1,
                    "detail":      f"Telnet session detected ({src_ip} → {dst_ip}:23) — inherently unencrypted",
                    "rule":        "cleartext_creds",
                })
            continue

        # For other protocols, scan the info / payload text for credential patterns
        text = pkt.get("info", "") + " " + pkt.get("payload", "")
        for pattern, label in _PATTERNS:
            if pattern.search(text):
                key = (src_ip, dst_port)
                if key not in seen:
                    seen.add(key)
                    alerts.append({
                        "timestamp":   now_str,
                        "alert_type":  "CLEARTEXT_CREDS",
                        "severity":    "HIGH",
                        "src_ip":      src_ip,
                        "dst_ip":      dst_ip,
                        "dst_port":    dst_port,
                        "event_count": 1,
                        "detail":      f"{label} detected in cleartext on {proto_name} (:{dst_port})",
                        "rule":        "cleartext_creds",
                    })
                break

    return alerts
