"""
Packtrix — Terminal Cybersecurity Toolkit
==========================================
A modular network security tool for ARP scanning, port scanning,
packet sniffing, traffic analysis, and a live terminal dashboard.

Modules:
    cli        — argparse CLI entry point (4 sub-commands)
    scanner    — ARP discovery and threaded TCP port scanning
    sniffer    — Live packet capture with scrolling table display
    analyzer   — Heuristic threat detection + plugin autodiscovery
    dashboard  — Flicker-free in-place terminal dashboard
    logger     — Structured logging and JSON/CSV/TXT report export
    utils      — Shared helpers, validators, OUI table, formatters
    _display   — ANSI primitives and CursorUI in-place renderer
"""

__version__ = "0.1.4"
__author__  = "Packtrix Contributors"
__license__ = "MIT"
