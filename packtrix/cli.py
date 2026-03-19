"""
cli.py — Terminal CLI Entry Point
==================================
Handles all command-line argument parsing and dispatches user commands to
their respective Packtrix modules.  Every module import is live — no None
placeholders remain.

Commands
--------
    scan      <network> [options]    Discover hosts and scan ports
    sniff     <interface> [options]  Capture live packets on an interface
    analyze   <logfile>  [options]   Detect threats in a log / capture file
    dashboard            [options]   Launch the live terminal dashboard

Usage
-----
    python -m packtrix [command] [options]
    python -m packtrix --help

    packtrix scan      192.168.1.0/24 --ports
    packtrix sniff     wlan0 --filter tcp
    packtrix analyze   logs/access.log
    packtrix dashboard

Quick-start examples (copy-paste ready)
----------------------------------------
    # ARP discovery only (no port scan)
    packtrix scan 192.168.1.0/24

    # Discovery + common-port scan, save results as JSON
    packtrix scan 192.168.1.0/24 --ports --output results.json

    # Capture all traffic on wlan0, 100 packets
    packtrix sniff wlan0 --count 100

    # Capture only TCP traffic, save to pcap
    packtrix sniff wlan0 --filter tcp --output session.pcap

    # Analyse a log file; export JSON alert report
    packtrix analyze logs/access.log --export json

    # Analyse using built-in placeholder data (no file needed)
    packtrix analyze --demo

    # Live dashboard at 0.5-second refresh
    packtrix dashboard --interface eth0 --refresh 0.5

Module wiring
-------------
All four modules are imported at the top of main() (lazy import) so that
import errors surface as clean, actionable messages rather than tracebacks.

Dependencies:
    argparse            — CLI argument parsing (stdlib)
    pathlib             — Output path handling (stdlib)
    signal / sys        — Graceful Ctrl+C shutdown (stdlib)
    textwrap            — Formatted help strings (stdlib)
    packtrix.scanner    — scan_network(network, scan_ports)
    packtrix.sniffer    — capture_packets(interface, filter, packet_limit)
    packtrix.analyzer   — analyze_logs(logfile, export, export_path)
    packtrix.dashboard  — show_dashboard(interface, refresh_rate)
    packtrix.logger     — setup_logger, export_scan_results, export_alerts
    packtrix.utils      — ANSI helpers, validate_ip, is_valid_cidr
"""

import argparse
import os
import pathlib
import signal
import sys
import textwrap
from typing import Optional

# ---------------------------------------------------------------------------
# ANSI helpers (inline — avoids a circular import with utils on first load)
# ---------------------------------------------------------------------------

_R  = "\033[0m"
_B  = "\033[1m"
_D  = "\033[2m"
_CY = "\033[36m"
_GR = "\033[32m"
_YL = "\033[33m"
_RD = "\033[31m"
_WH = "\033[97m"
_GY = "\033[90m"


def _c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + _R


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = (
    _c(r"""
  ██████╗  █████╗  ██████╗██╗  ██╗████████╗██████╗ ██╗██╗  ██╗
  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
  ██████╔╝███████║██║     █████╔╝    ██║   ██████╔╝██║ ╚███╔╝
  ██╔═══╝ ██╔══██║██║     ██╔═██╗    ██║   ██╔══██╗██║ ██╔██╗
  ██║     ██║  ██║╚██████╗██║  ██╗   ██║   ██║  ██║██║██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
""", _CY, _B)
    + _c("  Terminal Cybersecurity Toolkit", _WH, _B)
    + "  "
    + _c("v0.1.4", _GY)
    + "\n"
    + _c("  " + "─" * 62, _GY)
    + "\n"
)

# Version string referenced by --version flag
VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Signal handler — graceful Ctrl+C across all commands
# ---------------------------------------------------------------------------

def _handle_sigint(sig, frame):           # noqa: ANN001
    """Handle SIGINT (Ctrl+C) by printing a polite exit message."""
    print(
        f"\n\n  {_c('[!]', _YL, _B)} Interrupted by user (Ctrl+C).  "
        f"Exiting Packtrix.\n"
    )
    sys.exit(0)

signal.signal(signal.SIGINT, _handle_sigint)

# ---------------------------------------------------------------------------
# Lazy module importer — surfaces import errors as tidy messages
# ---------------------------------------------------------------------------

def _import(module_path: str, func_name: str):
    """
    Lazily import *func_name* from *module_path* and return it.

    If the import fails (module missing, syntax error, missing dependency),
    print a human-readable error and exit with code 1 rather than dumping a
    raw traceback on the user.

    Args:
        module_path: Dotted module path, e.g. ``"packtrix.scanner"``.
        func_name:   Name of the callable to import from that module.

    Returns:
        The requested callable.
    """
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, func_name)
    except ImportError as exc:
        print(
            f"\n  {_c('[!]', _RD, _B)} Cannot import {_c(module_path, _WH)}: {exc}\n"
            f"  Run {_c('pip install -r requirements.txt', _CY)} to install dependencies.\n"
        )
        sys.exit(1)
    except AttributeError:
        print(
            f"\n  {_c('[!]', _RD, _B)} {_c(func_name, _WH)} not found in "
            f"{_c(module_path, _WH)}.\n"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Pre-flight validators
# ---------------------------------------------------------------------------

def _validate_network(network: str) -> None:
    """
    Exit with a clear message if *network* is not a valid CIDR string.

    Args:
        network: User-supplied subnet string.
    """
    from packtrix.utils import is_valid_cidr
    if not is_valid_cidr(network):
        print(
            f"\n  {_c('[!]', _RD, _B)} Invalid network: {_c(network, _WH)}\n"
            f"  Expected CIDR notation, e.g. {_c('192.168.1.0/24', _CY)}\n"
        )
        sys.exit(1)


def _validate_filter(filter_str: str) -> None:
    """
    Exit with a clear message if *filter_str* is not a supported protocol.

    The sniffer accepts ``tcp``, ``udp``, ``icmp``, or empty string (all).

    Args:
        filter_str: User-supplied filter expression.
    """
    allowed = {"", "tcp", "udp", "icmp"}
    if filter_str.lower() not in allowed:
        print(
            f"\n  {_c('[!]', _RD, _B)} Unsupported filter: {_c(filter_str, _WH)}\n"
            f"  Allowed values: {_c('tcp', _CY)}  {_c('udp', _CY)}  "
            f"{_c('icmp', _CY)}  (leave blank for all traffic)\n"
        )
        sys.exit(1)


def _resolve_output_fmt(filepath: str, fallback: str = "json") -> str:
    """
    Infer the export format from a file extension.

    Args:
        filepath: Output file path supplied by the user.
        fallback: Default format when the extension is unrecognised.

    Returns:
        Format string — ``"json"``, ``"csv"``, or ``"txt"``.
    """
    ext = pathlib.Path(filepath).suffix.lower()
    return {"json": "json", ".json": "json",
            ".csv": "csv",  "csv":  "csv",
            ".txt": "txt",  "txt":  "txt"}.get(ext, fallback)


# ---------------------------------------------------------------------------
# Per-command header printers
# ---------------------------------------------------------------------------

def _print_cmd_header(title: str, params: list[tuple[str, str]]) -> None:
    """
    Print a consistent two-line command header with labelled parameters.

    Example output::

        ╭─────────────────────────────────────╮
        │  ▸ Scan  │  subnet=192.168.1.0/24  │
        ╰─────────────────────────────────────╯

    Args:
        title:  Short command name, e.g. ``"Scan"``.
        params: List of (label, value) pairs to display.
    """
    pairs = "  ".join(
        f"{_c(label + ':', _GY)} {_c(str(val), _WH, _B)}"
        for label, val in params
    )
    inner = f"  {_c('▸', _CY)} {_c(title, _CY, _B)}  {_c('│', _GY)}  {pairs}  "

    # Compute visible width (strip ANSI codes)
    import re
    ansi = re.compile(r'\x1b\[[0-9;]*m')
    vis  = len(ansi.sub('', inner))
    bar  = "─" * vis

    print(_c("╭" + bar + "╮", _GY))
    print(_c("│", _GY) + inner + _c("│", _GY))
    print(_c("╰" + bar + "╯", _GY))
    print()


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> None:
    """
    Handler for: ``packtrix scan <network> [--ports] [--output FILE] [-v]``

    Runs ARP host discovery on *network*, optionally follows with a TCP
    port scan of the three common ports (22, 80, 443), then prints a
    formatted table of discovered hosts.

    If ``--output`` is given the results are also exported via
    ``logger.export_scan_results()`` — format is inferred from the file
    extension (``.json`` or ``.csv``).

    Args:
        args.network  CIDR subnet, e.g. ``"192.168.1.0/24"``
        args.ports    Flag — when True, enable port scanning
        args.output   Optional output file path (JSON or CSV)
        args.verbose  When True, log at DEBUG level
    """
    # ── Pre-flight ────────────────────────────────────────────────────────
    _validate_network(args.network)

    # ── Header ───────────────────────────────────────────────────────────
    print(BANNER)
    scan_mode = "ARP + Port Scan" if args.ports else "ARP Discovery Only"
    _print_cmd_header("Network Scan", [
        ("target",  args.network),
        ("mode",    scan_mode),
        ("output",  args.output or "—"),
    ])

    # ── Setup logger ─────────────────────────────────────────────────────
    setup_logger = _import("packtrix.logger", "setup_logger")
    log = setup_logger(
        name    = "scanner",
        verbose = args.verbose,
        log_file= ""  # console only unless --output directs to a log path
    )

    from packtrix.logger import log_event
    log_event(
        "SCAN_START", level="INFO", event_type="SCAN_START",
        detail={"network": args.network, "ports": args.ports},
        module="scanner",
    )

    # ── Execute ───────────────────────────────────────────────────────────
    scan_network = _import("packtrix.scanner", "scan_network")
    try:
        results = scan_network(args.network, scan_ports=args.ports)
    except ValueError as exc:
        print(f"\n  {_c('[!]', _RD, _B)} {exc}\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Scan error: {exc}\n")
        if args.verbose:
            raise
        sys.exit(1)

    # ── Export (optional) ─────────────────────────────────────────────────
    if args.output and results:
        _export_scan(results, args.output, args.verbose)

    # ── Summary footer ────────────────────────────────────────────────────
    host_count = len(results) if isinstance(results, (list, dict)) else 0
    log_event(
        "SCAN_COMPLETE", level="INFO", event_type="SCAN_COMPLETE",
        detail={"hosts_found": host_count},
        module="scanner",
    )


def cmd_sniff(args: argparse.Namespace) -> None:
    """
    Handler for: ``packtrix sniff <interface> [--filter PROTO] [--count N]
    [--output FILE] [-v]``

    Opens a live (placeholder) capture session on *interface*, applies an
    optional protocol filter, and streams decoded packet rows to the terminal.

    The sniffer runs until *count* packets are captured (default: unlimited)
    or the user presses Ctrl+C.

    Args:
        args.interface  Network interface name, e.g. ``"wlan0"``
        args.filter     Protocol filter: ``"tcp"``, ``"udp"``, ``"icmp"``,
                        or ``""`` for all traffic
        args.count      Stop after N packets; 0 = unlimited
        args.output     Optional ``.pcap`` output file path
        args.verbose    Enable DEBUG logging
    """
    # ── Pre-flight ────────────────────────────────────────────────────────
    filter_str = (args.filter or "").strip().lower()
    _validate_filter(filter_str)

    # ── Header ───────────────────────────────────────────────────────────
    print(BANNER)
    _print_cmd_header("Packet Sniffer", [
        ("interface", args.interface),
        ("filter",    filter_str or "all"),
        ("limit",     f"{args.count} pkts" if args.count else "unlimited"),
        ("output",    args.output or "—"),
    ])
    print(f"  {_c('[*]', _CY)} Press {_c('Ctrl+C', _WH, _B)} to stop capture.\n")

    # ── Setup logger ─────────────────────────────────────────────────────
    setup_logger = _import("packtrix.logger", "setup_logger")
    setup_logger(name="sniffer", verbose=args.verbose, log_file="")

    from packtrix.logger import log_event
    log_event(
        "CAPTURE_START", level="INFO", event_type="CAPTURE_START",
        detail={"interface": args.interface, "filter": filter_str or "all",
                "limit": args.count},
        module="sniffer",
    )

    # ── Execute ───────────────────────────────────────────────────────────
    capture_packets = _import("packtrix.sniffer", "capture_packets")
    try:
        packets = capture_packets(
            interface    = args.interface,
            filter       = filter_str or None,
            packet_limit = args.count,
            show_header  = True,
        )
    except ValueError as exc:
        # capture_packets raises ValueError for unsupported filter strings
        print(f"\n  {_c('[!]', _RD, _B)} {exc}\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Sniffer error: {exc}\n")
        if args.verbose:
            raise
        sys.exit(1)

    # ── Optional .pcap export ─────────────────────────────────────────────
    if args.output and packets:
        _export_pcap(packets, args.output, args.verbose)

    log_event(
        "CAPTURE_COMPLETE", level="INFO", event_type="CAPTURE_COMPLETE",
        detail={"packets_captured": len(packets) if packets else 0},
        module="sniffer",
    )


def cmd_analyze(args: argparse.Namespace) -> None:
    """
    Handler for: ``packtrix analyze [<logfile>] [--demo] [--export FMT]
    [--export-path DIR] [-v]``

    Reads *logfile* (JSON, NDJSON, or CSV), runs all detection rules
    (brute-force, port scan, traffic spike), and prints a colour-coded
    alert report.

    When ``--demo`` is set the built-in placeholder dataset is used so
    the command works without a real capture file.

    If ``--export`` is given alerts are written to ``--export-path`` in
    the requested format (``json`` or ``csv``).

    Args:
        args.logfile      Path to the log file, or ``None`` when ``--demo``
        args.demo         Use placeholder data instead of a file
        args.export       Export format: ``"json"`` or ``"csv"``
        args.export_path  Directory for exported alert files
        args.verbose      Enable DEBUG logging
    """
    # ── Resolve logfile target ────────────────────────────────────────────
    if args.demo or not args.logfile:
        logfile = "__placeholder__"
        source_label = "[placeholder demo data]"
    else:
        logfile = args.logfile
        source_label = logfile

    # ── Header ───────────────────────────────────────────────────────────
    print(BANNER)
    _print_cmd_header("Security Analyzer", [
        ("source",  source_label),
        ("export",  args.export or "—"),
        ("out-dir", args.export_path if args.export else "—"),
    ])

    # ── Setup logger ─────────────────────────────────────────────────────
    setup_logger = _import("packtrix.logger", "setup_logger")
    setup_logger(name="analyzer", verbose=args.verbose, log_file="")

    from packtrix.logger import log_event
    log_event(
        "ANALYZE_START", level="INFO", event_type="ANALYZE_START",
        detail={"source": source_label},
        module="analyzer",
    )

    # ── Execute ───────────────────────────────────────────────────────────
    analyze_logs = _import("packtrix.analyzer", "analyze_logs")
    try:
        alerts = analyze_logs(
            logfile     = logfile,
            export      = args.export or None,
            export_path = args.export_path,
        )
    except FileNotFoundError:
        print(f"\n  {_c('[!]', _RD, _B)} File not found: {_c(logfile, _WH)}\n"
              f"  Tip: use {_c('--demo', _CY)} to run with placeholder data.\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Analysis error: {exc}\n")
        if args.verbose:
            raise
        sys.exit(1)

    log_event(
        "ANALYZE_COMPLETE", level="INFO", event_type="ANALYZE_COMPLETE",
        detail={"alerts_raised": len(alerts)},
        module="analyzer",
    )


def cmd_dashboard(args: argparse.Namespace) -> None:
    """
    Handler for: ``packtrix dashboard [--interface IFACE] [--refresh SECS] [-v]``

    Launches the full-screen live terminal dashboard.  The dashboard occupies
    the alternate screen buffer, so normal terminal history is preserved on exit.

    Press ``q`` to quit, ``p`` to pause, ``c`` to clear alerts, ``r`` to reset
    stats.

    Args:
        args.interface  Interface name shown in the header (default ``eth0``)
        args.refresh    Redraw interval in seconds (default ``1.0``)
        args.verbose    Enable DEBUG logging
    """
    # ── Header ───────────────────────────────────────────────────────────
    print(BANNER)
    _print_cmd_header("Live Dashboard", [
        ("interface", args.interface),
        ("refresh",   f"{args.refresh}s"),
    ])
    print(
        f"  {_c('[*]', _CY)} Starting in 1 second…  "
        f"Press {_c('q', _WH, _B)} to quit, "
        f"{_c('p', _WH, _B)} to pause.\n"
    )

    # ── Setup logger ─────────────────────────────────────────────────────
    setup_logger = _import("packtrix.logger", "setup_logger")
    setup_logger(name="dashboard", verbose=args.verbose, log_file="")

    from packtrix.logger import log_event
    log_event(
        "DASHBOARD_START", level="INFO", event_type="DASHBOARD_START",
        detail={"interface": args.interface, "refresh": args.refresh},
        module="dashboard",
    )

    # Brief pause so the header is readable before the dashboard takes over
    import time
    time.sleep(1.0)

    # ── Execute ───────────────────────────────────────────────────────────
    show_dashboard = _import("packtrix.dashboard", "show_dashboard")
    try:
        show_dashboard(interface=args.interface, refresh_rate=args.refresh)
    except Exception as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Dashboard error: {exc}\n")
        if args.verbose:
            raise
        sys.exit(1)

    log_event(
        "DASHBOARD_STOP", level="INFO", event_type="DASHBOARD_STOP",
        module="dashboard",
    )


# ---------------------------------------------------------------------------
# Export helpers  (called by cmd_scan / cmd_sniff after execution)
# ---------------------------------------------------------------------------

def _export_scan(results, output_path: str, verbose: bool = False) -> None:
    """
    Export scan results to *output_path* using ``logger.export_scan_results()``.

    The export format is inferred from the file extension:
    ``.json`` → JSON,  ``.csv`` → CSV.

    Handles both the ``list[dict]`` structure returned by the current
    ``scan_network()`` and the hypothetical ``{ip: host}`` dict form so the
    function stays compatible with future refactors.

    Args:
        results:     Return value of ``scan_network()`` — list of host dicts.
        output_path: Destination file path.
        verbose:     Log the export action when True.
    """
    from packtrix.logger import export_scan_results, log_event

    # Normalise list → dict keyed by IP so export_scan_results() is satisfied
    if isinstance(results, list):
        results_dict = {h["ip"]: h for h in results if "ip" in h}
    else:
        results_dict = results

    fmt = _resolve_output_fmt(output_path, fallback="json")
    try:
        out = export_scan_results(results_dict, output_path, fmt=fmt)
        print(f"\n  {_c('[+]', _GR)} Results exported → {_c(out, _CY, _B)}\n")
        log_event(f"Scan results saved ({fmt.upper()})",
                  level="INFO", module="scanner")
    except Exception as exc:
        print(f"\n  {_c('[!]', _YL)} Export failed: {exc}\n")
        if verbose:
            raise


def _export_pcap(packets: list, output_path: str, verbose: bool = False) -> None:
    """
    Save captured packets to *output_path* via ``sniffer.save_pcap()``.

    The ``.pcap`` format requires Scapy; this function handles the ImportError
    gracefully and falls back to a JSON dump so the user always gets some output.

    Args:
        packets:     List of packet dicts from ``capture_packets()``.
        output_path: Destination file path (should end in ``.pcap``).
        verbose:     Surface Scapy errors when True.
    """
    from packtrix.logger import log_event
    try:
        save_pcap = _import("packtrix.sniffer", "save_pcap")
        save_pcap(packets, output_path)
        print(f"\n  {_c('[+]', _GR)} Capture saved → {_c(output_path, _CY, _B)}\n")
        log_event(f"Capture saved to {output_path}", level="INFO", module="sniffer")
    except SystemExit:
        # _import() calls sys.exit on failure — catch it and fall back to JSON
        import json, pathlib
        fb_path = str(pathlib.Path(output_path).with_suffix(".json"))
        with open(fb_path, "w") as fh:
            json.dump(packets, fh, indent=2, default=str)
        print(
            f"\n  {_c('[!]', _YL)} Scapy unavailable — saved as JSON instead:"
            f" {_c(fb_path, _CY)}\n"
        )
    except Exception as exc:
        print(f"\n  {_c('[!]', _YL)} Save failed: {exc}\n")
        if verbose:
            raise


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Construct and return the fully-configured top-level ``ArgumentParser``.

    Each sub-command has its own parser with detailed help text, example
    invocations in the epilog, and ``set_defaults(func=cmd_*)`` so
    ``args.func(args)`` dispatches correctly without an explicit if/elif chain.

    Returns:
        Configured ``argparse.ArgumentParser`` ready for ``parse_args()``.
    """
    # ── Top-level parser ──────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog="packtrix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Packtrix — Terminal Cybersecurity Toolkit
            ==========================================
            Scan networks, capture packets, detect threats, and monitor
            traffic in real time — all from your terminal.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              packtrix scan      192.168.1.0/24 --ports
              packtrix sniff     wlan0 --filter tcp
              packtrix analyze   logs/access.log
              packtrix analyze   --demo
              packtrix dashboard --interface eth0 --refresh 0.5

            Run `packtrix <command> --help` for per-command options.
        """),
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose / debug output.",
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        metavar="<command>",
    )

    # ── scan ──────────────────────────────────────────────────────────────
    scan_p = subparsers.add_parser(
        "scan",
        help="Discover hosts and scan ports on a subnet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Scan Command
            ============
            Phase 1 — ARP discovery: find every live host on the subnet.
            Phase 2 — (optional) TCP port scan of ports 22, 80, 443.
            Phase 3 — Vendor lookup via OUI table.
            Phase 4 — Render results as a colour-coded terminal table.

            Placeholder mode: works without root / Scapy using simulated hosts.
            Real ARP scanning requires root: sudo packtrix scan …
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # ARP discovery only
              packtrix scan 192.168.1.0/24

              # Discovery + port scan (22, 80, 443)
              packtrix scan 192.168.1.0/24 --ports

              # Save results as JSON
              packtrix scan 192.168.1.0/24 --ports --output results.json

              # Save results as CSV
              packtrix scan 192.168.1.0/24 --output results.csv
        """),
    )
    scan_p.add_argument(
        "network",
        metavar="<network>",
        help="Target subnet in CIDR notation, e.g. 192.168.1.0/24.",
    )
    scan_p.add_argument(
        "--ports",
        action="store_true",
        default=False,
        help=(
            "Enable TCP port scanning of common ports (22, 80, 443) on each "
            "discovered host. Without this flag only ARP discovery is performed."
        ),
    )
    scan_p.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write results to FILE. Format inferred from extension (.json/.csv).",
    )
    scan_p.set_defaults(func=cmd_scan)

    # ── sniff ─────────────────────────────────────────────────────────────
    sniff_p = subparsers.add_parser(
        "sniff",
        help="Capture live packets on a network interface.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Sniff Command
            =============
            Stream decoded packet information to the terminal in a live
            colour-coded table.  Each row shows timestamp, source and
            destination, protocol, service, size, TCP flags, and a brief
            summary.

            Placeholder mode: works without root / Scapy using simulated traffic.
            Real capture requires root:  sudo packtrix sniff <interface>
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # Capture all traffic on wlan0 (unlimited)
              packtrix sniff wlan0

              # Capture only TCP traffic
              packtrix sniff wlan0 --filter tcp

              # Stop after 200 UDP packets
              packtrix sniff eth0 --filter udp --count 200

              # Save 100 packets to pcap
              packtrix sniff eth0 --count 100 --output session.pcap
        """),
    )
    sniff_p.add_argument(
        "interface",
        metavar="<interface>",
        help="Network interface to capture on, e.g. eth0, wlan0.",
    )
    sniff_p.add_argument(
        "--filter",
        metavar="PROTO",
        default="",
        dest="filter",
        help=(
            "Protocol filter: tcp, udp, or icmp. "
            "Leave blank to capture all traffic."
        ),
    )
    sniff_p.add_argument(
        "--count",
        metavar="N",
        type=int,
        default=0,
        help="Stop after N packets. Default: 0 (unlimited).",
    )
    sniff_p.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Save raw capture to FILE (.pcap; falls back to JSON if Scapy unavailable).",
    )
    sniff_p.set_defaults(func=cmd_sniff)

    # ── analyze ───────────────────────────────────────────────────────────
    analyze_p = subparsers.add_parser(
        "analyze",
        help="Analyse a captured log file for security threats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Analyze Command
            ===============
            Reads a previously captured log file (JSON array, NDJSON, or CSV),
            runs three detection rules:

              • Brute-force  — many SYN attempts to SSH/FTP/RDP from one IP
              • Port scan    — one IP probing many distinct ports rapidly
              • Traffic spike — a source IP generating far more traffic than peers

            Outputs a colour-coded alert table sorted by severity.
            Use --demo to run with built-in placeholder data (no file required).
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # Analyse a real log file
              packtrix analyze logs/access.log

              # Run with built-in demo data (no file needed)
              packtrix analyze --demo

              # Analyse and export alerts as JSON
              packtrix analyze logs/capture.json --export json

              # Analyse and export alerts as CSV to a custom directory
              packtrix analyze logs/capture.log --export csv --export-path reports/
        """),
    )
    analyze_p.add_argument(
        "logfile",
        metavar="<logfile>",
        nargs="?",
        default=None,
        help=(
            "Path to the log file to analyse (.json, .log, .csv). "
            "Omit when using --demo."
        ),
    )
    analyze_p.add_argument(
        "--demo",
        action="store_true",
        default=False,
        help="Use built-in placeholder packet data instead of a file.",
    )
    analyze_p.add_argument(
        "--export",
        metavar="FMT",
        default=None,
        choices=["json", "csv"],
        dest="export",
        help="Export alerts to a file in the given format (json or csv).",
    )
    analyze_p.add_argument(
        "--export-path",
        metavar="DIR",
        default=".",
        dest="export_path",
        help="Directory to write exported alert files. Default: current directory.",
    )
    analyze_p.set_defaults(func=cmd_analyze)

    # ── dashboard ─────────────────────────────────────────────────────────
    dash_p = subparsers.add_parser(
        "dashboard",
        help="Launch the live full-screen terminal dashboard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Dashboard Command
            =================
            Renders a full-screen, auto-refreshing terminal dashboard with
            six live panels:

              • Header          — interface, uptime, pkt/s, KB/s, clock
              • Protocol chart  — TCP / UDP / ICMP / ARP bar chart
              • Top talkers     — busiest source IPs by packet count
              • Packet feed     — scrolling live packet stream
              • Alert feed      — security alerts colour-coded by severity
              • Connections     — active 4-tuple connections with age

            Keyboard shortcuts:
              q — quit    p — pause/resume    c — clear alerts    r — reset

            Placeholder mode: works without root / Scapy using simulated traffic.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # Launch on default interface (eth0), 1-second refresh
              packtrix dashboard

              # Launch on wlan0 with faster refresh
              packtrix dashboard --interface wlan0 --refresh 0.5

              # Smooth 250 ms refresh for more responsive display
              packtrix dashboard --interface eth0 --refresh 0.25
        """),
    )
    dash_p.add_argument(
        "--interface",
        metavar="IFACE",
        default="eth0",
        help="Interface name shown in the dashboard header. Default: eth0.",
    )
    dash_p.add_argument(
        "--refresh",
        metavar="SECS",
        type=float,
        default=1.0,
        help="Dashboard redraw interval in seconds. Default: 1.0.",
    )
    dash_p.set_defaults(func=cmd_dashboard)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Main entry point — invoked by ``python -m packtrix`` or the
    ``packtrix`` console script defined in ``pyproject.toml``.

    Parses CLI arguments and dispatches to the appropriate command handler.
    Prints the banner + help text when no sub-command is given.
    """
    parser = build_parser()
    args   = parser.parse_args()

    # No sub-command — show banner + help
    if args.command is None:
        print(BANNER)
        parser.print_help()
        print()
        sys.exit(0)

    # Dispatch: each subparser sets  set_defaults(func=cmd_*)
    args.func(args)


if __name__ == "__main__":
    main()
