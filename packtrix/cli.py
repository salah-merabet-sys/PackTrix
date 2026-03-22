"""
cli.py — Terminal CLI Entry Point
===================================
Argument parsing and command dispatch for all Packtrix sub-commands.

Commands
--------
    scan      <network> [options]    Host discovery + multi-type port scanning
    sniff     <interface> [options]  Live packet capture with deep inspection
    analyze   [logfile]  [options]   Threat detection and alert reporting
    dashboard            [options]   Live terminal dashboard

New scan options (v0.1.4)
--------------------------
    --scan-type  syn|connect|fin|null|xmas|udp   choose scan technique
    --os         OS fingerprinting per host
    --services   deep service version detection
    --udp        UDP port scan
    --ports-list custom comma-separated port list
    --traceroute trace route to each discovered host
    --icmp       ICMP ping sweep instead of ARP

New sniff options (v0.1.4)
---------------------------
    --deep       HTTP / DNS / TLS / ARP-spoof layer-7 inspection
    --bpf        full BPF filter expression (e.g. 'tcp port 80')
    --duration   background capture for N seconds then exit

Usage
-----
    packtrix scan      192.168.1.0/24 --ports
    packtrix scan      192.168.1.0/24 --ports --scan-type syn --os --services
    packtrix sniff     eth0 --filter tcp --deep
    packtrix sniff     eth0 --bpf "tcp port 443 and host 192.168.1.1"
    packtrix analyze   logs/capture.json --export json
    packtrix analyze   --demo
    packtrix dashboard --interface eth0 --refresh 0.5
"""

import argparse
import os
import pathlib
import signal
import sys
import textwrap
from typing import Optional

# ── ANSI helpers (inline — avoids circular import with utils on first load) ──
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


# ── Banner ────────────────────────────────────────────────────────────────
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
    + "  " + _c("v0.1.4", _GY)
    + "\n"
    + _c("  " + "─" * 62, _GY)
    + "\n"
)

VERSION = "0.1.4"

# ── Signal handler ────────────────────────────────────────────────────────
def _handle_sigint(sig, frame):
    print(f"\n\n  {_c('[!]', _YL, _B)} Interrupted.  Exiting Packtrix.\n")
    sys.exit(0)

signal.signal(signal.SIGINT, _handle_sigint)


# ── Lazy importer ─────────────────────────────────────────────────────────
def _import(module_path: str, func_name: str):
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, func_name)
    except ImportError as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Cannot import {_c(module_path, _WH)}: {exc}\n"
              f"  Run {_c('pip install -r requirements.txt', _CY)} to install.\n")
        sys.exit(1)
    except AttributeError:
        print(f"\n  {_c('[!]', _RD, _B)} {_c(func_name, _WH)} not found in "
              f"{_c(module_path, _WH)}.\n")
        sys.exit(1)


# ── Pre-flight validators ─────────────────────────────────────────────────
def _validate_network(network: str) -> None:
    from packtrix.utils import is_valid_cidr
    if not is_valid_cidr(network):
        print(f"\n  {_c('[!]', _RD, _B)} Invalid network: {_c(network, _WH)}\n"
              f"  Expected CIDR e.g. {_c('192.168.1.0/24', _CY)}\n")
        sys.exit(1)


def _validate_filter(filter_str: str) -> None:
    allowed = {"", "tcp", "udp", "icmp", "arp", "dns"}
    if filter_str.lower() not in allowed:
        print(f"\n  {_c('[!]', _RD, _B)} Unsupported filter: {_c(filter_str, _WH)}\n"
              f"  Allowed: tcp  udp  icmp  arp  dns  (blank = all)\n"
              f"  For complex filters use {_c('--bpf', _CY)}: "
              f"e.g. --bpf \"tcp port 443\"\n")
        sys.exit(1)


def _resolve_output_fmt(filepath: str, fallback: str = "json") -> str:
    ext = pathlib.Path(filepath).suffix.lower()
    return {".json": "json", ".csv": "csv", ".txt": "txt"}.get(ext, fallback)


def _parse_ports(ports_str: str) -> list[int]:
    """Parse '22,80,443,8000-8010' into a sorted list of ints."""
    ports: set[int] = set()
    for token in ports_str.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            lo, hi = token.split("-", 1)
            ports.update(range(int(lo.strip()), int(hi.strip()) + 1))
        else:
            ports.add(int(token))
    return sorted(ports)


# ── Command header printer ────────────────────────────────────────────────
def _print_cmd_header(title: str, params: list[tuple[str, str]]) -> None:
    import re
    ansi = re.compile(r'\x1b\[[0-9;]*m')
    pairs = "  ".join(
        f"{_c(label + ':', _GY)} {_c(str(val), _WH, _B)}"
        for label, val in params
    )
    inner = f"  {_c('▸', _CY)} {_c(title, _CY, _B)}  {_c('│', _GY)}  {pairs}  "
    vis   = len(ansi.sub('', inner))
    bar   = "─" * vis
    print(_c("╭" + bar + "╮", _GY))
    print(_c("│", _GY) + inner + _c("│", _GY))
    print(_c("╰" + bar + "╯", _GY))
    print()



# ── Scan demo mode ────────────────────────────────────────────────────────

def _run_scan_demo(network: str = "192.168.1.0/24") -> None:
    """
    Run a full visible pipeline using simulated hosts — no root or Scapy needed.

    Shows every scan type and feature in sequence with real terminal output
    so you can see exactly what each command produces.
    """
    import time
    from packtrix.scanner import (
        arp_scan, connect_scan, syn_scan, fin_scan,
        null_scan, xmas_scan, udp_scan,
        os_fingerprint, service_detect, traceroute,
        lookup_vendor, _print_host_table, _print_port_table,
        COMMON_SCAN,
    )

    print(f"\n  {_c('DEMO MODE', _YL, _B)}  {_c('Simulated hosts — no root or Scapy needed', _GY)}")
    print(f"  {_c('─' * 56, _GY)}\n")

    demo_ip = "192.168.1.10"   # single target for per-host demos

    # ── 1. ARP discovery ─────────────────────────────────────────────
    print(f"  {_c('[1/8]', _GY)} {_c('ARP Discovery', _CY, _B)}  "
          f"{_c('(finds all live hosts via ARP broadcast)', _GY)}")
    print(f"  {_c('Command:', _GY)} {_c(f'packtrix scan {network}', _WH)}\n")
    hosts = arp_scan(network)
    for h in hosts:
        h["vendor"]   = lookup_vendor(h.get("mac", ""))
        h["ports"]    = []
        h["udp_ports"]= []
        h["os"]       = ""
    _print_host_table(hosts, False, 0.1)
    time.sleep(0.3)

    # ── 2. TCP connect scan (no root) ─────────────────────────────────
    print(f"  {_c('[2/8]', _GY)} {_c('TCP Connect Scan', _CY, _B)}  "
          f"{_c('(full handshake — no root needed)', _GY)}")
    print(f"  {_c('Command:', _GY)} {_c(f'packtrix scan {network} --ports --scan-type connect', _WH)}\n")
    r = connect_scan(demo_ip, [22, 80, 443, 8080, 3306, 5432])
    _print_port_table(demo_ip, r, "CONNECT")
    time.sleep(0.3)

    # ── 3. TCP SYN scan ───────────────────────────────────────────────
    print(f"  {_c('[3/8]', _GY)} {_c('TCP SYN Stealth Scan', _CY, _B)}  "
          f"{_c('(half-open — needs root + Scapy in live mode)', _GY)}")
    print(f"  {_c('Command:', _GY)} {_c(f'packtrix scan {network} --ports --scan-type syn', _WH)}\n")
    r = syn_scan(demo_ip, [22, 80, 443, 8080])
    _print_port_table(demo_ip, r, "SYN")
    time.sleep(0.3)

    # ── 4. FIN scan ───────────────────────────────────────────────────
    print(f"  {_c('[4/8]', _GY)} {_c('TCP FIN Evasion Scan', _CY, _B)}  "
          f"{_c('(bypasses stateless firewalls — needs root + Scapy)', _GY)}")
    print(f"  {_c('Command:', _GY)} {_c(f'packtrix scan {network} --ports --scan-type fin', _WH)}\n")
    r = fin_scan(demo_ip, [22, 80, 443])
    _print_port_table(demo_ip, r, "FIN")
    time.sleep(0.3)

    # ── 5. NULL scan ──────────────────────────────────────────────────
    print(f"  {_c('[5/8]', _GY)} {_c('TCP NULL Evasion Scan', _CY, _B)}  "
          f"{_c('(no flags set — RFC 793 evasion)', _GY)}")
    print(f"  {_c('Command:', _GY)} {_c(f'packtrix scan {network} --ports --scan-type null', _WH)}\n")
    r = null_scan(demo_ip, [22, 80, 443])
    _print_port_table(demo_ip, r, "NULL")
    time.sleep(0.3)

    # ── 6. XMAS scan ──────────────────────────────────────────────────
    print(f"  {_c('[6/8]', _GY)} {_c('TCP XMAS Evasion Scan', _CY, _B)}  "
          f"{_c('(FIN+PSH+URG — named for lit-up flags)', _GY)}")
    print(f"  {_c('Command:', _GY)} {_c(f'packtrix scan {network} --ports --scan-type xmas', _WH)}\n")
    r = xmas_scan(demo_ip, [22, 80, 443])
    _print_port_table(demo_ip, r, "XMAS")
    time.sleep(0.3)

    # ── 7. OS fingerprint ─────────────────────────────────────────────
    print(f"  {_c('[7/8]', _GY)} {_c('OS Fingerprinting', _CY, _B)}  "
          f"{_c('(TTL + TCP window heuristics — needs root + Scapy in live mode)', _GY)}")
    print(f"  {_c('Command:', _GY)} {_c(f'packtrix scan {network} --ports --os', _WH)}\n")
    fp = os_fingerprint(demo_ip)
    print(f"  {_c('Target     ', _GY)}  {_c(demo_ip, _WH)}")
    print(f"  {_c('OS         ', _GY)}  {_c(fp.get('os', 'Unknown'), _WH)}")
    print(f"  {_c('Confidence ', _GY)}  {_c(fp.get('confidence', 'low'), _GY)}")
    print(f"  {_c('TTL        ', _GY)}  {_c(str(fp.get('ttl', 0)), _GY)}")
    print(f"  {_c('TCP Window ', _GY)}  {_c(str(fp.get('window', 0)), _GY)}\n")
    time.sleep(0.3)

    # ── 8. Service detection ──────────────────────────────────────────
    print(f"  {_c('[8/8]', _GY)} {_c('Service Version Detection', _CY, _B)}  "
          f"{_c('(banner grab + protocol probe)', _GY)}")
    print(f"  {_c('Command:', _GY)} {_c(f'packtrix scan {network} --ports --services', _WH)}\n")
    for port in [22, 80, 443, 3306]:
        svc = service_detect(demo_ip, port)
        state_col = _GR if svc["state"] == "open" else _GY
        banner    = (svc.get("banner") or svc.get("version") or "—")[:50]
        print(f"  {_c(f'{port:>5}', _WH)}/TCP"
              f"  {_c(svc['state'], state_col)}"
              f"  {_c(svc['service'][:10], _CY)}"
              f"  {_c(banner, _GY)}")
    print()

    # ── Summary ───────────────────────────────────────────────────────
    print(_c("  ─" * 30, _GY))
    print(f"  {_c('Demo complete.', _WH, _B)}")
    print(f"  Use {_c('sudo packtrix scan', _CY)} for real ARP/SYN/OS results.")
    print(f"  Use {_c('pip install \"packtrix[live]\"', _CY)} to install Scapy.\n")


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

def cmd_scan(args: argparse.Namespace) -> None:
    """
    Handler for: packtrix scan <network> [options]

    Orchestrates the full discovery pipeline:
        ARP sweep → vendor lookup → (ICMP sweep) → (OS fingerprint)
        → (TCP port scan) → (UDP scan) → (service detect) → (traceroute)

    All Scapy-dependent features fall back to demo data when Scapy
    is not installed or root is not available.
    """
    _validate_network(args.network)

    # Parse custom port list if provided
    custom_ports = None
    if args.ports_list:
        try:
            custom_ports = _parse_ports(args.ports_list)
        except ValueError as e:
            print(f"\n  {_c('[!]', _RD, _B)} Invalid port list: {e}\n")
            sys.exit(1)

    # Build feature summary for header
    features = []
    if args.ports:        features.append(f"TCP {args.scan_type.upper()}")
    if args.udp:          features.append("UDP")
    if args.os:           features.append("OS detect")
    if args.services:     features.append("service detect")
    if args.icmp:         features.append("ICMP sweep")
    if args.traceroute:   features.append("traceroute")

    print(BANNER)
    _print_cmd_header("Network Scan", [
        ("target",   args.network),
        ("features", " · ".join(features) if features else "ARP only"),
        ("output",   args.output or "—"),
    ])

    scan_network = _import("packtrix.scanner", "scan_network")

    # Demo mode: run every scan type in sequence on simulated hosts
    if getattr(args, "scan_demo", False):
        _run_scan_demo(args.network)
        return

    try:
        results = scan_network(
            network      = args.network,
            scan_ports   = args.ports,
            scan_type    = args.scan_type,
            do_os        = args.os,
            do_services  = args.services,
            do_udp       = args.udp,
            do_icmp      = args.icmp,
            custom_ports = custom_ports,
        )
    except ValueError as exc:
        print(f"\n  {_c('[!]', _RD, _B)} {exc}\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Scan error: {exc}\n")
        if args.verbose:
            raise
        sys.exit(1)

    # Traceroute (optional, per discovered host)
    if args.traceroute and results:
        traceroute = _import("packtrix.scanner", "traceroute")
        for host in results[:5]:   # cap at 5 hosts to avoid very long output
            print(f"\n  {_c('Traceroute →', _GY)} {_c(host['ip'], _CY)}")
            traceroute(host["ip"])

    # Export
    if args.output and results:
        try:
            from packtrix.logger import export_scan_results
            hosts_dict = {h["ip"]: h for h in results if "ip" in h}
            fmt = _resolve_output_fmt(args.output)
            out = export_scan_results(hosts_dict, args.output, fmt=fmt)
            print(f"\n  {_c('[+]', _GR)} Results saved → {_c(out, _CY, _B)}\n")
        except Exception as exc:
            print(f"\n  {_c('[!]', _YL)} Export failed: {exc}\n")


def cmd_sniff(args: argparse.Namespace) -> None:
    """
    Handler for: packtrix sniff <interface> [options]

    Supports both simple protocol filters and full BPF expressions.
    Deep inspection mode adds HTTP/DNS/TLS/ARP-spoof decoding below
    each packet row.
    Duration mode captures for N seconds then exits automatically.
    """
    filter_str = (args.filter or "").strip().lower()
    if filter_str and not args.bpf:
        _validate_filter(filter_str)

    print(BANNER)
    _print_cmd_header("Packet Sniffer", [
        ("interface",  args.interface),
        ("filter",     args.bpf or filter_str or "all"),
        ("limit",      f"{args.count} pkts" if args.count else "unlimited"),
        ("deep",       "ON" if args.deep else "off"),
        ("output",     args.output or "—"),
    ])

    if not args.duration:
        print(f"  {_c('[*]', _CY)} Press {_c('Ctrl+C', _WH, _B)} "
              f"to stop capture.\n")

    capture_packets = _import("packtrix.sniffer", "capture_packets")
    stream_capture  = _import("packtrix.sniffer", "stream_capture")

    try:
        if args.duration:
            # Background capture for fixed duration
            print(f"  {_c('[*]', _CY)} Capturing for "
                  f"{_c(str(args.duration), _WH)}s…\n")
            packets = stream_capture(
                interface  = args.interface,
                filter     = filter_str or None,
                duration   = args.duration,
                bpf_filter = args.bpf or None,
            )
            print(f"  {_c('[+]', _GR)} Captured "
                  f"{_c(str(len(packets)), _WH, _B)} packets\n")
        else:
            packets = capture_packets(
                interface    = args.interface,
                filter       = filter_str or None,
                packet_limit = args.count,
                show_header  = True,
                deep_inspect = args.deep,
                bpf_filter   = args.bpf or None,
            )
    except ValueError as exc:
        print(f"\n  {_c('[!]', _RD, _B)} {exc}\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Sniffer error: {exc}\n")
        if args.verbose:
            raise
        sys.exit(1)

    # Save output
    if args.output and packets:
        try:
            save_pcap = _import("packtrix.sniffer", "save_pcap")
            save_pcap(packets, args.output)
            print(f"  {_c('[+]', _GR)} Saved → {_c(args.output, _CY, _B)}\n")
        except Exception as exc:
            # Fall back to JSON
            import json
            fp = str(pathlib.Path(args.output).with_suffix(".json"))
            with open(fp, "w") as fh:
                json.dump(packets, fh, indent=2, default=str)
            print(f"  {_c('[+]', _GR)} Saved (JSON) → {_c(fp, _CY)}\n")


def cmd_analyze(args: argparse.Namespace) -> None:
    """Handler for: packtrix analyze [logfile] [options]"""
    logfile = "__placeholder__" if (args.demo or not args.logfile) \
              else args.logfile
    source_label = "[demo data]" if logfile == "__placeholder__" else logfile

    print(BANNER)
    _print_cmd_header("Security Analyzer", [
        ("source",   source_label),
        ("export",   args.export or "—"),
        ("out-dir",  args.export_path if args.export else "—"),
    ])

    analyze_logs = _import("packtrix.analyzer", "analyze_logs")

    try:
        alerts = analyze_logs(
            logfile     = logfile,
            export      = args.export or None,
            export_path = args.export_path,
        )
    except FileNotFoundError:
        print(f"\n  {_c('[!]', _RD, _B)} File not found: {_c(logfile, _WH)}\n"
              f"  Tip: use {_c('--demo', _CY)} to run with demo data.\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Analysis error: {exc}\n")
        if args.verbose:
            raise
        sys.exit(1)

    print(f"  {_c('Alerts raised', _GY)}  "
          f"{_c(str(len(alerts)), _WH, _B)}\n")


def cmd_dashboard(args: argparse.Namespace) -> None:
    """Handler for: packtrix dashboard [options]"""
    print(BANNER)
    _print_cmd_header("Live Dashboard", [
        ("interface", args.interface),
        ("refresh",   f"{args.refresh}s"),
    ])
    print(f"  {_c('[*]', _CY)} Starting…  "
          f"Keys: {_c('q', _WH, _B)} quit  "
          f"{_c('p', _WH, _B)} pause  "
          f"{_c('c', _WH, _B)} clear  "
          f"{_c('r', _WH, _B)} reset  "
          f"{_c('↑↓', _WH, _B)} scroll\n")

    import time
    time.sleep(0.8)

    show_dashboard = _import("packtrix.dashboard", "show_dashboard")
    try:
        show_dashboard(interface=args.interface, refresh_rate=args.refresh)
    except Exception as exc:
        print(f"\n  {_c('[!]', _RD, _B)} Dashboard error: {exc}\n")
        if args.verbose:
            raise
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packtrix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Packtrix — Terminal Cybersecurity Toolkit  v0.1.4
            ==================================================
            Scan networks, capture packets, detect threats, and monitor
            traffic in real time — all from your terminal.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              packtrix scan      192.168.1.0/24 --ports
              packtrix scan      192.168.1.0/24 --ports --scan-type syn --os --services
              packtrix sniff     eth0 --filter tcp --deep
              packtrix sniff     eth0 --bpf "tcp port 443"
              packtrix analyze   --demo
              packtrix dashboard --interface eth0 --refresh 0.5

            Run `packtrix <command> --help` for per-command options.
        """),
    )

    parser.add_argument("--version", "-V", action="version",
                        version=f"%(prog)s {VERSION}")
    parser.add_argument("--verbose", "-v", action="store_true",
                        default=False, help="Enable verbose / debug output.")

    sub = parser.add_subparsers(title="commands", dest="command",
                                metavar="<command>")

    # ── scan ──────────────────────────────────────────────────────────────
    scan_p = sub.add_parser(
        "scan",
        help="Discover hosts and scan ports on a subnet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Scan Command
            ============
            Phase 1 — Host discovery: ARP sweep (default) or ICMP ping sweep (--icmp).
            Phase 2 — Vendor lookup: MAC OUI prefix → manufacturer name.
            Phase 3 — OS fingerprint: TTL + TCP window heuristics (--os, root).
            Phase 4 — TCP port scan: SYN/connect/FIN/NULL/XMAS (--ports, --scan-type).
            Phase 5 — UDP port scan: DNS/SNMP/NTP services (--udp, root).
            Phase 6 — Service detection: banner grab + version probe (--services).
            Phase 7 — Traceroute: ICMP hop-by-hop path (--traceroute, root).

            Use --demo to see output for every scan type without root or Scapy.
            SYN/FIN/NULL/XMAS/UDP/OS/traceroute need root + Scapy in live mode.
            connect scan works without root.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # See all scan types with output — no root or Scapy needed
              packtrix scan 192.168.1.0/24 --demo

              # ARP discovery only
              packtrix scan 192.168.1.0/24

              # TCP connect scan — no root needed
              packtrix scan 192.168.1.0/24 --ports --scan-type connect

              # SYN stealth scan (needs root + Scapy)
              sudo packtrix scan 192.168.1.0/24 --ports
              sudo packtrix scan 192.168.1.0/24 --ports --scan-type syn

              # Firewall evasion scans (needs root + Scapy)
              sudo packtrix scan 192.168.1.0/24 --ports --scan-type fin
              sudo packtrix scan 192.168.1.0/24 --ports --scan-type null
              sudo packtrix scan 192.168.1.0/24 --ports --scan-type xmas

              # ICMP ping sweep instead of ARP
              sudo packtrix scan 192.168.1.0/24 --icmp

              # OS fingerprint + service version detection
              sudo packtrix scan 192.168.1.0/24 --ports --os --services

              # UDP port scan (DNS 53, NTP 123, SNMP 161...)
              sudo packtrix scan 192.168.1.0/24 --udp

              # Traceroute each discovered host
              sudo packtrix scan 192.168.1.0/24 --traceroute

              # Custom ports: list and ranges
              packtrix scan 192.168.1.0/24 --ports --ports-list 22,80,443,8080-8090

              # Full pipeline + save output
              sudo packtrix scan 192.168.1.0/24 --ports --udp --os \\
                   --services --traceroute --output scan.json
        """),
    )
    scan_p.add_argument("network", metavar="<network>",
                        help="Target subnet in CIDR notation, e.g. 192.168.1.0/24.")
    scan_p.add_argument("--ports", action="store_true", default=False,
                        help="Enable TCP port scanning.")
    scan_p.add_argument(
        "--scan-type", metavar="TYPE", default="syn",
        choices=["syn", "connect", "fin", "null", "xmas"],
        help=(
            "TCP scan technique (default: syn). "
            "syn=stealth/fast (root), connect=safe/no-root, "
            "fin/null/xmas=firewall evasion (root)."
        ),
    )
    scan_p.add_argument("--udp", action="store_true", default=False,
                        help="Also run a UDP port scan (root required).")
    scan_p.add_argument("--os", action="store_true", default=False,
                        help="Run OS fingerprinting on each discovered host (root required).")
    scan_p.add_argument("--services", action="store_true", default=False,
                        help="Run service version detection on open ports.")
    scan_p.add_argument("--icmp", action="store_true", default=False,
                        help="Use ICMP ping sweep instead of ARP for host discovery.")
    scan_p.add_argument("--traceroute", action="store_true", default=False,
                        help="Trace the network path to each discovered host.")
    scan_p.add_argument(
        "--ports-list", metavar="PORTS", default=None,
        help=(
            "Custom port list, overrides the default. "
            "Accepts: 22,80,443 or ranges: 8000-8100 or mixed: 22,80,8000-8010"
        ),
    )
    scan_p.add_argument("--output", metavar="FILE", default=None,
                        help="Save results to FILE (.json or .csv).")
    scan_p.add_argument(
        "--demo", action="store_true", default=False, dest="scan_demo",
        help=(
            "Demo mode: run a full visible scan pipeline using simulated hosts. "
            "Shows every scan type in sequence so you can see output format "
            "without needing root or Scapy."
        ),
    )
    scan_p.set_defaults(func=cmd_scan)

    # ── sniff ─────────────────────────────────────────────────────────────
    sniff_p = sub.add_parser(
        "sniff",
        help="Capture live packets on a network interface.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Sniff Command
            =============
            Captures packets and streams them to the terminal in a live
            scrolling table: No. · Time · Source · Dest · Proto · Svc · Bytes · Flags

            --deep  adds a decoded second line under each packet:
              ↳ HTTP  GET example.com/path
              ↳ DNS   query A google.com  →  answer 142.250.80.46
              ↳ TLS   ClientHello TLS 1.2 SNI=bank.com
              ↳ ARP ⚠ SPOOF  IP 192.168.1.1 changed MAC (MITM alert)

            --bpf   passes a libpcap BPF expression to the kernel for
                    precise filtering before packets reach Packtrix.
                    e.g. "tcp port 443 and host 192.168.1.1"

            --duration  captures for N seconds then exits automatically.

            Falls back to realistic simulated data without Scapy + root.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # Demo mode — simulated traffic, no root needed
              packtrix sniff eth0

              # Protocol filters
              packtrix sniff eth0 --filter tcp
              packtrix sniff eth0 --filter udp
              packtrix sniff eth0 --filter icmp
              packtrix sniff eth0 --filter arp
              packtrix sniff eth0 --filter dns

              # BPF expressions (live mode — needs root + Scapy)
              sudo packtrix sniff eth0 --bpf "tcp port 443"
              sudo packtrix sniff eth0 --bpf "host 192.168.1.1"
              sudo packtrix sniff eth0 --bpf "tcp port 80 or tcp port 8080"
              sudo packtrix sniff eth0 --bpf "not arp and not broadcast"

              # Deep packet inspection
              packtrix sniff eth0 --deep
              sudo packtrix sniff eth0 --deep --bpf "port 53"

              # Stop after N packets
              packtrix sniff eth0 --count 200

              # Fixed duration then exit
              packtrix sniff eth0 --duration 30
              sudo packtrix sniff eth0 --duration 60 --output session.pcap

              # Save capture
              sudo packtrix sniff eth0 --count 500 --output session.pcap

              # Capture then analyze pipeline
              packtrix sniff eth0 --count 500 --output cap.json
              packtrix analyze cap.json --export json
        """),
    )
    sniff_p.add_argument("interface", metavar="<interface>",
                         help="Network interface, e.g. eth0, wlan0.")
    sniff_p.add_argument(
        "--filter", metavar="PROTO", default="", dest="filter",
        help="Simple protocol filter: tcp, udp, icmp, arp, dns. "
             "Leave blank for all. Use --bpf for complex filters.",
    )
    sniff_p.add_argument(
        "--bpf", metavar="EXPR", default=None, dest="bpf",
        help=(
            "Full BPF filter expression passed to libpcap. "
            "Overrides --filter. "
            "e.g. \"tcp port 80\", \"host 10.0.0.1 and udp\""
        ),
    )
    sniff_p.add_argument("--count", metavar="N", type=int, default=0,
                         help="Stop after N packets. Default: 0 (unlimited).")
    sniff_p.add_argument(
        "--deep", action="store_true", default=False,
        help=(
            "Enable deep packet inspection: decode HTTP method/URL, "
            "DNS queries/answers, TLS SNI/version, detect ARP spoofing."
        ),
    )
    sniff_p.add_argument(
        "--duration", metavar="SECS", type=float, default=0.0,
        help="Capture for SECS seconds then exit automatically.",
    )
    sniff_p.add_argument("--output", metavar="FILE", default=None,
                         help="Save capture to FILE (.pcap or .json fallback).")
    sniff_p.set_defaults(func=cmd_sniff)

    # ── analyze ───────────────────────────────────────────────────────────
    analyze_p = sub.add_parser(
        "analyze",
        help="Analyse a captured log file for security threats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Analyze Command
            ===============
            Reads a packet log file (JSON array, NDJSON, or CSV) and
            runs all detection rules — built-in and plugin:

              Built-in: brute_force, port_scan, traffic_spike
              Plugins:  dns_tunneling, icmp_flood, cleartext_creds,
                        arp_spoof, plus any file in packtrix/plugins/

            Use --demo to run with built-in placeholder data (no file needed).
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # Run with built-in demo data — no file needed
              packtrix analyze --demo

              # Analyze a file from sniff
              packtrix analyze capture.json
              packtrix analyze logs/capture.json

              # Export alerts
              packtrix analyze capture.json --export json
              packtrix analyze capture.json --export csv
              packtrix analyze capture.json --export csv --export-path reports/

              # Full pipeline: capture → analyze → export
              packtrix sniff eth0 --count 200 --output cap.json
              packtrix analyze cap.json --export json --export-path reports/
        """),
    )
    analyze_p.add_argument("logfile", metavar="<logfile>", nargs="?",
                            default=None,
                            help="Path to .json, .jsonl, or .csv capture file.")
    analyze_p.add_argument("--demo", action="store_true", default=False,
                            help="Use built-in demo data instead of a file.")
    analyze_p.add_argument("--export", metavar="FMT", default=None,
                            choices=["json", "csv"], dest="export",
                            help="Export alerts as json or csv.")
    analyze_p.add_argument("--export-path", metavar="DIR", default=".",
                            dest="export_path",
                            help="Directory for exported alert files.")
    analyze_p.set_defaults(func=cmd_analyze)

    # ── dashboard ─────────────────────────────────────────────────────────
    dash_p = sub.add_parser(
        "dashboard",
        help="Launch the live full-screen terminal dashboard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Dashboard Command
            =================
            Flicker-free in-place terminal dashboard. Only lines that changed
            are rewritten each refresh — zero screen flicker at any refresh rate.

            Seven panels:
              Header          — interface · uptime · pkts · pkt/s · KB/s · clock
                                Shows [DEMO] or [LIVE] and live alert count
              Protocol chart  — TCP/UDP/ICMP/ARP/OTHER bar chart with %
              Top Talkers     — busiest source IPs; attacker IPs in red
              Recent Packets  — scrollable live feed; attack traffic in red
              Security Alerts — CRITICAL/HIGH/MEDIUM/LOW colour coded
              Connections     — active flows with age, evicted after 30s
              Threat Timeline — timestamped log of every threat event (NEW)

            Demo mode — no root or Scapy needed:
              Threats fire automatically every 20-40 seconds.
              Press [t] to inject a threat instantly.
              7 scenarios: SSH brute-force · port scan · ICMP flood
              ARP spoofing · DNS tunneling · traffic spike · cleartext creds

            Keyboard shortcuts:
              q / Ctrl+C  quit
              p           pause / resume
              c           clear alerts and threat timeline
              r           reset all stats to zero
              ↑ or k      scroll packet feed up
              ↓ or j      scroll packet feed down
              t           inject a random threat (demo mode)
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # Demo mode — threats fire every 20-40 s automatically
              packtrix dashboard

              # Press [t] to inject a threat scenario at any time
              # Press [p] to pause  [c] to clear  [r] to reset
              # Press [↑]/[↓] or [k]/[j] to scroll the packet feed

              # Faster refresh
              packtrix dashboard --refresh 0.5

              # Change interface name in header
              packtrix dashboard --interface wlan0

              # Live capture (needs root + Scapy installed)
              sudo packtrix dashboard --interface eth0 --refresh 0.5
        """),
    )
    dash_p.add_argument("--interface", metavar="IFACE", default="eth0",
                        help="Interface name shown in header. Default: eth0.")
    dash_p.add_argument("--refresh", metavar="SECS", type=float, default=1.0,
                        help="Redraw interval in seconds. Default: 1.0.")
    dash_p.set_defaults(func=cmd_dashboard)

    return parser


# ── Entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.command is None:
        print(BANNER)
        parser.print_help()
        print()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
