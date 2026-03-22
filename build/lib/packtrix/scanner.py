"""
scanner.py  –  Network discovery and port scanning
====================================================
Expanded scanning module using Scapy for real network interaction.

Scan types available:
    arp_scan()          ARP host discovery (layer 2, most reliable on LAN)
    syn_scan()          TCP SYN stealth scan (half-open, fast, needs root)
    connect_scan()      TCP connect scan    (no root needed)
    udp_scan()          UDP port scan       (finds DNS, SNMP, DHCP etc.)
    fin_scan()          TCP FIN scan        (firewall evasion)
    null_scan()         TCP NULL scan       (firewall evasion)
    xmas_scan()         TCP XMAS scan       (firewall evasion)
    icmp_sweep()        ICMP ping sweep     (find live hosts without ARP)
    os_fingerprint()    TCP/IP OS detection (TTL + window size heuristics)
    service_detect()    Banner grabbing     (exact service + version)
    traceroute()        ICMP traceroute     (path to target)
    scan_network()      Full pipeline       (called by CLI)
"""

import os
import socket
import ipaddress
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from packtrix.utils import COMMON_PORTS, port_service, is_valid_cidr, utc_now
from packtrix._display import (
    c, pad, bar, term_size,
    BOLD, DIM, GRY, WHT, CYN, GREEN, YEL, MAG, RED, BRED,
)

# ── Constants ──────────────────────────────────────────────────────────────
PORT_TIMEOUT  = 0.5      # seconds per TCP connect attempt
SYN_TIMEOUT   = 0.5      # seconds per SYN probe
UDP_TIMEOUT   = 1.0      # seconds per UDP probe (slower — no handshake)
MAX_WORKERS   = 100      # max concurrent threads for port scanning
COMMON_SCAN   = [        # default port list for quick scans
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 27017,
]

# OUI table — MAC prefix → vendor name
OUI_TABLE = {
    "B827EB": "Raspberry Pi",  "DCA632": "Raspberry Pi",
    "3C22FB": "Apple",         "A4C361": "Apple",
    "001372": "Dell",          "F48E38": "Dell",
    "FCFBFB": "Cisco",         "001A2F": "Cisco",
    "00155D": "Microsoft",     "7C1E52": "Microsoft",
    "080027": "VirtualBox",    "000C29": "VMware",
    "005056": "VMware",        "525400": "VirtualBox",
    "B47C9C": "Amazon",        "40B4CD": "Amazon",
    "704D7B": "Google",        "F4F5E8": "Google",
    "001B21": "Intel",         "34E6D7": "Intel",
    "14CCA3": "TP-Link",       "50C7BF": "TP-Link",
    "C4ADFE": "Google",        "3499E3": "Google",
    "002339": "Samsung",       "CC07AB": "Samsung",
    "001083": "HP",            "3C4A92": "HP",
    "000FB5": "Netgear",       "08EEEE": "Netgear",
}


def lookup_vendor(mac: str) -> str:
    """Look up manufacturer from MAC OUI prefix."""
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    return OUI_TABLE.get(oui, "Unknown")


def _has_scapy() -> bool:
    """Return True if Scapy is importable."""
    try:
        import scapy.all  # type: ignore
        return True
    except ImportError:
        return False


def _is_root() -> bool:
    """Return True if running as root."""
    return os.geteuid() == 0


# ── Simulated hosts for demo mode ─────────────────────────────────────────

_DEMO_HOSTS = [
    {"ip": "192.168.1.1",   "mac": "fc:fb:fb:01:02:03", "hostname": "router.local"},
    {"ip": "192.168.1.10",  "mac": "b8:27:eb:aa:bb:cc", "hostname": "pi.local"},
    {"ip": "192.168.1.42",  "mac": "3c:22:fb:de:ad:01", "hostname": "macbook.local"},
    {"ip": "192.168.1.55",  "mac": "00:15:5d:f0:0d:02", "hostname": ""},
    {"ip": "192.168.1.101", "mac": "dc:d9:16:ca:fe:03", "hostname": "phone.local"},
    {"ip": "192.168.1.200", "mac": "08:00:27:be:ef:04", "hostname": "vm.local"},
]


# ═══════════════════════════════════════════════════════════════════════════
# HOST DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════

def arp_scan(subnet: str) -> list[dict]:
    """
    Layer-2 ARP host discovery.

    Sends an ARP broadcast to every IP in the subnet and collects replies.
    The most reliable discovery method on a local network — ARP cannot be
    blocked without breaking the network itself.

    Requires: Scapy + root.
    Fallback: returns six simulated hosts.

    Args:
        subnet: CIDR notation, e.g. '192.168.1.0/24'

    Returns:
        list[dict] with keys: ip, mac, hostname
    """
    try:
        if not _is_root():
            raise PermissionError("root required")
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
        conf.verb = 0

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=2,
            iface_hint=subnet,
            verbose=0,
        )
        hosts = []
        for _, rcv in ans:
            ip  = rcv[ARP].psrc
            mac = rcv[Ether].src
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""
            hosts.append({"ip": ip, "mac": mac, "hostname": hostname})

        print(f"  {c('[ARP]', CYN)} Real scan complete — "
              f"{c(str(len(hosts)), BOLD, GREEN)} hosts found")
        return hosts

    except ImportError:
        print(f"  {c('[i]', YEL)} Scapy not installed — using demo hosts")
    except PermissionError:
        print(f"  {c('[i]', YEL)} Root required for ARP scan — using demo hosts")
    except Exception as e:
        print(f"  {c('[!]', YEL)} ARP error: {e} — using demo hosts")

    return [dict(h) for h in _DEMO_HOSTS]


def icmp_sweep(subnet: str, timeout: float = 0.5) -> list[str]:
    """
    ICMP ping sweep — find live hosts without ARP.

    Works across routed networks (not just local subnet) but can be
    blocked by firewalls. Sends one ICMP echo request per host and
    collects replies. Runs all probes concurrently.

    Requires: Scapy + root.
    Fallback: returns IPs from demo host list.

    Args:
        subnet:  CIDR notation
        timeout: seconds to wait per probe

    Returns:
        list of live IP address strings
    """
    try:
        if not _is_root():
            raise PermissionError("root required")
        from scapy.all import IP, ICMP, sr, conf  # type: ignore
        conf.verb = 0

        network = ipaddress.ip_network(subnet, strict=False)
        hosts   = list(network.hosts())

        print(f"  {c('[ICMP]', YEL)} Sweeping {len(hosts)} hosts…",
              end="", flush=True)

        pkts = [IP(dst=str(ip)) / ICMP() for ip in hosts]
        ans, _ = sr(pkts, timeout=timeout, verbose=0)

        live = [rcv[IP].src for _, rcv in ans if rcv.haslayer(ICMP)
                and rcv[ICMP].type == 0]

        print(f"  {c(str(len(live)), BOLD, GREEN)} responded")
        return live

    except ImportError:
        print(f"  {c('[i]', YEL)} Scapy not installed — using demo hosts")
    except PermissionError:
        print(f"  {c('[i]', YEL)} Root required — using demo hosts")
    except Exception as e:
        print(f"  {c('[!]', YEL)} ICMP sweep error: {e}")

    return [h["ip"] for h in _DEMO_HOSTS]


# ═══════════════════════════════════════════════════════════════════════════
# PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════

def connect_scan(target: str,
                 ports: list[int] | None = None) -> list[dict]:
    """
    TCP connect scan — full three-way handshake per port.

    The safest scan type — does not require root because it uses the
    OS TCP stack. Slower than SYN scan and more visible in logs because
    the connection is fully established before being reset.

    No root required. Works on any OS.

    Args:
        target: IP address string
        ports:  list of port numbers (default: COMMON_SCAN)

    Returns:
        list[dict]: {port, state, service, banner}
    """
    if ports is None:
        ports = COMMON_SCAN

    def _probe(port: int) -> dict:
        banner = ""
        try:
            with socket.create_connection(
                (target, port), timeout=PORT_TIMEOUT
            ) as s:
                # Banner grab on services that push data on connect
                if port in {21, 22, 23, 25, 80, 110, 143, 443,
                            465, 587, 993, 995, 3306, 5432}:
                    try:
                        s.settimeout(0.3)
                        raw    = s.recv(256)
                        banner = raw.decode("utf-8", errors="replace") \
                                    .split("\n")[0].strip()[:80]
                    except Exception:
                        pass
                return {"port": port, "state": "open",
                        "service": port_service(port), "banner": banner}
        except Exception:
            return {"port": port, "state": "closed",
                    "service": port_service(port), "banner": ""}

    results = []
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ports))) as ex:
        futures = {ex.submit(_probe, p): p for p in ports}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                p = futures[fut]
                results.append({"port": p, "state": "error",
                                 "service": port_service(p), "banner": ""})

    return sorted(results, key=lambda r: r["port"])


def syn_scan(target: str,
             ports: list[int] | None = None) -> list[dict]:
    """
    TCP SYN stealth scan — half-open scan, never completes handshake.

    Faster and stealthier than connect_scan. Sends a SYN packet and
    reads the reply:
        SYN-ACK  → port is OPEN    (we send RST to close)
        RST      → port is CLOSED
        No reply → port is FILTERED (firewall blocking)

    Because the connection is never completed, many application-layer
    logs never see the attempt. IDS systems still detect it.

    Requires: Scapy + root.
    Fallback: connect_scan().

    Args:
        target: IP address string
        ports:  list of port numbers (default: COMMON_SCAN)

    Returns:
        list[dict]: {port, state, service, banner}
    """
    if not _has_scapy() or not _is_root():
        print(f"  {c('[i]', YEL)} SYN scan needs Scapy + root — "
              f"falling back to connect scan")
        return connect_scan(target, ports)

    from scapy.all import IP, TCP, sr, conf  # type: ignore
    conf.verb = 0

    if ports is None:
        ports = COMMON_SCAN

    # Build all SYN packets at once
    pkts = [
        IP(dst=target) / TCP(dport=p, flags="S", sport=12345)
        for p in ports
    ]

    print(f"  {c('[SYN]', CYN)} Probing {len(ports)} ports on {target}…",
          end="", flush=True)

    ans, unans = sr(pkts, timeout=SYN_TIMEOUT, verbose=0)

    results   = {}
    open_count = 0

    # Answered packets
    for snd, rcv in ans:
        port = snd[TCP].dport
        if rcv.haslayer(TCP):
            flags = int(rcv[TCP].flags)
            if flags == 0x12:       # SYN-ACK → open
                results[port] = {"port": port, "state": "open",
                                  "service": port_service(port), "banner": ""}
                open_count += 1
                # Send RST to close cleanly
                from scapy.all import send  # type: ignore
                send(IP(dst=target) / TCP(
                    dport=port, flags="R",
                    sport=12345, seq=rcv[TCP].ack
                ), verbose=0)
            elif flags & 0x04:      # RST → closed
                results[port] = {"port": port, "state": "closed",
                                  "service": port_service(port), "banner": ""}

    # Unanswered packets = filtered
    for snd in unans:
        port = snd[TCP].dport
        if port not in results:
            results[port] = {"port": port, "state": "filtered",
                              "service": port_service(port), "banner": ""}

    print(f"  {c(str(open_count), BOLD, GREEN)} open")
    return sorted(results.values(), key=lambda r: r["port"])


def udp_scan(target: str,
             ports: list[int] | None = None) -> list[dict]:
    """
    UDP port scan.

    UDP has no handshake so detection relies on ICMP responses:
        No reply            → open|filtered (many open UDP ports are silent)
        ICMP Port Unreachable → closed
        ICMP other          → filtered

    Much slower than TCP scans. Requires root for ICMP reception.

    Common UDP services: DNS(53), DHCP(67/68), TFTP(69), NTP(123),
                         SNMP(161), mDNS(5353), WireGuard(51820)

    Requires: Scapy + root.
    Fallback: returns empty list with a warning.

    Args:
        target: IP address string
        ports:  list of UDP port numbers
                (default: common UDP services)

    Returns:
        list[dict]: {port, state, service, proto='UDP'}
    """
    UDP_DEFAULTS = [53, 67, 68, 69, 123, 137, 138, 161,
                    162, 500, 514, 1194, 5353, 51820]

    if ports is None:
        ports = UDP_DEFAULTS

    if not _has_scapy() or not _is_root():
        print(f"  {c('[i]', YEL)} UDP scan needs Scapy + root")
        return []

    from scapy.all import IP, UDP, ICMP, sr, conf  # type: ignore
    conf.verb = 0

    print(f"  {c('[UDP]', MAG)} Probing {len(ports)} UDP ports on {target}…",
          end="", flush=True)

    pkts    = [IP(dst=target) / UDP(dport=p) for p in ports]
    ans, unans = sr(pkts, timeout=UDP_TIMEOUT, verbose=0)

    results = {}

    for snd, rcv in ans:
        port = snd[UDP].dport
        if rcv.haslayer(ICMP):
            icmp_type = rcv[ICMP].type
            icmp_code = rcv[ICMP].code
            if icmp_type == 3 and icmp_code == 3:
                results[port] = {"port": port, "state": "closed",
                                  "service": port_service(port),
                                  "proto": "UDP", "banner": ""}
            else:
                results[port] = {"port": port, "state": "filtered",
                                  "service": port_service(port),
                                  "proto": "UDP", "banner": ""}
        elif rcv.haslayer(UDP):
            results[port] = {"port": port, "state": "open",
                              "service": port_service(port),
                              "proto": "UDP", "banner": ""}

    for snd in unans:
        port = snd[UDP].dport
        if port not in results:
            results[port] = {"port": port, "state": "open|filtered",
                              "service": port_service(port),
                              "proto": "UDP", "banner": ""}

    open_count = sum(1 for r in results.values()
                     if r["state"] in ("open", "open|filtered"))
    print(f"  {c(str(open_count), BOLD, GREEN)} open or open|filtered")
    return sorted(results.values(), key=lambda r: r["port"])


def fin_scan(target: str,
             ports: list[int] | None = None) -> list[dict]:
    """
    TCP FIN scan — firewall evasion technique.

    Sends a FIN packet (which normally only appears at end of a connection).
    RFC 793 says:
        Closed port  → must reply with RST
        Open port    → silently drops the packet (no reply)
        Filtered     → no reply (same as open — ambiguous)

    Many stateless firewalls pass FIN packets because they only filter SYN.
    Does NOT work against Windows (Windows always replies with RST).

    Requires: Scapy + root.

    Args:
        target: IP address string
        ports:  list of port numbers

    Returns:
        list[dict]: {port, state, service}
        state values: 'open|filtered', 'closed'
    """
    return _flag_scan(target, ports, flag="F", scan_name="FIN")


def null_scan(target: str,
              ports: list[int] | None = None) -> list[dict]:
    """
    TCP NULL scan — sends packet with NO flags set.

    Same RFC 793 logic as FIN scan. Even more unusual than FIN —
    a real TCP stack should never send a packet with no flags set.
    Some intrusion detection systems miss this because it is so unusual.

    Requires: Scapy + root.

    Args:
        target: IP address string
        ports:  list of port numbers

    Returns:
        list[dict]: {port, state, service}
    """
    return _flag_scan(target, ports, flag="", scan_name="NULL")


def xmas_scan(target: str,
              ports: list[int] | None = None) -> list[dict]:
    """
    TCP XMAS scan — sets FIN + PSH + URG flags simultaneously.

    Named 'Christmas' because all the flags light up like a Christmas tree.
    Same RFC 793 logic as FIN and NULL scans. Gets its name from the
    combination of three unusual flags appearing together.

    Requires: Scapy + root.

    Args:
        target: IP address string
        ports:  list of port numbers

    Returns:
        list[dict]: {port, state, service}
    """
    return _flag_scan(target, ports, flag="FPU", scan_name="XMAS")


def _flag_scan(target: str,
               ports: list[int] | None,
               flag: str,
               scan_name: str) -> list[dict]:
    """
    Internal implementation for FIN / NULL / XMAS scans.
    All three use the same RFC 793 logic — only the flags differ.
    """
    if ports is None:
        ports = COMMON_SCAN

    if not _has_scapy() or not _is_root():
        print(f"  {c('[i]', YEL)} {scan_name} scan needs Scapy + root")
        return []

    from scapy.all import IP, TCP, sr, conf  # type: ignore
    conf.verb = 0

    print(f"  {c(f'[{scan_name}]', YEL)} Probing {len(ports)} ports…",
          end="", flush=True)

    pkts = [
        IP(dst=target) / TCP(dport=p, flags=flag, sport=12345)
        for p in ports
    ]
    ans, unans = sr(pkts, timeout=SYN_TIMEOUT, verbose=0)

    results = {}

    for snd, rcv in ans:
        port = snd[TCP].dport
        if rcv.haslayer(TCP) and int(rcv[TCP].flags) & 0x04:
            results[port] = {"port": port, "state": "closed",
                              "service": port_service(port)}

    for snd in unans:
        port = snd[TCP].dport
        if port not in results:
            results[port] = {"port": port, "state": "open|filtered",
                              "service": port_service(port)}

    open_count = sum(1 for r in results.values()
                     if r["state"] == "open|filtered")
    print(f"  {c(str(open_count), BOLD, GREEN)} open|filtered")
    return sorted(results.values(), key=lambda r: r["port"])


# ═══════════════════════════════════════════════════════════════════════════
# SERVICE AND OS DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def service_detect(target: str, port: int) -> dict:
    """
    Deep service version detection via protocol-specific probes.

    After finding an open port, sends a protocol-appropriate probe
    and reads the response to identify the exact service and version.

    Probes implemented:
        HTTP/HTTPS  — HEAD request, reads Server header
        SSH         — reads the banner (SSH-2.0-OpenSSH_8.9p1 etc.)
        FTP         — reads the 220 greeting
        SMTP        — reads the 220 greeting
        POP3        — reads the +OK greeting
        IMAP        — reads the * OK greeting
        MySQL       — reads the handshake packet
        Redis       — sends PING, reads +PONG
        Generic     — reads whatever the service sends immediately

    Args:
        target: IP address string
        port:   port number to probe

    Returns:
        dict: {port, state, service, version, banner, proto}
    """
    base = {
        "port":    port,
        "state":   "open",
        "service": port_service(port),
        "version": "",
        "banner":  "",
        "proto":   "TCP",
    }

    try:
        with socket.create_connection((target, port),
                                      timeout=PORT_TIMEOUT) as s:
            s.settimeout(1.0)

            # HTTP probe
            if port in (80, 8080, 8008, 8888):
                s.send(b"HEAD / HTTP/1.0\r\nHost: " +
                       target.encode() + b"\r\n\r\n")
                resp = s.recv(1024).decode("utf-8", errors="replace")
                for line in resp.split("\n"):
                    if line.lower().startswith("server:"):
                        base["version"] = line.split(":", 1)[1].strip()
                        break
                base["banner"] = resp.split("\n")[0].strip()[:80]

            # HTTPS probe (just read TLS banner)
            elif port in (443, 8443):
                try:
                    import ssl
                    ctx  = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    with ctx.wrap_socket(s, server_hostname=target) as ss:
                        cert    = ss.getpeercert(binary_form=False) or {}
                        subject = dict(x[0] for x in cert.get("subject", []))
                        base["version"] = ss.version() or "TLS"
                        base["banner"]  = (
                            subject.get("commonName", "")[:60]
                        )
                except Exception:
                    base["banner"] = "TLS (cert read failed)"

            # Redis
            elif port == 6379:
                s.send(b"PING\r\n")
                resp = s.recv(64).decode("utf-8", errors="replace").strip()
                base["banner"]  = resp
                base["version"] = "Redis" if "PONG" in resp else ""

            # Generic banner grab — works for SSH, FTP, SMTP, POP3, IMAP
            else:
                raw = s.recv(256)
                banner = raw.decode("utf-8", errors="replace") \
                            .split("\n")[0].strip()[:80]
                base["banner"] = banner

                # Extract version from SSH banner
                if banner.startswith("SSH-"):
                    parts = banner.split("-", 2)
                    if len(parts) >= 3:
                        base["version"] = parts[2].split(" ")[0]

    except Exception:
        base["state"] = "closed"

    return base


def os_fingerprint(target: str) -> dict:
    """
    Passive OS fingerprinting via TCP/IP stack behaviour.

    Sends a SYN probe to port 80 (or 443 if 80 closed) and analyses
    the SYN-ACK reply. Different operating systems have distinct
    TCP window sizes, TTL values, and TCP option orders that reveal
    which OS stack generated the packet.

    Heuristic database covers Linux kernels, Windows versions, macOS,
    FreeBSD, and network devices. More accurate than a simple TTL check
    but less accurate than nmap's 5,000-fingerprint database.

    Requires: Scapy + root.
    Fallback: TTL-only heuristic via socket.

    Args:
        target: IP address string

    Returns:
        dict: {os, confidence, ttl, window, method}
    """
    result = {
        "os":         "Unknown",
        "confidence": "low",
        "ttl":        0,
        "window":     0,
        "method":     "none",
    }

    # ── Scapy fingerprinting (more accurate) ──────────────────────────
    if _has_scapy() and _is_root():
        try:
            from scapy.all import IP, TCP, sr1, conf  # type: ignore
            conf.verb = 0

            for probe_port in (80, 443, 22):
                pkt   = IP(dst=target, ttl=128) / TCP(
                    dport=probe_port, flags="S",
                    sport=12345,
                    options=[("MSS", 1460), ("NOP", None),
                             ("WScale", 8),  ("NOP", None),
                             ("NOP", None),  ("SAckOK", b"")]
                )
                reply = sr1(pkt, timeout=SYN_TIMEOUT, verbose=0)

                if reply and reply.haslayer(TCP):
                    ttl    = reply[IP].ttl
                    window = reply[TCP].window
                    result["ttl"]    = ttl
                    result["window"] = window
                    result["method"] = "scapy-syn"

                    # Fingerprint database
                    # (ttl_range, window) → (os_name, confidence)
                    FP_DB = [
                        # Linux
                        ((60, 64),  65535, "Linux 3.x / 4.x",       "high"),
                        ((60, 64),   5840, "Linux 2.4 / 2.6",        "high"),
                        ((60, 64),  29200, "Linux 4.x / 5.x",        "high"),
                        ((60, 64),  43690, "Linux 5.x",              "medium"),
                        # Windows
                        ((120, 128), 65535, "Windows 10 / Server 2016/2019", "high"),
                        ((120, 128),  8192, "Windows 7 / Server 2008", "high"),
                        ((120, 128), 64240, "Windows 10 (newer)",    "high"),
                        ((120, 128), 65392, "Windows 11",             "medium"),
                        # macOS / BSD
                        ((60, 64),  65535, "macOS / FreeBSD",         "medium"),
                        ((60, 64),  65228, "macOS Ventura+",          "medium"),
                        # Network devices
                        ((250, 255), 4128,  "Cisco IOS",              "medium"),
                        ((250, 255), 16384, "Cisco IOS / JunOS",      "medium"),
                        ((60, 64),   8760,  "FreeBSD / OpenBSD",      "medium"),
                    ]

                    for (ttl_lo, ttl_hi), win, os_name, conf_lvl in FP_DB:
                        if ttl_lo <= ttl <= ttl_hi and window == win:
                            result["os"]         = os_name
                            result["confidence"] = conf_lvl
                            break

                    if result["os"] == "Unknown":
                        # Fallback TTL heuristic
                        if 60 <= ttl <= 64:
                            result["os"] = f"Linux/Unix (TTL={ttl}, WIN={window})"
                        elif 120 <= ttl <= 128:
                            result["os"] = f"Windows (TTL={ttl}, WIN={window})"
                        elif ttl > 200:
                            result["os"] = f"Cisco/Network device (TTL={ttl})"

                    break   # got a reply — stop trying ports

        except Exception as e:
            result["method"] = f"scapy-error: {e}"

    return result


def traceroute(target: str, max_hops: int = 30,
               timeout: float = 1.0) -> list[dict]:
    """
    ICMP traceroute — discover the network path to a target.

    Sends ICMP echo requests with increasing TTL values (1, 2, 3…).
    Each router decrements the TTL. When it reaches 0 the router sends
    back ICMP Time Exceeded, revealing its IP address. The target sends
    ICMP Echo Reply when it receives a packet with sufficient TTL.

    Requires: Scapy + root.

    Args:
        target:   destination IP or hostname
        max_hops: maximum number of hops to trace (default 30)
        timeout:  seconds to wait per hop

    Returns:
        list[dict]: [{hop, ip, hostname, rtt_ms}, ...]
        ip is '*' if the hop did not respond.
    """
    if not _has_scapy() or not _is_root():
        print(f"  {c('[i]', YEL)} Traceroute needs Scapy + root")
        return []

    from scapy.all import IP, ICMP, sr1, conf  # type: ignore
    conf.verb = 0

    hops    = []
    print(f"\n  {c('Traceroute to', GRY)} {c(target, CYN, BOLD)}")
    print(f"  {c('─' * 50, GRY)}")

    for ttl in range(1, max_hops + 1):
        pkt   = IP(dst=target, ttl=ttl) / ICMP()
        t0    = time.perf_counter()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        rtt   = (time.perf_counter() - t0) * 1000   # ms

        if reply is None:
            hop = {"hop": ttl, "ip": "*", "hostname": "*", "rtt_ms": 0.0}
            print(f"  {c(str(ttl), GRY):>4}  {c('*', DIM)}")
        else:
            ip = reply.src
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ip
            hop = {"hop": ttl, "ip": ip,
                   "hostname": hostname, "rtt_ms": round(rtt, 2)}

            rtt_col = GREEN if rtt < 20 else YEL if rtt < 100 else RED
            print(f"  {c(str(ttl), GRY):>4}  "
                  f"{c(ip, WHT):<18}  "
                  f"{c(hostname[:35], DIM):<37}  "
                  f"{c(f'{rtt:.1f}ms', rtt_col)}")

            # Reached the target
            if reply.haslayer(ICMP) and reply[ICMP].type == 0:
                hops.append(hop)
                break

        hops.append(hop)

    print(f"  {c('─' * 50, GRY)}\n")
    return hops


# ═══════════════════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _print_host_table(hosts: list[dict], show_ports: bool,
                      elapsed: float) -> None:
    """Print the host discovery results as a box-drawing table."""
    if not hosts:
        print(f"  {c('No hosts found.', YEL)}\n")
        return

    w_ip  = max(10, max(len(h["ip"])                  for h in hosts))
    w_mac = max(17, max(len(h.get("mac", ""))         for h in hosts))
    w_vnd = max(7,  max(len(lookup_vendor(
                              h.get("mac", "000000"))) for h in hosts))
    w_hn  = max(8,  max(len(h.get("hostname") or "—") for h in hosts))
    w_os  = max(4,  max(len(h.get("os", ""))          for h in hosts))

    cols  = [w_ip, w_mac, w_vnd, w_hn, w_os]
    segs  = ["─" * (w + 2) for w in cols]

    if show_ports:
        # Add one column per open port found across all hosts
        all_open = sorted({
            r["port"] for h in hosts
            for r in h.get("ports", [])
            if r.get("state") == "open"
        })
        for p in all_open[:8]:   # cap at 8 port columns
            segs.append("─" * (max(4, len(f":{p}")) + 2))

    vb  = c("│", GRY)
    top = c("┌" + "┬".join(segs) + "┐", GRY)
    sep = c("├" + "┼".join(segs) + "┤", GRY)
    bot = c("└" + "┴".join(segs) + "┘", GRY)

    def _row(cells: list[str]) -> str:
        return vb + vb.join(f" {cell} " for cell in cells) + vb

    hdr = [
        c(pad("IP Address", w_ip,  "<"), BOLD, WHT),
        c(pad("MAC",        w_mac, "<"), BOLD, WHT),
        c(pad("Vendor",     w_vnd, "<"), BOLD, WHT),
        c(pad("Hostname",   w_hn,  "<"), BOLD, WHT),
        c(pad("OS",         w_os,  "<"), BOLD, WHT),
    ]
    if show_ports:
        for p in all_open[:8]:
            lbl = f":{p}"
            hdr.append(c(pad(lbl, max(4, len(lbl)), "^"), BOLD, WHT))

    print(f"\n  {c('Results', BOLD, WHT)}  {c(utc_now(), GRY)}  "
          f"{c(f'{elapsed:.1f}s', DIM)}\n")
    print(top)
    print(_row(hdr))
    print(sep)

    for host in hosts:
        vendor   = lookup_vendor(host.get("mac", "000000"))
        hostname = host.get("hostname") or "—"
        os_name  = host.get("os", "")
        if len(os_name) > w_os:
            os_name = os_name[:w_os - 1] + "…"

        cells = [
            c(pad(host["ip"],  w_ip,  "<"), WHT),
            c(pad(host.get("mac", ""), w_mac, "<"), CYN),
            c(pad(vendor,      w_vnd, "<"), YEL),
            c(pad(hostname,    w_hn,  "<"), GREEN),
            c(pad(os_name,     w_os,  "<"), MAG),
        ]

        if show_ports:
            port_map = {r["port"]: r for r in host.get("ports", [])}
            for p in all_open[:8]:
                w   = max(4, len(f":{p}"))
                res = port_map.get(p, {})
                if res.get("state") == "open":
                    cells.append(c(pad("OPEN", w, "^"), BOLD, GREEN))
                elif res.get("state") == "filtered":
                    cells.append(c(pad("FILT", w, "^"), YEL))
                else:
                    cells.append(c(pad("·", w, "^"), DIM))

        print(_row(cells))

    print(bot)

    open_hosts = sum(
        1 for h in hosts
        if any(r.get("state") == "open" for r in h.get("ports", []))
    ) if show_ports else 0

    print(f"\n  {c('Hosts', GRY)}  {c(str(len(hosts)), BOLD, WHT)}", end="")
    if show_ports:
        print(f"   {c('With open ports', GRY)}  "
              f"{c(str(open_hosts), BOLD, GREEN)}", end="")
    print("\n")


def _print_port_table(target: str, results: list[dict],
                      scan_type: str) -> None:
    """Print port scan results as a compact table."""
    open_ports = [r for r in results if r.get("state") == "open"]

    print(f"\n  {c(scan_type, BOLD, CYN)} → {c(target, WHT)}  "
          f"{c(f'{len(open_ports)} open', BOLD, GREEN)}\n")

    if not open_ports:
        print(f"  {c('No open ports found.', DIM)}\n")
        return

    for r in open_ports:
        banner  = r.get("banner", "") or r.get("version", "")
        version = r.get("version", "")
        service = r.get("service", "unknown")
        proto   = r.get("proto", "TCP")

        line = (f"  {c(str(r['port']), BOLD, GREEN):>8}"
                f"/{c(proto, GRY):<5}"
                f"  {c(pad(service, 12, '<'), CYN)}"
                f"  {c(pad(version or banner, 50, '<'), DIM)}")
        print(line)

    print()


# ═══════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE  (called by CLI)
# ═══════════════════════════════════════════════════════════════════════════

def port_scan(target: str, ports: list[int] | None = None,
              scan_type: str = "syn") -> list[dict]:
    """
    Run a port scan of the chosen type against a single target.

    Args:
        target:    IP address string
        ports:     list of ports (default: COMMON_SCAN)
        scan_type: 'syn' | 'connect' | 'udp' | 'fin' | 'null' | 'xmas'

    Returns:
        list[dict]: port results
    """
    scanners = {
        "syn":     syn_scan,
        "connect": connect_scan,
        "udp":     udp_scan,
        "fin":     fin_scan,
        "null":    null_scan,
        "xmas":    xmas_scan,
    }
    fn = scanners.get(scan_type.lower(), syn_scan)
    return fn(target, ports)


def scan_network(network: str,
                 scan_ports:  bool = False,
                 scan_type:   str  = "syn",
                 do_os:       bool = False,
                 do_services: bool = False,
                 do_udp:      bool = False,
                 do_icmp:     bool = False,
                 custom_ports: list[int] | None = None) -> list[dict]:
    """
    Full discovery pipeline. Called by CLI's cmd_scan().

    Phases:
        1  Host discovery    — ARP sweep (default) or ICMP ping sweep (--icmp)
        2  Vendor lookup     — identify manufacturers from MAC OUI table
        3  OS fingerprint    — guess OS via TCP/IP stack behaviour (--os)
        4  TCP port scan     — find open TCP ports (--ports, type via --scan-type)
        5  UDP port scan     — find open UDP ports (--udp)
        6  Service detect    — banner grab + version detection (--services)

    Args:
        network:      CIDR subnet, e.g. '192.168.1.0/24'
        scan_ports:   run TCP port scan
        scan_type:    'syn' | 'connect' | 'fin' | 'null' | 'xmas'
        do_os:        run OS fingerprinting on each host
        do_services:  run service version detection on open ports
        do_udp:       run UDP port scan
        do_icmp:      use ICMP ping sweep instead of ARP for discovery
        custom_ports: override default port list

    Returns:
        list[dict] — one dict per host with all discovered data
    """
    if not is_valid_cidr(network):
        raise ValueError(
            f"Invalid network: {network!r}  (expected CIDR e.g. 192.168.1.0/24)"
        )

    ports = custom_ports or COMMON_SCAN

    # Announce
    print(f"\n  {c('Target', GRY)}   {c(network, CYN, BOLD)}")
    features = []
    if do_icmp:     features.append("ICMP discovery")
    if scan_ports:  features.append(f"TCP {scan_type.upper()}")
    if do_udp:      features.append("UDP")
    if do_os:       features.append("OS detect")
    if do_services: features.append("service detect")
    if features:
        print(f"  {c('Features', GRY)}  {c(' · '.join(features), WHT)}")
    print()

    t_start = time.perf_counter()
    phase   = 0

    def _ph(name: str) -> None:
        nonlocal phase
        phase += 1
        print(f"  {c(f'[{phase}]', GRY)} {name}…", end="", flush=True)

    # Phase 1 — Host discovery (ARP or ICMP)
    if do_icmp:
        _ph("ICMP ping sweep")
        live_ips = icmp_sweep(network)
        # Convert live IP list to host dicts (no MAC available via ICMP)
        hosts = [{"ip": ip, "mac": "00:00:00:00:00:00",
                  "hostname": "", "vendor": "Unknown"}
                 for ip in live_ips]
        if not hosts:
            print(f"  {c('No hosts responded', YEL)}\n")
            return []
    else:
        _ph("ARP sweep")
        hosts = arp_scan(network)
        if not hosts:
            print(f"  {c('No hosts found', YEL)}\n")
            return []

    # Phase 2 — Vendor
    _ph("Vendor lookup")
    for h in hosts:
        h["vendor"] = lookup_vendor(h.get("mac", "000000"))
    print(f"  {c('done', DIM)}")

    # Phase 3 — OS
    if do_os:
        _ph("OS fingerprint")
        for h in hosts:
            fp    = os_fingerprint(h["ip"])
            h["os"] = fp.get("os", "")
            h["os_confidence"] = fp.get("confidence", "")
        print(f"  {c('done', DIM)}")
    else:
        for h in hosts:
            h["os"] = ""

    # Phase 4 — TCP port scan
    if scan_ports:
        _ph(f"TCP {scan_type.upper()} scan ({len(ports)} ports)")
        for h in hosts:
            h["ports"] = port_scan(h["ip"], ports, scan_type)
        open_total = sum(
            1 for h in hosts
            for r in h.get("ports", [])
            if r.get("state") == "open"
        )
        print(f"  {c(str(open_total), BOLD, GREEN)} open ports total")
    else:
        for h in hosts:
            h["ports"] = []

    # Phase 5 — UDP scan
    if do_udp:
        _ph("UDP scan")
        for h in hosts:
            udp_results = udp_scan(h["ip"])
            h["udp_ports"] = udp_results
        print(f"  {c('done', DIM)}")
    else:
        for h in hosts:
            h["udp_ports"] = []

    # Phase 6 — Service detection on open ports
    if do_services and scan_ports:
        _ph("Service version detection")
        for h in hosts:
            enriched = []
            for r in h.get("ports", []):
                if r.get("state") == "open":
                    detail = service_detect(h["ip"], r["port"])
                    r.update(detail)
                enriched.append(r)
            h["ports"] = enriched
        print(f"  {c('done', DIM)}")

    elapsed = time.perf_counter() - t_start
    _print_host_table(hosts, scan_ports or do_udp, elapsed)
    return hosts
