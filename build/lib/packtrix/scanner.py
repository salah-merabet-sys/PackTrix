"""
scanner.py  –  Network discovery and port scanning
====================================================
ARP host discovery (real via Scapy when root, simulated otherwise)
followed by threaded TCP port scanning with banner grabbing.
"""

import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from packtrix.utils import COMMON_PORTS, port_service, is_valid_cidr, utc_now
from packtrix._display import (
    c, pad, vlen, bar, term_size,
    RST, BOLD, DIM, GRY, WHT, CYN, GREEN, YEL, MAG, RED,
)

SCAN_PORTS   = [22, 80, 443]
PORT_TIMEOUT = 0.5
MAX_WORKERS  = 50

# OUI table (first 6 hex chars of MAC → vendor)
OUI_TABLE = {
    "B827EB": "Raspberry Pi", "3C22FB": "Apple", "FCFBFB": "Cisco",
    "00155D": "Microsoft",    "080027": "VirtualBox", "000C29": "VMware",
    "DCA632": "Raspberry Pi", "A4C361": "Intel",  "001372": "Dell",
}


def lookup_vendor(mac: str) -> str:
    oui = mac.replace(":", "").upper()[:6]
    return OUI_TABLE.get(oui, "Unknown")


def _probe_port(target: str, port: int) -> dict:
    """TCP connect probe with optional banner grab."""
    banner = ""
    try:
        with socket.create_connection((target, port), timeout=PORT_TIMEOUT) as s:
            if port in {22, 21, 25, 80, 110, 143}:
                try:
                    s.settimeout(0.3)
                    raw = s.recv(256)
                    banner = raw.decode("utf-8", errors="replace") \
                               .split("\n")[0].strip()[:60]
                except Exception:
                    pass
            return {"port": port, "state": "open",
                    "service": port_service(port), "banner": banner}
    except Exception:
        return {"port": port, "state": "closed",
                "service": port_service(port), "banner": ""}


def arp_scan(subnet: str) -> list[dict]:
    """
    Return a list of live hosts on *subnet*.
    Uses real Scapy ARP sweep when available + root, simulated otherwise.
    """
    try:
        import os
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
        if os.geteuid() != 0:
            raise PermissionError("root required")
        conf.verb = 0
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=2, iface_hint=subnet,
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
        return hosts

    except ImportError:
        print(f"  {c('[i]', YEL)} Scapy not installed – using simulated hosts.\n")
    except PermissionError:
        print(f"  {c('[i]', YEL)} Run with sudo for real ARP scan – using simulated hosts.\n")
    except Exception as e:
        print(f"  {c('[!]', YEL)} ARP error ({e}) – using simulated hosts.\n")

    # Simulated fallback
    return [
        {"ip": "192.168.1.1",   "mac": "fc:fb:fb:01:02:03", "hostname": "router.local"},
        {"ip": "192.168.1.10",  "mac": "b8:27:eb:aa:bb:cc", "hostname": "pi.local"},
        {"ip": "192.168.1.42",  "mac": "3c:22:fb:de:ad:01", "hostname": "macbook.local"},
        {"ip": "192.168.1.55",  "mac": "00:15:5d:f0:0d:02", "hostname": ""},
        {"ip": "192.168.1.101", "mac": "dc:d9:16:ca:fe:03", "hostname": "phone.local"},
        {"ip": "192.168.1.200", "mac": "08:00:27:be:ef:04", "hostname": "vm.local"},
    ]


def port_scan(target: str, ports: list[int] | None = None) -> list[dict]:
    """Concurrent TCP connect scan. Returns sorted list of port result dicts."""
    if ports is None:
        ports = SCAN_PORTS
    results = []
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ports))) as ex:
        futures = {ex.submit(_probe_port, target, p): p for p in ports}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                p = futures[fut]
                results.append({"port": p, "state": "error",
                                 "service": port_service(p), "banner": ""})
    return sorted(results, key=lambda r: r["port"])


def _print_results(hosts: list[dict], scan_ports: bool, elapsed: float) -> None:
    """Print a compact host table to stdout."""
    if not hosts:
        print(f"  {c('No hosts found.', YEL)}\n")
        return

    # Column widths
    w_ip   = max(10, max(len(h["ip"])                      for h in hosts))
    w_mac  = max(17, max(len(h["mac"])                     for h in hosts))
    w_vnd  = max(7,  max(len(lookup_vendor(h["mac"]))      for h in hosts))
    w_hn   = max(8,  max(len(h.get("hostname") or "—")     for h in hosts))

    sep_parts = [
        "─" * (w_ip  + 2),
        "─" * (w_mac + 2),
        "─" * (w_vnd + 2),
        "─" * (w_hn  + 2),
    ]
    if scan_ports:
        for p in SCAN_PORTS:
            sep_parts.append("─" * (max(4, len(f":{p}")) + 2))

    vb  = c("│", GRY)
    top = c("┌" + "┬".join(sep_parts) + "┐", GRY)
    sep = c("├" + "┼".join(sep_parts) + "┤", GRY)
    bot = c("└" + "┴".join(sep_parts) + "┘", GRY)

    def _row(cells):
        return vb + vb.join(f" {cell} " for cell in cells) + vb

    hdr = [
        c(pad("IP Address", w_ip,  "<"), BOLD, WHT),
        c(pad("MAC",        w_mac, "<"), BOLD, WHT),
        c(pad("Vendor",     w_vnd, "<"), BOLD, WHT),
        c(pad("Hostname",   w_hn,  "<"), BOLD, WHT),
    ]
    if scan_ports:
        for p in SCAN_PORTS:
            lbl = f":{p}"
            hdr.append(c(pad(lbl, max(4, len(lbl)), "^"), BOLD, WHT))

    print(f"\n  {c('Scan results', BOLD, WHT)}  "
          f"{c(utc_now(), GRY)}  "
          f"{c(f'{elapsed:.1f}s', DIM)}\n")
    print(top)
    print(_row(hdr))
    print(sep)

    for host in hosts:
        vendor   = lookup_vendor(host["mac"])
        hostname = host.get("hostname") or "—"
        cells = [
            c(pad(host["ip"], w_ip,  "<"), WHT),
            c(pad(host["mac"], w_mac, "<"), CYN),
            c(pad(vendor,   w_vnd, "<"), YEL),
            c(pad(hostname, w_hn,  "<"), GREEN),
        ]
        if scan_ports:
            port_map = {r["port"]: r for r in host.get("ports", [])}
            for p in SCAN_PORTS:
                w   = max(4, len(f":{p}"))
                res = port_map.get(p, {})
                if res.get("state") == "open":
                    cells.append(c(pad("OPEN", w, "^"), BOLD, GREEN))
                else:
                    cells.append(c(pad("·",    w, "^"), DIM))
        print(_row(cells))

    print(bot)

    # Summary line
    open_hosts = sum(
        1 for h in hosts
        if any(r["state"] == "open" for r in h.get("ports", []))
    ) if scan_ports else 0

    print(f"\n  {c('Hosts found', GRY)}  {c(str(len(hosts)), BOLD, WHT)}", end="")
    if scan_ports:
        print(f"   {c('With open ports', GRY)}  {c(str(open_hosts), BOLD, GREEN)}", end="")
    print("\n")


def scan_network(network: str, scan_ports: bool = False) -> list[dict]:
    """
    Full pipeline: validate → ARP discover → (optional) port scan → print table.

    Returns list of host dicts.
    """
    if not is_valid_cidr(network):
        raise ValueError(f"Invalid network: {network!r}  (expected CIDR like 192.168.1.0/24)")

    print(f"\n  {c('Scanning', GRY)}  {c(network, CYN, BOLD)}", end="")
    if scan_ports:
        print(f"  {c('+ port scan', GRY)}  "
              f"{c(' '.join(str(p) for p in SCAN_PORTS), DIM)}", end="")
    print("\n")

    t_start = time.perf_counter()

    # Phase 1: ARP discovery
    print(f"  {c('[1/3]', GRY)} ARP sweep …", end="", flush=True)
    hosts = arp_scan(network)
    print(f"  {c(str(len(hosts)), BOLD, GREEN)} hosts")

    # Phase 2: Vendor lookup
    print(f"  {c('[2/3]', GRY)} Vendor lookup …", end="", flush=True)
    for h in hosts:
        h["vendor"] = lookup_vendor(h["mac"])
    print(f"  {c('done', DIM)}")

    # Phase 3: Port scan (optional)
    if scan_ports:
        print(f"  {c('[3/3]', GRY)} Port scanning {len(hosts)} hosts …", end="", flush=True)
        for h in hosts:
            h["ports"] = port_scan(h["ip"])
        print(f"  {c('done', DIM)}")
    else:
        print(f"  {c('[3/3]', GRY)} Port scan skipped  {c('(use --ports)', GRY)}")
        for h in hosts:
            h["ports"] = []

    elapsed = time.perf_counter() - t_start
    _print_results(hosts, scan_ports, elapsed)
    return hosts
