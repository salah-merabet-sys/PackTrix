"""
sniffer.py  –  Live packet capture
===================================
Captures packets (real via Scapy when root, simulated otherwise) and
streams them to the terminal in a compact scrolling table.

Ctrl+C exits cleanly and prints a summary.
"""

import random
import signal
import sys
import time
import threading
import queue
from datetime import datetime
from typing import Optional

from packtrix.utils import port_service, utc_now
from packtrix._display import (
    c, pad, vlen, proto_colour, sev_colour, term_size,
    RST, BOLD, DIM, GRY, WHT, CYN, GREEN, YEL, MAG, RED, BRED,
)

# ── Protocol weights for simulated traffic ─────────────────────────────────
_PROTO_WEIGHTS = [("TCP", 55), ("UDP", 30), ("ICMP", 10), ("ARP", 5)]
_IPS = [
    "192.168.1.1",  "192.168.1.10", "192.168.1.42",
    "192.168.1.99", "10.0.0.5",     "8.8.8.8",
]


def _weighted_choice(choices):
    total  = sum(w for _, w in choices)
    r      = random.uniform(0, total)
    upto   = 0
    for item, weight in choices:
        upto += weight
        if r <= upto:
            return item
    return choices[-1][0]


# ── Placeholder stream ─────────────────────────────────────────────────────

def _placeholder_stream(filter_proto: str | None = None):
    """Yield realistic simulated packet dicts forever."""
    tcp_pairs = [(random.randint(49152, 65535), p, s) for p, s in [
        (80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (3306, "MySQL"),
    ]]
    udp_pairs = [(random.randint(49152, 65535), p, s) for p, s in [
        (53, "DNS"), (67, "DHCP"), (123, "NTP"),
    ]]
    flags_seq = ["SYN", "SYN|ACK", "ACK", "PSH|ACK", "FIN|ACK", "RST"]

    f = filter_proto.upper() if filter_proto else None

    while True:
        proto = _weighted_choice(_PROTO_WEIGHTS)
        if f and proto != f:
            continue

        src = random.choice(_IPS)
        dst = random.choice([i for i in _IPS if i != src])
        now = time.time()

        if proto == "TCP":
            pair = random.choice(tcp_pairs)
            yield {
                "timestamp": now, "src_ip": src, "dst_ip": dst,
                "src_port": random.randint(49152, 65535), "dst_port": pair[1],
                "protocol": "TCP", "service": pair[2],
                "size": random.randint(54, 1514),
                "flags": random.choice(flags_seq),
                "info": f"{src} -> {dst}:{pair[1]} [{random.choice(flags_seq)}]",
            }
        elif proto == "UDP":
            pair = random.choice(udp_pairs)
            yield {
                "timestamp": now, "src_ip": src, "dst_ip": dst,
                "src_port": random.randint(49152, 65535), "dst_port": pair[1],
                "protocol": "UDP", "service": pair[2],
                "size": random.randint(28, 512),
                "flags": "", "info": f"{src} -> {dst}:{pair[1]} {pair[2]}",
            }
        elif proto == "ICMP":
            yield {
                "timestamp": now, "src_ip": src, "dst_ip": dst,
                "src_port": None, "dst_port": None,
                "protocol": "ICMP", "service": "ICMP",
                "size": random.randint(28, 84),
                "flags": "", "info": f"{src} -> {dst}  Echo",
            }
        else:  # ARP
            yield {
                "timestamp": now, "src_ip": src, "dst_ip": dst,
                "src_port": None, "dst_port": None,
                "protocol": "ARP", "service": "ARP",
                "size": 42, "flags": "",
                "info": f"{src} -> {dst}  Who has?",
            }

        # Inter-packet delay – gives Ctrl+C a chance to land
        time.sleep(random.uniform(0.08, 0.35))


# ── Scapy packet parser ────────────────────────────────────────────────────

def parse_packet(pkt) -> dict:
    """Decode a raw Scapy packet into a standard packet dict."""
    try:
        from scapy.all import IP, TCP, UDP, ICMP, ARP as ScapyARP  # type: ignore
        ts = float(getattr(pkt, "time", time.time()))
        sz = len(pkt)
        src_ip = dst_ip = ""
        src_port = dst_port = None
        proto = "OTHER"; service = "unknown"; flags = ""; info = ""; payload = ""

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if pkt.haslayer(TCP):
                proto    = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                service  = port_service(dst_port)
                flag_map = {0x02:"SYN",0x10:"ACK",0x04:"RST",
                            0x01:"FIN",0x08:"PSH",0x12:"SYN|ACK"}
                flags    = flag_map.get(int(pkt[TCP].flags), str(pkt[TCP].flags))
                info     = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flags}]"
            elif pkt.haslayer(UDP):
                proto    = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                service  = port_service(dst_port)
                info     = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} {service}"
            elif pkt.haslayer(ICMP):
                proto   = "ICMP"; service = "ICMP"
                info    = f"{src_ip} -> {dst_ip} ICMP"
        elif pkt.haslayer(ScapyARP):
            proto  = "ARP"; service = "ARP"
            src_ip = pkt[ScapyARP].psrc
            dst_ip = pkt[ScapyARP].pdst
            info   = f"{src_ip} -> {dst_ip} ARP"

        return {
            "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": proto, "service": service,
            "size": sz, "flags": flags, "info": info, "payload": payload,
        }
    except Exception:
        return {
            "timestamp": time.time(), "src_ip": "", "dst_ip": "",
            "src_port": None, "dst_port": None,
            "protocol": "OTHER", "service": "unknown",
            "size": 0, "flags": "", "info": "parse error", "payload": "",
        }


# ── Display ────────────────────────────────────────────────────────────────

# Fixed column widths
_W = {"no":5, "time":12, "src":21, "dst":21,
      "proto":6, "svc":10, "size":6, "flags":9}


def _hdr() -> str:
    vb = c("│", GRY)
    cols = [
        (pad("No.",   _W["no"],    ">"), BOLD + GRY),
        (pad("Time",  _W["time"],  "<"), BOLD + WHT),
        (pad("Source",_W["src"],   "<"), BOLD + WHT),
        (pad("Dest",  _W["dst"],   "<"), BOLD + WHT),
        (pad("Proto", _W["proto"], "^"), BOLD + WHT),
        (pad("Svc",   _W["svc"],   "<"), BOLD + WHT),
        (pad("Bytes", _W["size"],  ">"), BOLD + WHT),
        (pad("Flags", _W["flags"], "<"), BOLD + WHT),
    ]
    cells = [f" {c(txt, col)} " for txt, col in cols]
    return vb + vb.join(cells) + vb


def _sep(top=False, bot=False) -> str:
    segs = ["─" * (v + 2) for v in _W.values()]
    if top:
        return c("┌" + "┬".join(segs) + "┐", GRY)
    if bot:
        return c("└" + "┴".join(segs) + "┘", GRY)
    return c("├" + "┼".join(segs) + "┤", GRY)


def _row(idx: int, pkt: dict) -> str:
    proto = pkt["protocol"]
    pc    = proto_colour(proto)
    vb    = c("│", GRY)

    ts = datetime.fromtimestamp(pkt["timestamp"]).strftime("%H:%M:%S.") + \
         f"{datetime.fromtimestamp(pkt['timestamp']).microsecond // 1000:03d}"

    src = pkt["src_ip"]
    if pkt.get("src_port"):
        src += f":{pkt['src_port']}"
    dst = pkt["dst_ip"]
    if pkt.get("dst_port"):
        dst += f":{pkt['dst_port']}"

    flags = pkt.get("flags", "")

    cells = [
        f" {c(pad(str(idx), _W['no'],    '>'), GRY)} ",
        f" {c(pad(ts,       _W['time'],  '<'), DIM)} ",
        f" {c(pad(src,      _W['src'],   '<'), WHT)} ",
        f" {c(pad(dst,      _W['dst'],   '<'), GRY)} ",
        f" {c(pad(proto,    _W['proto'], '^'), BOLD + pc)} ",
        f" {c(pad(pkt['service'], _W['svc'], '<'), pc)} ",
        f" {c(pad(str(pkt['size']), _W['size'], '>'), DIM)} ",
        f" {c(pad(flags,    _W['flags'], '<'), DIM)} ",
    ]
    return vb + vb.join(cells) + vb


# ── Main capture function ──────────────────────────────────────────────────

def capture_packets(
    interface:    str       = "eth0",
    filter:       str | None = None,
    packet_limit: int       = 0,
    show_header:  bool      = True,
) -> list[dict]:
    """
    Capture packets and stream them to the terminal.

    Press Ctrl+C to stop. When packet_limit is set the capture stops
    automatically after that many packets.

    Args:
        interface:    Network interface (used with real Scapy capture).
        filter:       Protocol filter: 'tcp', 'udp', 'icmp', or None for all.
        packet_limit: Stop after N packets (0 = unlimited).
        show_header:  Print table header and footer.

    Returns:
        List of captured packet dicts.
    """
    filter_upper = filter.upper() if filter else None
    if filter and filter.lower() not in {"tcp", "udp", "icmp"}:
        raise ValueError(
            f"Unsupported filter '{filter}'. Use: tcp, udp, icmp, or leave blank."
        )

    # ── Announce ────────────────────────────────────────────────────────
    print(f"\n  {c('Interface', GRY)}  {c(interface, CYN, BOLD)}")
    print(f"  {c('Filter   ', GRY)}  {c(filter_upper or 'ALL', BOLD, WHT)}")
    print(f"  {c('Limit    ', GRY)}  "
          f"{c(str(packet_limit) if packet_limit else 'unlimited', DIM)}")
    print(f"  {c('Source   ', GRY)}  {c('simulated data', YEL)}  "
          f"{c('(install scapy + sudo for live capture)', GRY)}")
    print(f"\n  {c('Press Ctrl+C to stop', GRY)}\n")

    # ── Try real Scapy capture ──────────────────────────────────────────
    pkt_queue: queue.Queue = queue.Queue()
    use_real  = False

    try:
        import os
        from scapy.all import sniff as _sniff, conf  # type: ignore
        if os.geteuid() != 0:
            raise PermissionError("root required")
        conf.verb = 0
        use_real  = True

        _stop_sniff = threading.Event()

        def _cb(pkt):
            pkt_queue.put(parse_packet(pkt))

        threading.Thread(
            target=_sniff,
            kwargs={
                "iface": interface,
                "filter": filter.lower() if filter else "",
                "prn": _cb,
                "store": False,
                "stop_filter": lambda _: _stop_sniff.is_set(),
            },
            daemon=True,
        ).start()

        print(f"  {c('Source', GRY)}  {c('LIVE – Scapy', GREEN, BOLD)}  "
              f"{c(interface, CYN)}\n")

    except ImportError:
        print(f"  {c('[i]', YEL)} Scapy not installed – using simulated data.\n")
    except PermissionError:
        print(f"  {c('[i]', YEL)} Run with sudo for live capture – using simulated data.\n")
    except Exception as e:
        print(f"  {c('[!]', YEL)} Scapy error ({e}) – using simulated data.\n")

    # ── Interrupt flag ──────────────────────────────────────────────────
    _stop = False

    def _sigint(sig, frame):
        nonlocal _stop
        _stop = True

    orig = signal.signal(signal.SIGINT, _sigint)

    # ── Header ──────────────────────────────────────────────────────────
    if show_header:
        print(_sep(top=True))
        print(_hdr())
        print(_sep())

    # ── Packet source ───────────────────────────────────────────────────
    sim_gen = None if use_real else _placeholder_stream(filter_proto=filter_upper)

    captured  = []
    counters  = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
    total_b   = 0
    idx       = 0
    t_start   = time.perf_counter()

    try:
        while not _stop:
            if use_real:
                try:
                    pkt = pkt_queue.get(timeout=0.15)
                except queue.Empty:
                    continue
            else:
                # Non-blocking next: run generator on thread so Ctrl+C
                # is checked every 0.1 s even during the inter-packet sleep
                result_q: queue.Queue = queue.Queue(1)

                def _advance():
                    try:
                        result_q.put(("ok", next(sim_gen)))
                    except StopIteration:
                        result_q.put(("stop", None))

                threading.Thread(target=_advance, daemon=True).start()

                pkt = None
                while pkt is None and not _stop:
                    try:
                        status, val = result_q.get(timeout=0.1)
                        if status == "stop":
                            _stop = True
                        else:
                            pkt = val
                    except queue.Empty:
                        continue

                if pkt is None:
                    break

            if _stop:
                break

            if packet_limit and idx >= packet_limit:
                break

            idx += 1
            proto_key = pkt["protocol"] if pkt["protocol"] in counters else "OTHER"
            counters[proto_key] += 1
            total_b += pkt.get("size", 0)
            captured.append(pkt)
            print(_row(idx, pkt))

    finally:
        signal.signal(signal.SIGINT, orig)
        if use_real:
            _stop_sniff.set()

    # ── Footer ──────────────────────────────────────────────────────────
    if show_header:
        print(_sep(bot=True))

    elapsed = time.perf_counter() - t_start

    if _stop and not (packet_limit and idx >= packet_limit):
        print(f"\n  {c('[!]', YEL, BOLD)} Stopped by user")

    # Summary
    print(f"\n  {c('─' * 40, GRY)}")
    print(f"  {c('Packets captured', GRY)}  {c(str(idx), BOLD, WHT)}")
    print(f"  {c('Elapsed         ', GRY)}  {c(f'{elapsed:.1f}s', WHT)}")
    print(f"  {c('Total bytes     ', GRY)}  {c(f'{total_b:,}', WHT)}")
    for proto, cnt in counters.items():
        if cnt:
            pc = proto_colour(proto)
            print(f"  {c(f'{proto:<7}', GRY)}  {c(str(cnt), pc, BOLD)}")
    print(f"  {c('─' * 40, GRY)}\n")

    return captured


# ── pcap I/O ───────────────────────────────────────────────────────────────

def save_pcap(packets: list, filepath: str) -> None:
    """Save packets to .pcap (Scapy) or .json fallback."""
    try:
        from scapy.all import wrpcap  # type: ignore
        wrpcap(filepath, packets)
        print(f"  Saved {len(packets)} packets → {filepath}")
    except (ImportError, TypeError):
        import json, pathlib
        fp = str(pathlib.Path(filepath).with_suffix(".json"))
        with open(fp, "w") as fh:
            json.dump(packets, fh, indent=2, default=str)
        print(f"  Saved {len(packets)} packet records (JSON) → {fp}")


def load_pcap(filepath: str) -> list[dict]:
    """Load packets from .pcap or .json."""
    import pathlib
    path = pathlib.Path(filepath)
    if path.suffix.lower() == ".json":
        import json
        with open(path) as fh:
            return json.load(fh)
    try:
        from scapy.all import rdpcap  # type: ignore
        return [parse_packet(p) for p in rdpcap(str(path))]
    except ImportError:
        print("  [!] Scapy not installed. Use a JSON packet dump.")
        return []
