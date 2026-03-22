"""
sniffer.py  –  Live packet capture and deep packet inspection
==============================================================
Captures packets (real via Scapy when root, simulated otherwise).

Capture modes:
    capture_packets()   Live scrolling packet feed
    stream_capture()    Background capture into a list (non-blocking)

Deep inspection:
    parse_packet()      Full 802.11 / IP / TCP / UDP / ICMP / ARP decode
    inspect_http()      Extract HTTP method, URL, headers, body
    inspect_dns()       Extract DNS queries and answers
    inspect_tls()       Extract TLS version, SNI, cipher from handshake
    inspect_arp()       Detect ARP spoofing from ARP packets
    reassemble_tcp()    Reconstruct TCP streams from individual packets

Filters:
    BPF filter strings passed directly to Scapy / libpcap kernel filter
    Examples: 'tcp port 80', 'udp port 53', 'icmp', 'host 192.168.1.1'

Ctrl+C exits cleanly and prints a summary.
"""

import random
import signal
import sys
import time
import threading
import queue
import struct
from collections import defaultdict
from datetime import datetime
from typing import Optional

from packtrix.utils import port_service, utc_now
from packtrix._display import (
    c, pad, proto_colour, term_size,
    BOLD, DIM, GRY, WHT, CYN, GREEN, YEL, MAG, RED, BRED,
)

# ── Protocol weights for simulated traffic ─────────────────────────────────
_PROTO_WEIGHTS = [("TCP", 55), ("UDP", 25), ("ICMP", 10),
                  ("ARP", 5),  ("DNS", 5)]
_IPS = [
    "192.168.1.1", "192.168.1.10", "192.168.1.42",
    "192.168.1.99", "10.0.0.5",    "8.8.8.8",
    "1.1.1.1",      "172.16.0.1",
]


def _weighted_choice(choices: list) -> str:
    total = sum(w for _, w in choices)
    r     = random.uniform(0, total)
    upto  = 0
    for item, weight in choices:
        upto += weight
        if r <= upto:
            return item
    return choices[-1][0]


# ═══════════════════════════════════════════════════════════════════════════
# PLACEHOLDER STREAM  (demo mode without Scapy / root)
# ═══════════════════════════════════════════════════════════════════════════

def _placeholder_stream(filter_expr: str | None = None):
    """
    Generate realistic simulated packet dicts indefinitely.

    filter_expr is matched loosely — 'tcp', 'udp', 'icmp', 'arp',
    or a BPF-style 'port 80', 'host 1.2.3.4' (simple matching only).
    """
    tcp_pairs  = [(random.randint(49152, 65535), p, s) for p, s in [
        (80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (3306, "MySQL"),
        (5432, "PostgreSQL"), (8080, "HTTP-ALT"), (25, "SMTP"),
    ]]
    udp_pairs  = [(random.randint(49152, 65535), p, s) for p, s in [
        (53, "DNS"), (67, "DHCP"), (123, "NTP"), (161, "SNMP"),
    ]]
    flags_seq  = ["SYN", "SYN|ACK", "ACK", "PSH|ACK", "FIN|ACK", "RST"]
    dns_names  = ["google.com", "cloudflare.com", "github.com",
                  "amazon.com", "netflix.com", "reddit.com"]

    proto_filter = None
    port_filter  = None
    host_filter  = None

    if filter_expr:
        fe = filter_expr.lower().strip()
        if fe in ("tcp", "udp", "icmp", "arp"):
            proto_filter = fe.upper()
        elif "port" in fe:
            try:
                port_filter = int(fe.split("port")[-1].strip())
            except ValueError:
                pass
        elif "host" in fe:
            host_filter = fe.split("host")[-1].strip()

    while True:
        proto = _weighted_choice(_PROTO_WEIGHTS)
        src   = random.choice(_IPS)
        dst   = random.choice([i for i in _IPS if i != src])
        now   = time.time()

        # Apply filters
        if proto_filter and proto != proto_filter:
            continue
        if host_filter and host_filter not in (src, dst):
            continue

        pkt = None

        if proto in ("TCP", "HTTPS"):
            pair = random.choice(tcp_pairs)
            sp   = random.randint(49152, 65535)
            dp   = pair[1]
            if port_filter and port_filter not in (sp, dp):
                continue
            flags = random.choice(flags_seq)
            pkt = {
                "timestamp": now, "src_ip": src, "dst_ip": dst,
                "src_port": sp, "dst_port": dp,
                "protocol": "TCP", "service": pair[2],
                "size": random.randint(54, 1514),
                "flags": flags,
                "info": f"{src}:{sp} -> {dst}:{dp} [{flags}]",
                "payload": b"",
                "layer7": {},
            }
            # Simulate HTTP payload on port 80
            if dp == 80 and "PSH" in flags:
                methods = ["GET", "POST", "HEAD"]
                urls    = ["/", "/index.html", "/api/data", "/login"]
                method  = random.choice(methods)
                url     = random.choice(urls)
                pkt["payload"] = (
                    f"{method} {url} HTTP/1.1\r\n"
                    f"Host: {dst}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                ).encode()
                pkt["layer7"] = {
                    "type": "http",
                    "method": method,
                    "url": url,
                    "host": dst,
                }

        elif proto == "UDP":
            pair = random.choice(udp_pairs)
            sp   = random.randint(49152, 65535)
            dp   = pair[1]
            if port_filter and port_filter not in (sp, dp):
                continue
            pkt = {
                "timestamp": now, "src_ip": src, "dst_ip": dst,
                "src_port": sp, "dst_port": dp,
                "protocol": "UDP", "service": pair[2],
                "size": random.randint(28, 512),
                "flags": "", "payload": b"",
                "info": f"{src}:{sp} -> {dst}:{dp} {pair[2]}",
                "layer7": {},
            }

        elif proto == "DNS":
            if port_filter and port_filter != 53:
                continue
            name = random.choice(dns_names)
            pkt = {
                "timestamp": now, "src_ip": src, "dst_ip": "8.8.8.8",
                "src_port": random.randint(49152, 65535), "dst_port": 53,
                "protocol": "UDP", "service": "DNS",
                "size": random.randint(40, 80),
                "flags": "", "payload": b"",
                "info": f"DNS query: {name}",
                "layer7": {"type": "dns", "query": name,
                            "qtype": "A", "answers": []},
            }

        elif proto == "ICMP":
            if port_filter:
                continue
            icmp_types = ["Echo Request", "Echo Reply",
                          "Dest Unreachable", "Time Exceeded"]
            t = random.choice(icmp_types)
            pkt = {
                "timestamp": now, "src_ip": src, "dst_ip": dst,
                "src_port": None, "dst_port": None,
                "protocol": "ICMP", "service": "ICMP",
                "size": random.randint(28, 84),
                "flags": "", "payload": b"",
                "info": f"{src} -> {dst}  ICMP {t}",
                "layer7": {"type": "icmp", "icmp_type": t},
            }

        else:  # ARP
            if proto_filter and proto_filter != "ARP":
                continue
            op = random.choice(["Who has?", "Is at"])
            pkt = {
                "timestamp": now, "src_ip": src, "dst_ip": dst,
                "src_port": None, "dst_port": None,
                "protocol": "ARP", "service": "ARP",
                "size": 42, "flags": "", "payload": b"",
                "info": f"{src} -> {dst}  ARP {op}",
                "layer7": {"type": "arp", "operation": op},
            }

        if pkt:
            yield pkt

        time.sleep(random.uniform(0.08, 0.30))


# ═══════════════════════════════════════════════════════════════════════════
# DEEP PACKET INSPECTION
# ═══════════════════════════════════════════════════════════════════════════

def inspect_http(payload: bytes) -> dict:
    """
    Extract HTTP information from a TCP payload.

    Parses both requests (GET /path HTTP/1.1) and responses
    (HTTP/1.1 200 OK). Extracts headers and body.

    Args:
        payload: raw TCP payload bytes

    Returns:
        dict with keys: type, method, url, status, host, content_type,
                        content_length, headers, body_preview
        Empty dict if not HTTP traffic.
    """
    if not payload:
        return {}

    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return {}

    if not text.startswith(("GET ", "POST ", "PUT ", "DELETE ",
                             "HEAD ", "PATCH ", "OPTIONS ",
                             "HTTP/1.", "HTTP/2")):
        return {}

    result = {"type": "http", "headers": {}}
    lines  = text.split("\r\n")
    if not lines:
        return {}

    first = lines[0]

    # Request: METHOD URL HTTP/version
    if any(first.startswith(m) for m in
           ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS")):
        parts = first.split(" ")
        result["direction"] = "request"
        result["method"]    = parts[0] if parts else ""
        result["url"]       = parts[1] if len(parts) > 1 else ""
        result["version"]   = parts[2] if len(parts) > 2 else ""

    # Response: HTTP/version STATUS message
    elif first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        result["direction"] = "response"
        result["version"]   = parts[0] if parts else ""
        result["status"]    = parts[1] if len(parts) > 1 else ""
        result["reason"]    = parts[2] if len(parts) > 2 else ""

    # Parse headers
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line == "":
            body_start = i + 1
            break
        if ":" in line:
            key, val = line.split(":", 1)
            result["headers"][key.strip().lower()] = val.strip()

    result["host"]           = result["headers"].get("host", "")
    result["content_type"]   = result["headers"].get("content-type", "")
    result["content_length"] = result["headers"].get("content-length", "")

    # Body preview (first 200 chars)
    if body_start and body_start < len(lines):
        body = "\r\n".join(lines[body_start:])
        result["body_preview"] = body[:200]
    else:
        result["body_preview"] = ""

    return result


def inspect_dns(payload: bytes) -> dict:
    """
    Parse a DNS packet payload (UDP payload starting at DNS header).

    DNS wire format (RFC 1035):
        Header: 12 bytes
            ID (2), Flags (2), QDCount (2), ANCount (2),
            NSCount (2), ARCount (2)
        Questions section
        Answers section

    Args:
        payload: UDP payload bytes starting at DNS header

    Returns:
        dict with keys: transaction_id, is_response, questions, answers
        Empty dict if parse fails.
    """
    if len(payload) < 12:
        return {}

    try:
        txid  = struct.unpack("!H", payload[0:2])[0]
        flags = struct.unpack("!H", payload[2:4])[0]
        qd    = struct.unpack("!H", payload[4:6])[0]
        an    = struct.unpack("!H", payload[6:8])[0]

        is_response = bool(flags & 0x8000)
        rcode       = flags & 0x000F
        rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
                       3: "NXDOMAIN", 4: "NOTIMP",  5: "REFUSED"}

        def _read_name(data: bytes, offset: int) -> tuple[str, int]:
            """Read a DNS name from wire format, handling compression."""
            parts   = []
            visited = set()
            while offset < len(data):
                if offset in visited:
                    break
                visited.add(offset)
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                elif (length & 0xC0) == 0xC0:   # pointer
                    ptr    = ((length & 0x3F) << 8) | data[offset + 1]
                    name, _ = _read_name(data, ptr)
                    parts.append(name)
                    offset += 2
                    break
                else:
                    offset += 1
                    parts.append(data[offset:offset + length].decode(
                        "ascii", errors="replace"))
                    offset += length
            return ".".join(parts), offset

        questions = []
        offset    = 12

        for _ in range(qd):
            name, offset = _read_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype  = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 4

            qtype_names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
                           15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
                           255: "ANY"}
            questions.append({
                "name":  name,
                "type":  qtype_names.get(qtype, str(qtype)),
            })

        answers = []
        for _ in range(an):
            if offset >= len(payload):
                break
            name, offset = _read_name(payload, offset)
            if offset + 10 > len(payload):
                break
            atype  = struct.unpack("!H", payload[offset:offset+2])[0]
            rdlen  = struct.unpack("!H", payload[offset+8:offset+10])[0]
            offset += 10

            rdata = payload[offset:offset + rdlen]
            offset += rdlen

            value = ""
            if atype == 1 and rdlen == 4:     # A record
                value = ".".join(str(b) for b in rdata)
            elif atype == 28 and rdlen == 16: # AAAA record
                value = ":".join(
                    f"{struct.unpack('!H', rdata[i:i+2])[0]:04x}"
                    for i in range(0, 16, 2)
                )
            elif atype in (2, 5, 12):         # NS, CNAME, PTR
                value, _ = _read_name(payload, offset - rdlen)

            qtype_names = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR",
                           15: "MX", 16: "TXT", 28: "AAAA"}
            answers.append({
                "name":  name,
                "type":  qtype_names.get(atype, str(atype)),
                "value": value,
            })

        return {
            "type":           "dns",
            "transaction_id": txid,
            "is_response":    is_response,
            "rcode":          rcode_names.get(rcode, str(rcode)),
            "questions":      questions,
            "answers":        answers,
        }

    except Exception:
        return {}


def inspect_tls(payload: bytes) -> dict:
    """
    Parse TLS handshake metadata from a TCP payload.

    Reads the TLS record header and ClientHello to extract:
        - TLS record version
        - Handshake type
        - SNI (Server Name Indication) — the hostname the client is connecting to
        - Offered cipher suites

    This only works on the first packet of a TLS connection (ClientHello).
    Encrypted application data cannot be read without the private key.

    Args:
        payload: raw TCP payload bytes

    Returns:
        dict with keys: type, tls_version, handshake_type, sni, ciphers
        Empty dict if not a TLS ClientHello.
    """
    if len(payload) < 6:
        return {}

    # TLS record: content_type(1) version(2) length(2)
    content_type = payload[0]
    if content_type != 0x16:   # 0x16 = Handshake
        return {}

    version_major = payload[1]
    version_minor = payload[2]

    version_map = {
        (3, 1): "TLS 1.0",
        (3, 2): "TLS 1.1",
        (3, 3): "TLS 1.2",
        (3, 4): "TLS 1.3",
    }
    version = version_map.get(
        (version_major, version_minor),
        f"TLS {version_major}.{version_minor}"
    )

    if len(payload) < 6:
        return {}

    handshake_type = payload[5]
    ht_names = {
        0x01: "ClientHello",
        0x02: "ServerHello",
        0x0B: "Certificate",
        0x0C: "ServerKeyExchange",
        0x0E: "ServerHelloDone",
        0x10: "ClientKeyExchange",
        0x14: "Finished",
    }
    ht_name = ht_names.get(handshake_type, f"type={handshake_type:#x}")

    sni     = ""
    ciphers = []

    # Parse ClientHello for SNI and cipher suites
    if handshake_type == 0x01 and len(payload) > 43:
        try:
            offset = 9    # skip record header(5) + handshake header(4)

            # Skip client version(2) + random(32) = 34 bytes
            offset += 34

            # Session ID length
            if offset < len(payload):
                sid_len  = payload[offset]
                offset  += 1 + sid_len

            # Cipher suites length
            if offset + 2 <= len(payload):
                cs_len  = struct.unpack("!H",
                    payload[offset:offset+2])[0]
                offset += 2

                # Read cipher suite IDs
                for i in range(0, cs_len, 2):
                    if offset + i + 2 <= len(payload):
                        cs_id = struct.unpack("!H",
                            payload[offset+i:offset+i+2])[0]
                        ciphers.append(f"{cs_id:#06x}")
                offset += cs_len

            # Compression methods
            if offset < len(payload):
                comp_len  = payload[offset]
                offset   += 1 + comp_len

            # Extensions
            if offset + 2 <= len(payload):
                ext_total = struct.unpack("!H",
                    payload[offset:offset+2])[0]
                offset   += 2
                ext_end   = offset + ext_total

                while offset + 4 <= ext_end and offset + 4 <= len(payload):
                    ext_type = struct.unpack("!H",
                        payload[offset:offset+2])[0]
                    ext_len  = struct.unpack("!H",
                        payload[offset+2:offset+4])[0]
                    offset  += 4

                    # Extension 0x0000 = SNI
                    if ext_type == 0x0000 and offset + 5 <= len(payload):
                        list_len  = struct.unpack("!H",
                            payload[offset:offset+2])[0]
                        name_type = payload[offset+2]
                        if name_type == 0:   # host_name
                            name_len = struct.unpack("!H",
                                payload[offset+3:offset+5])[0]
                            sni = payload[
                                offset+5:offset+5+name_len
                            ].decode("ascii", errors="replace")

                    offset += ext_len

        except Exception:
            pass

    return {
        "type":           "tls",
        "tls_version":    version,
        "handshake_type": ht_name,
        "sni":            sni,
        "ciphers":        ciphers[:5],   # first 5 only
    }


def inspect_arp(pkt: dict, arp_table: dict) -> dict | None:
    """
    Detect ARP spoofing by comparing ARP replies against a known table.

    ARP spoofing works by sending gratuitous ARP replies that map the
    attacker's MAC to a victim's IP, intercepting all traffic destined
    for that IP. This function detects when a MAC address changes for
    a previously seen IP.

    Args:
        pkt:       packet dict from parse_packet()
        arp_table: {ip: mac} dict maintained across calls (mutated here)

    Returns:
        Alert dict if spoofing detected, None otherwise.
    """
    if pkt.get("protocol") != "ARP":
        return None

    layer7 = pkt.get("layer7", {})
    if not layer7:
        return None

    ip  = pkt.get("src_ip", "")
    mac = pkt.get("src_mac", "")   # populated by parse_packet from Scapy

    if not ip or not mac or mac == "ff:ff:ff:ff:ff:ff":
        return None

    if ip in arp_table:
        if arp_table[ip] != mac:
            return {
                "alert_type":  "ARP_SPOOF",
                "severity":    "HIGH",
                "src_ip":      ip,
                "dst_ip":      "",
                "dst_port":    None,
                "event_count": 1,
                "detail": (
                    f"IP {ip} changed MAC: "
                    f"{arp_table[ip]} → {mac}  "
                    f"(possible MITM attack)"
                ),
                "rule": "arp_spoof",
            }
    else:
        arp_table[ip] = mac

    return None


class TCPStreamReassembler:
    """
    Reassemble TCP byte streams from individual packets.

    Tracks sequence numbers per TCP connection and reconstructs
    the application-layer data in the correct order, even when
    packets arrive out of order (which is common on busy networks).

    Usage:
        reassembler = TCPStreamReassembler()
        for pkt in packets:
            data = reassembler.add(pkt)
            if data:
                print("Stream data:", data[:100])
        streams = reassembler.get_all_streams()
    """

    def __init__(self, max_streams: int = 100):
        self._streams:   dict = defaultdict(dict)
        self._base_seq:  dict = {}
        self._max        = max_streams

    def _key(self, pkt: dict) -> tuple:
        return (
            pkt.get("src_ip", ""),
            pkt.get("src_port", 0),
            pkt.get("dst_ip", ""),
            pkt.get("dst_port", 0),
        )

    def add(self, pkt: dict) -> bytes | None:
        """
        Add a packet to its stream. Returns reassembled bytes when
        contiguous data is available from the beginning, or None.
        """
        if pkt.get("protocol") != "TCP":
            return None

        payload = pkt.get("payload", b"")
        if not payload:
            return None

        flags = pkt.get("flags", "")
        seq   = pkt.get("seq", 0)
        key   = self._key(pkt)

        # Record base sequence number on SYN
        if "SYN" in flags and key not in self._base_seq:
            self._base_seq[key] = seq + 1
            return None

        base   = self._base_seq.get(key, seq)
        offset = seq - base

        if offset < 0:
            return None

        # Limit total tracked streams
        if len(self._streams) >= self._max and key not in self._streams:
            return None

        self._streams[key][offset] = payload if isinstance(
            payload, bytes) else payload.encode("utf-8", errors="replace")

        # Try to assemble contiguous data from offset 0
        stream  = self._streams[key]
        result  = b""
        current = 0
        while current in stream:
            result  += stream[current]
            current += len(stream[current])

        return result if result else None

    def get_all_streams(self) -> dict:
        """Return all partially or fully reassembled streams."""
        out = {}
        for key, offsets in self._streams.items():
            result  = b""
            current = 0
            while current in offsets:
                result  += offsets[current]
                current += len(offsets[current])
            if result:
                out[key] = result
        return out


# ═══════════════════════════════════════════════════════════════════════════
# PACKET PARSER
# ═══════════════════════════════════════════════════════════════════════════

def parse_packet(pkt) -> dict:
    """
    Decode a raw Scapy packet into a comprehensive packet dict.

    Handles: Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP (partial),
             TLS (ClientHello metadata only).

    Args:
        pkt: raw Scapy packet object

    Returns:
        Packet dict with keys: timestamp, src_ip, dst_ip, src_port,
        dst_port, src_mac, dst_mac, protocol, service, size, flags,
        ttl, seq, ack, info, payload, layer7
    """
    result = {
        "timestamp": time.time(),
        "src_ip":    "", "dst_ip":   "",
        "src_mac":   "", "dst_mac":  "",
        "src_port":  None, "dst_port": None,
        "protocol":  "OTHER", "service": "unknown",
        "size":      0, "flags":  "",
        "ttl":       0, "seq":    0, "ack": 0,
        "info":      "", "payload": b"",
        "layer7":    {},
    }

    try:
        from scapy.all import (  # type: ignore
            IP, IPv6, TCP, UDP, ICMP, ARP as ScapyARP,
            Ether, DNS, DNSQR, DNSRR, Raw,
        )

        result["timestamp"] = float(getattr(pkt, "time", time.time()))
        result["size"]      = len(pkt)

        # Ethernet
        if pkt.haslayer(Ether):
            result["src_mac"] = pkt[Ether].src
            result["dst_mac"] = pkt[Ether].dst

        # IP layer
        if pkt.haslayer(IP):
            result["src_ip"] = pkt[IP].src
            result["dst_ip"] = pkt[IP].dst
            result["ttl"]    = pkt[IP].ttl

            # TCP
            if pkt.haslayer(TCP):
                result["protocol"] = "TCP"
                result["src_port"] = pkt[TCP].sport
                result["dst_port"] = pkt[TCP].dport
                result["service"]  = port_service(pkt[TCP].dport)
                result["seq"]      = pkt[TCP].seq
                result["ack"]      = pkt[TCP].ack

                # Decode TCP flags from bitmask
                f   = int(pkt[TCP].flags)
                fns = []
                if f & 0x02: fns.append("SYN")
                if f & 0x10: fns.append("ACK")
                if f & 0x01: fns.append("FIN")
                if f & 0x04: fns.append("RST")
                if f & 0x08: fns.append("PSH")
                if f & 0x20: fns.append("URG")
                result["flags"] = "|".join(fns)

                # Payload
                payload = b""
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                result["payload"] = payload

                result["info"] = (
                    f"{result['src_ip']}:{result['src_port']} -> "
                    f"{result['dst_ip']}:{result['dst_port']} "
                    f"[{result['flags']}] seq={result['seq']}"
                )

                # Deep inspection
                if payload:
                    dp = result["dst_port"]
                    sp = result["src_port"]

                    if dp in (80, 8080, 8008) or sp in (80, 8080, 8008):
                        http = inspect_http(payload)
                        if http:
                            result["layer7"]  = http
                            result["service"] = "HTTP"

                    elif dp in (443, 8443) or sp in (443, 8443):
                        tls = inspect_tls(payload)
                        if tls:
                            result["layer7"]  = tls
                            result["service"] = "HTTPS/TLS"
                            if tls.get("sni"):
                                result["info"] += f" SNI={tls['sni']}"

            # UDP
            elif pkt.haslayer(UDP):
                result["protocol"] = "UDP"
                result["src_port"] = pkt[UDP].sport
                result["dst_port"] = pkt[UDP].dport
                result["service"]  = port_service(pkt[UDP].dport)

                payload = b""
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                result["payload"] = payload

                result["info"] = (
                    f"{result['src_ip']}:{result['src_port']} -> "
                    f"{result['dst_ip']}:{result['dst_port']} "
                    f"{result['service']}"
                )

                # DNS inspection
                if pkt.haslayer(DNS):
                    dns_pkt = pkt[DNS]
                    questions = []
                    answers   = []

                    for i in range(dns_pkt.qdcount):
                        try:
                            q = dns_pkt.qd
                            for _ in range(i):
                                q = q.payload
                            questions.append({
                                "name":  q.qname.decode(
                                    "ascii", errors="replace").rstrip("."),
                                "type":  {1:"A", 28:"AAAA", 2:"NS",
                                          5:"CNAME", 15:"MX",
                                          16:"TXT"}.get(q.qtype, str(q.qtype))
                            })
                        except Exception:
                            pass

                    for i in range(dns_pkt.ancount):
                        try:
                            a = dns_pkt.an
                            for _ in range(i):
                                a = a.payload
                            answers.append({
                                "name":  getattr(a, "rrname", b"").decode(
                                    "ascii", errors="replace").rstrip("."),
                                "type":  {1:"A", 28:"AAAA"}.get(
                                    getattr(a, "type", 0), "?"),
                                "value": str(getattr(a, "rdata", "")),
                            })
                        except Exception:
                            pass

                    result["layer7"]  = {
                        "type":        "dns",
                        "is_response": bool(dns_pkt.qr),
                        "questions":   questions,
                        "answers":     answers,
                    }
                    result["service"] = "DNS"

                    if questions:
                        q_name  = questions[0]["name"]
                        q_type  = questions[0]["type"]
                        if dns_pkt.qr:
                            ans_str = ", ".join(
                                a["value"] for a in answers[:3]
                            )
                            result["info"] = (
                                f"DNS {q_type} {q_name} → {ans_str}"
                            )
                        else:
                            result["info"] = f"DNS query {q_type} {q_name}"

            # ICMP
            elif pkt.haslayer(ICMP):
                result["protocol"] = "ICMP"
                result["service"]  = "ICMP"
                icmp_type = pkt[ICMP].type
                icmp_code = pkt[ICMP].code
                type_names = {
                    0: "Echo Reply",     3: "Dest Unreachable",
                    8: "Echo Request",  11: "Time Exceeded",
                    5: "Redirect",      13: "Timestamp",
                }
                t_name = type_names.get(icmp_type,
                                        f"type={icmp_type}")
                result["flags"] = t_name
                result["info"]  = (
                    f"{result['src_ip']} -> {result['dst_ip']}  "
                    f"ICMP {t_name} code={icmp_code}"
                )

        # IPv6
        elif pkt.haslayer(IPv6):
            result["src_ip"]   = pkt[IPv6].src
            result["dst_ip"]   = pkt[IPv6].dst
            result["protocol"] = "IPv6"
            result["info"]     = (
                f"{result['src_ip']} -> {result['dst_ip']} IPv6"
            )

        # ARP
        elif pkt.haslayer(ScapyARP):
            result["protocol"] = "ARP"
            result["service"]  = "ARP"
            result["src_ip"]   = pkt[ScapyARP].psrc
            result["dst_ip"]   = pkt[ScapyARP].pdst
            result["src_mac"]  = pkt[ScapyARP].hwsrc
            op = "request" if pkt[ScapyARP].op == 1 else "reply"
            result["layer7"]  = {
                "type":      "arp",
                "operation": op,
                "sender_ip": pkt[ScapyARP].psrc,
                "target_ip": pkt[ScapyARP].pdst,
            }
            result["info"] = (
                f"ARP {op}: {pkt[ScapyARP].psrc} → {pkt[ScapyARP].pdst}"
            )

    except Exception as e:
        result["info"] = f"parse error: {e}"

    return result


# ═══════════════════════════════════════════════════════════════════════════
# DISPLAY
# ═══════════════════════════════════════════════════════════════════════════

_W = {"no": 5, "time": 12, "src": 22, "dst": 22,
      "proto": 6, "svc": 10, "size": 6, "flags": 11}


def _hdr() -> str:
    vb   = c("│", GRY)
    cols = [
        (pad("No.",    _W["no"],    ">"), BOLD + GRY),
        (pad("Time",   _W["time"],  "<"), BOLD + WHT),
        (pad("Source", _W["src"],   "<"), BOLD + WHT),
        (pad("Dest",   _W["dst"],   "<"), BOLD + WHT),
        (pad("Proto",  _W["proto"], "^"), BOLD + WHT),
        (pad("Svc",    _W["svc"],   "<"), BOLD + WHT),
        (pad("Bytes",  _W["size"],  ">"), BOLD + WHT),
        (pad("Flags",  _W["flags"], "<"), BOLD + WHT),
    ]
    cells = [f" {c(txt, col)} " for txt, col in cols]
    return vb + vb.join(cells) + vb


def _sep(top: bool = False, bot: bool = False) -> str:
    segs = ["─" * (v + 2) for v in _W.values()]
    if top: return c("┌" + "┬".join(segs) + "┐", GRY)
    if bot: return c("└" + "┴".join(segs) + "┘", GRY)
    return c("├" + "┼".join(segs) + "┤", GRY)


def _row(idx: int, pkt: dict) -> str:
    """Format one packet as a coloured table row."""
    proto = pkt["protocol"]
    pc    = proto_colour(proto)
    vb    = c("│", GRY)

    dt = datetime.fromtimestamp(pkt["timestamp"])
    ts = dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"

    src = pkt["src_ip"]
    if pkt.get("src_port"):
        src += f":{pkt['src_port']}"
    dst = pkt["dst_ip"]
    if pkt.get("dst_port"):
        dst += f":{pkt['dst_port']}"

    flags   = pkt.get("flags", "")
    service = pkt.get("service", "")

    # Show extra layer7 info in service column
    l7 = pkt.get("layer7", {})
    if l7.get("type") == "http":
        method = l7.get("method", "")
        url    = l7.get("url", "")[:8]
        service = f"{method} {url}".strip()[:10]
    elif l7.get("type") == "dns":
        qs = l7.get("questions", [])
        if qs:
            service = qs[0].get("name", "DNS")[:10]
    elif l7.get("type") == "tls":
        sni = l7.get("sni", "")
        if sni:
            service = sni[:10]

    cells = [
        f" {c(pad(str(idx), _W['no'],    '>'), GRY)} ",
        f" {c(pad(ts,       _W['time'],  '<'), DIM)} ",
        f" {c(pad(src,      _W['src'],   '<'), WHT)} ",
        f" {c(pad(dst,      _W['dst'],   '<'), GRY)} ",
        f" {c(pad(proto,    _W['proto'], '^'), BOLD + pc)} ",
        f" {c(pad(service,  _W['svc'],   '<'), pc)} ",
        f" {c(pad(str(pkt['size']), _W['size'], '>'), DIM)} ",
        f" {c(pad(flags,    _W['flags'], '<'), DIM)} ",
    ]
    return vb + vb.join(cells) + vb


# ═══════════════════════════════════════════════════════════════════════════
# MAIN CAPTURE FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

def capture_packets(
    interface:    str        = "eth0",
    filter:       str | None = None,
    packet_limit: int        = 0,
    show_header:  bool       = True,
    deep_inspect: bool       = False,
    bpf_filter:   str | None = None,
) -> list[dict]:
    """
    Capture packets and stream them to the terminal.

    Args:
        interface:    Network interface for real capture
        filter:       Simple protocol filter: 'tcp', 'udp', 'icmp', 'arp'
        packet_limit: Stop after N packets (0 = unlimited)
        show_header:  Print table header and footer
        deep_inspect: Enable HTTP/DNS/TLS parsing and display
        bpf_filter:   Full BPF filter string (overrides filter if set)
                      e.g. 'tcp port 80', 'host 192.168.1.1 and udp'

    Returns:
        list[dict] of captured packet dicts
    """
    # Resolve filter
    effective_filter = bpf_filter or filter or None
    filter_upper = filter.upper() if filter else None

    if filter and not bpf_filter and \
       filter.lower() not in {"tcp", "udp", "icmp", "arp", "dns"}:
        raise ValueError(
            f"Unsupported filter '{filter}'. "
            "Use: tcp, udp, icmp, arp, dns — or pass bpf_filter= for full BPF."
        )

    # Announce
    print(f"\n  {c('Interface  ', GRY)} {c(interface, CYN, BOLD)}")
    print(f"  {c('Filter     ', GRY)} {c(effective_filter or 'ALL', WHT)}")
    print(f"  {c('Limit      ', GRY)} "
          f"{c(str(packet_limit) if packet_limit else 'unlimited', DIM)}")
    if deep_inspect:
        print(f"  {c('Deep inspect', GRY)} {c('ON', GREEN, BOLD)}"
              f"  {c('(HTTP · DNS · TLS · ARP spoof)', GRY)}")
    print(f"  {c('Press Ctrl+C to stop', GRY)}\n")

    # Try real Scapy capture
    pkt_queue:  queue.Queue = queue.Queue()
    stop_sniff: threading.Event = threading.Event()
    use_real    = False

    try:
        import os
        from scapy.all import sniff as _sniff, conf  # type: ignore
        if os.geteuid() != 0:
            raise PermissionError("root required")
        conf.verb = 0
        use_real  = True

        bpf = bpf_filter or (filter.lower() if filter else "")

        def _cb(pkt):
            pkt_queue.put(parse_packet(pkt))

        threading.Thread(
            target=_sniff,
            kwargs={
                "iface":       interface,
                "filter":      bpf,
                "prn":         _cb,
                "store":       False,
                "stop_filter": lambda _: stop_sniff.is_set(),
            },
            daemon=True,
        ).start()

        print(f"  {c('Source', GRY)}  {c('LIVE – Scapy', GREEN, BOLD)}  "
              f"{c(interface, CYN)}  {c(bpf or 'all traffic', DIM)}\n")

    except ImportError:
        print(f"  {c('[i]', YEL)} Scapy not installed – simulated data\n")
    except PermissionError:
        print(f"  {c('[i]', YEL)} Root required – simulated data\n")
    except Exception as e:
        print(f"  {c('[!]', YEL)} Error: {e} – simulated data\n")

    # Interrupt handler
    _stop = False

    def _sigint(sig, frame):
        nonlocal _stop
        _stop = True

    orig = signal.signal(signal.SIGINT, _sigint)

    # Table header
    if show_header:
        print(_sep(top=True))
        print(_hdr())
        print(_sep())

    # Packet source
    sim_gen = (None if use_real
               else _placeholder_stream(effective_filter))

    # State
    captured  = []
    counters  = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
    total_b   = 0
    idx       = 0
    t_start   = time.perf_counter()
    arp_table: dict = {}   # for ARP spoof detection

    # Optional: TCP stream reassembler
    reassembler = TCPStreamReassembler() if deep_inspect else None

    try:
        while not _stop:
            if use_real:
                try:
                    pkt = pkt_queue.get(timeout=0.15)
                except queue.Empty:
                    continue
            else:
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
            proto_key = pkt["protocol"] if pkt["protocol"] in counters \
                else "OTHER"
            counters[proto_key] += 1
            total_b += pkt.get("size", 0)
            captured.append(pkt)

            # Print main row
            print(_row(idx, pkt))

            # Deep inspection output
            if deep_inspect:
                l7 = pkt.get("layer7", {})
                l7_type = l7.get("type", "")

                if l7_type == "http":
                    method  = l7.get("method", "")
                    url     = l7.get("url", "")
                    host    = l7.get("host", "")
                    status  = l7.get("status", "")
                    if method:
                        print(f"  {c('  ↳ HTTP', CYN)} "
                              f"{c(method, BOLD)} {c(host + url, WHT)}")
                    elif status:
                        print(f"  {c('  ↳ HTTP', CYN)} "
                              f"{c(status, YEL)}")

                elif l7_type == "dns":
                    qs  = l7.get("questions", [])
                    ans = l7.get("answers", [])
                    for q in qs[:2]:
                        print(f"  {c('  ↳ DNS', YEL)} "
                              f"{c('query', GRY)} "
                              f"{c(q.get('name', ''), WHT)} "
                              f"{c(q.get('type', ''), DIM)}")
                    for a in ans[:3]:
                        print(f"  {c('  ↳ DNS', YEL)} "
                              f"{c('answer', GRY)} "
                              f"{c(a.get('name', ''), WHT)} "
                              f"{c('→', GRY)} "
                              f"{c(a.get('value', ''), GREEN)}")

                elif l7_type == "tls":
                    sni = l7.get("sni", "")
                    ver = l7.get("tls_version", "")
                    ht  = l7.get("handshake_type", "")
                    print(f"  {c('  ↳ TLS', BRED)} "
                          f"{c(ht, GRY)} "
                          f"{c(ver, DIM)}"
                          + (f" {c('SNI=' + sni, WHT)}" if sni else ""))

                elif l7_type == "arp":
                    alert = inspect_arp(pkt, arp_table)
                    if alert:
                        print(f"  {c('  ↳ ⚠ ARP SPOOF', RED, BOLD)} "
                              f"{c(alert['detail'], WHT)}")

                # TCP stream reassembly
                if reassembler:
                    data = reassembler.add(pkt)

    finally:
        signal.signal(signal.SIGINT, orig)
        if use_real:
            stop_sniff.set()

    # Footer
    if show_header:
        print(_sep(bot=True))

    elapsed = time.perf_counter() - t_start

    if _stop and not (packet_limit and idx >= packet_limit):
        print(f"\n  {c('[!]', YEL, BOLD)} Stopped by user")

    # Summary
    print(f"\n  {c('─' * 44, GRY)}")
    print(f"  {c('Packets captured', GRY)}  {c(str(idx), BOLD, WHT)}")
    print(f"  {c('Elapsed         ', GRY)}  {c(f'{elapsed:.1f}s', WHT)}")
    print(f"  {c('Total bytes     ', GRY)}  {c(f'{total_b:,}', WHT)}")
    rate = idx / elapsed if elapsed > 0 else 0
    print(f"  {c('Capture rate    ', GRY)}  {c(f'{rate:.1f} pkt/s', WHT)}")
    for proto, cnt in counters.items():
        if cnt:
            pc = proto_colour(proto)
            print(f"  {c(f'{proto:<7}', GRY)}  {c(str(cnt), pc, BOLD)}")

    if deep_inspect and reassembler:
        streams = reassembler.get_all_streams()
        if streams:
            print(f"  {c('TCP streams', GRY)}   {c(str(len(streams)), BOLD, CYN)}")

    print(f"  {c('─' * 44, GRY)}\n")
    return captured


def stream_capture(
    interface:    str        = "eth0",
    filter:       str | None = None,
    duration:     float      = 30.0,
    bpf_filter:   str | None = None,
) -> list[dict]:
    """
    Capture packets in the background for a fixed duration.

    Non-blocking version of capture_packets(). Returns after
    *duration* seconds with all captured packets. No terminal
    output — suitable for programmatic use.

    Args:
        interface:  Network interface
        filter:     Simple filter: 'tcp', 'udp', 'icmp'
        duration:   How many seconds to capture (default 30)
        bpf_filter: Full BPF expression

    Returns:
        list[dict] of captured packet dicts
    """
    captured   = []
    stop_event = threading.Event()

    def _worker():
        pkts = capture_packets(
            interface    = interface,
            filter       = filter,
            packet_limit = 0,
            show_header  = False,
            bpf_filter   = bpf_filter,
        )
        captured.extend(pkts)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    time.sleep(duration)
    stop_event.set()
    t.join(timeout=2.0)
    return captured


# ═══════════════════════════════════════════════════════════════════════════
# PCAP I/O
# ═══════════════════════════════════════════════════════════════════════════

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
        print(f"  Saved {len(packets)} records (JSON) → {fp}")


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
