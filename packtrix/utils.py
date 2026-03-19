"""
utils.py — Shared Helpers, Constants & Terminal Utilities
==========================================================
Single source of truth for constants, validation functions, ANSI
rendering primitives, and formatting helpers used across every
Packtrix module (scanner, sniffer, analyzer, dashboard, logger, cli).

Importing this module is the only place modules should need to reach
for anything "cross-cutting" — colour codes, box-drawing, table
formatting, IP/MAC validation, OUI lookup, timestamp generation, etc.

Sections
--------
1.  Constants          — COMMON_PORTS, PROTOCOL_NAMES, TCP_FLAGS,
                         SEVERITY_COLOURS, OUI_TABLE
2.  ANSI helpers       — escape codes + c(), strip_ansi(), visible_len(),
                         fit(), clamp_str()
3.  Bar / spark charts — bar_chart(), sparkline()
4.  Box drawing        — BoxStyle dataclass, box_top/sep/bot/row helpers
5.  Table formatter    — format_table()
6.  Network validation — validate_ip(), validate_ipv4(), is_valid_ip(),
                         is_valid_cidr(), is_valid_mac(), parse_port_range()
7.  MAC / OUI helpers  — normalise_mac(), lookup_mac_vendor()
8.  Interface helpers  — list_interfaces(), get_interface_ip()
9.  Privilege helpers  — is_root(), require_root()
10. Protocol helpers   — protocol_name(), tcp_flags_str(), port_service()
11. Byte / rate format — human_bytes(), human_rate(), human_duration()
12. Hostname helpers   — resolve_hostname(), safe_resolve()
13. Timestamp helpers  — utc_now(), timestamp_filename(), epoch_to_hms()

Dependencies (all stdlib):
    socket      — gethostbyaddr, inet_pton
    ipaddress   — IP/CIDR validation
    re          — MAC address pattern matching
    os / sys    — Platform and privilege detection
    datetime    — UTC timestamp generation
    dataclasses — BoxStyle config object
    shutil      — Terminal width detection
"""

import os
import re
import socket
import sys
import shutil
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ============================================================================
# 1.  Constants
# ============================================================================

# Port number → common service name.
# Used by scanner (open-port labelling) and sniffer (packet annotation).
COMMON_PORTS: dict[int, str] = {
    20: "FTP-DATA",   21: "FTP",        22: "SSH",        23: "Telnet",
    25: "SMTP",       53: "DNS",        67: "DHCP",       68: "DHCP",
    69: "TFTP",       80: "HTTP",      110: "POP3",      119: "NNTP",
    123: "NTP",      135: "RPC",       137: "NetBIOS",   138: "NetBIOS",
    139: "NetBIOS",  143: "IMAP",      161: "SNMP",      162: "SNMP-TRAP",
    179: "BGP",      194: "IRC",       389: "LDAP",      443: "HTTPS",
    445: "SMB",      465: "SMTPS",     500: "IKE",       514: "Syslog",
    587: "SMTP-ALT", 631: "IPP",       636: "LDAPS",     989: "FTPS-DATA",
    990: "FTPS",     993: "IMAPS",     995: "POP3S",    1080: "SOCKS",
   1194: "OpenVPN", 1433: "MSSQL",    1521: "Oracle",   1723: "PPTP",
   2049: "NFS",     2222: "SSH-ALT",  3306: "MySQL",    3389: "RDP",
   4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
   6379: "Redis",   6881: "BitTorrent", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
   8888: "Jupyter", 9200: "Elasticsearch", 9300: "Elasticsearch",
  27017: "MongoDB", 27018: "MongoDB",  50000: "SAP",
}

# IP protocol number → name string.
# Used by sniffer and analyzer for packet annotation.
PROTOCOL_NAMES: dict[int, str] = {
    1: "ICMP",   2: "IGMP",    6: "TCP",   17: "UDP",
   41: "IPv6",  43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE",
   50: "ESP",   51: "AH",     58: "ICMPv6",  89: "OSPF",
  103: "PIM",  112: "VRRP",  115: "L2TP",  132: "SCTP",
}

# TCP flag bitmask → abbreviation.
# Used by sniffer (packet display) and analyzer (brute-force detection).
TCP_FLAGS: dict[int, str] = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}

# Severity level → Rich colour string.
# Kept for backward compatibility; ANSI equivalents live in section 2.
SEVERITY_COLOURS: dict[str, str] = {
    "INFO":     "bright_blue",
    "LOW":      "green",
    "MEDIUM":   "yellow",
    "HIGH":     "orange3",
    "CRITICAL": "bold red",
}

# OUI prefix (first 3 octets, upper-case, no separators) → vendor name.
# Covers the most common vendors found on home/office/cloud networks.
# Source: https://www.wireshark.org/tools/oui-lookup.html (curated subset)
OUI_TABLE: dict[str, str] = {
    # Apple
    "3C22FB": "Apple",       "A4C361": "Apple",       "000A27": "Apple",
    "001124": "Apple",       "001451": "Apple",       "001B63": "Apple",
    "001CB3": "Apple",       "0021E9": "Apple",       "002312": "Apple",
    "002500": "Apple",       "003065": "Apple",       "0050E4": "Apple",
    "606970": "Apple",       "6C4008": "Apple",       "70CD60": "Apple",
    "8C7B9D": "Apple",       "A45E60": "Apple",       "F0DBF8": "Apple",
    # Cisco
    "FCFBFB": "Cisco",       "001A2F": "Cisco",       "000142": "Cisco",
    "0007B4": "Cisco",       "000A8A": "Cisco",       "000C85": "Cisco",
    "000DBD": "Cisco",       "00601D": "Cisco",       "204CA7": "Cisco",
    "58F39C": "Cisco",       "70B3D5": "Cisco",       "885A92": "Cisco",
    # Raspberry Pi Foundation
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    # Microsoft / Hyper-V
    "00155D": "Microsoft Hyper-V",
    "002248": "Microsoft",   "7C1E52": "Microsoft",
    # Oracle / VirtualBox
    "080027": "Oracle VirtualBox",
    "525400": "Oracle VirtualBox",
    # Huawei
    "DCD916": "Huawei",      "000E5E": "Huawei",      "0019CB": "Huawei",
    "002568": "Huawei",      "0025C6": "Huawei",      "28E31F": "Huawei",
    "44C346": "Huawei",      "54894E": "Huawei",      "6881BC": "Huawei",
    "74A063": "Huawei",      "8C97EA": "Huawei",      "A082CB": "Huawei",
    # Samsung
    "002339": "Samsung",     "001632": "Samsung",     "7825AD": "Samsung",
    "8425DB": "Samsung",     "CC07AB": "Samsung",     "F4428F": "Samsung",
    # Intel
    "001B21": "Intel",       "001CC0": "Intel",       "0022FB": "Intel",
    "0024D6": "Intel",       "00269E": "Intel",       "002732": "Intel",
    "34E6D7": "Intel",       "3C970E": "Intel",       "48F8B3": "Intel",
    "7085C2": "Intel",       "94659C": "Intel",       "A4C361": "Intel",
    # Dell
    "001372": "Dell",        "0014D1": "Dell",        "00188B": "Dell",
    "001A4B": "Dell",        "001EF0": "Dell",        "002564": "Dell",
    "1866DA": "Dell",        "F48E38": "Dell",        "F0272D": "Dell",
    # Hewlett-Packard / HPE
    "001083": "HP",          "00110A": "HP",          "001708": "HP",
    "001A4B": "HP",          "3C4A92": "HP",          "5061BF": "HP",
    # Netgear
    "000FB5": "Netgear",     "001B2F": "Netgear",     "002196": "Netgear",
    "08EEEE": "Netgear",     "30469A": "Netgear",
    # TP-Link
    "14CCA3": "TP-Link",     "1C3BF3": "TP-Link",     "50C7BF": "TP-Link",
    "60E327": "TP-Link",     "80EA96": "TP-Link",     "B0BE76": "TP-Link",
    "C46E1F": "TP-Link",     "D46AA8": "TP-Link",     "F81A67": "TP-Link",
    # Asus
    "001A92": "ASUSTek",     "002354": "ASUSTek",     "08606E": "ASUSTek",
    "107B44": "ASUSTek",     "1C872C": "ASUSTek",     "2C56DC": "ASUSTek",
    # VMware
    "000C29": "VMware",      "000569": "VMware",      "001C14": "VMware",
    "005056": "VMware",
    # Google (Chromecasts, Nest, Pixel phones, Cloud infra)
    "00E04C": "Google",      "3499E3": "Google",      "54EFA8": "Google",
    "704D7B": "Google",      "7CC70E": "Google",      "C4ADFE": "Google",
    "F4F5E8": "Google",
    # Amazon (Echo, FireTV, AWS)
    "0C47C9": "Amazon",      "40B4CD": "Amazon",      "44650D": "Amazon",
    "74C246": "Amazon",      "A002DC": "Amazon",      "B47C9C": "Amazon",
    "F0272D": "Amazon",
}


# ============================================================================
# 2.  ANSI helpers
# ============================================================================

# Raw escape code strings — import these directly where speed matters.
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
ULINE  = "\033[4m"
BLINK  = "\033[5m"

# Foreground colours
BLACK  = "\033[30m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
BLUE   = "\033[34m"
MAG    = "\033[35m"
CYAN   = "\033[36m"
WHITE  = "\033[97m"
GREY   = "\033[90m"

# Bright variants
BRIGHT_RED    = "\033[91m"
BRIGHT_GREEN  = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_BLUE   = "\033[94m"
BRIGHT_MAG    = "\033[95m"
BRIGHT_CYAN   = "\033[96m"

# Background colours (common use-cases)
BG_RED    = "\033[41m"
BG_GREEN  = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE   = "\033[44m"
BG_DARK   = "\033[48;5;235m"   # near-black for header bars
BG_ACCENT = "\033[48;5;24m"    # deep teal accent

# Severity level → ANSI colour (used by analyzer, dashboard, logger)
SEV_ANSI: dict[str, str] = {
    "CRITICAL": RED   + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     GREY,
}

# Protocol → ANSI colour (consistent across sniffer + dashboard)
PROTO_ANSI: dict[str, str] = {
    "TCP":   CYAN,
    "UDP":   GREEN,
    "ICMP":  YELLOW,
    "ARP":   MAG,
    "OTHER": GREY,
}

# Compiled regex for stripping ANSI escape sequences from strings.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mK]")


def c(text: str, *codes: str) -> str:
    """
    Wrap *text* with one or more raw ANSI escape codes and append a reset.

    This is the canonical colour helper — every module should import and
    use this rather than defining its own ``_c()`` equivalent.

    Args:
        text:  The string to colour/style.
        *codes: One or more ANSI code constants, e.g. ``BOLD``, ``RED``.

    Returns:
        String with codes prepended and ``RESET`` appended.

    Example:
        >>> from packtrix.utils import c, BOLD, RED
        >>> print(c("Error!", BOLD, RED))
    """
    return "".join(codes) + str(text) + RESET


def strip_ansi(text: str) -> str:
    """
    Remove all ANSI escape sequences from *text*.

    Useful for computing visible string widths and for writing plain-text
    log lines from strings that were built with ``c()``.

    Args:
        text: String that may contain ANSI escape sequences.

    Returns:
        Plain string with all escape sequences removed.

    Example:
        >>> strip_ansi(c("hello", BOLD, RED))
        'hello'
    """
    return _ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    """
    Return the *visible* (terminal-rendered) character count of *text*.

    ANSI escape codes are excluded from the count; only printable characters
    contribute to the returned length.

    Args:
        text: String that may contain ANSI escape sequences.

    Returns:
        Number of visible characters.

    Example:
        >>> visible_len(c("hello", BOLD))
        5
    """
    return len(strip_ansi(text))


def fit(text: str, width: int, pad: bool = True, align: str = "left") -> str:
    """
    Truncate or pad *text* to exactly *width* visible characters.

    ANSI codes are excluded from width measurements so coloured strings
    align correctly in tables without manual length adjustment.

    Args:
        text:  String that may contain ANSI escape sequences.
        width: Target visible character width (must be ≥ 1).
        pad:   If True (default), right-pad with spaces to reach *width*.
        align: ``"left"`` (default), ``"right"``, or ``"centre"`` / ``"center"``.
               Ignored when *pad* is False.

    Returns:
        String of exactly *width* visible characters (ANSI codes intact).

    Example:
        >>> fit(c("hi", CYAN), 10)       # "hi        "  (8 padding spaces)
        >>> fit("too long string", 6)    # "too lo…"
    """
    width = max(1, width)
    vlen  = visible_len(text)

    if vlen > width:
        # Truncate the plain text (ANSI codes before the cut point are lost
        # but this is acceptable — most truncated cells are short labels)
        plain = strip_ansi(text)
        return plain[:width - 1] + "…"

    if not pad:
        return text

    padding = width - vlen
    if align in ("right",):
        return " " * padding + text
    if align in ("centre", "center"):
        left_pad  = padding // 2
        right_pad = padding - left_pad
        return " " * left_pad + text + " " * right_pad
    return text + " " * padding   # left-align (default)


def clamp_str(text: str, max_len: int, suffix: str = "…") -> str:
    """
    Return *text* truncated to *max_len* visible characters with *suffix*.

    Unlike ``fit()``, this function does not pad and works on plain strings
    (no ANSI handling needed for the common use-case it targets).

    Args:
        text:    Plain string to clamp.
        max_len: Maximum visible length.
        suffix:  Truncation indicator appended when truncation occurs.

    Returns:
        Original string if short enough; truncated + suffix otherwise.

    Example:
        >>> clamp_str("hello world", 8)
        'hello w…'
    """
    if len(text) <= max_len:
        return text
    trim = max_len - len(suffix)
    return text[:max(0, trim)] + suffix


def sev_colour(severity: str) -> str:
    """
    Return the ANSI colour code for a severity level string.

    Args:
        severity: One of ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, ``INFO``
                  (case-insensitive).

    Returns:
        ANSI escape code string.  Falls back to ``WHITE`` for unknown values.

    Example:
        >>> print(c("CRITICAL", sev_colour("CRITICAL")))
    """
    return SEV_ANSI.get(severity.upper(), WHITE)


def proto_colour(protocol: str) -> str:
    """
    Return the ANSI colour code for a protocol name string.

    Args:
        protocol: One of ``TCP``, ``UDP``, ``ICMP``, ``ARP``
                  (case-insensitive).

    Returns:
        ANSI escape code string.  Falls back to ``GREY`` for unknown values.

    Example:
        >>> print(c("TCP", proto_colour("TCP")))
    """
    return PROTO_ANSI.get(protocol.upper(), GREY)


# ============================================================================
# 3.  Bar / spark charts
# ============================================================================

_BAR_FULL  = "█"
_BAR_EMPTY = "░"
_SPARK_CHARS = " ▁▂▃▄▅▆▇█"


def bar_chart(
    value:   float,
    maximum: float,
    width:   int   = 20,
    colour:  str   = CYAN,
    empty_colour: str = GREY,
) -> str:
    """
    Render a horizontal bar chart segment for a single value.

    Produces a string like ``"███████░░░░░░"`` scaled so that *maximum*
    fills the full *width*.

    Args:
        value:        Current value (clamped to [0, maximum]).
        maximum:      Value that corresponds to a full bar.
        width:        Total bar width in characters (default 20).
        colour:       ANSI code for the filled portion (default CYAN).
        empty_colour: ANSI code for the empty portion (default GREY).

    Returns:
        ANSI-coloured bar string of exactly *width* visible characters.

    Example:
        >>> print(bar_chart(30, 100, width=10))   # "███░░░░░░░"
    """
    if maximum <= 0:
        return c(_BAR_EMPTY * width, empty_colour)
    ratio  = min(1.0, max(0.0, value / maximum))
    filled = round(ratio * width)
    empty  = width - filled
    return c(_BAR_FULL * filled, colour) + c(_BAR_EMPTY * empty, empty_colour)


def sparkline(values: list[float], width: int = 10, colour: str = CYAN) -> str:
    """
    Render a compact sparkline from a list of numeric samples.

    Uses the Unicode block characters ``▁▂▃▄▅▆▇█`` to represent relative
    magnitudes.  Useful for the dashboard bandwidth history panel.

    Args:
        values: List of numeric samples (oldest first, newest last).
        width:  Number of characters in the output (default 10).
        colour: ANSI colour for the sparkline (default CYAN).

    Returns:
        ANSI-coloured sparkline string of *width* visible characters.

    Example:
        >>> print(sparkline([1, 3, 2, 8, 5, 7]))
    """
    if not values:
        return c(" " * width, colour)

    # Use the last *width* samples; pad with zeros on the left if shorter
    samples = list(values[-width:])
    if len(samples) < width:
        samples = [0.0] * (width - len(samples)) + samples

    mn = min(samples)
    mx = max(samples)
    rng = mx - mn if mx != mn else 1

    chars = []
    for v in samples:
        idx = int((v - mn) / rng * (len(_SPARK_CHARS) - 1))
        chars.append(_SPARK_CHARS[idx])

    return c("".join(chars), colour)


# ============================================================================
# 4.  Box drawing
# ============================================================================

@dataclass
class BoxStyle:
    """
    Configuration for the box-drawing characters used in a table or panel.

    The defaults produce a mixed-weight box (╭ rounded corners, ─ thin sides):

    ::

        ╭──┬──╮
        │  │  │
        ├──┼──┤
        │  │  │
        ╰──┴──╯

    Override fields to produce heavy (═ ╔ ╗ ╚ ╝), or simple (+ - |) boxes.

    Attributes:
        top_left, top_right, bot_left, bot_right — corner characters
        h_top, h_mid, h_bot — horizontal rule characters for each zone
        v_left, v_mid, v_right — vertical separator characters
        cross, t_top, t_bot, t_left, t_right — junction characters
        colour — ANSI colour code applied to all box-drawing characters
    """
    # Corners
    top_left:  str = "╭"
    top_right: str = "╮"
    bot_left:  str = "╰"
    bot_right: str = "╯"
    # Horizontal rules
    h_top:     str = "─"
    h_mid:     str = "─"
    h_bot:     str = "─"
    # Verticals
    v_left:    str = "│"
    v_mid:     str = "│"
    v_right:   str = "│"
    # Junctions
    cross:     str = "┼"
    t_top:     str = "┬"
    t_bot:     str = "┴"
    t_left:    str = "├"
    t_right:   str = "┤"
    # Colour applied to all structural characters
    colour:    str = field(default=GREY)


# Pre-defined box style instances for convenience
BOX_THIN   = BoxStyle()                          # default thin rounded box
BOX_HEAVY  = BoxStyle(                           # heavy double-line box
    top_left="╔", top_right="╗", bot_left="╚", bot_right="╝",
    h_top="═", h_mid="═", h_bot="═",
    v_left="║", v_mid="║", v_right="║",
    cross="╬", t_top="╦", t_bot="╩", t_left="╠", t_right="╣",
)
BOX_ASCII  = BoxStyle(                           # plain ASCII (safe fallback)
    top_left="+", top_right="+", bot_left="+", bot_right="+",
    h_top="-", h_mid="-", h_bot="-",
    v_left="|", v_mid="|", v_right="|",
    cross="+", t_top="+", t_bot="+", t_left="+", t_right="+",
    colour="",
)


def _box_line(style: BoxStyle, seg_widths: list[int],
              left: str, fill: str, mid: str, right: str) -> str:
    """
    Render one horizontal box-drawing rule given segment widths.

    Args:
        style:       BoxStyle instance.
        seg_widths:  List of inner column widths (not including padding).
        left:        Left-edge character.
        fill:        Character repeated to fill each segment.
        mid:         Junction character between segments.
        right:       Right-edge character.

    Returns:
        Coloured box-rule string ready to print.
    """
    segs = [fill * (w + 2) for w in seg_widths]
    line = left + mid.join(segs) + right
    return c(line, style.colour) if style.colour else line


def box_top(style: BoxStyle, seg_widths: list[int]) -> str:
    """Return the top border of a box using *style*."""
    return _box_line(style, seg_widths,
                     style.top_left, style.h_top, style.t_top, style.top_right)


def box_sep(style: BoxStyle, seg_widths: list[int]) -> str:
    """Return an interior horizontal separator using *style*."""
    return _box_line(style, seg_widths,
                     style.t_left, style.h_mid, style.cross, style.t_right)


def box_bot(style: BoxStyle, seg_widths: list[int]) -> str:
    """Return the bottom border of a box using *style*."""
    return _box_line(style, seg_widths,
                     style.bot_left, style.h_bot, style.t_bot, style.bot_right)


def box_row(style: BoxStyle, cells: list[str], seg_widths: list[int]) -> str:
    """
    Render a data row with *cells* fitted to *seg_widths*.

    Each cell is left-padded by one space and fitted (truncated or padded)
    to its column width, then right-padded by one space.

    Args:
        style:      BoxStyle for the vertical separator characters.
        cells:      List of cell content strings (may contain ANSI codes).
        seg_widths: List of inner column widths (one per cell).

    Returns:
        Full row string with border characters on each side.
    """
    vl = c(style.v_left,  style.colour) if style.colour else style.v_left
    vm = c(style.v_mid,   style.colour) if style.colour else style.v_mid
    vr = c(style.v_right, style.colour) if style.colour else style.v_right

    parts = []
    for cell, w in zip(cells, seg_widths):
        parts.append(" " + fit(cell, w) + " ")
    return vl + vm.join(parts) + vr


# ============================================================================
# 5.  Table formatter
# ============================================================================

def format_table(
    data:         list[dict],
    columns:      Optional[list[str]]       = None,
    headers:      Optional[dict[str, str]]  = None,
    col_colours:  Optional[dict[str, str]]  = None,
    header_colour: str                      = BOLD + WHITE,
    style:        BoxStyle                  = BOX_THIN,
    max_col_width: int                      = 40,
    min_col_width: int                      = 4,
    title:        Optional[str]             = None,
    show_index:   bool                      = False,
    empty_message: str                      = "(no data)",
) -> str:
    """
    Format a list of dicts as a Unicode box-drawing table string.

    This is the canonical table helper for all Packtrix modules.  Every
    module that previously built its own ``_render_table()`` should call
    this instead.

    Column widths are computed automatically from header + data content and
    clamped to [*min_col_width*, *max_col_width*].  Long values are truncated
    with a ``…`` suffix.

    Args:
        data:          List of dicts, each dict being one row.  All dicts
                       should have the same keys; missing keys render as
                       ``"—"``.
        columns:       Ordered list of dict keys to include.  If None,
                       all keys from the first row are used in insertion order.
        headers:       Mapping of key → display header label.  If None,
                       keys are title-cased and underscores replaced by spaces.
        col_colours:   Mapping of key → ANSI code for data cells.  Header
                       cells always use *header_colour*.
        header_colour: ANSI code(s) applied to all header cells.
        style:         BoxStyle instance (default BOX_THIN).
        max_col_width: Maximum visible width of any column (default 40).
        min_col_width: Minimum visible width of any column (default 4).
        title:         Optional title string printed above the top border.
        show_index:    If True, prepend a ``#`` index column (1-based).
        empty_message: String printed when *data* is empty.

    Returns:
        Multi-line string ready to ``print()``.  Does NOT add a trailing
        newline so callers can decide whether to chain output.

    Example:
        >>> rows = [
        ...     {"ip": "192.168.1.1", "port": 22,  "service": "SSH"},
        ...     {"ip": "192.168.1.1", "port": 443, "service": "HTTPS"},
        ... ]
        >>> print(format_table(rows, title="Open Ports"))

    Output::

        Open Ports
        ╭────────────────┬──────┬─────────╮
        │ IP             │ Port │ Service │
        ├────────────────┼──────┼─────────┤
        │ 192.168.1.1    │ 22   │ SSH     │
        │ 192.168.1.1    │ 443  │ HTTPS   │
        ╰────────────────┴──────┴─────────╯
    """
    if not data:
        return c(f"  {empty_message}", DIM)

    # ── Column list ──────────────────────────────────────────────────────
    if columns is None:
        columns = list(data[0].keys())

    if show_index:
        columns = ["__idx__"] + columns

    # ── Header labels ────────────────────────────────────────────────────
    def _default_header(key: str) -> str:
        if key == "__idx__":
            return "#"
        return key.replace("_", " ").title()

    hdr_labels: dict[str, str] = {}
    for key in columns:
        hdr_labels[key] = (headers or {}).get(key, _default_header(key))

    # ── Column widths ────────────────────────────────────────────────────
    widths: dict[str, int] = {}
    for key in columns:
        # Start from the header width
        w = len(hdr_labels[key])
        # Expand to fit data values
        for idx, row in enumerate(data, start=1):
            if key == "__idx__":
                cell = str(idx)
            else:
                cell = str(row.get(key, "—"))
            w = max(w, len(cell))
        # Clamp
        widths[key] = min(max_col_width, max(min_col_width, w))

    seg_widths = [widths[k] for k in columns]

    lines: list[str] = []

    # ── Optional title ────────────────────────────────────────────────────
    if title:
        lines.append(c(f"  {title}", BOLD, WHITE))

    # ── Top border ───────────────────────────────────────────────────────
    lines.append(box_top(style, seg_widths))

    # ── Header row ───────────────────────────────────────────────────────
    header_cells = [
        c(fit(hdr_labels[k], widths[k]), header_colour)
        for k in columns
    ]
    lines.append(box_row(style, header_cells, seg_widths))

    # ── Header / data separator ──────────────────────────────────────────
    lines.append(box_sep(style, seg_widths))

    # ── Data rows ─────────────────────────────────────────────────────────
    col_clrs = col_colours or {}
    for row_idx, row in enumerate(data, start=1):
        cells = []
        for key in columns:
            if key == "__idx__":
                raw = str(row_idx)
                cell_colour = GREY
            else:
                raw = str(row.get(key, "—"))
                cell_colour = col_clrs.get(key, WHITE)
            cells.append(c(fit(raw, widths[key]), cell_colour))
        lines.append(box_row(style, cells, seg_widths))

    # ── Bottom border ─────────────────────────────────────────────────────
    lines.append(box_bot(style, seg_widths))

    return "\n".join(lines)


# ============================================================================
# 6.  Network validation
# ============================================================================

def validate_ip(ip: str) -> bool:
    """
    Return True if *ip* is a valid IPv4 address string.

    This is the primary IPv4 validation helper requested for this module.
    For broader IPv4/IPv6 validation use ``is_valid_ip()``.

    Args:
        ip: String to validate, e.g. ``"192.168.1.1"``.

    Returns:
        True if valid IPv4; False for IPv6, hostnames, empty strings, etc.

    Example:
        >>> validate_ip("192.168.1.1")
        True
        >>> validate_ip("::1")
        False
        >>> validate_ip("999.0.0.1")
        False
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4
    except ValueError:
        return False


def validate_ipv4(ip: str) -> bool:
    """Alias for ``validate_ip()`` — explicit IPv4-only validation."""
    return validate_ip(ip)


def is_valid_ip(address: str) -> bool:
    """
    Return True if *address* is a valid IPv4 **or** IPv6 address string.

    Args:
        address: IP address string.

    Returns:
        True for any valid IP address; False otherwise.

    Example:
        >>> is_valid_ip("::1")
        True
        >>> is_valid_ip("not an ip")
        False
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_cidr(subnet: str) -> bool:
    """
    Return True if *subnet* is a valid CIDR notation string.

    Accepts both strict (``192.168.1.0/24``) and loose (``192.168.1.5/24``)
    notation.

    Args:
        subnet: CIDR notation string.

    Returns:
        True if parseable as an IP network; False otherwise.

    Example:
        >>> is_valid_cidr("10.0.0.0/8")
        True
        >>> is_valid_cidr("10.0.0.0/99")
        False
    """
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def is_valid_mac(mac: str) -> bool:
    """
    Return True if *mac* is a valid colon-separated MAC address string.

    Accepts mixed case.  Does NOT accept dash-separated (``AA-BB-CC-DD-EE-FF``)
    or un-separated (``AABBCCDDEEFF``) formats; normalise first with
    ``normalise_mac()`` if needed.

    Args:
        mac: MAC address string, e.g. ``"aa:bb:cc:dd:ee:ff"``.

    Returns:
        True if the MAC matches ``XX:XX:XX:XX:XX:XX`` (hex octets); False otherwise.

    Example:
        >>> is_valid_mac("de:ad:be:ef:00:01")
        True
        >>> is_valid_mac("DE-AD-BE-EF-00-01")
        False   # use normalise_mac() first
    """
    return bool(re.fullmatch(
        r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac.strip()
    ))


def parse_port_range(ports_str: str) -> list[int]:
    """
    Parse a port specification string into a sorted, deduplicated list of
    port integers.

    Supported formats:
        ``"80"``              → ``[80]``
        ``"22,80,443"``       → ``[22, 80, 443]``
        ``"1-1024"``          → ``[1, 2, …, 1024]``
        ``"22,80,8000-8080"`` → mixed list

    Args:
        ports_str: Port specification string.

    Returns:
        Sorted list of integer port numbers in range [1, 65535].

    Raises:
        ValueError: If any token is malformed or a port is out of range.

    Example:
        >>> parse_port_range("22,80,8000-8010")
        [22, 80, 8000, 8001, …, 8010]
    """
    ports: set[int] = set()
    for token in ports_str.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            try:
                lo, hi = int(parts[0].strip()), int(parts[1].strip())
            except ValueError:
                raise ValueError(f"Invalid port range token: '{token}'")
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(
                    f"Port range '{token}' must be within 1–65535 and lo ≤ hi."
                )
            ports.update(range(lo, hi + 1))
        else:
            try:
                port = int(token)
            except ValueError:
                raise ValueError(f"Invalid port token: '{token}'")
            if not 1 <= port <= 65535:
                raise ValueError(
                    f"Port {port} out of valid range 1–65535."
                )
            ports.add(port)
    return sorted(ports)


# ============================================================================
# 7.  MAC / OUI helpers
# ============================================================================

def normalise_mac(mac: str) -> str:
    """
    Normalise a MAC address to colon-separated, upper-case format.

    Accepts any of these common representations and converts them all to
    the canonical ``AA:BB:CC:DD:EE:FF`` form::

        aa:bb:cc:dd:ee:ff        →  AA:BB:CC:DD:EE:FF
        AA-BB-CC-DD-EE-FF        →  AA:BB:CC:DD:EE:FF
        AABBCCDDEEFF             →  AA:BB:CC:DD:EE:FF
        aabb.ccdd.eeff           →  AA:BB:CC:DD:EE:FF   (Cisco dot notation)

    Args:
        mac: MAC address string in any supported format.

    Returns:
        Upper-case colon-separated MAC string.

    Raises:
        ValueError: If *mac* cannot be parsed as a 6-octet MAC address.

    Example:
        >>> normalise_mac("de-ad-be-ef-00-01")
        'DE:AD:BE:EF:00:01'
        >>> normalise_mac("deadbeef0001")
        'DE:AD:BE:EF:00:01'
    """
    # Strip separators: colons, dashes, dots, spaces
    stripped = re.sub(r"[:\-\. ]", "", mac).upper()
    if len(stripped) != 12 or not re.fullmatch(r"[0-9A-F]{12}", stripped):
        raise ValueError(f"Cannot parse '{mac}' as a MAC address.")
    return ":".join(stripped[i:i+2] for i in range(0, 12, 2))


def lookup_mac_vendor(mac: str) -> str:
    """
    Return the vendor name for a MAC address using the built-in OUI table.

    Extracts the first three octets (the Organisationally Unique Identifier)
    and looks them up in ``OUI_TABLE``.  The lookup is case-insensitive and
    tolerates any separator (colons, dashes, dots) via ``normalise_mac()``.

    This is an *offline* lookup using ``OUI_TABLE`` — it works without an
    internet connection and adds no latency.  The table covers ~80 common
    vendors; anything not found returns ``"Unknown"``.

    Args:
        mac: MAC address string in any format accepted by ``normalise_mac()``.

    Returns:
        Vendor name string, e.g. ``"Apple"``, ``"Cisco"``, or ``"Unknown"``.

    Example:
        >>> lookup_mac_vendor("b8:27:eb:aa:bb:cc")
        'Raspberry Pi Foundation'
        >>> lookup_mac_vendor("00:00:00:00:00:00")
        'Unknown'
    """
    try:
        norm = normalise_mac(mac)
    except ValueError:
        return "Unknown"
    # OUI is the first 3 octets with colons removed, upper-case
    oui = norm.replace(":", "")[:6]
    return OUI_TABLE.get(oui, "Unknown")


# ============================================================================
# 8.  Interface helpers
# ============================================================================

def list_interfaces() -> list[str]:
    """
    Return a list of available network interface names on this system.

    On Linux, reads ``/proc/net/dev`` (always available, no third-party lib).
    On macOS and other POSIX systems, falls back to ``socket``-based detection.
    On Windows, returns a best-effort list from ``socket.gethostbyname_ex()``.

    Returns:
        List of interface name strings, e.g. ``["eth0", "wlan0", "lo"]``.
        Returns an empty list if detection fails rather than raising.

    Example:
        >>> list_interfaces()
        ['lo', 'eth0', 'wlan0']
    """
    interfaces: list[str] = []

    # ── Linux: parse /proc/net/dev (fastest, always present) ─────────────
    proc_dev = "/proc/net/dev"
    if os.path.exists(proc_dev):
        try:
            with open(proc_dev, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if ":" in line:
                        iface = line.split(":")[0].strip()
                        if iface:
                            interfaces.append(iface)
            return interfaces
        except OSError:
            pass

    # ── Fallback: try netifaces if installed ─────────────────────────────
    try:
        import netifaces  # type: ignore
        return netifaces.interfaces()
    except ImportError:
        pass

    # ── Last resort: use socket module (limited, hostname-based) ─────────
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None)
        seen: set[str] = set()
        for addr in addrs:
            ip = addr[4][0]
            if ip not in seen:
                seen.add(ip)
                interfaces.append(ip)   # IP as fallback label
    except OSError:
        pass

    return interfaces


def get_interface_ip(interface: str) -> Optional[str]:
    """
    Return the primary IPv4 address assigned to *interface*.

    Reads ``/proc/net/fib_trie`` on Linux for a fast, dependency-free lookup.
    Falls back to ``netifaces`` if installed, then to a socket-based scan.

    Args:
        interface: Interface name string, e.g. ``"eth0"`` or ``"wlan0"``.

    Returns:
        IPv4 address string (e.g. ``"192.168.1.100"``), or ``None`` if the
        interface is not found or has no IPv4 address.

    Example:
        >>> get_interface_ip("eth0")
        '192.168.1.100'
    """
    # ── netifaces (most reliable when installed) ──────────────────────────
    try:
        import netifaces  # type: ignore
        addrs = netifaces.ifaddresses(interface)
        inet  = addrs.get(netifaces.AF_INET, [])
        if inet:
            return inet[0].get("addr")
    except (ImportError, ValueError, KeyError):
        pass

    # ── Linux /proc/net/if_inet6 isn't helpful; try ip command output ─────
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass

    return None


# ============================================================================
# 9.  Privilege helpers
# ============================================================================

def is_root() -> bool:
    """
    Return True if the current process is running with root/administrator
    privileges.

    On POSIX systems (Linux, macOS) checks ``os.geteuid() == 0``.
    On Windows checks the ``IsUserAnAdmin`` function via ``ctypes``.

    Returns:
        True if root/admin; False otherwise.

    Example:
        >>> if not is_root():
        ...     print("Run with sudo for ARP scanning")
    """
    if os.name == "nt":   # Windows
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def require_root(
    message: str = "This feature requires root/administrator privileges.",
    exit_code: int = 1,
) -> None:
    """
    Print *message* to stderr and exit if not running as root/admin.

    Args:
        message:   Error message printed to ``sys.stderr`` when check fails.
        exit_code: Process exit code used when check fails (default 1).

    Returns:
        None (returns normally when running as root).

    Example:
        >>> require_root("ARP scanning requires root. Run with sudo.")
    """
    if not is_root():
        print(c(f"[!] {message}", BOLD, RED), file=sys.stderr)
        sys.exit(exit_code)


# ============================================================================
# 10. Protocol helpers
# ============================================================================

def protocol_name(proto_num: int) -> str:
    """
    Resolve an IP protocol number to its canonical name string.

    Args:
        proto_num: Integer IP protocol number (e.g. ``6`` for TCP).

    Returns:
        Name string (e.g. ``"TCP"``), or ``"PROTO-<n>"`` for unknown numbers.

    Example:
        >>> protocol_name(17)
        'UDP'
        >>> protocol_name(99)
        'PROTO-99'
    """
    return PROTOCOL_NAMES.get(proto_num, f"PROTO-{proto_num}")


def tcp_flags_str(flags_int: int) -> str:
    """
    Convert a TCP flags integer bitmask to a readable pipe-separated string.

    Args:
        flags_int: Integer bitmask of TCP flags.

    Returns:
        Pipe-separated flag abbreviation string, e.g. ``"SYN|ACK"``.
        Returns ``""`` when *flags_int* is 0 or no flags are set.

    Example:
        >>> tcp_flags_str(0x12)   # SYN + ACK
        'SYN|ACK'
        >>> tcp_flags_str(0x02)   # SYN only
        'SYN'
    """
    active = [name for mask, name in TCP_FLAGS.items() if flags_int & mask]
    return "|".join(active)


def port_service(port: Optional[int]) -> str:
    """
    Return the known service name for a port number, or ``"unknown"``.

    Args:
        port: Integer port number, or None.

    Returns:
        Service name string (e.g. ``"HTTPS"``) or ``"unknown"``.

    Example:
        >>> port_service(443)
        'HTTPS'
        >>> port_service(None)
        'unknown'
    """
    if port is None:
        return "unknown"
    return COMMON_PORTS.get(int(port), "unknown")


# ============================================================================
# 11. Byte / rate formatting
# ============================================================================

def human_bytes(num_bytes: float, precision: int = 1) -> str:
    """
    Format a byte count as a human-readable string with the appropriate
    SI prefix (B → KB → MB → GB → TB).

    Args:
        num_bytes: Raw byte count (may be float for computed rates).
        precision: Decimal places in the formatted output (default 1).

    Returns:
        Formatted string, e.g. ``"1.4 MB"``, ``"856 B"``.

    Example:
        >>> human_bytes(1536)
        '1.5 KB'
        >>> human_bytes(1073741824)
        '1.0 GB'
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            if unit == "B":
                return f"{int(num_bytes)} {unit}"
            return f"{num_bytes:.{precision}f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.{precision}f} PB"


def human_rate(bytes_per_sec: float, precision: int = 1) -> str:
    """
    Format a bytes-per-second bandwidth value as a human-readable string.

    Args:
        bytes_per_sec: Transfer rate in bytes per second.
        precision:     Decimal places (default 1).

    Returns:
        Formatted rate string, e.g. ``"12.3 KB/s"``, ``"2.1 MB/s"``.

    Example:
        >>> human_rate(15360)
        '15.0 KB/s'
    """
    return human_bytes(bytes_per_sec, precision=precision) + "/s"


def human_duration(seconds: float) -> str:
    """
    Format an elapsed time in seconds as ``HH:MM:SS`` or ``MM:SS``.

    Args:
        seconds: Duration in seconds (floats are truncated to int).

    Returns:
        Formatted duration string.  Returns ``"0s"`` for sub-second values.

    Example:
        >>> human_duration(3661)
        '01:01:01'
        >>> human_duration(75)
        '01:15'
        >>> human_duration(9)
        '0:09'
    """
    s = int(seconds)
    if s < 0:
        return "0s"
    h, rem = divmod(s, 3600)
    m, sec  = divmod(rem, 60)
    if h:
        return f"{h:02d}:{m:02d}:{sec:02d}"
    return f"{m}:{sec:02d}"


# ============================================================================
# 12. Hostname helpers
# ============================================================================

def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """
    Perform a reverse-DNS lookup for *ip* and return the hostname.

    Uses a short *timeout* so scans are not blocked by unresponsive DNS.

    Args:
        ip:      IPv4 or IPv6 address string.
        timeout: Socket timeout in seconds (default 0.5).

    Returns:
        Hostname string, or empty string ``""`` if the lookup fails or times out.

    Example:
        >>> resolve_hostname("8.8.8.8")
        'dns.google'
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


def safe_resolve(ip: str, timeout: float = 0.3) -> str:
    """
    Resolve *ip* to a hostname, returning ``ip`` unchanged on failure.

    Convenience wrapper around ``resolve_hostname()`` that guarantees a
    non-empty return value (falls back to the raw IP string).

    Args:
        ip:      IP address string.
        timeout: DNS timeout in seconds (default 0.3).

    Returns:
        Hostname string if resolution succeeds; *ip* string otherwise.

    Example:
        >>> safe_resolve("8.8.8.8")
        'dns.google'
        >>> safe_resolve("10.255.255.1")
        '10.255.255.1'
    """
    hostname = resolve_hostname(ip, timeout=timeout)
    return hostname if hostname else ip


# ============================================================================
# 13. Timestamp helpers
# ============================================================================

def utc_now() -> str:
    """
    Return the current UTC time as an ISO-8601 string with second precision.

    Returns:
        String of the form ``"2026-03-10T14:03:07+00:00"``.

    Example:
        >>> utc_now()
        '2026-03-10T14:03:07+00:00'
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def timestamp_filename(prefix: str = "packtrix", ext: str = "log") -> str:
    """
    Generate a timestamped filename to avoid overwriting previous sessions.

    Args:
        prefix: Filename prefix (default ``"packtrix"``).
        ext:    File extension without the leading dot (default ``"log"``).

    Returns:
        Filename string, e.g. ``"packtrix_20260310_140307.log"``.

    Example:
        >>> timestamp_filename("scan", "json")
        'scan_20260310_140307.json'
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.{ext}"


def epoch_to_hms(epoch: float) -> str:
    """
    Convert a Unix epoch float to a ``HH:MM:SS`` local-time string.

    Used by sniffer and dashboard for packet timestamp display.

    Args:
        epoch: Unix timestamp float.

    Returns:
        Local-time string ``"HH:MM:SS"``.

    Example:
        >>> epoch_to_hms(1700000000.0)
        '14:13:20'   # local time will vary
    """
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def epoch_to_hms_ms(epoch: float) -> str:
    """
    Convert a Unix epoch float to ``HH:MM:SS.mmm`` with milliseconds.

    Used by the sniffer packet feed for high-resolution timestamps.

    Args:
        epoch: Unix timestamp float.

    Returns:
        Local-time string ``"HH:MM:SS.mmm"``.

    Example:
        >>> epoch_to_hms_ms(1700000000.512)
        '14:13:20.512'
    """
    dt = datetime.fromtimestamp(epoch)
    return dt.strftime("%H:%M:%S") + f".{dt.microsecond // 1000:03d}"
