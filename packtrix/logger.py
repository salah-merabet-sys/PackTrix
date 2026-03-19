"""
logger.py — Structured Logging & Report Exporting
===================================================
Central logging facility for the entire Packtrix toolkit.

Every module (scanner, sniffer, analyzer, dashboard) imports the
module-level ``get_logger()`` factory and calls ``log_event()`` to emit
structured, colour-coded log lines — both to the terminal and optionally
to a rotating log file.

Quick-start (any Packtrix module):
    from packtrix.logger import get_logger, log_event

    _log = get_logger("scanner")          # one call at module level
    log_event(_log, "INFO",  "SCAN_START",  {"subnet": "192.168.1.0/24"})
    log_event(_log, "ERROR", "SCAN_FAIL",   {"reason": "permission denied"})

Log levels (lowest → highest severity):
    DEBUG   — verbose developer output; suppressed unless verbose=True
    INFO    — normal operational messages
    WARNING — recoverable problems; something unexpected happened
    ERROR   — non-fatal failures; a feature could not complete
    CRITICAL— fatal errors; the tool cannot continue

On-disk format (plain text, one record per line):
    2026-03-10 14:03:07.512 | ERROR    | scanner  | SCAN_FAIL | {"reason": "…"}

Terminal format (ANSI colour, same fields):
    [14:03:07] [ERROR   ] [scanner ] SCAN_FAIL  reason=permission denied

Exports (via export_scan_results / export_alerts / generate_report):
    JSON  — pretty-printed, human and machine readable
    CSV   — flat rows, importable into spreadsheets / SIEM tools
    TXT   — plain English alert report for email / ticket attachment

Dependencies (all stdlib):
    logging             — core logging machinery
    logging.handlers    — RotatingFileHandler for size-capped log files
    json                — structured event serialisation
    csv                 — tabular export
    pathlib             — cross-platform file paths
    shutil              — file copy for report bundling
    datetime            — timestamps and filenames
    dataclasses         — asdict() for Alert serialisation
"""

import csv
import json
import logging
import logging.handlers
import os
import shutil
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default directory for log files: ~/.packtrix/logs/
DEFAULT_LOG_DIR: Path = Path.home() / ".packtrix" / "logs"

# Maximum single log-file size before rotation kicks in (5 MB)
LOG_MAX_BYTES: int = 5 * 1024 * 1024

# Number of rotated backup files to keep alongside the active log
LOG_BACKUP_COUNT: int = 3

# On-disk record format: timestamp | level | logger-name | message
_FILE_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)-10s | %(message)s"
_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

# Valid level names accepted by log_event() (case-insensitive)
_VALID_LEVELS: frozenset[str] = frozenset(
    {"debug", "info", "warning", "warn", "error", "critical"}
)

# ---------------------------------------------------------------------------
# ANSI colour helpers  (stdlib only — no third-party deps)
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

_RED    = "\033[31m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_BLUE   = "\033[34m"
_CYAN   = "\033[36m"
_WHITE  = "\033[97m"
_GREY   = "\033[90m"
_MAG    = "\033[35m"


def _c(text: str, *codes: str) -> str:
    """Wrap *text* with ANSI escape codes and append a reset sentinel."""
    return "".join(codes) + str(text) + _RESET


# Level → (display label, ANSI colour code)
_LEVEL_STYLE: dict[str, tuple[str, str]] = {
    "DEBUG":    ("DEBUG   ", _GREY),
    "INFO":     ("INFO    ", _CYAN),
    "WARNING":  ("WARNING ", _YELLOW),
    "ERROR":    ("ERROR   ", _RED),
    "CRITICAL": ("CRITICAL", _RED + _BOLD),
}

# Source-module → accent colour (cosmetic only — makes mixed logs scannable)
_MODULE_COLOUR: dict[str, str] = {
    "scanner":   _CYAN,
    "sniffer":   _GREEN,
    "analyzer":  _YELLOW,
    "dashboard": _MAG,
    "cli":       _BLUE,
    "packtrix":  _WHITE,
}


def _module_colour(name: str) -> str:
    """Return the ANSI colour associated with *name*, falling back to grey."""
    # Strip any dotted hierarchy (e.g. "packtrix.scanner" → "scanner")
    short = name.split(".")[-1]
    return _MODULE_COLOUR.get(short, _GREY)


# ---------------------------------------------------------------------------
# ColourStreamHandler — ANSI-aware console handler
# ---------------------------------------------------------------------------

class _ColourStreamHandler(logging.StreamHandler):
    """
    A logging.StreamHandler subclass that wraps each emitted record with
    ANSI colour codes for level and module name.

    Terminal format:
        [HH:MM:SS] [LEVEL   ] [module    ] EVENT_TYPE  key=val key=val …

    The handler checks whether stdout is a real TTY before emitting colour
    codes so that piped output (e.g. ``packtrix scan … | grep ERROR``) stays
    clean.
    """

    def emit(self, record: logging.LogRecord) -> None:  # type: ignore[override]
        """
        Format and write a single log record to the stream.

        Overrides StreamHandler.emit() to inject ANSI colours when the
        output stream is connected to an interactive terminal.

        Args:
            record: The LogRecord to emit.
        """
        try:
            use_colour = hasattr(self.stream, "isatty") and self.stream.isatty()

            ts    = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            level = record.levelname
            name  = record.name
            msg   = record.getMessage()

            if use_colour:
                label, lc = _LEVEL_STYLE.get(level, (level, _WHITE))
                mc        = _module_colour(name)
                line = (
                    f"{_c('[' + ts + ']', _GREY)}"
                    f" {_c('[' + label + ']', _BOLD, lc)}"
                    f" {_c('[' + f'{name:<10}' + ']', mc)}"
                    f"  {msg}"
                )
            else:
                # Plain format for pipes / file redirection
                line = f"[{ts}] [{level:<8}] [{name:<10}]  {msg}"

            self.stream.write(line + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


# ---------------------------------------------------------------------------
# Logger registry — one logger instance per named module
# ---------------------------------------------------------------------------

# Module-level cache: {logger_name: logging.Logger}
# This prevents duplicate handlers from accumulating when a module calls
# get_logger() more than once (e.g. during tests or reloads).
_logger_registry: dict[str, logging.Logger] = {}

# Path of the active log file for the current session (set by setup_logger)
_active_log_file: Optional[Path] = None


def get_logger(name: str = "packtrix") -> logging.Logger:
    """
    Return a named logger for *name*, creating it on first call.

    This is the recommended entry point for all Packtrix modules.  Call it
    once at module level, then pass the result to ``log_event()``::

        # In scanner.py:
        from packtrix.logger import get_logger, log_event
        _log = get_logger("scanner")

    The returned logger writes to the terminal (coloured) by default.  To
    additionally write to a log file, call ``setup_logger()`` once at
    startup (typically in ``cli.main()``).

    Args:
        name: Short logger name, e.g. "scanner", "sniffer", "analyzer".
              Conventionally matches the Packtrix module name.

    Returns:
        Configured ``logging.Logger`` instance.
    """
    if name in _logger_registry:
        return _logger_registry[name]

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)   # handlers filter their own levels
    logger.propagate = False         # stop double-printing via root logger

    # Attach a colour console handler at INFO level by default
    if not any(isinstance(h, _ColourStreamHandler) for h in logger.handlers):
        ch = _ColourStreamHandler(stream=sys.stdout)
        ch.setLevel(logging.INFO)
        logger.addHandler(ch)

    _logger_registry[name] = logger
    return logger


def setup_logger(
    name:        str            = "packtrix",
    log_file:    Optional[str]  = None,
    level:       int            = logging.INFO,
    verbose:     bool           = False,
    rotate:      bool           = True,
) -> logging.Logger:
    """
    Configure a named logger with both a console handler and an optional
    rotating file handler.  Call this once during application startup
    (typically inside ``cli.main()``) to set the global logging policy.

    Args:
        name:     Logger name.  Should match the calling module, e.g.
                  ``"packtrix"`` for the root application logger.
        log_file: Absolute or relative path for the log file.
                  • If None (default): auto-generated timestamped path
                    under ``DEFAULT_LOG_DIR`` (~/.packtrix/logs/).
                  • Pass ``""`` (empty string) to disable file logging.
        level:    Minimum logging level for the *console* handler.
                  Defaults to ``logging.INFO``.  Use ``logging.DEBUG`` for
                  verbose developer output.
        verbose:  Shortcut for ``level=logging.DEBUG``.  When True, DEBUG
                  records appear on the console regardless of *level*.
        rotate:   If True (default), use a ``RotatingFileHandler`` that caps
                  each log file at 5 MB and keeps 3 backups.  If False,
                  append to a plain file handler.

    Returns:
        Configured ``logging.Logger`` instance (also cached in registry).

    Side effects:
        Sets the module-level ``_active_log_file`` path so that
        ``generate_report()`` can copy the session log into the report dir.

    Example:
        >>> from packtrix.logger import setup_logger
        >>> log = setup_logger("packtrix", verbose=True)
    """
    global _active_log_file

    # Re-use cached logger if already configured by a prior setup_logger call
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Clear any handlers left from a previous setup_logger call on this name
    # (important for tests and REPL sessions that re-initialise).
    logger.handlers.clear()

    # ── Console handler ────────────────────────────────────────────────────
    console_level = logging.DEBUG if verbose else level
    ch = _ColourStreamHandler(stream=sys.stdout)
    ch.setLevel(console_level)
    logger.addHandler(ch)

    # ── File handler (optional) ────────────────────────────────────────────
    if log_file != "":
        # Auto-generate a timestamped filename if none supplied
        if not log_file:
            DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
            ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_path = DEFAULT_LOG_DIR / f"packtrix_{ts}.log"
        else:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

        _active_log_file = log_path

        file_fmt = logging.Formatter(_FILE_FORMAT, datefmt=_DATE_FORMAT)

        if rotate:
            fh: logging.Handler = logging.handlers.RotatingFileHandler(
                filename   = log_path,
                maxBytes   = LOG_MAX_BYTES,
                backupCount= LOG_BACKUP_COUNT,
                encoding   = "utf-8",
            )
        else:
            fh = logging.FileHandler(log_path, encoding="utf-8")

        fh.setLevel(logging.DEBUG)   # file always captures everything
        fh.setFormatter(file_fmt)
        logger.addHandler(fh)

    _logger_registry[name] = logger
    return logger


# ---------------------------------------------------------------------------
# log_event — primary public logging function
# ---------------------------------------------------------------------------

def log_event(
    message:    str,
    level:      str             = "INFO",
    event_type: str             = "",
    detail:     Optional[dict]  = None,
    logger:     Optional[logging.Logger] = None,
    module:     str             = "packtrix",
) -> None:
    """
    Emit a structured, optionally file-backed log event.

    This is the primary function imported and called by every Packtrix module.

    Terminal output (coloured):
        [14:03:07] [INFO    ] [scanner   ]  SCAN_START  subnet=192.168.1.0/24

    File output (plain text):
        2026-03-10 14:03:07 | INFO     | scanner    | SCAN_START | {"subnet": "…"}

    The function is designed to work in two styles:

    **Simple style** (module doesn't hold a logger instance)::

        from packtrix.logger import log_event
        log_event("Scan started",          level="INFO")
        log_event("Permission denied",     level="ERROR", module="scanner")

    **Structured style** (module holds a pre-configured logger)::

        from packtrix.logger import get_logger, log_event
        _log = get_logger("scanner")
        log_event("SCAN_START", level="INFO",  event_type="SCAN_START",
                  detail={"subnet": "192.168.1.0/24"}, logger=_log)

    Args:
        message:    Human-readable log message string.  In structured usage
                    this is typically the same as ``event_type``.
        level:      Severity level string — one of:
                    "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
                    (case-insensitive).  Defaults to "INFO".
        event_type: Optional short machine-readable label appended to the
                    message, e.g. "SCAN_START", "ALERT_FIRED", "PORT_OPEN".
                    When provided, it is prepended to the terminal line and
                    serialised into the file record.
        detail:     Optional dict of structured key-value context.  Values
                    are JSON-serialised for the file handler and rendered as
                    ``key=value`` pairs on the terminal.
        logger:     An existing ``logging.Logger`` instance (from
                    ``get_logger()`` or ``setup_logger()``).  When None, the
                    module-level logger for *module* is used.
        module:     Fallback logger name when *logger* is None.
                    Defaults to ``"packtrix"``.

    Returns:
        None

    Raises:
        ValueError: If *level* is not a recognised level string.

    Examples:
        >>> # Minimal — just print a message
        >>> log_event("Scan complete")

        >>> # With level and module context
        >>> log_event("Port 22 open", level="WARNING", module="scanner")

        >>> # Fully structured — level + type + detail dict
        >>> log_event("BRUTE_FORCE", level="ERROR",
        ...           event_type="BRUTE_FORCE",
        ...           detail={"src_ip": "10.0.0.5", "count": 18},
        ...           module="analyzer")
    """
    # ── Normalise level string ─────────────────────────────────────────────
    level_upper = level.upper().strip()
    if level_upper == "WARN":
        level_upper = "WARNING"   # accept "warn" as alias for "warning"
    if level_upper not in {l.upper() for l in _VALID_LEVELS}:
        raise ValueError(
            f"Unknown log level '{level}'. "
            f"Valid levels: {sorted(_VALID_LEVELS)}"
        )

    # ── Resolve logger instance ────────────────────────────────────────────
    # Use the supplied logger; fall back to the registry; create lazily if needed.
    _logger = logger or get_logger(module)

    # ── Build the message string for the terminal ──────────────────────────
    parts: list[str] = []
    if event_type:
        parts.append(event_type)
    if message and message != event_type:
        parts.append(message)
    if detail:
        # Render detail as space-separated key=value pairs for the terminal
        kv_pairs = "  ".join(
            f"{_c(k, _GREY)}={_c(str(v), _WHITE)}"
            for k, v in detail.items()
        )
        parts.append(kv_pairs)

    terminal_msg = "  ".join(parts) if parts else "(no message)"

    # ── Build the structured record for the file handler ──────────────────
    # File handlers receive raw (no-ANSI) text via the stdlib logging system.
    # Embed the event_type and detail dict as a pipe-separated suffix so that
    # the file line can be grepped or parsed programmatically.
    record_parts = [message]
    if event_type and event_type != message:
        record_parts.insert(0, event_type)
    if detail:
        try:
            record_parts.append(json.dumps(detail, default=str))
        except (TypeError, ValueError):
            record_parts.append(str(detail))

    file_msg = " | ".join(record_parts)

    # ── Emit to file handlers via stdlib logging ───────────────────────────
    # We temporarily swap to plain file_msg so file records stay uncoloured.
    log_fn = getattr(_logger, level_upper.lower(), _logger.info)

    # Detach console handlers, emit to file only, then re-attach.
    # This lets us send a coloured message to console handlers manually.
    console_handlers = [h for h in _logger.handlers
                        if isinstance(h, _ColourStreamHandler)]
    file_handlers    = [h for h in _logger.handlers
                        if not isinstance(h, _ColourStreamHandler)]

    # Emit plain text to file handlers via the logger
    if file_handlers:
        for h in console_handlers:
            _logger.removeHandler(h)
        try:
            log_fn(file_msg)
        finally:
            for h in console_handlers:
                _logger.addHandler(h)

    # ── Emit coloured text to console handlers directly ────────────────────
    if console_handlers:
        # Build a minimal LogRecord for the colour handler so it can
        # check the level filter correctly.
        numeric_level = getattr(logging, level_upper, logging.INFO)
        console_record = logging.LogRecord(
            name     = _logger.name,
            level    = numeric_level,
            pathname = "",
            lineno   = 0,
            msg      = terminal_msg,
            args     = (),
            exc_info = None,
        )
        for h in console_handlers:
            if console_record.levelno >= h.level:
                h.emit(console_record)


# ---------------------------------------------------------------------------
# Convenience wrappers  (thin sugar over log_event)
# ---------------------------------------------------------------------------

def debug(message: str, module: str = "packtrix", detail: Optional[dict] = None,
          logger: Optional[logging.Logger] = None) -> None:
    """Emit a DEBUG-level log event.  Suppressed unless verbose mode is on."""
    log_event(message, level="DEBUG", module=module, detail=detail, logger=logger)


def info(message: str, module: str = "packtrix", detail: Optional[dict] = None,
         logger: Optional[logging.Logger] = None) -> None:
    """Emit an INFO-level log event."""
    log_event(message, level="INFO", module=module, detail=detail, logger=logger)


def warning(message: str, module: str = "packtrix", detail: Optional[dict] = None,
            logger: Optional[logging.Logger] = None) -> None:
    """Emit a WARNING-level log event."""
    log_event(message, level="WARNING", module=module, detail=detail, logger=logger)


def error(message: str, module: str = "packtrix", detail: Optional[dict] = None,
          logger: Optional[logging.Logger] = None) -> None:
    """Emit an ERROR-level log event."""
    log_event(message, level="ERROR", module=module, detail=detail, logger=logger)


def critical(message: str, module: str = "packtrix", detail: Optional[dict] = None,
             logger: Optional[logging.Logger] = None) -> None:
    """Emit a CRITICAL-level log event."""
    log_event(message, level="CRITICAL", module=module, detail=detail, logger=logger)


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def export_scan_results(
    results:  dict,
    filepath: str,
    fmt:      str = "json",
) -> str:
    """
    Write scan results to a file in JSON or CSV format.

    The *results* dict is the value returned by ``scanner.scan_network()``:
    a mapping of IP address → {mac, hostname, vendor, ports}.

    CSV output is *flattened*: one row per (host × open-port) combination,
    with a sentinel ``"no open ports"`` row for hosts with an empty port list.

    Args:
        results:  Dict mapping IP → host info dict.
        filepath: Destination file path (created/overwritten).
        fmt:      ``"json"`` (default) or ``"csv"``.

    Returns:
        Absolute path string of the written file.

    Raises:
        ValueError: If *fmt* is not ``"json"`` or ``"csv"``.
        IOError:    If the file cannot be written.
    """
    fmt = fmt.lower().strip()
    if fmt not in ("json", "csv"):
        raise ValueError(f"Unsupported format '{fmt}'. Use 'json' or 'csv'.")

    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        with path.open("w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=str)

    else:  # csv
        # Flatten: one row per (ip, port) pair
        fieldnames = ["ip", "mac", "vendor", "hostname",
                      "port", "state", "service"]
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames,
                                    extrasaction="ignore")
            writer.writeheader()
            for ip, host in results.items():
                ports = host.get("ports", [])
                if not ports:
                    # Write a host row even when no ports were scanned
                    writer.writerow({
                        "ip":       ip,
                        "mac":      host.get("mac", ""),
                        "vendor":   host.get("vendor", ""),
                        "hostname": host.get("hostname", ""),
                        "port":     "",
                        "state":    "",
                        "service":  "",
                    })
                for p in ports:
                    writer.writerow({
                        "ip":       ip,
                        "mac":      host.get("mac", ""),
                        "vendor":   host.get("vendor", ""),
                        "hostname": host.get("hostname", ""),
                        "port":     p.get("port", ""),
                        "state":    p.get("state", ""),
                        "service":  p.get("service", ""),
                    })

    log_event(f"Scan results exported → {path}", level="INFO", module="logger")
    return str(path.resolve())


def export_alerts(
    alerts:   list,
    filepath: str,
    fmt:      str = "json",
) -> str:
    """
    Write security alerts to a file in JSON, CSV, or TXT format.

    Accepts both ``Alert`` dataclass instances (from ``analyzer.py``) and
    plain dicts — whichever form ``analyze_logs()`` returns.

    TXT format produces a human-readable report suitable for email
    attachments or ticket notes::

        ═══════════════════════════════════════
        PACKTRIX SECURITY ALERT REPORT
        Generated: 2026-03-10 14:03:07 UTC
        ═══════════════════════════════════════
        [1] HIGH     PORT_SCAN       10.0.0.99
            20 unique ports probed within 10s window — ports: 21, 22, …
        ...

    Args:
        alerts:   List of ``Alert`` dataclass objects or plain dicts.
        filepath: Destination file path (created/overwritten).
        fmt:      ``"json"`` (default), ``"csv"``, or ``"txt"``.

    Returns:
        Absolute path string of the written file.

    Raises:
        ValueError: If *fmt* is not ``"json"``, ``"csv"``, or ``"txt"``.
    """
    fmt = fmt.lower().strip()
    if fmt not in ("json", "csv", "txt"):
        raise ValueError(
            f"Unsupported format '{fmt}'. Use 'json', 'csv', or 'txt'."
        )

    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Normalise to plain dicts regardless of whether we received dataclass
    # instances or pre-serialised dicts (e.g. loaded from a previous export).
    alert_dicts: list[dict] = []
    for a in alerts:
        if hasattr(a, "__dataclass_fields__"):
            alert_dicts.append(asdict(a))
        elif isinstance(a, dict):
            alert_dicts.append(a)
        else:
            alert_dicts.append(vars(a))

    if fmt == "json":
        with path.open("w", encoding="utf-8") as fh:
            json.dump(alert_dicts, fh, indent=2, default=str)

    elif fmt == "csv":
        if alert_dicts:
            fieldnames = list(alert_dicts[0].keys())
        else:
            fieldnames = ["timestamp", "alert_type", "severity",
                          "src_ip", "dst_ip", "dst_port",
                          "event_count", "detail", "rule"]
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames,
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(alert_dicts)

    else:  # txt
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_alerts = sorted(
            alert_dicts,
            key=lambda a: sev_order.get(a.get("severity", "INFO"), 9),
        )
        lines: list[str] = [
            "═" * 55,
            "PACKTRIX — SECURITY ALERT REPORT",
            f"Generated : {now}",
            f"Total     : {len(sorted_alerts)} alert(s)",
            "═" * 55,
            "",
        ]
        for idx, alert in enumerate(sorted_alerts, start=1):
            sev    = alert.get("severity",    "?")
            atype  = alert.get("alert_type",  "?")
            src    = alert.get("src_ip",      "?")
            count  = alert.get("event_count", 0)
            detail = alert.get("detail",      "")
            ts     = alert.get("timestamp",   "")
            port   = alert.get("dst_port",    "")
            port_s = f"  port={port}" if port else ""
            lines += [
                f"[{idx}] {sev:<10} {atype:<16} {src}{port_s}",
                f"    Events   : {count}",
                f"    Detail   : {detail}",
                f"    At       : {ts}",
                "",
            ]
        with path.open("w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    log_event(f"Alerts exported ({fmt.upper()}) → {path}",
              level="INFO", module="logger")
    return str(path.resolve())


def export_packets(
    packets:  list,
    filepath: str,
    fmt:      str = "json",
) -> str:
    """
    Export a captured packet list to JSON or CSV with full timestamps.

    Each packet row includes a human-readable ``datetime`` column derived
    from the Unix-epoch ``timestamp`` field so exported files are immediately
    readable without extra processing.

    Args:
        packets:  List of packet dicts from ``sniffer.capture_packets()``.
        filepath: Destination file path.
        fmt:      ``"json"`` (default) or ``"csv"``.

    Returns:
        Absolute path string of the written file.

    Raises:
        ValueError: If *fmt* is not ``"json"`` or ``"csv"``.
    """
    fmt = fmt.lower().strip()
    if fmt not in ("json", "csv"):
        raise ValueError(f"Unsupported format '{fmt}'. Use 'json' or 'csv'.")

    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Enrich each packet with a human-readable datetime field
    enriched: list[dict] = []
    for pkt in packets:
        row = dict(pkt)
        try:
            ts  = float(row.get("timestamp", 0))
            row["datetime"] = datetime.fromtimestamp(ts, tz=timezone.utc) \
                                      .strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
        except (TypeError, ValueError, OSError):
            row["datetime"] = ""
        enriched.append(row)

    if fmt == "json":
        with path.open("w", encoding="utf-8") as fh:
            json.dump(enriched, fh, indent=2, default=str)

    else:  # csv
        if enriched:
            # Move datetime to be the first column
            all_keys = list(enriched[0].keys())
            if "datetime" in all_keys:
                all_keys = ["datetime"] + [k for k in all_keys if k != "datetime"]
        else:
            all_keys = ["datetime", "src_ip", "dst_ip", "src_port", "dst_port",
                        "protocol", "service", "size", "flags", "info"]
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=all_keys, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(enriched)

    log_event(f"Packets exported ({fmt.upper()}, {len(packets)} pkts) → {path}",
              level="INFO", module="logger")
    return str(path.resolve())


# ---------------------------------------------------------------------------
# Session report generator
# ---------------------------------------------------------------------------

def generate_report(
    scan_results: dict,
    alerts:       list,
    output_dir:   str = ".",
) -> dict[str, str]:
    """
    Bundle all session outputs into a single timestamped report directory.

    Creates the following files under *output_dir*:

    ::

        <output_dir>/
        ├── scan_results.json     — full host/port data (JSON)
        ├── scan_results.csv      — flattened host/port rows (CSV)
        ├── alerts.json           — machine-readable alert list (JSON)
        ├── alerts.csv            — flat alert table (CSV)
        ├── alerts.txt            — human-readable narrative report (TXT)
        └── session.log           — copy of the active session log file
                                    (omitted if file logging was not set up)

    Prints a summary table of created files to the terminal.

    Args:
        scan_results: Dict from ``scanner.scan_network()``.
        alerts:       List of ``Alert`` objects from ``analyzer.analyze_logs()``.
        output_dir:   Directory to write report files into.
                      Created (including parents) if it does not exist.

    Returns:
        Dict mapping file role → absolute path string for every file written.
        E.g. ``{"scan_json": "/path/to/scan_results.json", ...}``

    Example:
        >>> from packtrix.logger import generate_report
        >>> paths = generate_report(scan_results, alerts, output_dir="reports/session1")
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    written: dict[str, str] = {}

    # ── Scan results ──────────────────────────────────────────────────────
    written["scan_json"] = export_scan_results(
        scan_results, str(out / "scan_results.json"), fmt="json"
    )
    written["scan_csv"] = export_scan_results(
        scan_results, str(out / "scan_results.csv"),  fmt="csv"
    )

    # ── Alerts ────────────────────────────────────────────────────────────
    written["alerts_json"] = export_alerts(
        alerts, str(out / "alerts.json"), fmt="json"
    )
    written["alerts_csv"] = export_alerts(
        alerts, str(out / "alerts.csv"),  fmt="csv"
    )
    written["alerts_txt"] = export_alerts(
        alerts, str(out / "alerts.txt"),  fmt="txt"
    )

    # ── Session log copy ─────────────────────────────────────────────────
    if _active_log_file and _active_log_file.exists():
        dest = out / "session.log"
        shutil.copy2(_active_log_file, dest)
        written["session_log"] = str(dest.resolve())
        log_event(f"Session log copied → {dest}", level="INFO", module="logger")

    # ── Print summary ─────────────────────────────────────────────────────
    _print_report_summary(written, out)

    return written


def _print_report_summary(written: dict[str, str], out: Path) -> None:
    """
    Print a neat summary table of all files written by generate_report().

    Args:
        written: Dict mapping role → absolute path string.
        out:     Report output directory Path.
    """
    border = _c("─" * 56, _GREY + _DIM)
    print(f"\n  {_c('Report generated', _BOLD, _WHITE)}"
          f"  {_c(str(out.resolve()), _CYAN)}")
    print(border)

    # Role label → friendly display name
    labels = {
        "scan_json":    "Scan results (JSON)",
        "scan_csv":     "Scan results (CSV) ",
        "alerts_json":  "Alerts      (JSON) ",
        "alerts_csv":   "Alerts      (CSV)  ",
        "alerts_txt":   "Alerts      (TXT)  ",
        "session_log":  "Session log        ",
    }
    for role, path_str in written.items():
        label = labels.get(role, role)
        fname = Path(path_str).name
        size  = Path(path_str).stat().st_size
        print(f"  {_c(label, _WHITE)}  {_c(fname, _CYAN)}"
              f"  {_c(f'({size:,} B)', _GREY + _DIM)}")
    print(border + "\n")
