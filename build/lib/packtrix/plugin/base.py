"""
plugins/base.py — Plugin Base Class & Alert Result
====================================================
Defines the ``DetectionRule`` abstract base class that all detection
rule plugins must subclass, and the ``AlertResult`` dataclass they return.

Every plugin file must:
    1. Import DetectionRule and AlertResult from this module.
    2. Define exactly one subclass of DetectionRule.
    3. Set class-level metadata: ``name``, ``description``, ``severity``.
    4. Implement ``analyze(packets) -> list[AlertResult]``.

The plugin system loads all subclasses automatically via
``PluginRegistry.load_directory()`` — no registration call needed.

Example minimal plugin::

    from packtrix.plugins.base import DetectionRule, AlertResult

    class MyRule(DetectionRule):
        name        = "MY_RULE"
        description = "Detects something suspicious."
        severity    = "HIGH"
        enabled     = True

        def analyze(self, packets: list[dict]) -> list[AlertResult]:
            results = []
            for pkt in packets:
                if pkt.get("dst_port") == 31337:
                    results.append(self.make_alert(
                        src_ip      = pkt["src_ip"],
                        event_count = 1,
                        detail      = "Back-Orifice port contacted",
                    ))
            return results
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# AlertResult dataclass — returned by every plugin
# ---------------------------------------------------------------------------

@dataclass
class AlertResult:
    """
    A single security alert produced by a ``DetectionRule`` plugin.

    This is the canonical alert structure used throughout the tool.  The
    ``analyzer`` module's ``Alert`` class mirrors this structure; both are
    accepted wherever alerts are consumed (dashboard, logger, CLI).

    Attributes:
        timestamp   UTC ISO-8601 string when the alert fired.
        alert_type  Machine-readable rule identifier, e.g. "BRUTE_FORCE".
        severity    One of: CRITICAL, HIGH, MEDIUM, LOW, INFO.
        src_ip      Source IP that triggered the rule.
        dst_ip      Destination IP, or "" when not applicable.
        dst_port    Destination port integer, or None.
        event_count Number of individual events that fired this alert.
        detail      Human-readable description with context.
        rule        Canonical rule name (populated by DetectionRule.make_alert).
        extra       Optional freeform dict for plugin-specific metadata.
    """
    timestamp:   str
    alert_type:  str
    severity:    str
    src_ip:      str
    dst_ip:      str
    dst_port:    Optional[int]
    event_count: int
    detail:      str
    rule:        str   = field(default="")
    extra:       dict  = field(default_factory=dict)

    # ── Compatibility helpers ─────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Return all fields as a plain dict (for JSON / CSV export)."""
        from dataclasses import asdict
        return asdict(self)

    @property
    def alert_dict(self) -> dict:
        """Alias for ``to_dict()`` — mirrors the analyzer.Alert API."""
        return self.to_dict()


# ---------------------------------------------------------------------------
# DetectionRule abstract base class
# ---------------------------------------------------------------------------

class DetectionRule(ABC):
    """
    Abstract base class for all Packtrix detection rule plugins.

    Subclass this, set the class-level metadata attributes, implement
    ``analyze()``, and drop the file into the ``plugins/`` directory (or
    any path on ``PACKTRIX_PLUGIN_PATH``).  The registry will discover
    and register it automatically.

    Class-level metadata attributes
    --------------------------------
    name : str
        Short machine-readable identifier, e.g. ``"BRUTE_FORCE"``.
        Used as ``alert_type`` in ``AlertResult`` objects.
    description : str
        Human-readable one-line description for ``packtrix plugins list``.
    severity : str
        Default severity level: CRITICAL, HIGH, MEDIUM, LOW, or INFO.
        Plugins may override per-alert inside ``analyze()``.
    enabled : bool
        When False the registry will load but not call the rule.
        Default: True.
    version : str
        Semantic version string for the plugin (default "1.0.0").
    author : str
        Plugin author / maintainer (optional, shown in ``plugins list``).

    Abstract method
    ---------------
    analyze(packets) -> list[AlertResult]
        Receive the full packet list (or sliding window), return any
        ``AlertResult`` objects for detected threats.
    """

    # ── Metadata (override in subclass) ──────────────────────────────────
    name:        str  = "UNNAMED_RULE"
    description: str  = "No description provided."
    severity:    str  = "MEDIUM"
    enabled:     bool = True
    version:     str  = "1.0.0"
    author:      str  = "packtrix"

    # ── Internal state reset between analysis runs ────────────────────────
    def reset(self) -> None:
        """
        Reset any internal state accumulated from previous ``analyze()`` calls.

        Stateful plugins (e.g. those tracking sliding windows) should override
        this to clear their counters so repeated calls on different packet lists
        are independent.

        The registry calls ``reset()`` before each full analysis run.
        """

    # ── Core method ───────────────────────────────────────────────────────
    @abstractmethod
    def analyze(self, packets: list[dict]) -> list["AlertResult"]:
        """
        Analyse *packets* and return any triggered alerts.

        Args:
            packets: Chronologically sorted list of packet dicts.
                     Each dict has at minimum the keys:
                     ``timestamp``, ``src_ip``, ``dst_ip``, ``protocol``,
                     ``src_port``, ``dst_port``, ``flags``, ``size``,
                     ``service``, ``info``.

        Returns:
            List of ``AlertResult`` objects (may be empty).
        """

    # ── Convenience factory ───────────────────────────────────────────────
    def make_alert(
        self,
        src_ip:       str,
        event_count:  int,
        detail:       str,
        dst_ip:       str           = "",
        dst_port:     Optional[int] = None,
        severity:     Optional[str] = None,
        extra:        Optional[dict] = None,
    ) -> "AlertResult":
        """
        Construct an ``AlertResult`` with this rule's metadata pre-filled.

        Plugins should call this instead of constructing ``AlertResult``
        directly to ensure ``alert_type`` and ``rule`` are consistent.

        Args:
            src_ip:       Source IP address that triggered the alert.
            event_count:  Number of matching events.
            detail:       Human-readable description.
            dst_ip:       Destination IP (optional).
            dst_port:     Destination port integer (optional).
            severity:     Override the class-level severity for this alert.
            extra:        Optional freeform metadata dict.

        Returns:
            Populated ``AlertResult`` instance.
        """
        return AlertResult(
            timestamp   = datetime.now(timezone.utc).isoformat(timespec="seconds"),
            alert_type  = self.name,
            severity    = severity or self.severity,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            dst_port    = dst_port,
            event_count = event_count,
            detail      = detail,
            rule        = f"{self.__class__.__module__}.{self.__class__.__name__}",
            extra       = extra or {},
        )

    # ── String representation ─────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} name={self.name!r} "
            f"severity={self.severity!r} enabled={self.enabled}>"
        )
