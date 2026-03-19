"""
plugins/registry.py — Plugin Registry & Loader
================================================
Discovers, loads, and manages all DetectionRule plugins.

The registry provides a single shared instance (``registry``) that
is used by the analyzer module and CLI.  Plugins are Python files
that subclass ``DetectionRule``; no explicit registration call is needed
— the registry finds them by scanning for subclasses after import.

Plugin discovery order:
    1. Built-in rules in ``packtrix/plugins/rules/``
    2. User plugins in any directory on ``PACKTRIX_PLUGIN_PATH`` env var
       (colon-separated list of paths, like ``PYTHONPATH``)
    3. Plugins in ``~/.packtrix/plugins/`` (auto-created if missing)

Usage::

    from packtrix.plugins.registry import registry

    # Load all built-in + user plugins
    registry.load_all()

    # Run every enabled plugin against a packet list
    alerts = registry.run_all(packets)

    # List loaded plugins
    for rule in registry.rules:
        print(rule.name, rule.enabled)

    # Enable / disable by name
    registry.disable("TRAFFIC_SPIKE")
    registry.enable("MY_CUSTOM_RULE")
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import sys
from pathlib import Path
from typing import Iterator, Optional

from packtrix.plugins.base import DetectionRule, AlertResult


class PluginRegistry:
    """
    Central registry for all ``DetectionRule`` plugins.

    Attributes:
        rules:  Ordered list of instantiated DetectionRule objects that
                have been loaded into this registry.
        _seen:  Set of class qualified names already registered (prevents
                duplicate registration when modules are reloaded).
    """

    def __init__(self) -> None:
        self.rules:  list[DetectionRule] = []
        self._seen:  set[str] = set()

    # ── Discovery & Loading ───────────────────────────────────────────────

    def load_all(self) -> "PluginRegistry":
        """
        Discover and load plugins from all standard locations.

        Loads in priority order:
            1. Built-in rules (``packtrix/plugins/rules/``)
            2. User home plugins (``~/.packtrix/plugins/``)
            3. Paths listed in ``PACKTRIX_PLUGIN_PATH`` env var

        Returns:
            Self, for method chaining.

        Example:
            >>> from packtrix.plugins.registry import registry
            >>> registry.load_all()
        """
        # 1. Built-in rules bundled with the package
        built_in = Path(__file__).parent / "rules"
        if built_in.is_dir():
            self.load_directory(built_in)

        # 2. User plugins in ~/.packtrix/plugins/
        user_dir = Path.home() / ".packtrix" / "plugins"
        user_dir.mkdir(parents=True, exist_ok=True)
        self.load_directory(user_dir)

        # 3. Extra paths from environment variable
        env_path = os.environ.get("PACKTRIX_PLUGIN_PATH", "")
        for path_str in env_path.split(":"):
            path_str = path_str.strip()
            if path_str:
                extra = Path(path_str)
                if extra.is_dir():
                    self.load_directory(extra)

        return self

    def load_directory(self, directory: Path) -> int:
        """
        Import every ``*.py`` file in *directory* and register any
        ``DetectionRule`` subclasses found in them.

        Files starting with ``_`` (e.g. ``__init__.py``) are skipped.

        Args:
            directory: Path to the directory to scan.

        Returns:
            Number of new rules registered during this call.
        """
        if not directory.is_dir():
            return 0

        loaded = 0
        for py_file in sorted(directory.glob("*.py")):
            if py_file.stem.startswith("_"):
                continue
            loaded += self._load_file(py_file)
        return loaded

    def _load_file(self, path: Path) -> int:
        """
        Import a single plugin file and register any DetectionRule subclasses.

        Args:
            path: Absolute path to the ``.py`` file.

        Returns:
            Number of new rules registered.
        """
        module_name = f"_packtrix_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                return 0
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)          # type: ignore[union-attr]
        except Exception as exc:
            # Log but do not crash on a broken plugin file
            _warn(f"Failed to load plugin '{path.name}': {exc}")
            return 0

        return self._register_from_module(module)

    def register(self, rule_cls: type) -> bool:
        """
        Register a single ``DetectionRule`` subclass.

        Args:
            rule_cls: A class (not instance) that subclasses DetectionRule.

        Returns:
            True if newly registered; False if already registered or invalid.
        """
        if not (isinstance(rule_cls, type)
                and issubclass(rule_cls, DetectionRule)
                and rule_cls is not DetectionRule):
            return False

        key = f"{rule_cls.__module__}.{rule_cls.__qualname__}"
        if key in self._seen:
            return False

        self._seen.add(key)
        self.rules.append(rule_cls())
        return True

    def _register_from_module(self, module) -> int:           # type: ignore
        """Register all DetectionRule subclasses found in *module*."""
        count = 0
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, DetectionRule)
                    and obj is not DetectionRule
                    and obj.__module__ == module.__name__):
                if self.register(obj):
                    count += 1
        return count

    # ── Execution ─────────────────────────────────────────────────────────

    def run_all(self, packets: list[dict]) -> list[AlertResult]:
        """
        Run every *enabled* plugin against *packets* and return all alerts.

        Each plugin's ``reset()`` is called before ``analyze()`` so stateful
        rules produce independent results each time ``run_all`` is called.

        Results are sorted by severity (CRITICAL first).

        Args:
            packets: Full list of packet dicts to analyse.

        Returns:
            Sorted list of ``AlertResult`` objects from all enabled rules.
        """
        _SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_alerts: list[AlertResult] = []

        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                rule.reset()
                alerts = rule.analyze(packets)
                all_alerts.extend(alerts)
            except Exception as exc:
                _warn(f"Rule '{rule.name}' raised an error: {exc}")

        all_alerts.sort(key=lambda a: (_SEV.get(a.severity, 9), a.src_ip))
        return all_alerts

    def run_one(self, rule_name: str, packets: list[dict]) -> list[AlertResult]:
        """
        Run only the plugin matching *rule_name* (case-insensitive).

        Args:
            rule_name: The ``name`` attribute of the rule to run.
            packets:   Packet list to analyse.

        Returns:
            Alerts from that rule, or empty list if not found / disabled.
        """
        for rule in self.rules:
            if rule.name.upper() == rule_name.upper():
                if not rule.enabled:
                    return []
                rule.reset()
                return rule.analyze(packets)
        return []

    # ── Enable / Disable ──────────────────────────────────────────────────

    def enable(self, name: str) -> bool:
        """Enable the rule matching *name*. Returns True if found."""
        return self._set_enabled(name, True)

    def disable(self, name: str) -> bool:
        """Disable the rule matching *name*. Returns True if found."""
        return self._set_enabled(name, False)

    def _set_enabled(self, name: str, state: bool) -> bool:
        for rule in self.rules:
            if rule.name.upper() == name.upper():
                rule.enabled = state
                return True
        return False

    # ── Introspection ─────────────────────────────────────────────────────

    def get(self, name: str) -> Optional[DetectionRule]:
        """Return the rule with *name*, or None if not found."""
        for rule in self.rules:
            if rule.name.upper() == name.upper():
                return rule
        return None

    def __iter__(self) -> Iterator[DetectionRule]:
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    def __repr__(self) -> str:
        return f"<PluginRegistry rules={len(self.rules)} loaded>"

    # ── Summary table ─────────────────────────────────────────────────────

    def summary_table(self) -> str:
        """
        Return a formatted table of all loaded plugins as a string.

        Columns: #, Name, Severity, Enabled, Version, Description

        Returns:
            Multi-line string ready to ``print()``.
        """
        from packtrix.utils import format_table, SEV_ANSI, c, GREEN, RED, RESET
        if not self.rules:
            return "  (no plugins loaded)"

        rows = []
        for rule in self.rules:
            sc  = SEV_ANSI.get(rule.severity, "")
            sev = c(rule.severity, sc) if sc else rule.severity
            en  = c("✔ yes", GREEN) if rule.enabled else c("✘ no", RED)
            rows.append({
                "name":        rule.name,
                "severity":    sev,
                "enabled":     en,
                "version":     rule.version,
                "author":      rule.author,
                "description": rule.description,
            })

        return format_table(
            rows,
            columns=["name", "severity", "enabled", "version", "description"],
            title=f"Loaded Plugins ({len(self.rules)})",
            show_index=True,
        )


# ---------------------------------------------------------------------------
# Module-level warning helper
# ---------------------------------------------------------------------------

def _warn(msg: str) -> None:
    """Print a warning to stderr without raising."""
    import sys
    print(f"\033[33m[!] {msg}\033[0m", file=sys.stderr)


# ---------------------------------------------------------------------------
# Shared singleton — import this from all consumers
# ---------------------------------------------------------------------------

#: Module-level singleton.  Import and call ``registry.load_all()`` once at
#: startup (typically in ``analyzer.analyze_logs`` or ``cli.main``).
registry: PluginRegistry = PluginRegistry()
