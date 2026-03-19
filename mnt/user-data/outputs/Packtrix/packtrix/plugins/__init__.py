"""
plugins/ — Detection Rule Plugin System
========================================
Provides the base class, registry, and loader for Packtrix detection rule
plugins.  Each plugin is a Python file that subclasses ``DetectionRule``.

Quick-start: drop a file into ~/.packtrix/plugins/ (or anywhere on
PACKTRIX_PLUGIN_PATH), inherit DetectionRule, implement analyze().
"""
from packtrix.plugins.base import DetectionRule, AlertResult
from packtrix.plugins.registry import PluginRegistry, registry

__all__ = ["DetectionRule", "AlertResult", "PluginRegistry", "registry"]
