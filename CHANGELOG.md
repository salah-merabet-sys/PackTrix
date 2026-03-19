# Changelog

All notable changes to Packtrix are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.4] — 2026-03-18

### Fixed
- Dashboard pause and quit keys not responding — replaced per-keypress
  raw-mode toggle (`_read_key`) with `_RawTerm` context manager that holds
  raw mode for the entire session; `read_key(timeout=refresh_rate)` now
  replaces `time.sleep()` so keys land instantly without pressing Enter
- Sniffer Ctrl+C not working — generator sleep runs on a background thread
  so the interrupt flag is checked every 100 ms regardless of inter-packet delay
- Dashboard flickering — `CursorUI` in-place renderer rewrites only changed
  lines; no full-screen clear on each refresh cycle

### Added
- `_display.py` — shared ANSI primitives, `CursorUI`, `bar()`, `pad()`,
  `sev_colour()`, `proto_colour()` used by scanner, sniffer, and dashboard
- `_RawTerm` context manager — single raw-mode session for reliable keyboard
  input in the dashboard
- `MANIFEST.in`, `LICENSE`, `PUBLISHING.md`, `CHANGELOG.md` for PyPI publishing

### Changed
- Dashboard rebuilt on `CursorUI` (zero third-party deps, no Rich, no Textual)
- Scanner and sniffer display updated to use shared `_display` helpers
- Version bumped to `0.1.4` in `__init__.py`, `pyproject.toml`, `requirements.txt`

---

## [0.1.0] — 2026-03-01

### Added
- Initial project scaffold with placeholder implementations for all four commands
- `scan`, `sniff`, `analyze`, `dashboard` CLI sub-commands
- Plugin autodiscovery system for `analyze`
- Structured logging with JSON / CSV / TXT export
