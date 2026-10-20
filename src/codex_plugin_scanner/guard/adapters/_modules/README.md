# Internal harness modules

Files here remain importable as `codex_plugin_scanner.guard.adapters.<module>`, not `codex_plugin_scanner.guard.adapters._modules.<family>.<module>`. This retains imports in existing CLI, daemon, and tests.

The parent `adapters/__init__.py` declares the searched family directories. These subdirectories intentionally have no Python `__init__.py`; do not create a second module identity or duplicate a file at the adapter root. Public adapter entrypoints and contract-pinned/path-sensitive files remain in the parent directory.

Families currently grouped here: `claude`, `cline`, `codex`, `copilot`, `cursor`, `devin`, `grok`, `opencode`, `pi`, `zcode`.

See [adapter contributions](../../../../../docs/guard/adapter-contributions.md) before relocating more files.
