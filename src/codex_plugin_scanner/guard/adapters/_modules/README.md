# Internal harness modules

Each family is an ordinary Python package. Import a helper by its source layout, for example `codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_events`. Keep `__init__.py` in `_modules/` and every family so Python, static analysis, and frozen-package collectors agree on module identity.

Public adapter classes and helpers bound by physical-path contracts remain in the parent directory. In particular, `codex_daemon_hook_resume.py` is authenticated by Codex manifests at its original path. Do not duplicate implementations or add compatibility search paths.

Families: `claude`, `cline`, `codex`, `copilot`, `cursor`, `devin`, `grok`, `opencode`, `pi`, `zcode`.

See [adapter contributions](../../../../../docs/guard/adapter-contributions.md) before relocating more files.
