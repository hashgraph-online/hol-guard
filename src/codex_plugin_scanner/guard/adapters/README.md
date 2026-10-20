# Adapter source map

Start with [the adapter contribution guide](../../../../docs/guard/adapter-contributions.md).

- `__init__.py`: public harness registry and stable import namespace.
- `base.py`: `HarnessAdapter`, `HarnessContext`, install ownership and shared utilities.
- `<harness>.py`: public adapter class. Examples: `cursor.py`, `cline.py`, `pi.py`, `gemini.py`.
- `contract_registry.py` and `contracts.py`: supported hosts and capability/setup contracts.
- `contract_*capabilities.py`: verified host-event capability declarations.
- `_modules/<family>/`: grouped internal helper files for Claude, Cline, Codex, Copilot, Cursor, Devin, Grok, OpenCode, Pi, and ZCode.
- Other root helpers: shared transports, MCP discovery, state protection, and code still at a path pinned by an ownership contract or dependent on `__file__`.

Existing `codex_plugin_scanner.guard.adapters.<module>` imports remain valid for grouped helpers. The package adds only installed `_modules` directories to its import search path. Never add workspace, home, or arbitrary user directories.

Before moving a remaining root file, check whether source-bound contracts or relative resource lookups refer to its original location. Update those and test the installed wheel along with source imports.
