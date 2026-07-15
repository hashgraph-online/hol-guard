"""PyInstaller entrypoint for the machine-owned HOL Guard runtime."""

from codex_plugin_scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
