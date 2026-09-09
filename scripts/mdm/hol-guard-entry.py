"""PyInstaller entrypoint for the machine-owned HOL Guard runtime."""

from __future__ import annotations

import json
import sys
from multiprocessing import freeze_support
from pathlib import Path

_FROZEN_DAEMON_SERVE_ARG = "--_hol-guard-daemon-serve"


def _consume_frozen_daemon_serve_gate() -> bool:
    """Read the parent gate before importing any Guard package code."""

    if len(sys.argv) != 3 or sys.argv[1] != _FROZEN_DAEMON_SERVE_ARG:
        return False
    try:
        payload = json.loads(sys.argv[2])
        if not isinstance(payload, dict) or set(payload) != {"guard_home", "home_dir", "port"}:
            raise ValueError
        guard_home = Path(payload["guard_home"])
        home_dir = Path(payload["home_dir"])
        port = payload["port"]
        if (
            not isinstance(payload["guard_home"], str)
            or not isinstance(payload["home_dir"], str)
            or not guard_home.is_absolute()
            or not home_dir.is_absolute()
            or guard_home != guard_home.resolve(strict=False)
            or home_dir != home_dir.resolve(strict=False)
            or type(port) is not int
            or not 1 <= port <= 65_535
            or Path(sys.argv[0]).expanduser().resolve(strict=True)
            != Path(sys.executable).expanduser().resolve(strict=True)
        ):
            raise ValueError
        gate_stream = getattr(sys.stdin, "buffer", sys.stdin)
        if gate_stream.read(1) != b"1":
            raise SystemExit(70)
    except SystemExit:
        raise
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        raise SystemExit(70) from None
    return True


if __name__ == "__main__":
    # Dispatch PyInstaller multiprocessing children before importing Guard.
    # Otherwise private resource-tracker argv is parsed as a public CLI command.
    freeze_support()

    daemon_gate_released = _consume_frozen_daemon_serve_gate()

    from codex_plugin_scanner.guard.frozen_daemon_runtime import install_frozen_daemon_runtime

    install_frozen_daemon_runtime()

    from codex_plugin_scanner.guard.frozen_codex_runtime import (
        install_frozen_codex_runtime,
        run_frozen_internal_command,
    )

    install_frozen_codex_runtime()
    if daemon_gate_released:
        internal_exit_code = run_frozen_internal_command(gate_already_released=True)
    else:
        internal_exit_code = run_frozen_internal_command()
    if internal_exit_code is not None:
        raise SystemExit(internal_exit_code)

    from codex_plugin_scanner.cli import main

    raise SystemExit(main())
