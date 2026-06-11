#!/usr/bin/env python3
"""Start a short-lived Guard daemon for cloud-to-local browser proofs."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from codex_plugin_scanner.guard.daemon import GuardDaemonServer  # noqa: E402
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token  # noqa: E402
from codex_plugin_scanner.guard.store import GuardStore  # noqa: E402


def _restore_home(original_home: str | None) -> None:
    if original_home is None:
        os.environ.pop("HOME", None)
    else:
        os.environ["HOME"] = original_home


def main() -> int:
    evidence_dir = Path(os.environ.get("GUARD_BROWSER_DAEMON_EVIDENCE_DIR", ".guard-browser-daemon")).resolve()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    original_home = os.environ.get("HOME")
    home_dir = evidence_dir / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home_dir)
    os.environ.setdefault("SHELL", "/bin/zsh")

    guard_home = evidence_dir / "guard-home"
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    try:
        daemon.start()
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        if auth_token is None:
            raise SystemExit("Guard daemon auth token was unavailable.")

        sys.stdout.write(
            json.dumps(
                {
                    "authToken": auth_token,
                    "origin": f"http://127.0.0.1:{daemon.port}",
                    "port": daemon.port,
                },
            )
            + "\n",
        )
        sys.stdout.flush()
        sys.stdin.read()
    finally:
        daemon.stop()
        _restore_home(original_home)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
