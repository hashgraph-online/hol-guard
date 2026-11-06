"""Load reviewed repository trust data for offline migration tools."""

from __future__ import annotations

import sys
from pathlib import Path


def repository_trust_map(repository: Path) -> dict:
    """Require authored bindings and use the trusted tooling checkout's parser."""
    bindings = repository / "contracts/extensions/trust"
    if not bindings.is_dir() or not any(bindings.glob("*.v1.json")):
        raise ValueError("repository authored trust bindings are missing")
    # The inspected repository supplies data only, never imported Python.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from codex_plugin_scanner.guard.runtime.extension_trust import trust_map_from_bindings

    return trust_map_from_bindings(bindings)
