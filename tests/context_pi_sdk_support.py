"""Guard store setup for the pinned Pi/OMP SDK execution fixture."""

from __future__ import annotations

import os
from pathlib import Path

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.store import GuardStore


def cli_bootstrap(repo: Path) -> str:
    root = repo / "src"
    if os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") == "1":
        import codex_plugin_scanner

        root = Path(codex_plugin_scanner.__file__).resolve().parents[1]
        assert root != (repo / "src").resolve(), "installed SDK delivery must not import the checkout"
    return f"sys.path.insert(0, {str(root)!r})\n"


def prepare_store(guard: Path, duration: str):
    settings: dict[str, object] = {"blocked_request_mode": "ask"}
    if duration == "quiet":
        settings.update(
            {
                "default_action": "allow",
                "subprocess_action": "allow",
                "risk_actions": {"network_egress": "allow", "persistence": "allow"},
            }
        )
    else:
        # Preserve deliberate Ask independently of temporary-directory policy.
        settings["subprocess_action"] = "require-reapproval"
    update_guard_settings(guard, settings)
    return GuardStore(guard)
