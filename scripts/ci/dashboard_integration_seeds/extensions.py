"""Seed data for the dashboard extensions integration specs.

The built-in command extensions come from the real catalog the daemon warms,
so the only record this module adds is one observed CLI tool Guard has not been
told to trust, which gives the custom-extensions list a deterministic row.
"""

from __future__ import annotations

from typing import Any

from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

from . import SeedContext

# The custom list sorts by most recently seen, so a far-future observation keeps
# the tool inside the list's short preview even when the machine running the
# daemon also has detected host connectors.
SEEN_AT = "2099-01-01T00:00:00Z"
CLI_NAME = "aaa-e2e-fixture-cli"
CLI_ID = f"local-cli.{CLI_NAME}"


def seed(context: SeedContext) -> dict[str, Any]:
    identity = UnlistedCliIdentity(
        cli_id=CLI_ID,
        name=CLI_NAME,
        kind="executable",
        identity_hash="e2".ljust(64, "0"),
        example_label=f"{CLI_NAME} deploy",
    )
    context.store.record_local_cli_observation(identity, seen_at=SEEN_AT, help_status="ok")
    return {"custom_cli_id": CLI_ID, "custom_cli_name": CLI_NAME, "custom_cli_example": identity.example_label}
