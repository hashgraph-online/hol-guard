"""Empty replacement ownership must preserve existing policy authority."""

from pathlib import Path

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore


def test_empty_owned_sources_preserve_all_existing_policies(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    for source in ("policy-bundle", "cloud-signed-memory", "team-policy"):
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id=f"command:ownership-{source}",
                source=source,
            ),
            "2026-09-17T12:00:00Z",
            remote_write_authorized=True,
        )
    before = store.list_policy_decisions()
    assert len(before) == 3
    with store._connect() as connection:
        store._replace_remote_policy_rows_locked(connection, [], sources=frozenset())
    assert store.list_policy_decisions() == before
