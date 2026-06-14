import pytest

from codex_plugin_scanner.guard.models import GuardReceipt, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore


def _store(tmp_path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def test_list_policy_decisions_enriches_source_receipt_and_command(tmp_path) -> None:
    store = _store(tmp_path)
    receipt = GuardReceipt(
        receipt_id="receipt-policy-ux-1",
        timestamp="2026-06-14T12:00:00+00:00",
        harness="codex",
        artifact_id="codex:project:package-request:abc123",
        artifact_hash="2dd8986742cb4f850ae2bb52a9aaa2820c6d9be809592ec0c4b3d207b83f9b6",
        policy_decision="allow",
        capabilities_summary="Package install via pnpm",
        changed_capabilities=("package-request",),
        provenance_summary="hook event for package install",
        artifact_name="pnpm install",
        source_scope="~/projects/hol-points-portal",
    )
    store.add_receipt(receipt)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="workspace",
            action="allow",
            artifact_id="codex:project:package-request:abc123",
            artifact_hash="sha256:2dd8986742cb4f850ae2bb52a9aaa2820c6d9be809592ec0c4b3d207b83f9b6",
            workspace="workspace:testhash",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )

    items = store.list_policy_decisions()
    assert len(items) == 1
    item = items[0]
    assert item["source_receipt_id"] == "receipt-policy-ux-1"
    assert item["remembered_command"] == "pnpm install"
    assert item["remembered_context"] == "Package install via pnpm"
    assert item["workspace_label"] == "hol-points-portal"


def test_list_policy_decisions_falls_back_to_inventory_launch_command(tmp_path) -> None:
    store = _store(tmp_path)
    with store._connect() as connection:
        connection.execute(
            """
            insert into artifact_inventory (
              artifact_id, harness, artifact_name, artifact_type, source_scope, config_path,
              first_seen_at, last_seen_at, last_policy_action, artifact_hash
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "codex:project:package-request:inv1",
                "codex",
                "pnpm",
                "package_request",
                "~/projects/hol-guard",
                "config.json",
                "2026-06-14T12:00:00+00:00",
                "2026-06-14T12:00:00+00:00",
                "allow",
                "hash-inv1",
            ),
        )
        connection.execute(
            "update artifact_inventory set launch_command = ? where artifact_id = ? and harness = ?",
            ("pnpm install --frozen-lockfile", "codex:project:package-request:inv1", "codex"),
        )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="workspace",
            action="allow",
            artifact_id="codex:project:package-request:inv1",
            artifact_hash="hash-inv1",
            workspace="workspace:inv",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )

    item = store.list_policy_decisions()[0]
    assert item["remembered_command"] == "pnpm install --frozen-lockfile"
    assert item["workspace_label"] == "hol-guard"
