"""Local command previews never enter the privacy-safe activity journal."""

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.local_action_preview import action_preview
from codex_plugin_scanner.guard.store import GuardStore


def test_preview_excludes_file_contents_and_redacts_credentials() -> None:
    assert action_preview({"tool_input": {"file_path": ".env", "content": "private-content"}}) is None
    preview = action_preview({"toolInput": {"command": "API_TOKEN=example-secret curl https://example.invalid"}})
    assert preview is not None
    assert "example-secret" not in preview
    assert action_preview({"command": "x" * 65537}) is None
    assert len(action_preview({"command": "echo " + "x" * 3000}) or "") == 2048


@pytest.mark.parametrize(
    ("command", "secret"),
    (
        ("tool --password=inline-password", "inline-password"),
        ("tool --credential=inline-credential", "inline-credential"),
        ('tool --password "quoted password"', "quoted password"),
        ("tool --credential 'quoted credential'", "quoted credential"),
        ('tool --password = "spaced equals password"', "spaced equals password"),
    ),
)
def test_preview_redacts_sensitive_arguments(command: str, secret: str) -> None:
    preview = action_preview({"toolInput": {"command": command}})

    assert preview is not None
    assert secret not in preview
    assert "[redacted]" in preview


def test_preview_omits_malformed_shell_input() -> None:
    assert action_preview({"toolInput": {"command": 'tool --password "unterminated'}}) is None


def test_native_preview_is_local_and_deleted_with_activity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    try:
        assert writer.submit_command_activity(
            harness="zcode",
            event="PreToolUse",
            succeeded=True,
            policy_action="allow",
            payload={"toolCallId": "call_example_123456789", "toolInput": {"command": "git status --short"}},
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    assert writer.stats()["failures"] == 0
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        assert connection.execute("select preview from local_action_previews").fetchall() == [("git status --short",)]
    deleted = store.clear_command_activity_evidence()
    assert deleted["deleted"]["activities"] == 1
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        assert connection.execute("select count(*) from local_action_previews").fetchone() == (0,)
    journal = store.guard_home / "runtime-hook-evidence.jsonl"
    if journal.exists():
        assert "git status" not in journal.read_text()


def test_post_only_preview_is_retained_without_inventing_a_decision(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    command = "tool --credential 'post-only-secret'"
    try:
        assert writer.submit_command_activity(
            harness="zcode",
            event="PostToolUse",
            succeeded=True,
            payload={"toolCallId": "post_only_call_123456789", "toolInput": {"command": command}},
        )
    finally:
        assert writer.stop(timeout_seconds=5)

    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        row = connection.execute(
            """
            select previews.preview, activity.policy_action, activity.execution_status, activity.proof_level
            from command_activity as activity
            join local_action_previews as previews on previews.activity_id = activity.activity_id
            """
        ).fetchone()
    assert row == ("tool --credential [redacted]", None, "unpaired_post", "unpaired_post")


def test_existing_database_adds_preview_storage(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute("drop table local_action_previews")
    assert not store._schema_is_current()
    GuardStore(store.guard_home, prime_policy_integrity=False)
    assert store._schema_is_current()


def test_preview_failure_does_not_retry_recorded_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)

    def fail_preview(_activity_id: str, _preview: str) -> None:
        raise sqlite3.OperationalError("preview storage unavailable")

    monkeypatch.setattr(store, "record_local_action_preview", fail_preview)
    writer = RuntimeHookEvidenceWriter(store=store)
    for index in range(2):
        assert writer.submit_command_activity(
            harness="zcode", event="PreToolUse", succeeded=True, policy_action="allow",
            payload={"toolCallId": f"call_example_12345678{index}", "toolInput": {"command": "git status --short"}},
        )
    assert writer.stop(timeout_seconds=5)
    assert writer.stats()["processed"] == 2
    assert writer.stats()["failures"] == 0
    assert writer.stats()["local_preview_failures"] == 2
