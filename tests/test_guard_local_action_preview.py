"""Local command previews never enter the privacy-safe activity journal."""

import base64
import sqlite3
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.local_action_preview import action_preview
from codex_plugin_scanner.guard.store import GuardStore

SYNTHETIC_USERINFO = ":".join(("fixture-user", "fixture-password"))
SYNTHETIC_BASIC = base64.b64encode(SYNTHETIC_USERINFO.encode()).decode()


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
        (f"curl -u {SYNTHETIC_USERINFO} https://example.invalid", SYNTHETIC_USERINFO),
        (f"curl --user={SYNTHETIC_USERINFO} https://example.invalid", SYNTHETIC_USERINFO),
        (f"curl -u{SYNTHETIC_USERINFO} https://example.invalid", SYNTHETIC_USERINFO),
        (f"curl https://{SYNTHETIC_USERINFO}@example.invalid", SYNTHETIC_USERINFO),
        (f'curl -H "Authorization: Basic {SYNTHETIC_BASIC}" https://example.invalid', SYNTHETIC_BASIC),
    ),
)
def test_preview_redacts_sensitive_arguments(command: str, secret: str) -> None:
    preview = action_preview({"toolInput": {"command": command}})

    assert preview is not None
    assert secret not in preview
    assert "[redacted]" in preview


def test_preview_omits_malformed_shell_input() -> None:
    assert action_preview({"toolInput": {"command": 'tool --password "unterminated'}}) is None


@pytest.mark.parametrize("key", ["access_token", "access%5Ftoken", "API-KEY", "X-Amz-Signature", "sig"])
def test_preview_redacts_query_credentials(key: str) -> None:
    command = f"curl 'https://example.invalid/data?page=2&{key}=fixture-query-value&limit=3'"
    preview = action_preview({"command": command})
    assert preview is not None
    assert "fixture-query-value" not in preview
    assert "https://example.invalid/data?page=2" in preview


def test_preview_bounds_match_dashboard_utf16_units() -> None:
    preview = action_preview({"command": "echo " + "\U0001f600" * 2048})
    assert preview is not None
    assert len(preview.encode("utf-16-le")) <= 4096


def test_journal_failure_discards_in_memory_preview(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    with patch.object(writer, "_append_journal", side_effect=OSError("disk unavailable")):
        assert writer.submit_command_activity(
            harness="codex", event="PreToolUse", succeeded=True,
            policy_action="allow", payload={"command": "git status"},
        )
        writer.stop(timeout_seconds=5)
    assert writer.stats()["dropped"] == 1
    assert not writer._local_previews


@pytest.mark.parametrize("container", ["tool_input", "toolInput", "arguments"])
@pytest.mark.parametrize("alias", ["command", "cmd", "shell_command", "shellCommand"])
def test_preview_retains_supported_command_aliases(container: str, alias: str) -> None:
    assert action_preview({container: {alias: "git status"}}) == "git status"


@pytest.mark.parametrize("alias", ["command", "cmd"])
def test_preview_retains_top_level_command_aliases(alias: str) -> None:
    assert action_preview({alias: "git status"}) == "git status"


@pytest.mark.parametrize(
    "command",
    [
        "env PASSWORD=hunter2 python app.py",
        'env PASSWORD="hunter2 with spaces" python app.py',
        'env "PASSWORD=hunter2 with spaces" python app.py',
        "export APP_PASSWORD=hunter2; python app.py",
    ],
)
def test_preview_redacts_inline_environment_credentials(command: str) -> None:
    preview = action_preview({"command": command})
    assert preview is not None
    assert "hunter2" not in preview
    assert "with spaces" not in preview


def test_preview_omits_escaped_environment_secret() -> None:
    assert action_preview({"command": 'env PASSWORD="hun""ter2" python app.py'}) is None


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


def test_existing_database_restores_preview_cleanup(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    assert writer.submit_command_activity(
        harness="zcode",
        event="PostToolUse",
        succeeded=True,
        payload={"toolCallId": "call_cleanup_123456789", "toolInput": {"command": "git status"}},
    )
    assert writer.stop(timeout_seconds=5)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute("drop trigger trg_command_activity_delete_local_action_previews")
    assert not store._schema_is_current()
    repaired = GuardStore(store.guard_home, prime_policy_integrity=False)
    assert repaired._schema_is_current()
    assert repaired.clear_command_activity_evidence()["deleted"]["activities"] == 1
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        assert connection.execute("select count(*) from local_action_previews").fetchone() == (0,)


def test_recovery_keeps_evidence_without_journaling_command_text(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    failed = threading.Event()

    def fail(**_kwargs: object) -> bool:
        failed.set()
        raise sqlite3.OperationalError("database unavailable")

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=fail,
    ):
        writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
        assert writer.submit_command_activity(
            harness="zcode",
            event="PostToolUse",
            succeeded=True,
            payload={"toolCallId": "call_recovery_123456789", "toolInput": {"command": "echo private-preview"}},
        )
        assert failed.wait(timeout=2)
        assert writer.stop(timeout_seconds=2)
        assert writer.stats()["durable_pending"] == 1
    assert "private-preview" not in (store.guard_home / "runtime-hook-evidence.jsonl").read_text()
    recovered = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert recovered.stop(timeout_seconds=2)
    assert recovered.stats()["recovered"] == 1
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        assert connection.execute("select count(*) from command_activity").fetchone() == (1,)
        assert connection.execute("select count(*) from local_action_previews").fetchone() == (0,)


def test_preview_failure_does_not_retry_recorded_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)

    def fail_preview(_activity_id: str, _preview: str) -> None:
        raise sqlite3.OperationalError("preview storage unavailable")

    monkeypatch.setattr(store, "record_local_action_preview", fail_preview)
    writer = RuntimeHookEvidenceWriter(store=store)
    for index in range(2):
        assert writer.submit_command_activity(
            harness="zcode",
            event="PreToolUse",
            succeeded=True,
            policy_action="allow",
            payload={"toolCallId": f"call_example_12345678{index}", "toolInput": {"command": "git status --short"}},
        )
    assert writer.stop(timeout_seconds=5)
    assert writer.stats()["processed"] == 2
    assert writer.stats()["failures"] == 0
    assert writer.stats()["local_preview_failures"] == 2
