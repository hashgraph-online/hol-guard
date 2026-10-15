from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_cli_grant_decision as decision
from codex_plugin_scanner.guard.local_cli_hook import apply_local_cli_grant
from codex_plugin_scanner.guard.local_cli_trust import matching_local_cli_grant, utc_now
from codex_plugin_scanner.guard.native_local_cli_grant import NativeLocalCliGrant
from codex_plugin_scanner.guard.native_local_cli_identity import LocalCliIdentityUnavailableError
from codex_plugin_scanner.guard.runtime.local_cli_identity import identify_unlisted_cli
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401


def _blocked_store(tmp_path: Path):
    script = tmp_path / "ship.py"
    script.write_text("print('hi')\n", encoding="utf-8")
    command = f"python3 {script} deploy"
    identity = identify_unlisted_cli(command, cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    store = GuardStore(tmp_path / "home")
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.upsert_local_cli_grant(identity=identity, state="blocked", expected_revision=0, updated_at=utc_now())
    return store, command, identity


@pytest.mark.parametrize("answer", ["none_reply", "other_identity"])
def test_native_failure_is_unavailable_never_no_grant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: str
) -> None:
    store, command, identity = _blocked_store(tmp_path)
    reply = (
        None
        if answer == "none_reply"
        else NativeLocalCliGrant(state="allowed", cli_id=identity.cli_id, identity_hash="f" * 64)
    )
    monkeypatch.setattr(decision, "native_local_cli_grant", lambda **_kwargs: reply)

    with pytest.raises(LocalCliIdentityUnavailableError):
        matching_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="allow")

    # A stored block rule exists, so an allowed command is held for review
    # instead of being waved through or silently treated as ungranted.
    assert (
        apply_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="allow")
        == "review"
    )
    assert (
        apply_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="block")
        == "block"
    )


def test_native_answer_is_presented_not_recomputed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store, command, identity = _blocked_store(tmp_path)
    calls: list[dict[str, object]] = []

    def answer(**kwargs: object) -> NativeLocalCliGrant:
        calls.append(kwargs)
        return NativeLocalCliGrant(state="allowed", cli_id=identity.cli_id, identity_hash=identity.identity_hash)

    monkeypatch.setattr(decision, "native_local_cli_grant", answer)

    # The store row says blocked; only the resident's answer decides.
    assert (
        apply_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="review")
        == "allow"
    )
    assert calls[0]["current_action"] == "review"
    assert calls[0]["source"] == identity.identity_source


def _grant_reply(monkeypatch: pytest.MonkeyPatch, status: str, code: object, *, prerequisite: bool = True):
    from codex_plugin_scanner.guard import native_local_cli_grant as client
    from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

    calls: list[str] = []

    def resident(*, operation: str, request: dict[str, object], **_kwargs: object) -> dict[str, object]:
        calls.append(operation)
        return {
            "schema": "guard-local-cli-grant-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": status,
            "code": code,
            "payload": None,
        }

    monkeypatch.setattr(client, "_resident_request", resident)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: prerequisite)
    return client, calls


def _ask(client, tmp_path: Path):
    return client.native_local_cli_grant(
        store_path=tmp_path / "guard.db",
        guard_home=tmp_path,
        current_action="review",
        source={"source": "registry_package", "name": "cowsay", "package_name": "cowsay"},
        command_id=None,
    )


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("native_local_cli_grant_schema_invalid", "native_local_cli_grant_schema_invalid"),
        ("native_local_cli_grant_store_unavailable", "native_local_cli_grant_store_unavailable"),
        ("free text from a reply", "native_local_cli_grant_unavailable"),
        (None, "native_local_cli_grant_unavailable"),
    ],
)
def test_resident_refusal_reason_reaches_the_caller(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: object, expected: str
) -> None:
    from codex_plugin_scanner.guard.native_local_cli_grant import NativeLocalCliGrantFailure

    client, _calls = _grant_reply(monkeypatch, "error", code)
    assert _ask(client, tmp_path) == NativeLocalCliGrantFailure(expected)


def test_grant_lookup_establishes_the_resident_prerequisite(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_local_cli_grant import NativeLocalCliGrantFailure

    client, calls = _grant_reply(monkeypatch, "ok", "ok", prerequisite=False)
    assert _ask(client, tmp_path) == NativeLocalCliGrantFailure("native_local_cli_grant_prerequisite_unavailable")
    assert calls == []


def test_failure_code_is_raised_and_logged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from codex_plugin_scanner.guard.native_local_cli_grant import NativeLocalCliGrantFailure

    store, command, _identity = _blocked_store(tmp_path)
    failure = NativeLocalCliGrantFailure("native_local_cli_grant_schema_invalid")
    monkeypatch.setattr(decision, "native_local_cli_grant", lambda **_kwargs: failure)

    with (
        caplog.at_level("WARNING", logger=decision.__name__),
        pytest.raises(LocalCliIdentityUnavailableError, match="native_local_cli_grant_schema_invalid"),
    ):
        matching_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="allow")
    assert "native_local_cli_grant_schema_invalid" in caplog.text


def test_catalog_read_failure_holds_instead_of_dropping_a_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store, command, _identity = _blocked_store(tmp_path)

    def broken_catalog(_cli_id: str) -> list[object]:
        raise sqlite3.OperationalError("no such column: usage")

    def native_must_not_run(**_kwargs: object) -> None:
        raise AssertionError("the resident must not be asked without a resolved command")

    monkeypatch.setattr(store, "read_local_cli_command_catalog", broken_catalog)
    monkeypatch.setattr(decision, "native_local_cli_grant", native_must_not_run)

    with pytest.raises(LocalCliIdentityUnavailableError, match="native_local_cli_grant_catalog_unavailable"):
        matching_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="allow")
    assert (
        apply_local_cli_grant(store=store, command=command, cwd=tmp_path, home_dir=tmp_path, current_action="allow")
        == "review"
    )
