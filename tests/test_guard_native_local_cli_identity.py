"""The Python side only accepts well-formed local CLI identities from native."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_local_cli_identity as module

_VALID = {
    "cli_id": "local-cli.eslint-144fb167",
    "name": "eslint",
    "kind": "executable",
    "identity_hash": "1fe2e43491b55ef10ac3bb3b8446a48cd4bf6714b2beaa7da04ef2b091b2c565",
}


def _answer(monkeypatch: pytest.MonkeyPatch, result: object) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def fake(kind: str, fields: dict[str, object], *, guard_home: Path) -> object:
        calls.append((kind, fields))
        return result

    monkeypatch.setattr(module, "native_context_digest", fake)
    return calls


def test_returns_native_identity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _answer(monkeypatch, {"status": "ok", "local_cli_identity": dict(_VALID)})
    source = {"source": "registry_package", "name": "eslint", "package_name": "eslint"}

    assert module.native_local_cli_identity(source, guard_home=tmp_path) == _VALID
    assert calls == [("local_cli_identity", {"source": source})]


@pytest.mark.parametrize(
    "result",
    [
        None,
        {"status": "error", "local_cli_identity": dict(_VALID)},
        {"status": "ok"},
        {"status": "ok", "local_cli_identity": {**_VALID, "extra": "x"}},
        {"status": "ok", "local_cli_identity": {**_VALID, "kind": "package"}},
        {"status": "ok", "local_cli_identity": {**_VALID, "identity_hash": "AB" * 32}},
        {"status": "ok", "local_cli_identity": {**_VALID, "cli_id": "local-cli.Bad_ID"}},
        {"status": "ok", "local_cli_identity": {**_VALID, "cli_id": "local-cli.a-b-c-d-e-f-g-h-i-j"}},
        {"status": "ok", "local_cli_identity": {**_VALID, "name": 3}},
    ],
)
def test_malformed_or_missing_identity_yields_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, result: object
) -> None:
    _answer(monkeypatch, result)

    assert module.native_local_cli_identity({"source": "script", "entrypoint": {}}, guard_home=tmp_path) is None


def test_failures_are_tracked_but_not_applicability(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = {"source": "script", "entrypoint": {}}
    _answer(monkeypatch, {"status": "ok"})
    with module.track_local_cli_identity_failures() as failures:
        assert module.native_local_cli_identity(source, guard_home=tmp_path) is None
    assert failures == []

    _answer(monkeypatch, None)
    with module.track_local_cli_identity_failures() as failures:
        assert module.native_local_cli_identity(source, guard_home=tmp_path) is None
    assert failures == ["native_local_cli_identity_unavailable"]


def test_no_resident_answer_for_the_local_cli_step_is_the_host_outage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Python used to pick the action here: review while a block rule existed,
    # the action unchanged otherwise. The resident holds an unverifiable grant
    # for review itself (``an_unreadable_grant_is_unverified`` in Rust); no
    # answer at all is an outage the hook answers with the host outage
    # response, as the direct hook path does, whatever the store holds.
    from codex_plugin_scanner.guard import local_cli_hook
    from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError

    monkeypatch.setattr(local_cli_hook, "native_local_cli_hook", lambda *_args, **_kwargs: None)

    class Store:
        guard_home = tmp_path
        path = tmp_path / "guard.db"
        guard_source = "local"

        def has_local_cli_block_rules(self) -> bool:
            raise AssertionError("the transport must not probe the store")

    for action in ("allow", "warn", "review", "block"):
        for grant_allowed in (True, False):
            with pytest.raises(NativeHookDecisionError) as raised:
                local_cli_hook.local_cli_grant_action(
                    store=Store(),  # type: ignore[arg-type]
                    command="tool",
                    cwd=tmp_path,
                    home_dir=tmp_path,
                    current_action=action,  # type: ignore[arg-type]
                    grant_allowed=grant_allowed,
                )
            assert raised.value.code == "native_local_cli_hook_unavailable"
    # No command launches no CLI: nothing to ask, the action stands.
    assert (
        local_cli_hook.local_cli_grant_action(
            store=Store(),  # type: ignore[arg-type]
            command=None,
            cwd=tmp_path,
            home_dir=tmp_path,
            current_action="allow",
            grant_allowed=True,
        )
        == "allow"
    )
