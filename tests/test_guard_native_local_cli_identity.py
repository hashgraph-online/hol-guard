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
