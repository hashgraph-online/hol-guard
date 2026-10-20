"""Local tool eligibility presents only a bound, well-formed resident answer."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import trusted_local_tools as client

_PAYLOAD: dict[str, object] = {
    "tool_name": "tsc",
    "tool_identity_hash": "a" * 64,
    "capability": "typecheck",
    "read_only_reason": "Authenticated local developer validation command",
    "trust_basis": "package-profile",
    "indefinite_allowed": False,
}


def _reply(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: str = "ok",
    code: str = "ok",
    payload: object = None,
    bind: bool = True,
    prerequisite: bool = True,
    schema: str = "guard-local-tool-eligibility-result.v1",
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def resident(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        calls.append(kwargs)
        digest = "sha256:" + client._canonical_request_sha256(request)
        return {
            "schema": schema,
            "request_id": request["request_id"],
            "request_sha256": digest if bind else "sha256:" + "0" * 64,
            "status": status,
            "code": code,
            "payload": payload,
        }

    monkeypatch.setattr(client, "_resident_request", resident)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: prerequisite)
    monkeypatch.setattr(client, "_resolve_existing_digest_home", lambda _home: Path("guard-home"))
    return calls


def _ask(tmp_path: Path, home_dir: Path | None = None) -> client.LocalToolApprovalEligibility | None:
    return client.local_tool_approval_eligibility("npx tsc --noEmit", cwd=tmp_path, home_dir=home_dir)


def test_presents_the_resident_eligibility(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOL_GUARD_TEST_MARKER", "present")
    calls = _reply(monkeypatch, payload=_PAYLOAD)

    eligibility = _ask(tmp_path)

    assert eligibility == client.LocalToolApprovalEligibility(
        tool_name="tsc",
        tool_identity_hash="a" * 64,
        capability="typecheck",
        read_only_reason="Authenticated local developer validation command",
        trust_basis="package-profile",
        indefinite_allowed=False,
    )
    assert calls[0]["operation"] == "local_tool_eligibility"
    assert calls[0]["required_feature"] == "local-tool-eligibility-v1"
    request = calls[0]["request"]
    assert isinstance(request, dict)
    assert set(request) == {"schema", "request_id", "command", "cwd", "home_dir", "user_home", "launch_env"}
    assert request["schema"] == "guard-local-tool-eligibility-request.v1"
    assert request["command"] == "npx tsc --noEmit"
    assert request["cwd"] == str(tmp_path)
    assert request["home_dir"] is None
    assert request["user_home"] == str(Path.home())
    launch_env = request["launch_env"]
    assert isinstance(launch_env, dict)
    assert launch_env["HOL_GUARD_TEST_MARKER"] == "present"


def test_sends_the_home_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _reply(monkeypatch)

    assert _ask(tmp_path, home_dir=tmp_path / "home") is None
    request = calls[0]["request"]
    assert isinstance(request, dict)
    assert request["home_dir"] == str(tmp_path / "home")


def test_null_payload_is_ineligible(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _ = _reply(monkeypatch, payload=None)

    assert _ask(tmp_path) is None


@pytest.mark.parametrize(
    "reply",
    [
        {"payload": _PAYLOAD, "bind": False},
        {"payload": _PAYLOAD, "status": "error"},
        {"payload": _PAYLOAD, "code": "native_failed"},
        {"payload": _PAYLOAD, "prerequisite": False},
        {"payload": _PAYLOAD, "schema": "guard-local-tool-eligibility-result.v0"},
        {"payload": [_PAYLOAD]},
        {"payload": {**_PAYLOAD, "extra": True}},
        {"payload": {key: value for key, value in _PAYLOAD.items() if key != "capability"}},
        {"payload": {**_PAYLOAD, "tool_name": " "}},
        {"payload": {**_PAYLOAD, "tool_name": 7}},
        {"payload": {**_PAYLOAD, "tool_identity_hash": "A" * 64}},
        {"payload": {**_PAYLOAD, "tool_identity_hash": "a" * 63}},
        {"payload": {**_PAYLOAD, "capability": ""}},
        {"payload": {**_PAYLOAD, "read_only_reason": None}},
        {"payload": {**_PAYLOAD, "trust_basis": "unverified"}},
        {"payload": {**_PAYLOAD, "trust_basis": ["package-profile"]}},
        {"payload": {**_PAYLOAD, "indefinite_allowed": 1}},
        {"payload": {**_PAYLOAD, "trust_basis": "verified-files", "indefinite_allowed": True}},
    ],
)
def test_refuses_unbound_or_malformed_replies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: dict[str, object]
) -> None:
    _ = _reply(monkeypatch, **reply)  # type: ignore[arg-type]

    assert _ask(tmp_path) is None


def test_missing_resident_is_ineligible(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(client, "_resident_request", lambda **_kwargs: None)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(client, "_resolve_existing_digest_home", lambda _home: Path("guard-home"))

    assert _ask(tmp_path) is None


def test_resident_failure_is_ineligible(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def broken(**_kwargs: object) -> dict[str, object]:
        raise OSError("resident unavailable")

    monkeypatch.setattr(client, "_resident_request", broken)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(client, "_resolve_existing_digest_home", lambda _home: Path("guard-home"))

    assert _ask(tmp_path) is None


def test_unknown_user_home_is_ineligible(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _reply(monkeypatch, payload=_PAYLOAD)

    def no_home() -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(client.Path, "home", staticmethod(no_home))

    assert _ask(tmp_path) is None
    assert calls == []
