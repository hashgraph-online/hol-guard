"""The package artifact adapter accepts only a bound, launch-free reply."""

from __future__ import annotations

from typing import Any

import pytest

from codex_plugin_scanner.guard import native_package_authority
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.runtime.package_intent_common import PackageIntent

_ARTIFACT = {
    "artifact_id": "codex:project:package-request:" + "a" * 64,
    "name": "npm install left-pad",
    "harness": "codex",
    "artifact_type": "package_request",
    "source_scope": "project",
    "config_path": "codex.json",
    "command": None,
    "args": [],
    "url": None,
    "transport": None,
    "publisher": None,
    "metadata": {},
    "runtime_private_metadata": {},
}

_INTENT = PackageIntent(
    package_manager="npm",
    intent_kind="install",
    command_tokens=("npm", "install", "left-pad"),
    redacted_command="npm install left-pad",
    targets=(),
)


def _install(monkeypatch: pytest.MonkeyPatch, mutate) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def fake(*, operation, request, max_request_bytes, **_kwargs):
        seen.append({"request": request, "max_request_bytes": max_request_bytes})
        assert operation == "package_request_artifact"
        response = {
            "schema": "guard-package-authority-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": dict(_ARTIFACT),
        }
        mutate(response)
        return response

    monkeypatch.setattr(native_package_authority, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_package_authority, "_resident_request", fake)
    return seen


def _call(tmp_path):
    return native_package_authority.package_request_artifact_native(
        _INTENT, harness="codex", config_path="codex.json", source_scope="project", guard_home=tmp_path
    )


def test_a_bound_reply_names_the_artifact_under_the_audit_budget(monkeypatch, tmp_path) -> None:
    seen = _install(monkeypatch, lambda response: None)
    assert _call(tmp_path).artifact_id == _ARTIFACT["artifact_id"]
    assert seen[0]["max_request_bytes"] == 4 * 1024 * 1024


@pytest.mark.parametrize(
    "mutate",
    [
        lambda response: response.update(request_id="other"),
        lambda response: response.update(request_sha256="sha256:" + "0" * 64),
        lambda response: response.update(payload=dict(_ARTIFACT, args=["x"])),
        lambda response: response.update(payload=dict(_ARTIFACT, publisher="p")),
        lambda response: response.update(payload=dict(_ARTIFACT, harness=None)),
    ],
)
def test_an_unbound_or_drifted_reply_names_nothing(monkeypatch, tmp_path, mutate) -> None:
    _install(monkeypatch, mutate)
    with pytest.raises(native_package_authority.NativePackageArtifactUnavailableError):
        _call(tmp_path)
