"""Fail-closed behaviour of the native package context build transport."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_execution
from codex_plugin_scanner.guard import native_package_context_build as transport
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.package_execution_context import build_package_execution_context


def _artifact(metadata: object) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="context-transport",
        name="npm install",
        harness="guard-cli",
        artifact_type="package_request",
        source_scope="project",
        config_path="hol-guard.toml",
        metadata=metadata,  # type: ignore[arg-type]
    )


def _status(features: tuple[str, ...] = ()) -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native"), sha256="resident-sha"),
        capabilities=SimpleNamespace(features=features),
    )


def _stub_guard_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[tuple[str, str]]:
    """Stub the home and runtime status; return the recorded health events."""

    events: list[tuple[str, str]] = []
    monkeypatch.setattr(transport, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(transport, "native_runtime_status", lambda: _status())
    monkeypatch.setattr(transport, "native_record_resident_success", lambda _sha, _home: events.append(("success", "")))
    monkeypatch.setattr(
        transport,
        "native_record_resident_failure",
        lambda _sha, _home, reason: events.append(("failure", reason)),
    )
    return events


def _call(tmp_path: Path, **overrides: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "workspace_dir": tmp_path,
        "metadata": {},
        "executable": None,
        "executable_args": (),
        "environment": {"PATH": "/usr/bin"},
    }
    arguments.update(overrides)
    return transport.native_build_package_context(**arguments)  # type: ignore[arg-type]


def test_build_fails_closed_without_a_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(transport, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(ValueError, match="native_package_context_build_unavailable"):
        build_package_execution_context(workspace_dir=tmp_path, artifact=_artifact({}))


def test_build_fails_closed_when_the_resident_returns_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_guard_home(monkeypatch, tmp_path)
    monkeypatch.setattr(transport, "_resident_request", lambda **_kwargs: None)
    with pytest.raises(ValueError, match="native_package_context_build_unavailable"):
        _call(tmp_path)


def test_build_rejects_a_result_not_bound_to_the_request(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    events = _stub_guard_home(monkeypatch, tmp_path)
    monkeypatch.setattr(
        transport,
        "_resident_request",
        lambda **_kwargs: {"schema": transport._RESULT_SCHEMA, "request_id": "other", "status": "ok", "code": "ok"},
    )
    with pytest.raises(ValueError, match="native_package_context_build_unbound"):
        _call(tmp_path)
    assert events == [("failure", "native_package_context_build_unbound")]


def test_build_surfaces_a_typed_native_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_guard_home(monkeypatch, tmp_path)

    def respond(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        return {
            "schema": transport._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + transport._canonical_request_sha256(request),
            "status": "error",
            "code": "native_package_context_build_failed",
        }

    monkeypatch.setattr(transport, "_resident_request", respond)
    with pytest.raises(ValueError, match="native_package_context_build_failed"):
        _call(tmp_path)


def test_request_carries_typed_metadata_and_process_facts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_guard_home(monkeypatch, tmp_path)
    seen: dict[str, object] = {}

    def respond(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        seen.update(request)
        return {
            "schema": transport._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + transport._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "context": {"digest": "d", "portable": True, "components": [], "non_portable_reason": None},
        }

    monkeypatch.setattr(transport, "_resident_request", respond)
    context = _call(
        tmp_path,
        metadata={
            "package_manager": "npm",
            "package_executable": 7,
            "flags": ("-g", 3, "--save"),
            "manifest_paths": "package.json",
            "unrelated": {"secret": "value"},
        },
    )
    assert context["digest"] == "d"
    assert seen["metadata"] == {
        "package_manager": "npm",
        "package_executable": None,
        "flags": ["-g", "--save"],
        "manifest_paths": [],
        "lockfile_paths": [],
    }
    assert seen["process_cwd"] and seen["process_home"]
    assert seen["environment"] == {"PATH": "/usr/bin"}


def test_non_string_environment_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="native_package_context_build_invalid_environment"):
        _call(tmp_path, environment={"PATH": 1})


def _bound_reply(kwargs: dict[str, object], **fields: object) -> dict[str, object]:
    request = kwargs["request"]
    assert isinstance(request, dict)
    from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

    reply: dict[str, object] = {
        "schema": transport._RESULT_SCHEMA,
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + _canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
    }
    reply.update(fields)
    return reply


@pytest.mark.parametrize(
    "context",
    [
        None,
        {},
        {"digest": "d", "portable": True, "non_portable_reason": None, "components": [{"name": "a"}]},
        {"digest": "d", "portable": "yes", "non_portable_reason": None, "components": []},
        {"digest": "d", "portable": True, "non_portable_reason": 3, "components": []},
        {"digest": "d", "portable": True, "non_portable_reason": None, "components": "x"},
    ],
)
def test_malformed_ok_context_is_rejected_and_counts_as_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, context: object
) -> None:
    events = _stub_guard_home(monkeypatch, tmp_path)
    monkeypatch.setattr(transport, "_resident_request", lambda **kwargs: _bound_reply(kwargs, context=context))
    with pytest.raises(ValueError, match="native_package_context_build_malformed"):
        _call(tmp_path)
    assert events == [("failure", "native_package_context_build_malformed")]


def test_well_formed_context_records_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    events = _stub_guard_home(monkeypatch, tmp_path)
    context = {
        "digest": "d",
        "portable": True,
        "non_portable_reason": None,
        "components": [{"name": "a", "digest": "b"}],
    }
    monkeypatch.setattr(transport, "_resident_request", lambda **kwargs: _bound_reply(kwargs, context=context))
    assert _call(tmp_path) == context
    assert events == [("success", "")]


def test_surrogate_environment_value_is_refused_before_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_guard_home(monkeypatch, tmp_path)
    monkeypatch.setattr(transport, "_resident_request", lambda **_kwargs: pytest.fail("must not reach the resident"))
    with pytest.raises(ValueError, match="native_package_context_build_non_utf8"):
        _call(tmp_path, environment={"PATH": "/usr/bin", "BAD": "\udcff"})


def test_typed_error_survives_the_shared_transport(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A status=error reply is accepted by the real envelope, not filtered to None."""

    events = _stub_guard_home(monkeypatch, tmp_path)
    features = (native_execution._RESIDENT_PROTOCOL_FEATURE, transport.PACKAGE_CONTEXT_BUILD_FEATURE)
    monkeypatch.setattr(transport, "native_runtime_status", lambda: _status(features))
    monkeypatch.setattr(native_execution, "_isolated_environment", lambda: {})
    sent: list[int] = []

    def client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        sent.append(len(payload))
        request = json.loads(payload)["request"]
        from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

        return json.dumps(
            {
                "schema": transport._RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + _canonical_request_sha256(request),
                "status": "error",
                "code": "native_package_context_build_failed",
            }
        ).encode()

    monkeypatch.setattr(native_execution, "native_resident_client_request", client)
    big = {"PATH": "/usr/bin", "BIG": "x" * (300 * 1024)}
    with pytest.raises(ValueError, match="native_package_context_build_failed"):
        _call(tmp_path, environment=big)
    assert sent and sent[0] > 256 * 1024
    assert events == [("success", "")]
