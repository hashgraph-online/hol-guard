"""Native request context: Python transport, adapter, parity and fail-closed."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_execution
from codex_plugin_scanner.guard import native_request_context as client
from codex_plugin_scanner.guard.native_context import _UNBOUND_PREFIX, _canonical_request_sha256
from codex_plugin_scanner.guard.runtime import shell_execution_context as shell
from codex_plugin_scanner.guard.runtime._shell_execution_context_support import ShellPathIdentity
from codex_plugin_scanner.guard.runtime.command_shell_read_factors import shell_read_floor_factors
from codex_plugin_scanner.guard.runtime.shell_secret_reads import assess_shell_reads

_FIXTURE = Path(__file__).parent / "fixtures" / "request-context-parity" / "cases.v1.json"


def _reply(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: str = "ok",
    code: object = "ok",
    payload: object = None,
    request_sha256: str | None = None,
    prerequisite: bool = True,
) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def resident(*, operation: str, request: dict[str, Any], **_kwargs: object) -> dict[str, Any]:
        assert operation == "request_context_build"
        seen.append(request)
        return {
            "schema": "guard-request-context-result.v1",
            "request_id": request["request_id"],
            "request_sha256": request_sha256 or "sha256:" + _canonical_request_sha256(request),
            "status": status,
            "code": code,
            "payload": payload,
        }

    monkeypatch.setattr(client, "_resident_request", resident)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: prerequisite)
    return seen


def _build(tmp_path: Path) -> client.NativeRequestContext | client.NativeRequestContextFailure:
    return client.native_request_context_build(
        source="direct_command", guard_home=tmp_path, script="ls", cwd=tmp_path, workspace=tmp_path
    )


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("native_request_context_owner_mismatch", "native_request_context_owner_mismatch"),
        ("native_request_context_budget_exceeded", "native_request_context_budget_exceeded"),
        ("free text", "native_request_context_unavailable"),
        (None, "native_request_context_unavailable"),
    ],
)
def test_resident_refusal_reason_reaches_the_caller(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: object, expected: str
) -> None:
    _reply(monkeypatch, status="error", code=code)
    assert _build(tmp_path) == client.NativeRequestContextFailure(expected)


def test_typed_refusal_survives_the_real_resident_transport(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="a" * 64),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", client.REQUEST_CONTEXT_FEATURE)),
    )

    def refuse(**kwargs: Any) -> bytes:
        request = json.loads(kwargs["payload"])["request"]
        return json.dumps(
            {
                "schema": "guard-request-context-result.v1",
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + _canonical_request_sha256(request),
                "status": "error",
                "code": "native_request_context_owner_mismatch",
                "payload": None,
            }
        ).encode()

    monkeypatch.setattr(native_execution, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_execution, "native_resident_client_request", refuse)
    monkeypatch.setattr(native_execution, "native_record_resident_success", lambda *_a, **_k: None)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: True)
    assert _build(tmp_path) == client.NativeRequestContextFailure("native_request_context_owner_mismatch")


def test_relative_paths_are_anchored_to_this_process_before_sending(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _reply(monkeypatch, status="error", code="native_request_context_budget_invalid")
    monkeypatch.chdir(tmp_path)
    client.native_request_context_build(
        source="hook", guard_home=tmp_path, script="ls", cwd=Path("."), workspace="ws", home_dir=Path("home")
    )
    body = seen[0]["action"]["body"]
    assert body["cwd"] == str(tmp_path)
    assert body["workspace"] == str(tmp_path / "ws")
    assert body["home_dir"] == str(tmp_path / "home")
    assert all(Path(body[key]).is_absolute() for key in ("cwd", "workspace", "home_dir"))


def test_partial_executable_is_sent_with_the_residents_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _reply(monkeypatch, status="error", code="native_request_context_budget_invalid")
    client.native_request_context_build(
        source="hook", guard_home=tmp_path, cwd=tmp_path, executable={"command": "/bin/ls", "args": ["-l"]}
    )
    client.native_request_context_build(source="hook", guard_home=tmp_path, cwd=tmp_path, executable={})
    assert seen[0]["action"]["body"]["executable"] == {
        "command": "/bin/ls",
        "args": ["-l"],
        "structured_command": False,
        "direct_executable": False,
        "search_path": None,
        "launch_env": None,
    }
    assert seen[1]["action"]["body"]["executable"]["args"] == []


def test_unbound_reply_and_missing_prerequisite_fail_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _reply(monkeypatch, request_sha256="sha256:" + "0" * 64, payload={})
    assert _build(tmp_path) == client.NativeRequestContextFailure("native_request_context_unavailable")
    seen = _reply(monkeypatch, prerequisite=False)
    assert _build(tmp_path) == client.NativeRequestContextFailure("native_request_context_prerequisite_unavailable")
    assert seen == []


def test_malformed_payload_is_not_an_authoritative_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _reply(monkeypatch, payload={"schema": "guard-request-context.v1", "extra": 1})
    assert _build(tmp_path) == client.NativeRequestContextFailure("native_request_context_payload_invalid")


def test_request_carries_owner_budget_and_process_cwd_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen = _reply(monkeypatch, status="error", code="native_request_context_budget_invalid")
    client.native_request_context_build(source="guard_run", guard_home=tmp_path, script="ls", budget_ms=1234)
    request = seen[0]
    assert request["source"] == "guard_run"
    assert request["budget_ms"] == 1234
    assert request["owner_uid"] == (os.geteuid() if hasattr(os, "geteuid") else None)
    assert request["action"]["kind"] == "build"
    assert request["action"]["body"]["cwd"] is None
    assert request["action"]["body"]["fallback_cwd"] == str(Path.cwd())


def test_unavailable_resident_yields_an_incomplete_context_never_an_allow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _reply(monkeypatch, prerequisite=False)
    context = shell.model_shell_execution_context("cd sub && ls", cwd=tmp_path, workspace_root=tmp_path)
    assert context.complete is False
    assert context.reason_code == shell.SHELL_CWD_NATIVE_UNAVAILABLE
    assert context.segments == ()
    assert context.directory_change_present is True
    assert context.context_hash.startswith(_UNBOUND_PREFIX)
    metadata = shell.shell_execution_context_metadata(context)
    assert metadata["shell_execution_context_complete"] is False
    segment = shell.ShellExecutionSegment(
        tokens=("ls",),
        segment_index=0,
        control_before=(),
        control_after=(),
        effective_cwd=tmp_path,
        cwd_identity=ShellPathIdentity(1, 2, 0o040000, 3, 4),
        cwd_path_proofs=(),
        cwd_source="workspace",
        directory_stack=(),
        complete=True,
    )
    forged = replace(
        context,
        workspace_root=tmp_path,
        workspace_identity=ShellPathIdentity(1, 2, 0o040000, 3, 4),
        segments=(segment,),
        complete=True,
        reason_code=None,
    )
    assert shell.validate_shell_execution_segment(forged, segment) == (None, shell.SHELL_CWD_NATIVE_UNAVAILABLE)
    assert shell.shell_execution_segment_hash(forged, segment).startswith(_UNBOUND_PREFIX)


def _valid_shell_report(tmp_path: Path) -> dict[str, Any]:
    segment = {
        "tokens": ["ls"],
        "segment_index": 0,
        "control_before": [],
        "control_after": [],
        "effective_cwd": str(tmp_path),
        "cwd_identity": {"device": 1, "inode": 2, "mode": 0o040000, "change_time_ns": 3, "creation_time_ns": 4},
        "cwd_path_proofs": [],
        "cwd_source": "workspace",
        "directory_stack": [],
        "complete": True,
        "reason_code": None,
        "directory_operation": None,
    }
    wire = {
        "command_text": "ls",
        "initial_cwd": str(tmp_path),
        "workspace_root": str(tmp_path),
        "workspace_identity": segment["cwd_identity"],
        "segments": [segment],
        "complete": True,
        "reason_code": None,
        "directory_change_present": False,
    }
    digest = "sha256:" + "1" * 64
    return {"context": wire, "context_hash": digest, "segment_hashes": [digest], "metadata": {}}


def _model_with_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, report: dict[str, Any]
) -> shell.ShellExecutionContext:
    shell_context = client.NativeRequestContext("sha256:" + "2" * 64, {}, report, None, None)
    monkeypatch.setattr(shell, "native_request_context_build", lambda **_kwargs: shell_context)
    return shell.model_shell_execution_context("ls", cwd=tmp_path, workspace_root=tmp_path)


def test_well_formed_shell_reply_becomes_a_native_bound_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context = _model_with_shell(monkeypatch, tmp_path, _valid_shell_report(tmp_path))
    assert context.complete is True
    assert context.native is not None
    assert [segment.tokens for segment in context.segments] == [("ls",)]


@pytest.mark.parametrize(
    "damage",
    [
        lambda report: report["context"].pop("segments"),
        lambda report: report["context"]["segments"][0].pop("tokens"),
        lambda report: report["context"]["segments"][0].update(complete="yes"),
        lambda report: report["context"]["segments"][0].update(tokens=[1]),
        lambda report: report["context"]["segments"][0].update(segment_index="0"),
        lambda report: report["context"].update(complete=None),
        lambda report: report["context"].update(command_text=None),
        lambda report: report["context"]["segments"][0].update(cwd_identity={"device": 1}),
    ],
)
def test_malformed_shell_reply_yields_the_incomplete_context_not_an_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, damage: Any
) -> None:
    report = _valid_shell_report(tmp_path)
    damage(report)
    context = _model_with_shell(monkeypatch, tmp_path, report)
    assert context.complete is False
    assert context.reason_code == shell.SHELL_CWD_NATIVE_UNAVAILABLE
    assert context.segments == ()
    assert context.native is None


@pytest.mark.parametrize("command", ["cat ~/.ssh/id_rsa", "./tool.sh"])
def test_unavailable_resident_keeps_the_mandatory_read_floors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str
) -> None:
    _reply(monkeypatch, prerequisite=False)
    assessment = assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path)
    assert assessment.requires_review is True
    factors = shell_read_floor_factors(command, "action:test", cwd=tmp_path, home_dir=tmp_path)
    assert [factor.reason_code for factor in factors] != []


def test_unavailable_resident_does_not_invent_a_floor_for_unrelated_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _reply(monkeypatch, prerequisite=False)
    assert assess_shell_reads("echo hello", cwd=tmp_path, home_dir=tmp_path).requires_review is False


def _materialize(root: Path, entries: list[dict[str, str]]) -> None:
    for entry in entries:
        path = root / entry["path"]
        if entry["kind"] == "dir":
            path.mkdir(parents=True, exist_ok=True)
        elif entry["kind"] == "file":
            path.write_text("x", encoding="utf-8")
        else:
            os.symlink(entry["target"], path)


def _rel(root: Path, value: Path | None) -> str | None:
    if value is None:
        return None
    text, base = str(value), str(root)
    if text == base:
        return "$ROOT"
    return "$ROOT" + text[len(base) :] if text.startswith(base + "/") else f"$OUTSIDE:{text}"


def _mode(identity: ShellPathIdentity | None) -> dict[str, int] | None:
    return None if identity is None else {"mode": identity.mode}


def _segment(root: Path, item: shell.ShellExecutionSegment) -> dict[str, Any]:
    return {
        "tokens": [token.replace(str(root), "$ROOT") for token in item.tokens],
        "segment_index": item.segment_index,
        "control_before": list(item.control_before),
        "control_after": list(item.control_after),
        "effective_cwd": _rel(root, item.effective_cwd),
        "cwd_identity": _mode(item.cwd_identity),
        "cwd_path_proofs": [
            {
                "lexical_path": _rel(root, proof.lexical_path),
                "resolved_path": _rel(root, proof.resolved_path),
                "identity": _mode(proof.identity),
            }
            for proof in item.cwd_path_proofs
        ],
        "cwd_source": item.cwd_source,
        "directory_stack": [_rel(root, path) for path in item.directory_stack],
        "complete": item.complete,
        "reason_code": item.reason_code,
        "directory_operation": item.directory_operation,
    }


_CASES = json.loads(_FIXTURE.read_text(encoding="utf-8"))["cases"]


@pytest.mark.usefixtures("package_intent_native")
@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_native_shell_model_matches_recorded_python_vectors(case: dict[str, Any], tmp_path: Path) -> None:
    root = tmp_path.resolve()
    _materialize(root, case["fs"])

    def resolve(key: str) -> Path | None:
        return root / case[key] if case[key] is not None else None

    context = shell.model_shell_execution_context(
        case["command"].replace("{ROOT}", str(root)),
        cwd=resolve("cwd"),
        workspace_root=resolve("workspace"),
        home_dir=resolve("home_dir"),
    )
    expected = case["expected"]
    assert context.complete == expected["complete"]
    assert context.reason_code == expected["reason_code"]
    assert context.directory_change_present == expected["directory_change_present"]
    assert _rel(root, context.initial_cwd) == expected["initial_cwd"]
    assert _rel(root, context.workspace_root) == expected["workspace_root"]
    assert _mode(context.workspace_identity) == expected["workspace_identity"]
    assert [_segment(root, item) for item in context.segments] == expected["segments"]
    assert [_rel(root, path) for path in context.effective_cwds] == expected["effective_cwds"]
    assert context.context_hash.startswith("sha256:")
    assert shell.shell_execution_context_hash(context) == context.context_hash


@pytest.mark.usefixtures("package_intent_native")
def test_resident_revalidation_detects_swaps_and_ignores_python_claims(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    (root / "ws" / "inner").mkdir(parents=True)
    (root / "ws" / "other").mkdir()
    os.symlink("inner", root / "ws" / "link")
    context = shell.model_shell_execution_context("cd link && ls", cwd=root / "ws", workspace_root=root / "ws")
    assert context.complete
    segment = context.segments[1]
    assert shell.validate_shell_execution_segment(context, segment) == (root / "ws" / "inner", None)

    identity = segment.cwd_identity
    assert identity is not None
    forged = replace(segment, cwd_identity=replace(identity, inode=identity.inode + 1))
    assert shell.validate_shell_execution_segment(context, forged) == (None, shell.SHELL_CWD_PATH_CHANGED)

    # A hash Python recomputes for altered data is not the resident-issued one.
    altered = replace(context, command_text="cd link && rm -rf .")
    assert altered.context_hash != context.context_hash
    assert shell.shell_execution_segment_hash(context, forged) != shell.shell_execution_segment_hash(context, segment)

    (root / "ws" / "link").unlink()
    os.symlink("other", root / "ws" / "link")
    assert shell.validate_shell_execution_segment(context, segment) == (None, shell.SHELL_CWD_PATH_CHANGED)
