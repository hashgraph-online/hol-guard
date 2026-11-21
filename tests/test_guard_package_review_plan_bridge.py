"""Reply validation and fail-closed behavior of the package review plan bridge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_package_review_plan as bridge

ARTIFACT_WIRE = {
    "artifact_id": "codex:project:package-request:npm:abc",
    "name": "npm install zod",
    "harness": "codex",
    "artifact_type": "package_request",
    "source_scope": "project",
    "config_path": "hol-guard.toml",
    "command": None,
    "args": [],
    "url": None,
    "transport": None,
    "publisher": None,
    "metadata": {"package_manager": "npm", "intent_kind": "install"},
    "runtime_private_metadata": {},
}
PAYLOAD = {"tool_input": {"command": "npm install zod"}}


def _reply(monkeypatch: pytest.MonkeyPatch, payload: object, **overrides: object) -> list[dict[str, Any]]:
    """Record the requests the bridge sends and answer each with ``payload``."""

    sent: list[dict[str, Any]] = []

    def fake(**kwargs: Any) -> dict[str, object]:
        request = kwargs["request"]
        sent.append(kwargs)
        response = {
            "schema": bridge._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + bridge._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }
        response.update(overrides)
        return response

    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(bridge, "_resident_request", fake)
    return sent


def _plan(tmp_path: Path, payload: object = PAYLOAD, **kwargs: Any) -> Any:
    return bridge.package_review_plan(
        payload,  # type: ignore[arg-type]
        harness="codex",
        workspace=tmp_path / "workspace",
        guard_home=tmp_path / "guard",
        review_reason=kwargs.pop("review_reason", "native_package_review"),
        **kwargs,
    )


def test_a_plan_returns_the_artifact_and_whether_it_may_allow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    retry = {"continue": False, "prompted": False}
    sent = _reply(
        monkeypatch,
        {"artifact": ARTIFACT_WIRE, "may_allow": True, "workspace": None, "keyed": True, "registry_retry": retry},
    )

    artifact, may_allow, workspace, keyed, registry_retry = _plan(tmp_path, home_dir=tmp_path / "home")

    assert may_allow is True
    assert workspace == tmp_path / "workspace"
    assert keyed is True
    assert registry_retry == retry
    assert artifact.artifact_id == ARTIFACT_WIRE["artifact_id"]
    assert artifact.metadata == ARTIFACT_WIRE["metadata"]
    assert sent[0]["operation"] == "package_review_plan"
    assert sent[0]["required_features"] == (bridge._PACKAGE_REVIEW_PLAN_FEATURE,)
    assert sent[0]["max_request_bytes"] > 5 * 1024 * 1024  # the most a hook payload reference reserves
    request = sent[0]["request"]
    assert request["schema"] == bridge._REQUEST_SCHEMA
    assert request["payload"] == PAYLOAD
    assert request["harness"] == "codex"
    assert request["home_dir"] == str(tmp_path / "home")
    assert request["review_reason"] == "native_package_review"
    assert request["include_registry_retry"] is True


def test_a_leading_cd_names_the_directory_the_install_runs_in(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    linked = tmp_path / "linked"
    _reply(monkeypatch, {"artifact": ARTIFACT_WIRE, "may_allow": False, "workspace": str(linked), "keyed": False})

    assert _plan(tmp_path).workspace == linked


def test_no_artifact_is_an_answer_not_a_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _reply(monkeypatch, {"artifact": None, "may_allow": False, "workspace": None, "keyed": False})

    assert _plan(tmp_path) == (None, False, tmp_path / "workspace", False, None)
    assert sent[0]["request"]["home_dir"] is None


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"artifact": None},
        {"may_allow": False},
        {"artifact": None, "may_allow": False},
        {"artifact": None, "may_allow": False, "workspace": None, "keyed": False, "extra": 1},
        {"artifact": None, "may_allow": True, "workspace": None, "keyed": False},
        {"artifact": ARTIFACT_WIRE, "may_allow": True, "workspace": None, "keyed": False},
        {"artifact": ARTIFACT_WIRE, "may_allow": False, "workspace": None, "keyed": False, "registry_retry": {}},
        {"artifact": None, "may_allow": False, "workspace": None, "keyed": True},
        {"artifact": ARTIFACT_WIRE, "may_allow": False, "workspace": None, "keyed": "yes"},
        {"artifact": ARTIFACT_WIRE, "may_allow": False, "workspace": None},
        {"artifact": None, "may_allow": False, "workspace": "/elsewhere", "keyed": False},
        {"artifact": ARTIFACT_WIRE, "may_allow": "yes", "workspace": None, "keyed": False},
        {"artifact": ARTIFACT_WIRE, "may_allow": False, "workspace": "relative/linked", "keyed": False},
        {"artifact": ARTIFACT_WIRE, "may_allow": False, "workspace": 3, "keyed": False},
        {"artifact": {**ARTIFACT_WIRE, "command": "npm"}, "may_allow": False, "workspace": None, "keyed": False},
        {"artifact": "npm install zod", "may_allow": False, "workspace": None, "keyed": False},
        "npm install zod",
    ],
)
def test_a_payload_that_is_not_the_contract_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: object
) -> None:
    _reply(monkeypatch, payload)

    with pytest.raises(bridge.NativePackageReviewPlanError):
        _plan(tmp_path)


@pytest.mark.parametrize(
    "override",
    [
        {"schema": "guard-other-result.v1"},
        {"request_id": "someone-elses"},
        {"request_sha256": "sha256:0"},
        {"status": "error"},
        {"code": "native_package_review_plan_invalid"},
    ],
)
def test_a_reply_for_another_request_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, override: dict[str, object]
) -> None:
    _reply(monkeypatch, {"artifact": None, "may_allow": False, "workspace": None, "keyed": False}, **override)

    with pytest.raises(bridge.NativePackageReviewPlanError):
        _plan(tmp_path)


def test_a_resident_that_cannot_answer_plans_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)

    with pytest.raises(bridge.NativePackageReviewPlanError):
        _plan(tmp_path)


def test_an_unserializable_payload_plans_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _reply(monkeypatch, {"artifact": None, "may_allow": False, "workspace": None, "keyed": False})

    with pytest.raises(bridge.NativePackageReviewPlanError):
        _plan(tmp_path, {"tool_input": object()})


@pytest.mark.usefixtures("package_intent_native")
@pytest.mark.parametrize(
    ("payload", "intent_kind"),
    [
        ({"tool_input": {"command": "npx create-vite@5.1.0"}}, "execute"),
        ({"toolName": "bash", "toolArgs": '{"command": "npm install minimist@1.2.8"}'}, "install"),
        # A large unrelated field must not push the plan past its request bound.
        ({"tool_input": {"command": "npm install minimist@1.2.8"}, "padding": "x" * (512 * 1024)}, "install"),
    ],
)
def test_the_resident_plans_exec_flows_and_copilot_tool_args(
    tmp_path: Path, package_intent_native: Path, payload: dict[str, object], intent_kind: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    plan = bridge.package_review_plan(
        payload,
        harness="copilot",
        workspace=workspace,
        guard_home=package_intent_native,
        review_reason="native_package_review",
    )

    assert plan.artifact is not None
    assert plan.artifact.metadata["intent_kind"] == intent_kind
    assert plan.may_allow is False
    assert plan.registry_retry is None


@pytest.mark.usefixtures("package_intent_native")
@pytest.mark.parametrize(
    ("command", "planned"),
    [("npx create-vite@5.1.0", True), ("bunx @angular/cli@19.0.0", True), ("npm install minimist@1.2.8", False)],
)
def test_the_resident_plans_a_command_review_only_for_npx_and_bunx(
    tmp_path: Path, package_intent_native: Path, command: str, planned: bool
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    plan = bridge.package_review_plan(
        {"tool_input": {"command": command}},
        harness="codex",
        workspace=workspace,
        guard_home=package_intent_native,
        review_reason="native_command_review_required",
    )

    assert (plan.artifact is not None) is planned
    assert plan.may_allow is False
    assert plan.registry_retry is None
