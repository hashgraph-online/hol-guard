"""An allowed local CLI grant widens the workspace sandbox; it never lifts it.

Each hop is pinned: the client presents the resident's contained grant, the
daemon and the direct CLI hook route an outside-roots review it covers into
the sandbox sink, and the sink asks the store itself, admits only a plan
widened by exactly that grant, and refuses one that changed before launch.
"""

from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import local_cli_hook as client
from codex_plugin_scanner.guard.adapters import zcode_contained_tests
from codex_plugin_scanner.guard.cli import commands_hook_native_containment as cli_route
from codex_plugin_scanner.guard.daemon import hook_contained_grant as routing
from codex_plugin_scanner.guard.runtime import restricted_workspace as workspace_sink
from codex_plugin_scanner.guard.runtime import restricted_workspace_grant_lookup as lookup
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError
from tests.test_guard_restricted_workspace import COMMAND, payload, plan, receipt

HASH = "ab" * 32
GRANT = {"cli_id": "local-cli.lanectl", "identity_hash": HASH, "name": "lanectl", "capabilities": ["loopback-network"]}
CONTAINED = client.ContainedGrant("local-cli.lanectl", HASH, "lanectl", ("loopback-network",))
OUTSIDE = routing.OUTSIDE_ROOTS_REASON


@pytest.fixture(autouse=True)
def macos_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workspace_sink, "_host_backend", lambda: "macos-seatbelt")


def _store(tmp_path: Path) -> object:
    return SimpleNamespace(
        path=tmp_path / "guard.db",
        guard_home=tmp_path,
        guard_source="local",
        _repair_store_permissions=lambda: None,
    )


def _resident(monkeypatch: pytest.MonkeyPatch, payload_value: object) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def resident(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        requests.append(request)
        return {
            "schema": "guard-local-cli-hook-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + client._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload_value,
        }

    monkeypatch.setattr(client, "_resident_request", resident)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: True)
    return requests


def _contained(tmp_path: Path, action: str = "review", reason: str | None = OUTSIDE) -> object:
    return client.local_cli_contained_grant(
        _store(tmp_path),  # type: ignore[arg-type]
        command="lanectl status",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action=action,  # type: ignore[arg-type]
        reason_code=reason,
    )


def test_client_sends_the_reason_and_presents_the_contained_grant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    requests = _resident(monkeypatch, {"action": client.ALLOW_CONTAINED_WITH_GRANT, "contained_grant": GRANT})
    assert _contained(tmp_path) == (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED)
    assert requests[-1]["current_reason_code"] == OUTSIDE
    assert _contained(tmp_path, "sandbox-required", None) == (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED)
    # Rust omits an absent reason from the digest, so the request does too.
    assert "current_reason_code" not in requests[-1]
    assert CONTAINED.prepare_input() == {"identity_hash": HASH, "name": "lanectl", "capabilities": ["loopback-network"]}
    # Callers of the plain action keep the sandbox-bound action, never `allow`.
    action = client.native_local_cli_hook(
        _store(tmp_path),  # type: ignore[arg-type]
        command="lanectl status",
        cwd=tmp_path,
        home_dir=None,
        current_action="sandbox-required",
        grant_allowed=True,
    )
    assert action == "sandbox-required"


@pytest.mark.parametrize(
    "reply",
    [
        {"action": client.ALLOW_CONTAINED_WITH_GRANT},
        {"action": client.ALLOW_CONTAINED_WITH_GRANT, "contained_grant": GRANT | {"identity_hash": "AB" * 32}},
        {"action": client.ALLOW_CONTAINED_WITH_GRANT, "contained_grant": GRANT | {"capabilities": ["network"]}},
        {
            "action": client.ALLOW_CONTAINED_WITH_GRANT,
            "contained_grant": GRANT | {"capabilities": ["state-dir-read", "loopback-network"]},
        },
        {"action": client.ALLOW_CONTAINED_WITH_GRANT, "contained_grant": GRANT | {"extra": 1}},
        {"action": "review", "contained_grant": GRANT},
        {"action": "review", "other": 1},
    ],
)
def test_client_refuses_a_malformed_contained_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: dict[str, object]
) -> None:
    _resident(monkeypatch, reply)
    assert _contained(tmp_path) is None


def test_client_widens_only_a_sandbox_bound_action(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _resident(monkeypatch, {"action": client.ALLOW_CONTAINED_WITH_GRANT, "contained_grant": GRANT})
    assert _contained(tmp_path, "warn", None) is None


def _decides(monkeypatch: pytest.MonkeyPatch, *answers: object) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []
    queue = list(answers)

    def decide(store: object, **kwargs: object) -> object:
        calls.append(kwargs)
        answer = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(client, "local_cli_contained_grant", decide)
    return calls


def _review(**changes: object) -> dict[str, object]:
    return {"decision": "deny", "minimum_action": "review", "policy_action": "review", "reason_code": OUTSIDE} | changes


def test_daemon_turns_a_granted_outside_roots_review_into_the_sandbox(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _decides(monkeypatch, (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED))
    granted = routing.granted_containment_result(
        object(), _review(), payload=payload("lanectl status"), workspace=tmp_path, home_dir=tmp_path
    )
    assert granted is not None
    assert granted["minimum_action"] == granted["policy_action"] == "sandbox-required"
    assert granted["reason_code"] == "native_workspace_containment_required"
    assert calls[0]["current_action"] == "review"
    assert calls[0]["reason_code"] == OUTSIDE


@pytest.mark.parametrize(
    ("result", "answer"),
    [
        (_review(reason_code="native_policy_review"), (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED)),
        (_review(minimum_action="allow"), (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED)),
        (_review(policy_action="require-reapproval"), (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED)),
        (_review(action={"action_type": "package"}), (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED)),
        (_review(action={"action_type": "guard_control"}), (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED)),
        (_review(), ("block", None)),
        (_review(), ("review", None)),
        (_review(), None),
        (_review(), RuntimeError("store down")),
    ],
)
def test_daemon_keeps_every_other_review(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, result: dict[str, object], answer: object
) -> None:
    _decides(monkeypatch, answer)
    assert (
        routing.granted_containment_result(
            object(), result, payload=payload("lanectl status"), workspace=tmp_path, home_dir=tmp_path
        )
        is None
    )


def test_daemon_routes_the_grant_and_answers_the_sink_with_the_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _decides(monkeypatch, (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED))
    rendered: list[dict[str, object]] = []
    monkeypatch.setattr(
        routing, "render_pre_tool", lambda harness, verdict, **kwargs: rendered.append(dict(verdict)) or receipt()
    )
    monkeypatch.setattr(zcode_contained_tests, "route_zcode_containment", lambda response, **kwargs: {"routed": True})
    common = {"harness": "omp", "guard_home": tmp_path, "home_dir": tmp_path, "workspace": tmp_path}
    routed = routing.granted_containment_response(object(), _review(), payload=payload("lanectl status"), **common)
    assert routed == {"routed": True}
    assert rendered[0]["policy_action"] == "sandbox-required"
    receipt_only = payload("lanectl status") | {"guard_containment_receipt_only": True}
    assert routing.granted_containment_response(object(), _review(), payload=receipt_only, **common) == receipt()
    # A call the sink cannot take keeps its review.
    monkeypatch.setattr(zcode_contained_tests, "route_zcode_containment", lambda response, **kwargs: response)
    assert (
        routing.granted_containment_response(object(), _review(), payload=payload("lanectl status"), **common) is None
    )


def test_direct_cli_hook_routes_a_granted_review(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli_route, "granted_containment_response", lambda store, result, **kwargs: {"routed": True})
    monkeypatch.setattr(cli_route, "record_pre_hook_command_activity_best_effort", lambda **kwargs: None)
    edge = {"event_name": "PreToolUse", "harness": "omp", "result": _review()}
    context = SimpleNamespace(guard_home=tmp_path, home_dir=tmp_path)
    stream = io.StringIO()
    assert cli_route.emit_native_containment_route(edge, payload(), context, tmp_path, stream, object()) == 0  # type: ignore[arg-type]
    assert stream.getvalue().strip() == '{"routed":true}'
    monkeypatch.setattr(cli_route, "granted_containment_response", lambda store, result, **kwargs: None)
    assert cli_route.emit_native_containment_route(edge, payload(), context, tmp_path, io.StringIO(), object()) is None  # type: ignore[arg-type]


def _granted_plan(workspace: Path, **changes: object) -> dict[str, object]:
    return plan(
        workspace,
        profile_version="workspace-contained-grant-v1",
        grant_identity_hash=HASH,
        capabilities=["loopback-network"],
        **changes,
    )


def _sink(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, grant_plan: dict[str, object]) -> dict[str, object]:
    seen: dict[str, object] = {"launched": 0}

    def fake_native(operation: str, fields: object, expected: object) -> object:
        assert isinstance(fields, dict)
        seen[operation] = fields
        return "(version 1)" if operation == "macos_profile" else grant_plan

    monkeypatch.setattr(workspace_sink, "restricted_native", fake_native)
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(workspace_sink, "_restricted_environment", lambda source, **kwargs: {"PATH": "/host/bin"})

    def launch(argv: object, **kwargs: object) -> int:
        seen["launched"] = int(str(seen["launched"])) + 1
        return 0

    monkeypatch.setattr(workspace_sink, "_run_backend_process", launch)
    return seen


def _run(tmp_path: Path) -> int:
    with lookup.grant_store(object()):  # type: ignore[arg-type]
        return workspace_sink.run_workspace_contained(
            payload(),
            workspace=tmp_path,
            cwd=tmp_path,
            authorize=lambda original: receipt(),
            first_receipt=receipt(),
            home_dir=tmp_path,
        )


def test_sink_widens_by_the_store_grant_and_passes_capabilities_to_the_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _decides(monkeypatch, (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED))
    seen = _sink(monkeypatch, tmp_path, _granted_plan(tmp_path))
    assert _run(tmp_path) == 0
    prepare = seen["prepare_workspace_contained"]
    assert isinstance(prepare, dict)
    assert prepare["grant"] == CONTAINED.prepare_input()
    profile = seen["macos_profile"]
    assert isinstance(profile, dict)
    assert profile["profile_version"] == "workspace-contained-grant-v1"
    assert profile["capabilities"] == ["loopback-network"]
    assert profile["home"] == tmp_path
    assert seen["launched"] == 1
    # Asked when planning and again after the second receipt.
    assert [call["current_action"] for call in calls] == ["sandbox-required", "sandbox-required"]
    assert calls[0]["command"] == COMMAND


@pytest.mark.parametrize(
    "second",
    [
        (client.ALLOW_CONTAINED_WITH_GRANT, client.ContainedGrant("local-cli.lanectl", "cd" * 32, "lanectl", ())),
        (client.ALLOW_CONTAINED_WITH_GRANT, client.ContainedGrant("local-cli.lanectl", HASH, "lanectl", ())),
        ("block", None),
        ("sandbox-required", None),
    ],
)
def test_sink_refuses_a_grant_that_changed_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, second: object
) -> None:
    _decides(monkeypatch, (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED), second)
    seen = _sink(monkeypatch, tmp_path, _granted_plan(tmp_path))
    with pytest.raises(RestrictedPytestError, match=lookup.GRANT_CHANGED):
        _run(tmp_path)
    assert seen["launched"] == 0


@pytest.mark.parametrize(
    "changes",
    [{"grant_identity_hash": "cd" * 32}, {"capabilities": ["loopback-network", "state-dir-read"]}],
)
def test_sink_refuses_a_plan_widened_beyond_the_decided_grant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, changes: dict[str, object]
) -> None:
    _decides(monkeypatch, (client.ALLOW_CONTAINED_WITH_GRANT, CONTAINED))
    seen = _sink(monkeypatch, tmp_path, _granted_plan(tmp_path) | changes)
    with pytest.raises(RestrictedPytestError, match="Invalid workspace sandbox plan"):
        _run(tmp_path)
    assert seen["launched"] == 0


def test_sink_stops_a_blocked_cli_and_keeps_the_base_sandbox_without_a_grant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _decides(monkeypatch, ("block", None))
    seen = _sink(monkeypatch, tmp_path, plan(tmp_path))
    with pytest.raises(RestrictedPytestError, match=lookup.GRANT_BLOCKED):
        _run(tmp_path)
    assert "prepare_workspace_contained" not in seen
    _decides(monkeypatch, ("sandbox-required", None))
    seen = _sink(monkeypatch, tmp_path, plan(tmp_path))
    assert _run(tmp_path) == 0
    prepare = seen["prepare_workspace_contained"]
    assert isinstance(prepare, dict)
    assert "grant" not in prepare
    profile = seen["macos_profile"]
    assert isinstance(profile, dict)
    assert profile["profile_version"] == "workspace-contained-v1"
    assert profile["capabilities"] == []


def test_expected_grant_names_the_state_directory_under_the_canonical_home(tmp_path: Path) -> None:
    stateful = client.ContainedGrant("local-cli.lanectl", HASH, "lanectl", ("state-dir-read",))
    expected = lookup.expected_grant(stateful, tmp_path)
    assert expected.state_dir == str(tmp_path.resolve() / ".lanectl")
    assert lookup.expected_grant(CONTAINED, tmp_path).state_dir is None


@pytest.mark.parametrize(
    "failure", [RuntimeError("store down"), OSError("disk"), TimeoutError(), ValueError("bad row")]
)
def test_a_store_that_cannot_answer_decides_no_grant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: Exception
) -> None:
    _decides(monkeypatch, failure)
    with lookup.grant_store(object()):  # type: ignore[arg-type]
        assert lookup.decided_grant(COMMAND, workspace=tmp_path, home=tmp_path) is None
        # Nothing was decided, so nothing is lost when it cannot answer again.
        lookup.require_unchanged(None, COMMAND, workspace=tmp_path, home=tmp_path)
        with pytest.raises(RestrictedPytestError, match=lookup.GRANT_CHANGED):
            lookup.require_unchanged(CONTAINED, COMMAND, workspace=tmp_path, home=tmp_path)


def test_sink_keeps_the_base_sandbox_when_the_store_cannot_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _decides(monkeypatch, RuntimeError("store down"))
    seen = _sink(monkeypatch, tmp_path, plan(tmp_path))
    assert _run(tmp_path) == 0
    prepare = seen["prepare_workspace_contained"]
    assert isinstance(prepare, dict)
    assert "grant" not in prepare
    assert seen["launched"] == 1


def _state_plan(*capabilities: str) -> dict[str, object]:
    return {"capabilities": list(capabilities)}


def test_state_directory_is_linked_where_the_private_home_looks_for_it(tmp_path: Path) -> None:
    home = tmp_path / "home"
    state = home / ".lanectl"
    state.mkdir(parents=True)
    private = tmp_path / "private"
    private.mkdir()
    stateful = client.ContainedGrant("local-cli.lanectl", HASH, "lanectl", ("state-dir-read",))
    lookup.link_state_dir(private, _state_plan("state-dir-read"), lookup.expected_grant(stateful, home))
    link = private / ".lanectl"
    assert link.is_symlink()
    assert link.resolve() == state.resolve()


@pytest.mark.parametrize("kind", ["no-capability-in-plan", "no-grant", "no-state-capability", "missing", "link"])
def test_state_directory_is_not_linked_without_the_grant_a_directory_and_a_capability(
    tmp_path: Path, kind: str
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    stateful = client.ContainedGrant("local-cli.lanectl", HASH, "lanectl", ("state-dir-read",))
    expected = lookup.expected_grant(stateful, home)
    plan_value = _state_plan("state-dir-read")
    if kind != "missing":
        (home / ".lanectl").mkdir()
    if kind == "link":
        (home / ".lanectl").rmdir()
        (home / ".lanectl").symlink_to(tmp_path)
    if kind == "no-capability-in-plan":
        plan_value = _state_plan("loopback-network")
    if kind == "no-grant":
        expected = None  # type: ignore[assignment]
    if kind == "no-state-capability":
        expected = lookup.expected_grant(CONTAINED, home)
    lookup.link_state_dir(private, plan_value, expected)
    assert list(private.iterdir()) == []
