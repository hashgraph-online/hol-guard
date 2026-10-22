from __future__ import annotations

import copy
import http.server
import re
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import (
    native_extension_control,
    native_extension_control_authority,
    store_extension_control_authority_commit,
    store_extension_control_authority_reads,
)
from codex_plugin_scanner.guard.daemon import client as daemon_client
from codex_plugin_scanner.guard.daemon import extension_control_timeouts as timeouts
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiError, ExtensionControlApiService
from codex_plugin_scanner.guard.daemon.extension_control_semantic_preview import (
    SEMANTIC_PREVIEW_SCHEMA,
    _render,
)
from codex_plugin_scanner.guard.native_extension_control import (
    PREVIEW_LIMIT_CODES,
    NativeExtensionControlError,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]


class _InvalidError(RuntimeError):
    pass


def _invalid() -> RuntimeError:
    return _InvalidError("invalid")


def _target() -> dict[str, object]:
    return {
        "target": {"kind": "permission", "target_id": "command.git.push"},
        "extension_id": "command.git",
        "label": "Push",
        "before_explicit": "inherited",
        "after_explicit": "disabled",
        "before_effective": "allowed",
        "after_effective": "blocked",
        "baseline_risk": "high",
        "baseline_floor": "ask",
        "affected_permission_ids": ["command.git.push"],
        "affected_rule_ids": ["git.push"],
        "affected_extension_ids": [],
        "dependency_permission_ids": [],
        "implied_permission_ids": [],
        "conflict_permission_ids": [],
        "provenance": ["local"],
        "warnings": [{"code": "indirect", "count": 2, "message": "Affects 2 permissions."}],
        "extension_name": "Git",
    }


def _preview() -> dict[str, object]:
    return {
        "schema_version": SEMANTIC_PREVIEW_SCHEMA,
        "global_lockdown": {"before": False, "after": False, "changed": False},
        "changed_target_count": 1,
        "affected_permission_count": 1,
        "affected_rule_count": 1,
        "changed_targets": [_target()],
        "approval_required": False,
        "summary": {"newly_blocked_permissions": 1, "newly_allowed_permissions": 0, "effective_change_count": 1},
    }


def _with_target(**changes: object) -> dict[str, object]:
    value = _preview()
    target = copy.deepcopy(_target())
    target.update(changes)
    value["changed_targets"] = [target]
    return value


def test_render_keeps_a_well_formed_preview_in_digest_order() -> None:
    value = _preview()
    shuffled = dict(reversed(list(value.items())))

    rendered = _render(shuffled, _invalid)

    assert rendered == value
    assert list(rendered) == list(value)


def test_render_accepts_a_target_without_its_optional_fields() -> None:
    target = _target()
    for name in ("baseline_risk", "baseline_floor", "extension_name"):
        del target[name]
    target["warnings"] = [{"code": "conflict", "message": "Conflicts.", "target_id": "command.git.force"}]
    value = _preview()
    value["changed_targets"] = [target]

    assert _render(value, _invalid) == value


@pytest.mark.parametrize(
    "mutate",
    [
        lambda v: v.update(changed_targets=["not-a-target"]),
        lambda v: v.update(changed_targets=[{}]),
        lambda v: v.update(global_lockdown={"before": False, "after": False}),
        lambda v: v.update(global_lockdown={"before": False, "after": False, "changed": "no"}),
        lambda v: v.update(global_lockdown={"before": 0, "after": False, "changed": False}),
        lambda v: v.update(summary={"newly_blocked_permissions": 1}),
        lambda v: v.update(
            summary={"newly_blocked_permissions": "1", "newly_allowed_permissions": 0, "effective_change_count": 1}
        ),
        lambda v: v.update(
            summary={"newly_blocked_permissions": True, "newly_allowed_permissions": 0, "effective_change_count": 1}
        ),
        lambda v: v.update(
            summary={"newly_blocked_permissions": -1, "newly_allowed_permissions": 0, "effective_change_count": 1}
        ),
        lambda v: v.update(affected_rule_count="1"),
        lambda v: v.update(affected_permission_count=-1),
        lambda v: v.update(changed_target_count=2),
        lambda v: v.update(approval_required=1),
        lambda v: v.update(schema_version="other"),
        lambda v: v.update(extra=1),
        lambda v: v.pop("summary"),
    ],
)
def test_render_refuses_a_malformed_top_level_or_nested_object(mutate) -> None:
    value = _preview()
    mutate(value)

    with pytest.raises(_InvalidError):
        _render(value, _invalid)


@pytest.mark.parametrize(
    "changes",
    [
        {"target": {"kind": "rule", "target_id": "command.git.push"}},
        {"target": {"kind": "permission"}},
        {"target": "command.git.push"},
        {"target": {"kind": ["permission"], "target_id": "command.git.push"}},
        {"extension_id": 7},
        {"label": None},
        {"before_explicit": "maybe"},
        {"after_explicit": None},
        {"before_effective": "inherited"},
        {"after_effective": "ask"},
        {"affected_permission_ids": "command.git.push"},
        {"affected_rule_ids": [1]},
        {"provenance": [["local"]]},
        {"warnings": {"code": "indirect"}},
        {"warnings": ["indirect"]},
        {"warnings": [{"code": "indirect"}]},
        {"warnings": [{"code": "indirect", "message": "m", "count": "2"}]},
        {"warnings": [{"code": "indirect", "message": "m", "target_id": 3}]},
        {"warnings": [{"code": "indirect", "message": "m", "unknown": 1}]},
        {"baseline_risk": 4},
        {"extension_name": ["Git"]},
        {"unknown": 1},
    ],
)
def test_render_refuses_a_malformed_changed_target(changes: dict[str, object]) -> None:
    with pytest.raises(_InvalidError):
        _render(_with_target(**changes), _invalid)


def test_render_refuses_a_target_missing_a_required_field() -> None:
    value = _preview()
    del value["changed_targets"][0]["affected_extension_ids"]  # type: ignore[index]

    with pytest.raises(_InvalidError):
        _render(value, _invalid)


def test_render_bounds_the_lists_it_forwards() -> None:
    too_many = [f"command.git.p{index}" for index in range(4097)]

    with pytest.raises(_InvalidError):
        _render(_with_target(affected_permission_ids=too_many), _invalid)
    with pytest.raises(_InvalidError):
        _render(_with_target(warnings=[{"code": "w", "message": "m"}] * 65), _invalid)


def test_preview_limit_refusals_report_a_limit_not_a_dead_runtime() -> None:
    assert {
        "native_extension_control_too_large",
        "native_extension_control_too_many_items",
        "native_extension_control_reply_too_large",
    } == PREVIEW_LIMIT_CODES
    service = ExtensionControlApiService.__new__(ExtensionControlApiService)
    service._preview_lock = threading.Lock()
    for code in sorted(PREVIEW_LIMIT_CODES):

        def refuse(_payload: dict[str, object], code: str = code) -> dict[str, object]:
            raise NativeExtensionControlError(code)

        service._preview_locked = refuse  # type: ignore[method-assign]
        with pytest.raises(ExtensionControlApiError) as limit:
            service.preview({})
        assert (limit.value.status, limit.value.code) == (400, "control_limit_exceeded")

    def unavailable(_payload: dict[str, object]) -> dict[str, object]:
        raise NativeExtensionControlError("native_extension_control_unavailable")

    service._preview_locked = unavailable  # type: ignore[method-assign]
    with pytest.raises(ExtensionControlApiError) as dead:
        service.preview({})
    assert (dead.value.status, dead.value.code) == (503, "native_runtime_unavailable")


def test_preview_deadlines_nest_from_the_resident_out_to_the_dashboard() -> None:
    granted = native_extension_control._PREVIEW_TIMEOUT_SECONDS
    ceiling = re.search(
        r"EXTENSION_CONTROL_TIMEOUT_CEILING_MS: u64 = ([0-9_]+);",
        (_REPO_ROOT / "rust/crates/guard-runtime/src/managed_resident_client_timeout.rs").read_text(),
    )

    assert ceiling is not None
    # The resident client clamps to its ceiling, so the ceiling must grant what Python asks for.
    assert int(ceiling.group(1).replace("_", "")) >= granted * 1000
    # The daemon answers only after the resident does; its client waits longer.
    assert granted < timeouts.PREVIEW_REQUEST_TIMEOUT_S


def test_the_client_budgets_add_up_the_resident_budgets_they_wait_for() -> None:
    # Each literal in the timeouts module is the budget its owner grants.
    assert native_extension_control_authority._TIMEOUT_SECONDS == timeouts.AUTHORITY_ROUND_TIMEOUT_S
    assert store_extension_control_authority_reads._MAX_READ_ROUNDS == timeouts.AUTHORITY_READ_ROUNDS
    assert native_extension_control._TIMEOUT_SECONDS == timeouts.COMPOSE_TIMEOUT_S
    assert native_extension_control._TIMEOUT_SECONDS == timeouts.MUTATION_TIMEOUT_S
    assert native_extension_control._PREVIEW_TIMEOUT_SECONDS == timeouts.SEMANTIC_PREVIEW_TIMEOUT_S
    assert store_extension_control_authority_commit._MAX_COMMIT_ROUNDS == timeouts.COMMIT_PLAN_ROUNDS

    read = timeouts.AUTHORITY_ROUND_TIMEOUT_S * timeouts.AUTHORITY_READ_ROUNDS
    assert read == timeouts.AUTHORITY_READ_TIMEOUT_S
    # A preview: two authority reads, the five mutation asks (bounds, candidate
    # nonce, validation, mutability and request digest), the composition and the
    # semantic preview.
    assert timeouts.PREVIEW_MUTATION_ASKS == 5
    assert 2 * read + 5 * 5.0 + 5.0 + 15.0 <= timeouts.PREVIEW_REQUEST_TIMEOUT_S
    # An apply: its authority reads, the request digest ask, the audit projection
    # of the change (the semantic preview's budget) and the commit rounds.
    assert timeouts.APPLY_MUTATION_ASKS == 1
    assert 4 * read + 1 * 5.0 + 15.0 + 4 * 10.0 <= timeouts.APPLY_REQUEST_TIMEOUT_S
    assert timeouts.APPLY_REQUEST_TIMEOUT_S >= timeouts.PREVIEW_REQUEST_TIMEOUT_S
    # Both go to the client, which waits exactly that long for the whole answer.
    sent: list[tuple[str, float, int | None]] = []

    def record(_self: object, path: str, _payload: dict[str, object], *, timeout: float, max_bytes: int | None = None):
        sent.append((path, timeout, max_bytes))
        return {}

    client = daemon_client.GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    original = daemon_client.GuardSurfaceDaemonClient._post
    daemon_client.GuardSurfaceDaemonClient._post = record  # type: ignore[method-assign,assignment]
    try:
        client.preview_extension_controls({})
        client.apply_extension_controls({})
    finally:
        daemon_client.GuardSurfaceDaemonClient._post = original  # type: ignore[method-assign]
    assert [(path.rsplit("/", 1)[1], timeout) for path, timeout, _ in sent] == [
        ("preview", timeouts.PREVIEW_REQUEST_TIMEOUT_S),
        ("apply", timeouts.APPLY_REQUEST_TIMEOUT_S),
    ]
    assert all(limit is not None for _, _, limit in sent)


class _Drip(http.server.BaseHTTPRequestHandler):
    """Answers with a body sent a byte at a time, so no single wait is long."""

    status = 200
    delay = 0.05

    def do_POST(self) -> None:
        body = b'{"a":"' + b"x" * 400 + b'"}'
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            for index in range(len(body)):
                self.wfile.write(body[index : index + 1])
                self.wfile.flush()
                time.sleep(self.delay)
        except OSError:
            return

    def log_message(self, *_args: object) -> None:
        return


class _DripError(_Drip):
    status = 503


class _Quick(_Drip):
    delay = 0.002


class _QuickError(_Quick):
    status = 503


def _drip_client(
    handler: type[_Drip],
) -> tuple[http.server.ThreadingHTTPServer, daemon_client.GuardSurfaceDaemonClient]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, daemon_client.GuardSurfaceDaemonClient(f"http://127.0.0.1:{server.server_address[1]}", "token")


@pytest.mark.parametrize("handler", [_Drip, _DripError])
def test_a_bounded_post_gives_up_on_a_slow_body_at_its_total_deadline(handler: type[_Drip]) -> None:
    server, client = _drip_client(handler)
    try:
        started = time.monotonic()
        # Each byte arrives well inside the socket timeout, so only a total deadline stops the read.
        with pytest.raises(daemon_client.GuardDaemonTimeoutError):
            client._post("/v1/extension-controls/preview", {}, timeout=0.5, max_bytes=1_000_000)
        assert time.monotonic() - started < 5.0
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("max_bytes", [None, 1_000_000])
def test_a_post_reads_a_body_that_finishes_in_time(max_bytes: int | None) -> None:
    server, client = _drip_client(_Quick)
    try:
        kwargs = {} if max_bytes is None else {"timeout": 20.0, "max_bytes": max_bytes}
        assert client._post("/v1/extension-controls/preview", {}, **kwargs) == {"a": "x" * 400}
    finally:
        server.shutdown()
        server.server_close()


def test_a_bounded_post_still_reports_an_http_error_that_arrives_in_time() -> None:
    server, client = _drip_client(_QuickError)
    try:
        with pytest.raises(daemon_client.GuardDaemonRequestError) as raised:
            client._post("/v1/extension-controls/preview", {}, timeout=20.0, max_bytes=1_000_000)
        assert raised.value.status == 503
    finally:
        server.shutdown()
        server.server_close()
