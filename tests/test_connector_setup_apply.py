"""Setting a connector up from a held request: one write path, then the group resolves."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals
from codex_plugin_scanner.guard.approval_gate_types import ApprovalGateError
from codex_plugin_scanner.guard.daemon import local_approval_continuation, local_cli_api, local_cli_http
from codex_plugin_scanner.guard.daemon import local_cli_connector_group as group
from codex_plugin_scanner.guard.daemon.approval_connector_recommendation import (
    build_approval_connector_recommendation,
)
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.daemon.local_cli_api_contract import LocalCliApiError
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import connector_setup_hint
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.store import GuardStore

_HASH = "a" * 64
_OTHER_HASH = "b" * 64
_CLI_ID = "local-cli.lanectl-0123abcd"
_GROUP = f"connector:{_HASH}:0123456789abcdef"
_SRC = Path(__file__).resolve().parents[1] / "src" / "codex_plugin_scanner" / "guard"


def _hint(cli_id: str = _CLI_ID, identity_hash: str = _HASH) -> dict[str, object] | None:
    return connector_setup_hint(cli_id=cli_id, identity_hash=identity_hash, display_name="lanectl", surface="cli")


def _queue(
    store: GuardStore, request_id: str, *, group_id: str = _GROUP, hint: object = None, harness: str = "codex"
) -> None:
    store.add_approval_request(
        GuardApprovalRequest(
            request_id=request_id,
            harness=harness,
            artifact_id=f"{harness}:native-pretool:Bash",
            artifact_name="Bash",
            artifact_hash=f"binding-{request_id}",
            policy_action="review",
            recommended_scope="artifact",
            changed_fields=("native_pre_tool",),
            source_scope="project",
            config_path="/workspace",
            review_command=f"hol-guard approvals approve {request_id}",
            approval_url=f"http://127.0.0.1/requests/{request_id}",
            launch_target="lanectl status",
            queue_group_id=group_id,
            extension_allow_hint=_hint() if hint is None else hint,
        ),
        "2026-10-17T10:00:00+00:00",
    )


@pytest.fixture
def store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard")
    _queue(store, "req-1")
    _queue(store, "req-2", group_id=f"connector:{_HASH}:1111111111111111", harness="claude-code")
    # Same group prefix but the hint names another connector: not this group.
    _queue(
        store,
        "req-spoof",
        group_id=f"connector:{_HASH}:fedcba9876543210",
        hint=_hint(cli_id="local-cli.other-0123abcd"),
    )
    _queue(
        store, "req-other", group_id=f"connector:{_OTHER_HASH}:0123456789abcdef", hint=_hint(identity_hash=_OTHER_HASH)
    )
    _queue(store, "req-tool", group_id="tool:abc", hint={"schema": "guard.extension-allow-hint.v1"})
    return store


def test_group_is_only_rows_naming_this_connector(store: GuardStore) -> None:
    ids = group.connector_group_request_ids(store, cli_id=_CLI_ID, identity_hash=_HASH)

    assert sorted(ids) == ["req-1", "req-2"]


@pytest.mark.parametrize(
    ("payload", "state", "code"),
    [
        ({"connector_group_request_id": 7}, "allowed", "invalid_connector_group_request_id"),
        ({"connector_group_request_id": " "}, "allowed", "invalid_connector_group_request_id"),
        ({"connector_group_request_id": "x" * 129}, "allowed", "invalid_connector_group_request_id"),
        ({"connector_group_request_id": "req-1"}, "blocked", "connector_group_requires_allowed"),
    ],
)
def test_group_request_id_is_checked_before_any_proof(payload: dict[str, object], state: str, code: str) -> None:
    with pytest.raises(LocalCliApiError) as raised:
        group.connector_group_request_id(payload, state)

    assert raised.value.code == code


def test_setup_from_a_row_outside_the_group_resolves_nothing(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(**_kwargs: object) -> dict[str, object]:
        raise AssertionError("bulk path must not run")

    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", unexpected)

    result = group.resolve_connector_group(
        store, cli_id=_CLI_ID, identity_hash=_HASH, request_id="req-other", approval_gate_input=None, now="t"
    )

    assert result == {"status": "not_in_group", "resolved_count": 0, "failed": []}


def test_group_goes_through_the_bulk_path_and_offers_the_continuation(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def bulk(**kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        return {"resolved_count": 1, "failed": [{"request_id": "req-2", "error": "ineligible"}]}

    continued: list[object] = []

    def resume(**kwargs: object) -> tuple[dict[str, object], dict[str, str]]:
        continued.append(kwargs["request_id"])
        updated = {"codexResume": {"status": "sent", "message": "Codex was told to continue."}}
        return updated, {"title": "Decision saved. Codex chat was notified.", "body": "Codex was told to continue."}

    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", bulk)
    monkeypatch.setattr(local_approval_continuation, "apply_local_approval_continuation", resume)

    result = group.resolve_connector_group(
        store, cli_id=_CLI_ID, identity_hash=_HASH, request_id="req-1", approval_gate_input=None, now="t"
    )

    assert sorted(seen["request_ids"]) == ["req-1", "req-2"]  # type: ignore[arg-type]
    # An ineligible row stays pending for a normal decision.
    assert result["status"] == "partial"
    continuation = result["continuation"]
    assert isinstance(continuation, dict)
    assert continuation["codexResume"] == {"status": "sent", "message": "Codex was told to continue."}
    assert continuation["retry_hint"] == "Codex was told to continue."
    # A row the bulk path did not approve is not continued.
    assert continued == ["req-1"]


def test_every_approved_row_continues_its_own_agent(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    continued: list[object] = []

    def resume(**kwargs: object) -> tuple[dict[str, object], object]:
        continued.append(kwargs["request_id"])
        return {}, kwargs["copy"]

    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", lambda **_k: {"resolved_count": 2, "failed": []})
    monkeypatch.setattr(local_approval_continuation, "apply_local_approval_continuation", resume)

    result = group.resolve_connector_group(
        store, cli_id=_CLI_ID, identity_hash=_HASH, request_id="req-2", approval_gate_input=None, now="t"
    )

    assert result["status"] == "resolved"
    assert sorted(continued) == ["req-1", "req-2"]  # type: ignore[type-var]
    continuation = result["continuation"]
    assert isinstance(continuation, dict) and continuation["request_id"] == "req-2"


def test_the_origin_row_is_found_past_a_long_queue(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    # The queue scan stopped before reaching this connector's rows.
    monkeypatch.setattr(group, "pending_connector_group_rows", lambda _store, _hash: ([], False))

    assert group.connector_group_request_ids(store, cli_id=_CLI_ID, identity_hash=_HASH, request_id="req-1") == [
        "req-1"
    ]
    assert group.connector_group_request_ids(store, cli_id=_CLI_ID, identity_hash=_HASH, request_id="req-spoof") == []
    assert group.connector_group_request_ids(store, cli_id=_CLI_ID, identity_hash=_HASH, request_id="req-other") == []


def test_other_harnesses_get_the_retry_hint_text(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", lambda **_k: {"resolved_count": 2, "failed": []})
    monkeypatch.setattr(local_approval_continuation, "apply_local_approval_continuation", lambda **k: ({}, k["copy"]))

    result = group.resolve_connector_group(
        store, cli_id=_CLI_ID, identity_hash=_HASH, request_id="req-2", approval_gate_input=None, now="t"
    )

    assert result["status"] == "resolved"
    assert result["continuation"]["retry_hint"] == "Return to Claude and retry"  # type: ignore[index]


def test_a_gate_failure_keeps_the_setup_and_the_rows(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    def gate(**_kwargs: object) -> dict[str, object]:
        raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")

    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", gate)

    result = group.resolve_connector_group(
        store, cli_id=_CLI_ID, identity_hash=_HASH, request_id="req-1", approval_gate_input=None, now="t"
    )

    assert result["status"] == "failed"
    assert result["error"] == "approval_gate_totp_required"
    assert {row["request_id"] for row in store.list_approval_requests(status="pending", limit=50)} >= {"req-1", "req-2"}


def _service(store: GuardStore) -> LocalCliApiService:
    return LocalCliApiService(store=store)


def _apply_body(state: str = "allowed", **extra: object) -> dict[str, object]:
    return {
        "cli_id": _CLI_ID,
        "identity_hash": _HASH,
        "name": "lanectl",
        "kind": "executable",
        "state": state,
        "previous_revision": 0,
        "session_nonce": "n" * 32,
        **extra,
    }


def test_apply_without_a_proof_writes_nothing_and_resolves_nothing(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_proof(*_args: object, **_kwargs: object) -> object:
        raise ApprovalGateError("approval_gate_password_required", "Approval password is required.")

    def unexpected(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("must not run without the one-use proof")

    monkeypatch.setattr(local_cli_api, "require_local_cli_trust", no_proof)
    monkeypatch.setattr(local_cli_api, "record_local_custom_extension_mutation", unexpected)
    monkeypatch.setattr(local_cli_api, "resolve_connector_group", unexpected)

    with pytest.raises(LocalCliApiError) as raised:
        _service(store).apply(_apply_body(connector_group_request_id="req-1"))

    assert raised.value.code == "approval_gate_password_required"


def test_blocked_setup_cannot_resolve_the_group_and_spends_no_proof(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("rejected before the proof")

    monkeypatch.setattr(local_cli_api, "require_local_cli_trust", unexpected)

    with pytest.raises(LocalCliApiError) as raised:
        _service(store).apply(_apply_body("blocked", connector_group_request_id="req-1"))

    assert raised.value.code == "connector_group_requires_allowed"


def test_group_resolves_only_after_the_proof_bound_write(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(local_cli_api, "require_local_cli_trust", lambda *_a, **_k: order.append("proof") or object())
    monkeypatch.setattr(local_cli_api, "consume_local_cli_trust_grant", lambda *_a, **_k: order.append("consume"))
    monkeypatch.setattr(
        local_cli_api, "record_local_custom_extension_mutation", lambda *_a, **_k: order.append("write") or 1
    )

    def resolve(_store: object, **kwargs: object) -> dict[str, object]:
        order.append("group")
        assert kwargs["request_id"] == "req-1" and kwargs["identity_hash"] == _HASH
        return {"status": "resolved", "resolved_count": 2, "failed": []}

    monkeypatch.setattr(local_cli_api, "resolve_connector_group", resolve)

    result = _service(store).apply(_apply_body(connector_group_request_id="req-1"))

    assert order == ["proof", "consume", "write", "group"]
    assert result["connector_group"] == {"status": "resolved", "resolved_count": 2, "failed": []}


def test_recommended_setup_is_a_body_for_the_same_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import approval_connector_recommendation as recommendation

    item = {
        "cli_id": _CLI_ID,
        "identity_hash": _HASH,
        "surface": "cli",
        "state": "unset",
        "name": "lanectl",
        "kind": "executable",
    }
    monkeypatch.setattr(recommendation, "listed_public_items", lambda _store: [item])
    snapshot = ExtensionControlRuntimeSnapshot(
        health=AuthorityHealth.PROTECTED,
        revision=3,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        effective_digest="e" * 64,
        layers=(),
    )
    approval = {"request_id": "req-1", "status": "pending", "queue_group_id": _GROUP, "extension_allow_hint": _hint()}

    built = build_approval_connector_recommendation(
        approval, store=object(), snapshot=snapshot, approval_gate_configured=True
    )

    assert built is not None
    body = built["setup_request"]
    assert isinstance(body, dict)
    assert body["state"] == "allowed" and body["connector_group_request_id"] == "req-1"
    assert built["setup_href"] == f"{built['deep_link']}?setup=req-1&identity={_HASH}"
    # Exactly what Protect's preview/apply accepts; no proof, nonce or revision is pre-filled.
    service = LocalCliApiService.__new__(LocalCliApiService)
    identity, state = service._mutation_from_payload(dict(body))
    assert (identity.cli_id, identity.identity_hash, state) == (_CLI_ID, _HASH, "allowed")
    assert not {"previous_revision", "session_nonce", "approval_password", "proof_id"} & set(body)


def test_list_filters_to_one_bound_identity(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(store)
    monkeypatch.setattr(
        service,
        "_listed_public_items",
        lambda: [{"cli_id": _CLI_ID, "identity_hash": _HASH}, {"cli_id": "local-cli.x", "identity_hash": _OTHER_HASH}],
    )
    seeded = [{"cli_id": "local-cli.profile-x", "identity_hash": _OTHER_HASH}]
    monkeypatch.setattr(service, "_list_payload", lambda items: {"items": items, "seeded_items": list(seeded)})

    # Seeded profile rows are other connectors, so a filtered list carries none.
    assert service.list_items(identity_hash=_HASH) == {
        "items": [{"cli_id": _CLI_ID, "identity_hash": _HASH}],
        "seeded_items": [],
    }
    assert service.list_items()["seeded_items"] == seeded
    assert len(service.list_items()["items"]) == 2  # type: ignore[arg-type]


class _Handler:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.written: list[tuple[dict[str, object], int]] = []
        self.local_cli_api = self

    def _daemon_server(self) -> _Handler:
        return self

    def list_items(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return {"items": []}

    def _write_json(self, payload: dict[str, object], status: int = 200, **_kwargs: object) -> None:
        self.written.append((payload, status))


@pytest.mark.parametrize(
    "query", ["identity=nothex", f"identity={_HASH}&identity={_HASH}", f"identity={_HASH.upper()}"]
)
def test_list_rejects_a_malformed_identity(query: str) -> None:
    handler = _Handler()

    local_cli_http.handle_local_cli_list(handler, query)

    assert handler.calls == []
    assert handler.written[0][1] == 400


def test_list_passes_a_valid_identity() -> None:
    handler = _Handler()

    local_cli_http.handle_local_cli_list(handler, f"identity={_HASH}")
    local_cli_http.handle_local_cli_list(handler, "")

    assert handler.calls == [{"identity_hash": _HASH}, {}]


# Every Python call site that writes a local-CLI grant. Connector setup adds
# none: it reaches the grant only through the proof-bound local-CLI apply.
_GRANT_WRITERS = {
    "_write_local_cli_grant",
    "apply_custom_extension_continuity_mutation_locked",
    "apply_custom_extension_continuity_transaction",
    "record_local_custom_extension_mutation",
    "upsert_local_cli_grant",
}
_KNOWN_WRITE_SITES = {
    ("daemon/local_cli_api.py", "apply", "record_local_custom_extension_mutation"),
    (
        "runtime/custom_extension_continuity.py",
        "apply_verified_custom_extension_continuity",
        "apply_custom_extension_continuity_transaction",
    ),
    (
        "runtime/custom_extension_continuity.py",
        "record_local_custom_extension_mutation",
        "apply_custom_extension_continuity_transaction",
    ),
    (
        "store_custom_extension_continuity.py",
        "apply_custom_extension_continuity_transaction",
        "apply_custom_extension_continuity_mutation_locked",
    ),
    (
        "store_custom_extension_continuity.py",
        "apply_custom_extension_continuity_mutation_locked",
        "_write_local_cli_grant",
    ),
    ("store_local_cli.py", "upsert_local_cli_grant", "_write_local_cli_grant"),
    (
        "store_policy_activation_preflight.py",
        "apply_continuity_rejection",
        "apply_custom_extension_continuity_mutation_locked",
    ),
}


def _write_sites() -> set[tuple[str, str, str]]:
    sites: set[tuple[str, str, str]] = set()
    for path in sorted(_SRC.rglob("*.py")):
        relative = path.relative_to(_SRC).as_posix()
        for function in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
                if name in _GRANT_WRITERS:
                    sites.add((relative, function.name, name))
    return sites


def test_no_other_path_can_set_a_connector_allowed() -> None:
    sites = _write_sites()

    # Nested functions are walked twice above; compare against the innermost owners.
    assert {site for site in sites if site in _KNOWN_WRITE_SITES} == _KNOWN_WRITE_SITES
    assert sites <= _KNOWN_WRITE_SITES, sorted(sites - _KNOWN_WRITE_SITES)
    connector_modules = {
        "daemon/approval_connector_recommendation.py",
        "daemon/local_cli_connector_group.py",
        "daemon/local_cli_http.py",
        "runtime/connector_setup_items.py",
    }
    assert not {site for site in sites if site[0] in connector_modules}
