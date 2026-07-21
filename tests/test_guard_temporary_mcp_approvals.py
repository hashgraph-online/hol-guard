from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
    tool_call_risk_categories,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest, PolicyDecision
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.temporary_mcp_approvals import (
    parse_temporary_mcp_grant_selection,
    temporary_mcp_approval_payload,
    temporary_mcp_grant_selector,
)


def _artifact(*, tool_name: str, identity_suffix: str = "a", schema: object | None = None):
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("-y", f"chrome-devtools-mcp@{identity_suffix}"),
        transport="stdio",
    )
    return build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
        tool_schema=schema,
    )


def _config(tmp_path):
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        mode="prompt",
    )


def _evaluate(tmp_path, store: GuardStore, artifact, arguments):
    config = _config(tmp_path)
    return evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=build_tool_call_hash(
            artifact,
            arguments,
            workspace=config.workspace,
            config=config,
        ),
        arguments=arguments,
        claim_saved_approval=False,
    )


def _browser_request(artifact, categories: tuple[str, ...]) -> dict[str, object]:
    identity = artifact.metadata["mcp_server_identity"]
    assert isinstance(identity, dict)
    return {
        "browser_intent": {
            "intent": "browser.interact",
            "mcp_server_identity_hash": identity["identity_hash"],
            "mcp_server_name": "chrome-devtools",
            "risk_categories": list(categories),
        }
    }


def test_navigation_url_schema_is_routine_without_false_mismatch(tmp_path) -> None:
    artifact = _artifact(
        tool_name="new_page",
        schema={"type": "object", "properties": {"url": {"type": "string"}}},
    )
    arguments = {"url": "https://hol.org"}
    categories = tool_call_risk_categories(artifact, arguments)

    assert categories == ("browser_navigation", "browser_external_domain")
    assert _evaluate(tmp_path, GuardStore(tmp_path / "guard-home"), artifact, arguments).action != "review"


def test_interaction_request_exposes_bounded_grant_contract() -> None:
    artifact = _artifact(tool_name="click")
    payload = temporary_mcp_approval_payload(_browser_request(artifact, ("browser_interaction",)))

    assert payload is not None
    assert payload["allowed_targets"] == ["exact", "category", "server"]
    assert payload["allowed_durations"] == ["once", "15m", "1h", "5h"]


@pytest.mark.parametrize(
    ("categories", "eligible"),
    [
        (("browser_interaction", "secret_access"), False),
        (("browser_privileged",), False),
        (("browser_interaction",), True),
    ],
)
def test_grant_contract_fails_closed_for_hard_risk(categories, eligible) -> None:
    artifact = _artifact(tool_name="click")
    payload = temporary_mcp_approval_payload(_browser_request(artifact, categories))
    assert (payload is not None) is eligible


def test_server_grant_allows_routine_interaction_until_expiry(tmp_path) -> None:
    artifact = _artifact(tool_name="click")
    arguments = {"uid": "button-1"}
    store = GuardStore(tmp_path / "guard-home")
    identity = artifact.metadata["mcp_server_identity"]
    assert isinstance(identity, dict)
    now = datetime.now(timezone.utc)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=temporary_mcp_grant_selector(str(identity["identity_hash"])),
            source="approval-gate",
            expires_at=(now + timedelta(hours=5)).isoformat(),
        ),
        now.isoformat(),
    )

    decision = _evaluate(tmp_path, store, artifact, arguments)

    assert decision.action == "allow"
    assert decision.source == "temporary-mcp-grant"


def test_server_grant_never_covers_privileged_browser_call(tmp_path) -> None:
    routine_artifact = _artifact(tool_name="click")
    privileged_artifact = _artifact(tool_name="evaluate_script")
    identity = routine_artifact.metadata["mcp_server_identity"]
    assert isinstance(identity, dict)
    store = GuardStore(tmp_path / "guard-home")
    now = datetime.now(timezone.utc)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=temporary_mcp_grant_selector(str(identity["identity_hash"])),
            source="approval-gate",
            expires_at=(now + timedelta(hours=5)).isoformat(),
        ),
        now.isoformat(),
    )

    decision = _evaluate(tmp_path, store, privileged_artifact, {"function": "() => document.cookie"})

    assert decision.action == "review"
    assert "browser_privileged" in decision.risk_categories


def test_category_grant_does_not_cover_another_routine_category(tmp_path) -> None:
    interaction_artifact = _artifact(tool_name="click")
    navigation_artifact = _artifact(tool_name="new_page")
    identity = interaction_artifact.metadata["mcp_server_identity"]
    assert isinstance(identity, dict)
    store = GuardStore(tmp_path / "guard-home")
    now = datetime.now(timezone.utc)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=temporary_mcp_grant_selector(
                str(identity["identity_hash"]),
                "browser_interaction",
            ),
            source="approval-gate",
            expires_at=(now + timedelta(hours=1)).isoformat(),
        ),
        now.isoformat(),
    )

    decision = _evaluate(tmp_path, store, navigation_artifact, {"url": "https://hol.org"})

    assert decision.source != "temporary-mcp-grant"


def test_saved_block_takes_precedence_over_server_grant(tmp_path) -> None:
    artifact = _artifact(tool_name="click")
    arguments = {"uid": "button-1"}
    config = _config(tmp_path)
    artifact_hash = build_tool_call_hash(
        artifact,
        arguments,
        workspace=config.workspace,
        config=config,
    )
    identity = artifact.metadata["mcp_server_identity"]
    assert isinstance(identity, dict)
    store = GuardStore(tmp_path / "guard-home")
    now = datetime.now(timezone.utc)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=temporary_mcp_grant_selector(str(identity["identity_hash"])),
            source="approval-gate",
            expires_at=(now + timedelta(hours=1)).isoformat(),
        ),
        now.isoformat(),
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
            source="approval-gate",
        ),
        now.isoformat(),
    )

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=False,
    )

    assert decision.action == "block"


def test_expired_or_other_fingerprint_grant_does_not_match(tmp_path) -> None:
    artifact = _artifact(tool_name="click", identity_suffix="b")
    other = _artifact(tool_name="click", identity_suffix="a")
    identity = other.metadata["mcp_server_identity"]
    assert isinstance(identity, dict)
    store = GuardStore(tmp_path / "guard-home")
    now = datetime.now(timezone.utc)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=temporary_mcp_grant_selector(str(identity["identity_hash"])),
            source="approval-gate",
            expires_at=(now - timedelta(seconds=1)).isoformat(),
        ),
        (now - timedelta(hours=1)).isoformat(),
    )

    assert _evaluate(tmp_path, store, artifact, {"uid": "button-1"}).action == "review"


def test_duration_is_enumerated_and_server_clock_derived() -> None:
    artifact = _artifact(tool_name="click")
    request = _browser_request(artifact, ("browser_interaction",))
    selection = parse_temporary_mcp_grant_selection(
        request,
        target="category",
        duration="5h",
        now="2026-07-21T12:00:00+00:00",
    )
    assert selection.expires_at == "2026-07-21T17:00:00+00:00"

    with pytest.raises(ValueError, match="invalid_mcp_grant_duration"):
        parse_temporary_mcp_grant_selection(
            request,
            target="server",
            duration="24h",
            now="2026-07-21T12:00:00+00:00",
        )


def test_resolution_persists_integrity_protected_category_grant(tmp_path) -> None:
    artifact = _artifact(tool_name="click")
    browser_intent = _browser_request(artifact, ("browser_interaction",))["browser_intent"]
    assert isinstance(browser_intent, dict)
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="mcp-request",
            harness="codex",
            artifact_id=artifact.artifact_id,
            artifact_name=artifact.name,
            artifact_type="tool_call",
            artifact_hash="exact-hash",
            policy_action="review",
            recommended_scope="artifact",
            changed_fields=("runtime_browser_tool_call",),
            source_scope="project",
            config_path=".mcp.json",
            review_command="hol-guard approvals approve mcp-request",
            approval_url="http://127.0.0.1/approvals/mcp-request",
            browser_intent=browser_intent,
        ),
        "2026-07-21T12:00:00+00:00",
    )

    result = apply_approval_resolution(
        store=store,
        request_id="mcp-request",
        action="allow",
        scope="artifact",
        workspace=None,
        reason="temporary browser QA",
        now="2026-07-21T12:01:00+00:00",
        mcp_grant_target="category",
        mcp_grant_duration="5h",
    )

    grant = result["temporary_mcp_grant"]
    assert isinstance(grant, dict)
    assert grant["expires_at"] == "2026-07-21T17:01:00+00:00"
    identity_hash = str(browser_intent["mcp_server_identity_hash"])
    lookup = store.resolve_policy_decision_lookup(
        "codex",
        temporary_mcp_grant_selector(identity_hash, "browser_interaction"),
        now="2026-07-21T12:02:00+00:00",
        consume_one_shot=False,
    )
    decision = lookup["decision"]
    assert decision is not None
    assert decision["integrity_status"] == "valid"


def test_invalid_temporary_grant_does_not_resolve_request(tmp_path) -> None:
    artifact = _artifact(tool_name="click")
    browser_intent = _browser_request(artifact, ("browser_interaction",))["browser_intent"]
    assert isinstance(browser_intent, dict)
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="invalid-mcp-request",
            harness="codex",
            artifact_id=artifact.artifact_id,
            artifact_name=artifact.name,
            artifact_type="tool_call",
            artifact_hash="exact-hash",
            policy_action="review",
            recommended_scope="artifact",
            changed_fields=("runtime_browser_tool_call",),
            source_scope="project",
            config_path=".mcp.json",
            review_command="hol-guard approvals approve invalid-mcp-request",
            approval_url="http://127.0.0.1/approvals/invalid-mcp-request",
            browser_intent=browser_intent,
        ),
        "2026-07-21T12:00:00+00:00",
    )

    with pytest.raises(ValueError, match="invalid_mcp_grant_duration"):
        apply_approval_resolution(
            store=store,
            request_id="invalid-mcp-request",
            action="allow",
            scope="artifact",
            workspace=None,
            reason=None,
            now="2026-07-21T12:01:00+00:00",
            mcp_grant_target="server",
            mcp_grant_duration="24h",
        )

    stored_request = store.get_approval_request("invalid-mcp-request")
    assert stored_request is not None
    assert stored_request["status"] == "pending"
