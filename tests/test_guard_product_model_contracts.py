"""Phase 02 product-model contracts for HOL Guard Local."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.models import DECISION_SCOPE_VALUES, GUARD_ACTION_VALUES
from codex_plugin_scanner.guard.product_model import (
    ACTION_CATEGORY_VALUES,
    ACTIVATION_STAGE_VALUES,
    AFFILIATE_FIELD_VALUES,
    BILLING_PLAN_VALUES,
    BRAND_TOKEN_KEYS,
    CANONICAL_HARNESS_VALUES,
    COPY_LINT_BANNED_TERMS,
    EVENT_PRIVACY_TIERS,
    EXTERNAL_INTEL_SOURCE_VALUES,
    FUNNEL_EVENT_VALUES,
    GUARD_PRODUCT_MODEL_VERSION,
    HERMES_OPENCLAW_RUNTIME_MODELS,
    LOCAL_API_OWNERSHIP,
    LOCAL_ROUTE_OWNERSHIP,
    MANAGER_FIELD_VALUES,
    PERSONA_VALUES,
    PRODUCT_DECISION_SCOPE_VALUES,
    REDACTION_FORBIDDEN_FIELD_VALUES,
    SEO_CONTENT_TYPE_VALUES,
    SETTINGS_GROUP_VALUES,
    SEVERITY_LABELS,
    STABLE_ID_PREFIXES,
    VIBE_CODER_FIELD_VALUES,
    build_next_action,
    export_product_model_v1,
    is_stable_guard_id,
)


def test_product_model_reuses_existing_guard_action_and_scope_contracts() -> None:
    exported = export_product_model_v1()

    assert tuple(exported["guard_actions"]) == GUARD_ACTION_VALUES
    assert tuple(exported["decision_scopes"]) == DECISION_SCOPE_VALUES
    assert PRODUCT_DECISION_SCOPE_VALUES == DECISION_SCOPE_VALUES


def test_personas_and_activation_stages_cover_local_cloud_users() -> None:
    assert PERSONA_VALUES == (
        "vibe_coder",
        "solo",
        "team_manager",
        "security_lead",
        "agent_operator",
    )
    assert ACTIVATION_STAGE_VALUES == (
        "not_installed",
        "installed_local",
        "cloud_connected",
        "team_started",
        "agents_started",
        "paid_value_ready",
    )


def test_canonical_harnesses_match_launch_harnesses_and_existing_contracts() -> None:
    contract_harnesses = {contract.harness for contract in HARNESS_CONTRACTS}

    assert CANONICAL_HARNESS_VALUES == (
        "codex",
        "claude-code",
        "opencode",
        "copilot",
        "cursor",
        "gemini",
        "hermes",
        "openclaw",
        "pi",
    )
    assert set(CANONICAL_HARNESS_VALUES).issubset(contract_harnesses)


def test_shared_action_categories_and_plain_labels_are_complete() -> None:
    assert ACTION_CATEGORY_VALUES == (
        "secrets",
        "network",
        "destructive",
        "mcp",
        "skill",
        "supply_chain",
        "config",
        "unknown",
    )
    assert set(SEVERITY_LABELS) == {"info", "low", "medium", "high", "critical"}
    assert SEVERITY_LABELS["critical"]["plain"] == "Stop and review now"


def test_next_action_contract_has_required_user_facing_fields() -> None:
    action = build_next_action(
        label="Review stopped command",
        reason="Command can send local secrets to an unknown host.",
        cta="Open review queue",
        target="/evidence?category=network",
        urgency="high",
    )

    assert action.to_dict() == {
        "label": "Review stopped command",
        "reason": "Command can send local secrets to an unknown host.",
        "cta": "Open review queue",
        "target": "/evidence?category=network",
        "urgency": "high",
    }


def test_persona_value_fields_are_explicit() -> None:
    assert MANAGER_FIELD_VALUES == ("team_members", "roles", "coverage", "incidents", "notifications", "agent_risk")
    assert VIBE_CODER_FIELD_VALUES == ("headline", "safe_explanation", "primary_action", "learn_more")
    assert "shared_memory" in export_product_model_v1()["paid_value_fields"]


def test_redaction_stable_ids_and_settings_contracts_are_shared() -> None:
    assert {"token", "api_key", "secret", "password", "credential", "private_key", "authorization"}.issubset(
        REDACTION_FORBIDDEN_FIELD_VALUES
    )
    assert STABLE_ID_PREFIXES == {
        "action": "sha256_hex",
        "request": "uuid_hex",
        "receipt": "guard-receipt",
        "incident": "inc",
        "agent_snapshot": "snap",
    }
    assert is_stable_guard_id("act_01HX8K7G6Y8M9N0P2Q3R4S5T6V")
    assert is_stable_guard_id("a" * 64)
    assert is_stable_guard_id("4b2f0a3e8c164a4fb4a1d4b8f2b6c9aa")
    assert is_stable_guard_id("guard-receipt-123e4567-e89b-12d3-a456-426614174000")
    assert not is_stable_guard_id("act")
    assert SETTINGS_GROUP_VALUES == (
        "preset",
        "custom",
        "per_harness",
        "per_category",
        "per_secret_source",
    )


def test_external_models_cover_agents_billing_affiliate_seo_funnel_and_privacy() -> None:
    assert EXTERNAL_INTEL_SOURCE_VALUES == ("cve", "advisory", "cisco", "openssf", "slsa", "trust_score")
    assert set(HERMES_OPENCLAW_RUNTIME_MODELS) == {"hermes", "openclaw"}
    for model in HERMES_OPENCLAW_RUNTIME_MODELS.values():
        assert model.token_scopes == ("runtime:sync", "runtime:read", "capabilities:read", "messenger:bind")
    assert BILLING_PLAN_VALUES == ("free", "pro", "team", "enterprise")
    assert AFFILIATE_FIELD_VALUES == (
        "affiliate",
        "link",
        "click",
        "commission",
        "payout",
        "points",
        "compliance",
        "fraud",
    )
    assert SEO_CONTENT_TYPE_VALUES == ("warning", "harness_page", "cve_page", "lab", "shareable_report")
    assert "first_block" in FUNNEL_EVENT_VALUES
    assert EVENT_PRIVACY_TIERS == ("public", "internal", "redacted")


def test_copy_lint_and_brand_contracts_are_explicit() -> None:
    assert "artifact" in COPY_LINT_BANNED_TERMS
    assert BRAND_TOKEN_KEYS == (
        "product_name",
        "logo_mark",
        "primary_color",
        "accent_color",
        "surface_color",
    )


def test_local_route_and_api_ownership_contracts_are_explicit() -> None:
    routes = {route.route: route for route in LOCAL_ROUTE_OWNERSHIP}

    assert routes["/"].auth_required is False
    assert routes["/home"].auth_required is False
    assert routes["/dashboard"].auth_required is False
    assert routes["/inbox"].writes_state is True
    assert routes["/requests"].writes_state is True
    assert routes["/requests/{id}"].writes_state is True
    assert routes["/approvals"].writes_state is True
    assert routes["/approvals/{id}"].writes_state is True
    assert routes["/protect"].writes_state is True
    assert routes["/apps/{slug}"].writes_state is True
    assert routes["/evidence"].writes_state is True
    assert routes["/supply-chain"].writes_state is True
    assert routes["/audit"].writes_state is True
    assert routes["/policy"].writes_state is True
    assert routes["/feed-health"].writes_state is True
    for route in routes:
        assert _GuardDaemonHandler._is_dashboard_route(route)
    apis_by_method = {(api.method, api.path): api for api in LOCAL_API_OWNERSHIP}
    assert apis_by_method[("POST", "/v1/initialize")].auth_required is False
    assert apis_by_method[("GET", "/v1/connect/state")].writes_state is False
    assert apis_by_method[("POST", "/v1/connect/requests")].auth_required is True
    assert apis_by_method[("POST", "/v1/connect/requests")].writes_state is False
    assert apis_by_method[("POST", "/v1/connect/complete")].auth_required is False
    assert apis_by_method[("POST", "/v1/connect/complete")].writes_state is False
    assert apis_by_method[("POST", "/v1/connect/result")].writes_state is False
    assert apis_by_method[("GET", "/v1/runtime")].writes_state is False
    assert apis_by_method[("GET", "/v1/harnesses")].writes_state is False
    assert apis_by_method[("POST", "/v1/harnesses/{harness}/install")].writes_state is True
    assert apis_by_method[("POST", "/v1/harnesses/{harness}/verify")].writes_state is False
    assert apis_by_method[("POST", "/v1/harnesses/{harness}/repair")].writes_state is True
    assert apis_by_method[("POST", "/v1/harnesses/{harness}/uninstall")].writes_state is True
    assert apis_by_method[("GET", "/v1/inventory")].writes_state is False
    assert apis_by_method[("GET", "/v1/requests/{id}")].writes_state is False
    assert apis_by_method[("POST", "/v1/requests/{id}/approve")].writes_state is True
    assert apis_by_method[("POST", "/v1/approvals/{id}/decision")].writes_state is True
    assert apis_by_method[("POST", "/approvals/{id}/decision")].writes_state is True
    assert apis_by_method[("GET", "/v1/receipts")].writes_state is False
    assert apis_by_method[("GET", "/v1/policy")].category == "config"
    assert apis_by_method[("POST", "/v1/policy/decisions")].writes_state is True
    assert apis_by_method[("POST", "/v1/policy/clear")].writes_state is True
    assert apis_by_method[("GET", "/v1/artifacts/{id}/diff")].writes_state is False
    assert apis_by_method[("DELETE", "/v1/evidence")].category == "destructive"
    assert apis_by_method[("POST", "/v1/daemon/repair")].writes_state is True
    assert apis_by_method[("GET", "/v1/evidence/export")].auth_required is True
    assert apis_by_method[("GET", "/v1/settings")].writes_state is False
    assert apis_by_method[("POST", "/v1/settings")].category == "config"


def test_exported_json_fixture_matches_runtime_contract() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "codex_plugin_scanner"
        / "guard"
        / "schemas"
        / "guard_product_model_v1.json"
    )

    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert fixture["version"] == GUARD_PRODUCT_MODEL_VERSION
    assert fixture == export_product_model_v1()
