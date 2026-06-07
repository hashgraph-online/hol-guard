"""Product-facing HOL Guard model contracts shared by Local and Cloud."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Literal

from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.models import DECISION_SCOPE_VALUES, GUARD_ACTION_VALUES, DecisionScope

GUARD_PRODUCT_MODEL_VERSION = "guard-product-model.v1"

Persona = Literal["vibe_coder", "solo", "team_manager", "security_lead", "agent_operator"]
ActivationStage = Literal[
    "not_installed",
    "installed_local",
    "cloud_connected",
    "team_started",
    "agents_started",
    "paid_value_ready",
]
ActionCategory = Literal["secrets", "network", "destructive", "mcp", "skill", "supply_chain", "config", "unknown"]
ActionUrgency = Literal["low", "medium", "high", "critical"]

PERSONA_VALUES: tuple[Persona, ...] = (
    "vibe_coder",
    "solo",
    "team_manager",
    "security_lead",
    "agent_operator",
)
ACTIVATION_STAGE_VALUES: tuple[ActivationStage, ...] = (
    "not_installed",
    "installed_local",
    "cloud_connected",
    "team_started",
    "agents_started",
    "paid_value_ready",
)
CANONICAL_HARNESS_VALUES = (
    "codex",
    "claude-code",
    "opencode",
    "copilot",
    "cursor",
    "gemini",
    "hermes",
    "openclaw",
)
SUPPORTED_HARNESS_VALUES = tuple(contract.harness for contract in HARNESS_CONTRACTS)
ACTION_CATEGORY_VALUES: tuple[ActionCategory, ...] = (
    "secrets",
    "network",
    "destructive",
    "mcp",
    "skill",
    "supply_chain",
    "config",
    "unknown",
)
PRODUCT_DECISION_SCOPE_VALUES: tuple[DecisionScope, ...] = DECISION_SCOPE_VALUES

SEVERITY_LABELS = {
    "info": {"label": "Info", "plain": "For awareness"},
    "low": {"label": "Low", "plain": "Safe to review later"},
    "medium": {"label": "Medium", "plain": "Worth a look"},
    "high": {"label": "High", "plain": "Act soon"},
    "critical": {"label": "Critical", "plain": "Stop and review now"},
}

MANAGER_FIELD_VALUES = ("team_members", "roles", "coverage", "incidents", "notifications", "agent_risk")
VIBE_CODER_FIELD_VALUES = ("headline", "safe_explanation", "primary_action", "learn_more")
PAID_VALUE_FIELD_VALUES = ("shared_memory", "alerts", "fleet", "agents", "incident_response", "export")

REDACTION_FORBIDDEN_FIELD_VALUES = (
    "token",
    "api_key",
    "secret",
    "password",
    "credential",
    "private_key",
    "authorization",
    "cookie",
    "session",
)
STABLE_ID_PREFIXES = {
    "action": "sha256_hex",
    "request": "uuid_hex",
    "receipt": "guard-receipt",
    "incident": "inc",
    "agent_snapshot": "snap",
}
SETTINGS_GROUP_VALUES = ("preset", "custom", "per_harness", "per_category", "per_secret_source")
EXTERNAL_INTEL_SOURCE_VALUES = ("cve", "advisory", "cisco", "openssf", "slsa", "trust_score")
BILLING_PLAN_VALUES = ("free", "pro", "team", "enterprise")
AFFILIATE_FIELD_VALUES = ("affiliate", "link", "click", "commission", "payout", "points", "compliance", "fraud")
SEO_CONTENT_TYPE_VALUES = ("warning", "harness_page", "cve_page", "lab", "shareable_report")
FUNNEL_EVENT_VALUES = ("ad_click", "landing", "signup", "install", "connect", "first_block", "upgrade")
EVENT_PRIVACY_TIERS = ("public", "internal", "redacted")
COPY_LINT_BANNED_TERMS = ("artifact", "daemon", "receipt", "attestation", "provenance", "SBOM")
BRAND_TOKEN_KEYS = ("product_name", "logo_mark", "primary_color", "accent_color", "surface_color")


@dataclass(frozen=True, slots=True)
class NextAction:
    """Plain-language action shown after Guard explains a risk."""

    label: str
    reason: str
    cta: str
    target: str
    urgency: ActionUrgency

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuntimeModel:
    """Hermes/OpenClaw hosted-runtime capability model."""

    runtime: str
    display_name: str
    inventory: bool
    docker_proof: bool
    drift: bool
    messenger_channels: tuple[str, ...]
    token_scopes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["messenger_channels"] = list(self.messenger_channels)
        payload["token_scopes"] = list(self.token_scopes)
        return payload


@dataclass(frozen=True, slots=True)
class RouteOwnership:
    """Route ownership contract for local Guard surfaces."""

    route: str
    persona: tuple[Persona, ...]
    auth_required: bool
    writes_state: bool

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["persona"] = list(self.persona)
        return payload


@dataclass(frozen=True, slots=True)
class ApiOwnership:
    """API ownership contract for local Guard daemon endpoints."""

    path: str
    method: str
    category: ActionCategory
    auth_required: bool
    writes_state: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


HERMES_OPENCLAW_RUNTIME_MODELS = {
    "hermes": RuntimeModel(
        runtime="hermes",
        display_name="Hermes",
        inventory=True,
        docker_proof=True,
        drift=True,
        messenger_channels=("telegram", "terminal", "api"),
        token_scopes=("runtime:sync", "runtime:read", "capabilities:read", "messenger:bind"),
    ),
    "openclaw": RuntimeModel(
        runtime="openclaw",
        display_name="OpenClaw",
        inventory=True,
        docker_proof=True,
        drift=True,
        messenger_channels=("terminal", "api"),
        token_scopes=("runtime:sync", "runtime:read", "capabilities:read", "messenger:bind"),
    ),
}

LOCAL_ROUTE_OWNERSHIP = (
    RouteOwnership(route="/", persona=("vibe_coder", "solo"), auth_required=False, writes_state=False),
    RouteOwnership(route="/home", persona=("vibe_coder", "solo"), auth_required=False, writes_state=False),
    RouteOwnership(
        route="/dashboard",
        persona=("vibe_coder", "solo"),
        auth_required=False,
        writes_state=False,
    ),
    RouteOwnership(route="/inbox", persona=("vibe_coder", "solo"), auth_required=True, writes_state=True),
    RouteOwnership(route="/requests", persona=("vibe_coder", "solo"), auth_required=True, writes_state=True),
    RouteOwnership(
        route="/requests/{id}",
        persona=("vibe_coder", "solo"),
        auth_required=True,
        writes_state=True,
    ),
    RouteOwnership(route="/approvals", persona=("vibe_coder", "solo"), auth_required=True, writes_state=True),
    RouteOwnership(
        route="/approvals/{id}",
        persona=("vibe_coder", "solo"),
        auth_required=True,
        writes_state=True,
    ),
    RouteOwnership(route="/fleet", persona=("solo", "team_manager"), auth_required=True, writes_state=True),
    RouteOwnership(route="/apps/{slug}", persona=("solo", "team_manager"), auth_required=True, writes_state=True),
    RouteOwnership(
        route="/evidence",
        persona=("solo", "security_lead"),
        auth_required=True,
        writes_state=True,
    ),
    RouteOwnership(route="/supply-chain", persona=("solo", "security_lead"), auth_required=True, writes_state=True),
    RouteOwnership(route="/audit", persona=("solo", "security_lead"), auth_required=True, writes_state=True),
    RouteOwnership(route="/policy", persona=("solo", "team_manager"), auth_required=True, writes_state=True),
    RouteOwnership(route="/feed-health", persona=("solo", "team_manager"), auth_required=True, writes_state=True),
    RouteOwnership(route="/settings", persona=("solo",), auth_required=True, writes_state=True),
)
LOCAL_API_OWNERSHIP = (
    ApiOwnership(path="/v1/initialize", method="POST", category="config", auth_required=False, writes_state=True),
    ApiOwnership(path="/v1/connect/state", method="GET", category="config", auth_required=False, writes_state=False),
    ApiOwnership(path="/v1/connect/requests", method="POST", category="config", auth_required=True, writes_state=False),
    ApiOwnership(
        path="/v1/connect/complete",
        method="POST",
        category="config",
        auth_required=False,
        writes_state=False,
    ),
    ApiOwnership(path="/v1/connect/result", method="POST", category="config", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/runtime", method="GET", category="config", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/harnesses", method="GET", category="config", auth_required=True, writes_state=False),
    ApiOwnership(
        path="/v1/harnesses/{harness}/install",
        method="POST",
        category="supply_chain",
        auth_required=True,
        writes_state=True,
    ),
    ApiOwnership(
        path="/v1/harnesses/{harness}/verify",
        method="POST",
        category="config",
        auth_required=True,
        writes_state=False,
    ),
    ApiOwnership(
        path="/v1/harnesses/{harness}/repair",
        method="POST",
        category="config",
        auth_required=True,
        writes_state=True,
    ),
    ApiOwnership(
        path="/v1/harnesses/{harness}/uninstall",
        method="POST",
        category="config",
        auth_required=True,
        writes_state=True,
    ),
    ApiOwnership(path="/v1/inventory", method="GET", category="config", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/requests", method="GET", category="unknown", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/requests/{id}", method="GET", category="unknown", auth_required=True, writes_state=False),
    ApiOwnership(
        path="/v1/requests/{id}/approve",
        method="POST",
        category="unknown",
        auth_required=True,
        writes_state=True,
    ),
    ApiOwnership(
        path="/v1/requests/{id}/block",
        method="POST",
        category="unknown",
        auth_required=True,
        writes_state=True,
    ),
    ApiOwnership(
        path="/v1/approvals/{id}/decision",
        method="POST",
        category="unknown",
        auth_required=True,
        writes_state=True,
    ),
    ApiOwnership(
        path="/approvals/{id}/decision",
        method="POST",
        category="unknown",
        auth_required=True,
        writes_state=True,
    ),
    ApiOwnership(path="/v1/receipts", method="GET", category="unknown", auth_required=True, writes_state=False),
    ApiOwnership(
        path="/v1/receipts/analytics",
        method="GET",
        category="unknown",
        auth_required=True,
        writes_state=False,
    ),
    ApiOwnership(path="/v1/receipts/latest", method="GET", category="unknown", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/receipts/{id}", method="GET", category="unknown", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/policy", method="GET", category="config", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/policy/decisions", method="POST", category="config", auth_required=True, writes_state=True),
    ApiOwnership(path="/v1/policy/clear", method="POST", category="config", auth_required=True, writes_state=True),
    ApiOwnership(
        path="/v1/requests/clear",
        method="POST",
        category="destructive",
        auth_required=True,
        writes_state=True,
    ),
    ApiOwnership(
        path="/v1/artifacts/{id}/diff",
        method="GET",
        category="unknown",
        auth_required=True,
        writes_state=False,
    ),
    ApiOwnership(path="/v1/evidence", method="GET", category="unknown", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/evidence", method="DELETE", category="destructive", auth_required=True, writes_state=True),
    ApiOwnership(path="/v1/evidence/export", method="GET", category="unknown", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/daemon/repair", method="POST", category="config", auth_required=True, writes_state=True),
    ApiOwnership(path="/v1/settings", method="GET", category="config", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/settings", method="POST", category="config", auth_required=True, writes_state=True),
    ApiOwnership(path="/v1/settings/export", method="GET", category="config", auth_required=True, writes_state=False),
    ApiOwnership(path="/v1/settings/import", method="POST", category="config", auth_required=True, writes_state=True),
    ApiOwnership(path="/v1/settings/reset", method="POST", category="config", auth_required=True, writes_state=True),
)

_STABLE_ID_PATTERN = re.compile(
    r"^(?:(act|inc|snap)_[0-9A-HJKMNP-TV-Z]{26}|[0-9a-f]{32}|[0-9a-f]{64}|guard-receipt-[0-9a-f]{8}-"
    r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)


def is_stable_guard_id(value: str) -> bool:
    """Return true when a value follows Guard's stable ID prefix contract."""

    return bool(_STABLE_ID_PATTERN.fullmatch(value))


def build_next_action(label: str, reason: str, cta: str, target: str, urgency: ActionUrgency) -> NextAction:
    """Build a typed next-action contract."""

    return NextAction(label=label, reason=reason, cta=cta, target=target, urgency=urgency)


def export_product_model_v1() -> dict[str, object]:
    """Export JSON-compatible model data for cross-repo parity tests."""

    return {
        "version": GUARD_PRODUCT_MODEL_VERSION,
        "personas": list(PERSONA_VALUES),
        "activation_stages": list(ACTIVATION_STAGE_VALUES),
        "guard_actions": list(GUARD_ACTION_VALUES),
        "decision_scopes": list(DECISION_SCOPE_VALUES),
        "canonical_harnesses": list(CANONICAL_HARNESS_VALUES),
        "supported_harnesses": list(SUPPORTED_HARNESS_VALUES),
        "action_categories": list(ACTION_CATEGORY_VALUES),
        "severity_labels": SEVERITY_LABELS,
        "manager_fields": list(MANAGER_FIELD_VALUES),
        "vibe_coder_fields": list(VIBE_CODER_FIELD_VALUES),
        "paid_value_fields": list(PAID_VALUE_FIELD_VALUES),
        "redaction_forbidden_fields": list(REDACTION_FORBIDDEN_FIELD_VALUES),
        "stable_id_prefixes": STABLE_ID_PREFIXES,
        "settings_groups": list(SETTINGS_GROUP_VALUES),
        "external_intel_sources": list(EXTERNAL_INTEL_SOURCE_VALUES),
        "runtime_models": {key: model.to_dict() for key, model in HERMES_OPENCLAW_RUNTIME_MODELS.items()},
        "billing_plans": list(BILLING_PLAN_VALUES),
        "affiliate_fields": list(AFFILIATE_FIELD_VALUES),
        "seo_content_types": list(SEO_CONTENT_TYPE_VALUES),
        "funnel_events": list(FUNNEL_EVENT_VALUES),
        "event_privacy_tiers": list(EVENT_PRIVACY_TIERS),
        "copy_lint_banned_terms": list(COPY_LINT_BANNED_TERMS),
        "brand_token_keys": list(BRAND_TOKEN_KEYS),
        "local_routes": [route.to_dict() for route in LOCAL_ROUTE_OWNERSHIP],
        "local_apis": [api.to_dict() for api in LOCAL_API_OWNERSHIP],
    }
