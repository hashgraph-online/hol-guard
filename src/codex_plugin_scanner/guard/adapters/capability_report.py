"""Versioned per-event harness capability reports.

The report is sourced only from :class:`HarnessProtectionContract` rows.  It
does not probe a host, inspect a file, or convert a synthetic canary into a
live enforcement claim.  Those observations can be supplied explicitly as
separate evidence fields and are rejected when incomplete or stale.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timezone
from html import escape as html_escape

from jsonschema import Draft202012Validator

from .contract_models import CAPABILITY_DECLARED_ACTIONS, HarnessCapabilityReport, HarnessEventCapability

CAPABILITY_REPORT_SCHEMA_VERSION = "harness-capability-report.v1"

CAPABILITY_REPORT_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://hol.org/schemas/guard/harness-capability-report.v1.schema.json",
    "title": "HOL Guard harness capability report v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "build", "commit", "requested_host", "capabilities"],
    "properties": {
        "schema_version": {"const": CAPABILITY_REPORT_SCHEMA_VERSION},
        "build": {"type": "string", "minLength": 1, "maxLength": 256},
        "commit": {"type": "string", "minLength": 1, "maxLength": 256},
        "requested_host": {"type": ["string", "null"], "maxLength": 256},
        "capabilities": {
            "type": "array",
            "minItems": 1,
            "items": {"$ref": "#/$defs/capability"},
        },
    },
    "$defs": {
        "capability": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "harness",
                "adapter",
                "host_version_scope",
                "os_arch",
                "local_hosted",
                "event",
                "transport",
                "mode",
                "declared_actions",
                "error_behavior",
                "mandatory_compatibility",
                "known_blind_spots",
                "source_reference",
                "deployment_health",
                "evidence_level",
                "observed_at",
                "expires_at",
                "evidence_reference",
                "evidence_build",
                "evidence_host_version_scope",
                "evidence_os_arch",
                "denied_witness_reference",
                "allowed_witness_reference",
                "compatibility_verified",
            ],
            "properties": {
                "harness": {"type": "string", "minLength": 1, "maxLength": 128},
                "adapter": {"type": "string", "minLength": 1, "maxLength": 128},
                "host_version_scope": {"type": "string", "minLength": 1, "maxLength": 256},
                "os_arch": {"type": "string", "minLength": 1, "maxLength": 128},
                "local_hosted": {"enum": ["local", "hosted", "unknown"]},
                "event": {"type": "string", "minLength": 1, "maxLength": 128},
                "transport": {"type": "string", "minLength": 1, "maxLength": 128},
                "mode": {"type": "string", "minLength": 1, "maxLength": 128},
                "declared_actions": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"enum": sorted(CAPABILITY_DECLARED_ACTIONS)},
                },
                "error_behavior": {"type": "string", "minLength": 1, "maxLength": 2_000},
                "mandatory_compatibility": {"type": "string", "minLength": 1, "maxLength": 2_000},
                "known_blind_spots": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 2_000},
                },
                "source_reference": {"type": "string", "minLength": 1, "maxLength": 512},
                "deployment_health": {"enum": ["unverified", "healthy", "degraded", "unavailable", "unknown"]},
                "evidence_level": {
                    "enum": [
                        "not_run",
                        "source_review",
                        "unit_test",
                        "synthetic_canary",
                        "live_block",
                        "independent_review",
                    ]
                },
                "observed_at": {"type": ["string", "null"], "maxLength": 64},
                "expires_at": {"type": ["string", "null"], "maxLength": 64},
                "evidence_reference": {"type": ["string", "null"], "maxLength": 512},
                "evidence_build": {"type": ["string", "null"], "maxLength": 256},
                "evidence_host_version_scope": {"type": ["string", "null"], "maxLength": 256},
                "evidence_os_arch": {"type": ["string", "null"], "maxLength": 128},
                "denied_witness_reference": {"type": ["string", "null"], "maxLength": 512},
                "allowed_witness_reference": {"type": ["string", "null"], "maxLength": 512},
                "compatibility_verified": {"type": "boolean"},
            },
            "allOf": [
                {
                    "if": {"properties": {"evidence_level": {"const": "not_run"}}},
                    "then": {
                        "properties": {
                            "observed_at": {"type": "null"},
                            "expires_at": {"type": "null"},
                            "evidence_reference": {"type": "null"},
                            "evidence_build": {"type": "null"},
                            "evidence_host_version_scope": {"type": "null"},
                            "evidence_os_arch": {"type": "null"},
                            "denied_witness_reference": {"type": "null"},
                            "allowed_witness_reference": {"type": "null"},
                            "compatibility_verified": {"const": False},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "evidence_level": {
                                "enum": [
                                    "source_review",
                                    "unit_test",
                                    "synthetic_canary",
                                    "live_block",
                                    "independent_review",
                                ]
                            }
                        }
                    },
                    "then": {
                        "required": ["observed_at", "expires_at", "evidence_reference"],
                        "properties": {
                            "observed_at": {"type": "string", "minLength": 1},
                            "expires_at": {"type": "string", "minLength": 1},
                            "evidence_reference": {"type": "string", "minLength": 1},
                        },
                    },
                },
            ],
        }
    },
}


def _payload(value: HarnessCapabilityReport | Mapping[str, object]) -> dict[str, object]:
    if isinstance(value, HarnessCapabilityReport):
        return value.to_dict()
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError("capability report must be a HarnessCapabilityReport or mapping")


def _parse_timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an RFC3339 timestamp")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_capability_report(
    report: HarnessCapabilityReport | Mapping[str, object],
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """Validate schema, evidence completeness, and evidence freshness.

    ``synthetic_canary`` is a valid evidence level, but remains a distinct
    value.  It is never upgraded to ``live_block`` by this validator.
    """

    payload = _payload(report)
    Draft202012Validator(CAPABILITY_REPORT_SCHEMA).validate(payload)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, list):  # pragma: no cover - schema catches this
        raise ValueError("capabilities must be a list")

    def require_live_scope(index: int, capability: Mapping[str, object]) -> None:
        actions = capability.get("declared_actions")
        if (
            not isinstance(actions, list)
            or "block" not in actions
            or capability.get("adapter") == "unsupported"
            or capability.get("transport") == "none"
            or capability.get("mode") == "unsupported"
            or capability.get("local_hosted") == "unknown"
        ):
            raise ValueError(f"capabilities[{index}] live block proof requires a declared blocking boundary")
        expected_scope = {
            "evidence_build": payload["build"],
            "evidence_host_version_scope": capability["host_version_scope"],
            "evidence_os_arch": capability["os_arch"],
        }
        for field, expected in expected_scope.items():
            if expected in {"unknown", ""}:
                raise ValueError(f"capabilities[{index}] live proof requires a known declared {field} scope")
            if capability.get(field) != expected:
                raise ValueError(f"capabilities[{index}] live proof requires exact {field} matching the declared scope")
        for field in ("denied_witness_reference", "allowed_witness_reference"):
            value = capability.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"capabilities[{index}] live proof requires {field}")

    for index, capability in enumerate(capabilities):
        if not isinstance(capability, Mapping):  # pragma: no cover - schema catches this
            continue
        evidence_level = capability.get("evidence_level")
        if evidence_level == "not_run":
            if capability.get("deployment_health") == "healthy":
                raise ValueError(f"capabilities[{index}] healthy deployment requires live_block evidence")
            if capability.get("compatibility_verified") is True:
                raise ValueError(f"capabilities[{index}] compatibility verification requires healthy live proof")
            continue
        observed_at = _parse_timestamp(capability.get("observed_at"), field=f"capabilities[{index}].observed_at")
        expires_at = _parse_timestamp(capability.get("expires_at"), field=f"capabilities[{index}].expires_at")
        if observed_at > current:
            raise ValueError(f"capabilities[{index}] evidence observation is in the future")
        if expires_at <= observed_at:
            raise ValueError(f"capabilities[{index}] evidence expiry must be after observation")
        if expires_at <= current:
            raise ValueError(f"capabilities[{index}] evidence is stale")
        if evidence_level == "live_block":
            require_live_scope(index, capability)
            if capability.get("deployment_health") == "unverified":
                raise ValueError(f"capabilities[{index}] live_block evidence cannot have unverified deployment health")
        if capability.get("deployment_health") == "healthy":
            if evidence_level != "live_block":
                raise ValueError(f"capabilities[{index}] healthy deployment requires live_block evidence")
            require_live_scope(index, capability)
            if capability.get("compatibility_verified") is not True:
                raise ValueError(f"capabilities[{index}] healthy deployment requires verified compatibility")
        if capability.get("compatibility_verified") is True and (
            evidence_level != "live_block" or capability.get("deployment_health") != "healthy"
        ):
            raise ValueError(f"capabilities[{index}] compatibility verification requires healthy live proof")
    return payload


def _bounded_host_label(host: str) -> str:
    """Normalize an unknown host label before it enters report metadata."""

    normalized = " ".join(host.strip().split())
    return (normalized or "unknown-host")[:128]


def _unsupported_capability(host: str) -> HarnessEventCapability:
    requested_input = _bounded_host_label(host)
    requested = requested_input.lower()
    return HarnessEventCapability(
        harness=requested,
        adapter="unsupported",
        host_version_scope="unknown",
        os_arch="unknown",
        local_hosted="unknown",
        event="unsupported",
        transport="none",
        mode="unsupported",
        declared_actions=("unavailable",),
        error_behavior="No adapter is registered, so Guard reports the host as unsupported and performs no hook claim.",
        mandatory_compatibility=(
            "A reviewed adapter and verified host event contract are required before support can be claimed."
        ),
        known_blind_spots=(
            f"Requested host {requested_input!r} has no registered Guard adapter or declared event surface.",
        ),
        source_reference="src/codex_plugin_scanner/guard/adapters/__init__.py:_ADAPTER_SPECS",
    )


def _apply_scope(
    capabilities: Sequence[HarnessEventCapability],
    *,
    host_version_scope: str | None,
    os_arch: str | None,
    local_hosted: str | None,
) -> tuple[HarnessEventCapability, ...]:
    rows: list[HarnessEventCapability] = []
    for capability in capabilities:
        rows.append(
            replace(
                capability,
                host_version_scope=host_version_scope or capability.host_version_scope,
                os_arch=os_arch or capability.os_arch,
                local_hosted=local_hosted or capability.local_hosted,  # type: ignore[arg-type]
            )
        )
    return tuple(rows)


def build_capability_report(
    *,
    build_id: str = "unknown",
    commit: str = "unknown",
    requested_host: str | None = None,
    host_version_scope: str | None = None,
    os_arch: str | None = None,
    local_hosted: str | None = None,
) -> HarnessCapabilityReport:
    """Build a report from the registered contract authority.

    Passing an unknown ``requested_host`` adds one explicit unsupported row;
    it never mutates or extends the adapter registry.
    """

    if not isinstance(build_id, str) or not build_id.strip():
        raise ValueError("build_id must be a non-empty string")
    if not isinstance(commit, str) or not commit.strip():
        raise ValueError("commit must be a non-empty string")
    from .contracts import HARNESS_CONTRACTS, contract_for

    requested_label = _bounded_host_label(requested_host) if requested_host is not None else None
    if requested_label is None or requested_label.lower() in {"", "all", "*"}:
        if any(value is not None for value in (host_version_scope, os_arch, local_hosted)):
            raise ValueError("host scope overrides require one requested host")
        capabilities = tuple(capability for contract in HARNESS_CONTRACTS for capability in contract.capability_events)
        report_host = None
    else:
        contract = contract_for(requested_label.lower()) or contract_for(requested_label)
        capabilities = (_unsupported_capability(requested_label),) if contract is None else contract.capability_events
        report_host = requested_label
    scoped = _apply_scope(
        capabilities,
        host_version_scope=host_version_scope,
        os_arch=os_arch,
        local_hosted=local_hosted,
    )
    report = HarnessCapabilityReport(
        schema_version=CAPABILITY_REPORT_SCHEMA_VERSION,
        build=build_id.strip(),
        commit=commit.strip(),
        requested_host=report_host,
        capabilities=scoped,
    )
    validate_capability_report(report)
    return report


def capability_report_for(
    requested_host: str,
    *,
    build_id: str = "unknown",
    commit: str = "unknown",
    host_version_scope: str | None = None,
    os_arch: str | None = None,
    local_hosted: str | None = None,
) -> HarnessCapabilityReport:
    """Return one host report, including an explicit row for unknown hosts."""

    return build_capability_report(
        build_id=build_id,
        commit=commit,
        requested_host=requested_host,
        host_version_scope=host_version_scope,
        os_arch=os_arch,
        local_hosted=local_hosted,
    )


def render_capability_report_json(report: HarnessCapabilityReport | Mapping[str, object]) -> str:
    """Render the validated report as deterministic machine JSON."""

    payload = validate_capability_report(report)
    return f"{json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}\n"


def _markdown_cell(value: object) -> str:
    if isinstance(value, (tuple, list)):
        value = ", ".join(str(item) for item in value)
    text = html_escape(str(value), quote=True).replace("`", "&#96;")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def render_capability_report_markdown(report: HarnessCapabilityReport | Mapping[str, object]) -> str:
    """Render the same validated rows as deterministic Markdown."""

    payload = validate_capability_report(report)
    capabilities = payload["capabilities"]
    assert isinstance(capabilities, list)  # validated above
    lines = [
        "# Harness event capability report",
        "",
        f"- Schema: `{_markdown_cell(payload['schema_version'])}`",
        f"- Build: `{_markdown_cell(payload['build'])}`",
        f"- Commit: `{_markdown_cell(payload['commit'])}`",
        f"- Requested host: `{_markdown_cell(payload['requested_host'] or 'all')}`",
        "",
        (
            "Rows describe declared boundaries. `unverified` / `not_run` is the default proof state; "
            "file presence and synthetic canaries do not establish a live block."
        ),
        "",
        (
            "| Harness | Adapter | Host/version scope | OS/arch | Local/hosted | Event | Transport | Mode | "
            "Declared actions | Error behavior | Mandatory compatibility | Known blind spots | Source reference | "
            "Deployment health | Evidence level | Observed at | Expires at | Evidence reference | Evidence build | "
            "Evidence host/version scope | Evidence OS/arch | Denied witness | Allowed witness | "
            "Compatibility verified |"
        ),
    ]
    fields = (
        "harness",
        "adapter",
        "host_version_scope",
        "os_arch",
        "local_hosted",
        "event",
        "transport",
        "mode",
        "declared_actions",
        "error_behavior",
        "mandatory_compatibility",
        "known_blind_spots",
        "source_reference",
        "deployment_health",
        "evidence_level",
        "observed_at",
        "expires_at",
        "evidence_reference",
        "evidence_build",
        "evidence_host_version_scope",
        "evidence_os_arch",
        "denied_witness_reference",
        "allowed_witness_reference",
        "compatibility_verified",
    )
    lines.append("| " + " | ".join("---" for _ in fields) + " |")
    for capability in capabilities:
        if not isinstance(capability, Mapping):  # pragma: no cover - schema catches this
            continue
        lines.append("| " + " | ".join(_markdown_cell(capability.get(field, "")) for field in fields) + " |")
    return "\n".join(lines) + "\n"


# Naming aliases keep the report discoverable beside the legacy table helper.
render_harness_capability_report_json = render_capability_report_json
render_harness_capability_report_markdown = render_capability_report_markdown
harness_capability_report = build_capability_report


__all__ = [
    "CAPABILITY_REPORT_SCHEMA",
    "CAPABILITY_REPORT_SCHEMA_VERSION",
    "build_capability_report",
    "capability_report_for",
    "harness_capability_report",
    "render_capability_report_json",
    "render_capability_report_markdown",
    "render_harness_capability_report_json",
    "render_harness_capability_report_markdown",
    "validate_capability_report",
]
