"""Guard CLI payload builders for read-only isolation introspection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IsolationStatusSnapshot:
    """Privacy-safe status record for a single isolation backend."""

    backend: str
    backend_available: bool
    health_state: str
    enforced_guarantees: tuple[str, ...] = ()
    absent_guarantees: tuple[str, ...] = ()
    trust: str = "unverified"


_HEALTH_OK_STATES = frozenset({"healthy", "ok", "passing"})


def _health_is_ok(health: str) -> bool:
    return health in _HEALTH_OK_STATES


def isolation_status_payload(
    *,
    snapshot: IsolationStatusSnapshot | None = None,
) -> dict[str, object]:
    """Return a privacy-safe status summary of the local isolation layer."""

    if snapshot is None:
        backend = "none"
        available = False
        health = "unconfigured"
        enforced: list[str] = []
        absent: list[str] = []
        trust = "unverified"
    else:
        backend = snapshot.backend
        available = snapshot.backend_available
        health = snapshot.health_state
        enforced = list(snapshot.enforced_guarantees)
        absent = list(snapshot.absent_guarantees)
        trust = snapshot.trust

    return _strip_sensitive_keys(
        {
            "command": "isolation.status",
            "status": "ok" if available and _health_is_ok(health) else "degraded",
            "provider": backend,
            "backend_available": available,
            "health_state": health,
            "enforced_guarantees": enforced,
            "absent_guarantees": absent,
            "trust": trust,
        }
    )


def providers_payload(
    *,
    snapshots: list[IsolationStatusSnapshot] | None = None,
) -> dict[str, object]:
    """Return a privacy-safe inventory of registered isolation providers."""

    providers = [
        {
            "id": snapshot.backend,
            "provider": snapshot.backend,
            "available": snapshot.backend_available,
            "health_state": snapshot.health_state,
            "enforced_guarantees": list(snapshot.enforced_guarantees),
            "absent_guarantees": list(snapshot.absent_guarantees),
            "trust": snapshot.trust,
        }
        for snapshot in snapshots or []
    ]
    return _strip_sensitive_keys(
        {
            "command": "isolation.providers",
            "provider_count": len(providers),
            "providers": providers,
        }
    )


_EXPLANATION_MAP: Mapping[str, dict[str, str]] = {
    "sandbox": {
        "kind": "sandbox",
        "label": "Process sandbox isolation",
        "description": (
            "Ensures the harness runs inside a confined execution environment "
            "that prevents filesystem and network escalation beyond permitted boundaries."
        ),
        "evidence": "Guard hooks record entry and exit from the sandbox boundary.",
    },
    "contained": {
        "kind": "contained",
        "label": "Contained write enforcement",
        "description": (
            "Guarantees that supported file-system writes run inside the bounded containment provider "
            "and remain confined to project-approved directories."
        ),
        "evidence": "Guard records the containment result for each supported write operation.",
    },
    "network": {
        "kind": "network",
        "label": "Network protection availability",
        "description": (
            "Reports whether this installation has a verified, active network provider. "
            "Policy models, static profiles, and reference implementations do not restrict traffic by themselves."
        ),
        "evidence": (
            "Only a live installed-provider probe, active policy generation, and independent observation "
            "can establish an achieved network grade."
        ),
    },
    "mcp": {
        "kind": "mcp",
        "label": "MCP proxy isolation",
        "description": (
            "Makes supported MCP server communication flow through the Guard MCP proxy so policy can be "
            "evaluated for each mediated request."
        ),
        "evidence": "MCP session metadata is captured only for communication that traverses the proxy.",
    },
    "sandbox-required": {
        "kind": "sandbox-required",
        "label": "Mandatory sandbox",
        "description": (
            "This action requires sandbox execution. Guard refuses to launch the supported action when the "
            "required sandbox provider is unavailable."
        ),
        "evidence": "Policy decision records carry the sandbox-required action literal.",
    },
}


def explain_isolation_payload(target: str | None = None) -> dict[str, object]:
    """Return static descriptions without implying live provider state."""

    if target is not None and target.strip():
        kind = target.strip()
        if kind in _EXPLANATION_MAP:
            explanations: dict[str, object] = {kind: dict(_EXPLANATION_MAP[kind])}
        else:
            explanations = {
                kind: {
                    "kind": kind,
                    "label": kind,
                    "description": "Unknown guarantee kind.",
                }
            }
    else:
        explanations = {kind: dict(info) for kind, info in _EXPLANATION_MAP.items()}

    return _strip_sensitive_keys(
        {
            "command": "isolation.explain",
            "mode": "description",
            "explanations": explanations,
        }
    )


def verify_isolation_payload(
    *,
    snapshot: IsolationStatusSnapshot | None = None,
) -> dict[str, object]:
    """Return a deterministic status dict verifying isolation health."""

    if snapshot is None:
        health = "unconfigured"
        available = False
        enforced: list[str] = []
        absent: list[str] = []
    else:
        health = snapshot.health_state
        available = snapshot.backend_available
        enforced = list(snapshot.enforced_guarantees)
        absent = list(snapshot.absent_guarantees)

    warnings: list[str] = []
    if not available:
        warnings.append("No isolation backend is available.")
    if not _health_is_ok(health):
        warnings.append(f"Backend health is '{health}' (expected healthy).")
    if absent:
        warnings.append(f"Absent guarantees: {', '.join(absent)}.")

    verified = available and _health_is_ok(health) and not absent
    return _strip_sensitive_keys(
        {
            "command": "isolation.verify",
            "verified": verified,
            "health": health,
            "available": available,
            "enforced_guarantees": enforced,
            "absent_guarantees": absent,
            "warnings": warnings,
        }
    )


def _strip_sensitive_keys(payload: dict[str, object]) -> dict[str, object]:
    sensitive = frozenset(
        {
            "path",
            "file_path",
            "command_content",
            "secrets",
            "password",
            "token",
            "key",
            "credential",
            "secret",
        }
    )
    return {key: value for key, value in payload.items() if not any(fragment in key.lower() for fragment in sensitive)}


__all__ = [
    "IsolationStatusSnapshot",
    "explain_isolation_payload",
    "isolation_status_payload",
    "providers_payload",
    "verify_isolation_payload",
]
