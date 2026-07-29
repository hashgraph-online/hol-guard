"""Guard CLI payload builders for read-only isolation introspection.

Pure data-plane functions returning stable ``dict[str, object]`` payloads
suitable for JSON serialisation and consumption by the render pipeline.

These builders work exclusively from a frozen/slots snapshot dataclass so they
stay offline and independent of provider runtime availability.
"""

# fmt: off
# ruff: noqa: I001

from __future__ import annotations

from dataclasses import dataclass

from collections.abc import Mapping


# ---------------------------------------------------------------------------
# Frozen snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IsolationStatusSnapshot:
    """Immutable status record for a single isolation backend.

    Privacy-safe: never carries absolute paths, secrets, or command content.
    """

    backend: str
    backend_available: bool
    health_state: str
    enforced_guarantees: tuple[str, ...] = ()
    absent_guarantees: tuple[str, ...] = ()
    trust: str = "unverified"


# ---------------------------------------------------------------------------
# 1. isolation_status_payload
# ---------------------------------------------------------------------------


_HEALTH_OK_STATES = ("healthy", "ok", "passing")


def _health_is_ok(health: str) -> bool:
    """Return whether a health state counts as healthy across status and verify."""

    return health in _HEALTH_OK_STATES


def isolation_status_payload(
    *,
    snapshot: IsolationStatusSnapshot | None = None,
) -> dict[str, object]:
    """Return a privacy-safe status summary of the local isolation layer.

    Parameters
    ----------
    snapshot:
        A frozen ``IsolationStatusSnapshot``.  When ``None`` a
        fully-offline default is returned.
    """
    if snapshot is not None:
        backend = snapshot.backend
        available = snapshot.backend_available
        health = snapshot.health_state
        enforced = list(snapshot.enforced_guarantees)
        absent = list(snapshot.absent_guarantees)
        trust = snapshot.trust
    else:
        backend = "none"
        available = False
        health = "unconfigured"
        enforced: list[str] = []
        absent: list[str] = []
        trust = "unverified"

    payload: dict[str, object] = {
        "command": "isolation.status",
        "status": "ok" if available and _health_is_ok(health) else "degraded",
        "provider": backend,
        "backend_available": available,
        "health_state": health,
        "enforced_guarantees": enforced,
        "absent_guarantees": absent,
        "trust": trust,
    }
    return _strip_sensitive_keys(payload)


# ---------------------------------------------------------------------------
# 2. providers_payload
# ---------------------------------------------------------------------------


def providers_payload(
    *,
    snapshots: list[IsolationStatusSnapshot] | None = None,
) -> dict[str, object]:
    """Return a privacy-safe inventory of registered isolation providers.

    Parameters
    ----------
    snapshots:
        A list of ``IsolationStatusSnapshot`` instances.
    """
    providers: list[dict[str, object]] = []
    if snapshots is not None:
        for snap in snapshots:
            providers.append(
                {
                    "id": snap.backend,
                    "provider": snap.backend,
                    "available": snap.backend_available,
                    "health_state": snap.health_state,
                    "enforced_guarantees": list(snap.enforced_guarantees),
                    "absent_guarantees": list(snap.absent_guarantees),
                    "trust": snap.trust,
                }
            )

    payload: dict[str, object] = {
        "command": "isolation.providers",
        "provider_count": len(providers),
        "providers": providers,
    }
    return _strip_sensitive_keys(payload)


# ---------------------------------------------------------------------------
# 3. explain_isolation_payload
# ---------------------------------------------------------------------------

_EXPLANATION_MAP: Mapping[str, dict[str, str]] = {
    "sandbox": {
        "kind": "sandbox",
        "label": "Process sandbox isolation",
        "description": (
            "Ensures the harness runs inside a confined execution environment "
            "that prevents filesystem and network escalation beyond permitted boundaries."
        ),
        "evidence": "Guard hooks record entry/exit from the sandbox boundary.",
    },
    "contained": {
        "kind": "contained",
        "label": "Contained write enforcement",
        "description": (
            "Guarantees that any file-system writes performed by the harness "
            "are confined to project-approved directories and captured in the "
            "write audit log."
        ),
        "evidence": "Guard records the write-claim envelope for every file operation.",
    },
    "network": {
        "kind": "network",
        "label": "Network access control",
        "description": (
            "Restricts outbound network connections to approved endpoints. "
            "Unlisted destinations are silently dropped and logged."
        ),
        "evidence": "Outbound connection attempts are recorded in the security audit trail.",
    },
    "mcp": {
        "kind": "mcp",
        "label": "MCP proxy isolation",
        "description": (
            "Makes MCP server communication flow through the Guard MCP proxy, "
            "enabling tool-call inspection and policy enforcement on each request."
        ),
        "evidence": "MCP session metadata is captured in the command activity store.",
    },
    "sandbox-required": {
        "kind": "sandbox-required",
        "label": "Mandatory sandbox",
        "description": (
            "This action requires sandbox execution. Guard will refuse to "
            "launch the harness outside the sandbox unless the sandbox provider "
            "is unavailable, in which case the action is blocked."
        ),
        "evidence": "Policy decision records carry the 'sandbox-required' action literal.",
    },
}


def explain_isolation_payload(
    target: str | None = None,
) -> dict[str, object]:
    """Return a pure description map keyed by guarantee kind.

    This function does **not** execute anything — no processes, no daemon
    queries, no live state access.  Static reference for the ``explain``
    renderer.

    Parameters
    ----------
    target:
        When non-empty, return the explanation for exactly that kind.
        Otherwise return the full map.
    """
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

    payload: dict[str, object] = {
        "command": "isolation.explain",
        "mode": "description",
        "explanations": explanations,
    }
    return _strip_sensitive_keys(payload)


# ---------------------------------------------------------------------------
# 4. verify_isolation_payload
# ---------------------------------------------------------------------------


def verify_isolation_payload(
    *,
    snapshot: IsolationStatusSnapshot | None = None,
) -> dict[str, object]:
    """Return a deterministic status dict verifying isolation health.

    Parameters
    ----------
    snapshot:
        A frozen ``IsolationStatusSnapshot``.  When ``None`` a fully-offline
        status is returned.
    """
    if snapshot is not None:
        health = snapshot.health_state
        available = snapshot.backend_available
        enforced = list(snapshot.enforced_guarantees)
        absent = list(snapshot.absent_guarantees)
    else:
        health = "unconfigured"
        available = False
        enforced: list[str] = []
        absent: list[str] = []

    warnings: list[str] = []
    if not available:
        warnings.append("No isolation backend is available.")
    if not _health_is_ok(health):
        warnings.append(f"Backend health is '{health}' (expected healthy).")
    if absent:
        warnings.append(f"Absent guarantees: {', '.join(absent)}.")

    verified = available and _health_is_ok(health) and not absent

    payload: dict[str, object] = {
        "command": "isolation.verify",
        "verified": verified,
        "health": health,
        "available": available,
        "enforced_guarantees": enforced,
        "absent_guarantees": absent,
        "warnings": warnings,
    }
    return _strip_sensitive_keys(payload)


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------


def _strip_sensitive_keys(payload: dict[str, object]) -> dict[str, object]:
    _sensitive = frozenset(
        (
            "path",
            "file_path",
            "command_content",
            "secrets",
            "password",
            "token",
            "key",
            "credential",
            "secret",
        )
    )
    return {
        k: v
        for k, v in payload.items()
        if not any(tok in k.lower() for tok in _sensitive)
    }


__all__ = [
    "IsolationStatusSnapshot",
    "explain_isolation_payload",
    "isolation_status_payload",
    "providers_payload",
    "verify_isolation_payload",
]
