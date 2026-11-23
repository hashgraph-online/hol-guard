"""Report-only bridge from scanned plugin surfaces to Guard coverage claims.

The bridge reads the checked-in Guard harness contract. It never probes a host,
installs Guard, or makes a network request. A claim in this report describes the
declared coverage contract only. It does not prove that Guard is installed or
that a live harness honored a decision.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any, cast

from .models import PackageSummary, ScanResult

GUARD_COVERAGE_BRIDGE_SCHEMA = "guard-coverage-bridge.v1"
GUARD_CLAIMS_URL = "https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/harness-claims.md"
GUARD_INSTALL_URL = "https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/get-started.md"

_ECOSYSTEM_HARNESSES = {
    "codex": "codex",
    "claude": "claude-code",
    "gemini": "gemini",
    "opencode": "opencode",
    "kimi": "kimi",
}

_COMPONENT_SURFACES = {
    "agents": "prompt",
    "commands": "prompt",
    "context_files": "prompt",
    "instructions": "prompt",
    "prompts": "prompt",
    "skills": "prompt",
    "system_prompt": "prompt",
    "bundle_patches": "shell",
    "clients": "shell",
    "plugin_modules": "shell",
    "hooks": "tool_result",
    "mcp_files": "mcp_tool",
    "mcp_servers": "mcp_tool",
}

_SURFACE_EVENT_NAMES = {
    "prompt": ("prompt", "userpromptsubmit"),
    "shell": ("shell", "bash", "terminal", "pretooluse", "beforeshellexecution"),
    "mcp_tool": ("mcp", "pretooluse", "beforemcpexecution", "aftermcpexecution"),
    "file_read": ("read", "pretooluse", "beforereadfile"),
    "file_write": ("write", "edit", "patch", "pretooluse"),
    "tool_result": ("posttooluse", "after"),
}

_DISPLAY_NAMES = {
    "claude-code": "Claude Code",
    "codex": "Codex",
    "gemini": "Gemini CLI",
    "kimi": "Kimi Code",
    "opencode": "OpenCode",
}


@lru_cache(maxsize=1)
def _harness_contracts() -> dict[str, dict[str, Any]]:
    """Load the local contract without invoking the native runtime."""

    try:
        contract_path = files("codex_plugin_scanner.guard.contracts").joinpath("harness-protection-contracts.v1.json")
        payload = json.loads(contract_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, TypeError, json.JSONDecodeError):
        return {}
    contracts = payload.get("contracts") if isinstance(payload, dict) else None
    if not isinstance(contracts, list):
        return {}
    return {
        str(contract["harness"]): contract
        for contract in contracts
        if isinstance(contract, dict) and isinstance(contract.get("harness"), str)
    }


def _detected_surfaces_by_ecosystem(packages: tuple[PackageSummary, ...]) -> dict[str, tuple[str, ...]]:
    surfaces_by_ecosystem: dict[str, set[str]] = {}
    for package in packages:
        surfaces = surfaces_by_ecosystem.setdefault(package.ecosystem, set())
        surfaces.update(
            _COMPONENT_SURFACES[component] for component in package.components if component in _COMPONENT_SURFACES
        )
    return {ecosystem: tuple(sorted(surfaces)) for ecosystem, surfaces in surfaces_by_ecosystem.items()}


def _event_matches_surface(event: dict[str, Any], surface: str) -> bool:
    event_name = str(event.get("event", "")).lower()
    tools = tuple(str(tool).lower() for tool in event.get("tools", ()) if isinstance(tool, str))
    tokens = _SURFACE_EVENT_NAMES[surface]
    if any(token in event_name for token in tokens if token != "pretooluse"):
        return True
    if any(any(token in tool for token in tokens) for tool in tools):
        return True
    return event_name == "pretooluse" and not tools and "pretooluse" in tokens


def _claim_rows(contract: dict[str, Any], surface: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in contract.get("capability_events", ()):
        if not isinstance(event, dict) or not _event_matches_surface(event, surface):
            continue
        claim = event.get("claim")
        state = claim.get("state") if isinstance(claim, dict) else None
        rows.append(
            {
                "event": str(event.get("event", "unknown")),
                "mode": str(event.get("mode", "unknown")),
                "state": str(state or "unknown"),
                "actions": sorted(
                    str(action) for action in event.get("declared_actions", ()) if isinstance(action, str)
                ),
            }
        )
    unique: dict[tuple[str, str, str, tuple[str, ...]], dict[str, Any]] = {}
    for row in rows:
        key = (row["event"], row["mode"], row["state"], tuple(row["actions"]))
        unique[key] = row
    return list(unique.values())


def _status(rows: list[dict[str, Any]]) -> str:
    states = {row["state"] for row in rows}
    if "configured" in states:
        return "configured"
    if "observe_only" in states:
        return "observe_only"
    if "unsupported" in states:
        return "unsupported"
    return "unknown"


def build_guard_coverage_bridge(result: ScanResult) -> dict[str, object] | None:
    """Build contextual Guard coverage data for a scan, when relevant."""

    surfaces_by_ecosystem = _detected_surfaces_by_ecosystem(result.packages)
    if not any(surfaces_by_ecosystem.values()):
        return None

    harnesses: list[dict[str, object]] = []
    contracts = _harness_contracts()
    for ecosystem in result.ecosystems:
        harness = _ECOSYSTEM_HARNESSES.get(ecosystem)
        if harness is None or harness not in contracts:
            continue
        contract = contracts[harness]
        surfaces = surfaces_by_ecosystem.get(ecosystem, ())
        contract_surfaces = {str(surface) for surface in contract.get("event_surfaces", ())}
        coverage: list[dict[str, object]] = []
        for surface in surfaces:
            if surface not in contract_surfaces:
                continue
            claims = _claim_rows(contract, surface)
            coverage.append(
                {
                    "surface": surface,
                    "status": _status(claims) if claims else "unknown",
                    "claims": claims,
                }
            )
        if not coverage:
            continue
        harnesses.append(
            {
                "harness": harness,
                "displayName": _DISPLAY_NAMES.get(harness, harness),
                "coverage": coverage,
                "coverageUrl": GUARD_CLAIMS_URL,
                "installUrl": GUARD_INSTALL_URL,
            }
        )

    if not harnesses:
        return None
    detected_surfaces = sorted({surface for values in surfaces_by_ecosystem.values() for surface in values})
    return {
        "schemaVersion": GUARD_COVERAGE_BRIDGE_SCHEMA,
        "detectedSurfaces": detected_surfaces,
        "harnesses": harnesses,
        "boundary": (
            "This is a static mapping from scanned package surfaces to Guard's declared coverage. "
            "It does not prove that Guard is installed, that the host version is supported, or that a live "
            "action was blocked."
        ),
        "coverageUrl": GUARD_CLAIMS_URL,
        "installUrl": GUARD_INSTALL_URL,
    }


def guard_coverage_markdown_lines(bridge: dict[str, object]) -> list[str]:
    """Render the bridge for Markdown and the GitHub Actions summary."""

    detected_surfaces = cast(list[str], bridge["detectedSurfaces"])
    harnesses = cast(list[dict[str, Any]], bridge["harnesses"])
    lines = [
        "## Guard coverage context",
        "",
        f"Detected runtime surfaces: **{', '.join(detected_surfaces)}**",
        "",
        str(bridge["boundary"]),
        "",
    ]
    for harness in harnesses:
        lines.append(f"- **{harness['displayName']}**")
        for coverage in harness["coverage"]:
            claims = coverage["claims"]
            claim_text = (
                "; ".join(
                    f"{claim['event']} ({claim['mode']}; {', '.join(claim['actions']) or 'no actions listed'})"
                    for claim in claims
                )
                or "no matching event claim"
            )
            lines.append(f"  - `{coverage['surface']}`: **{coverage['status']}** via {claim_text}")
        lines.append(f"  - [View the Guard coverage matrix]({harness['coverageUrl']})")
        lines.append(f"  - [Install Guard locally]({harness['installUrl']})")
    return lines


def guard_coverage_text_lines(bridge: dict[str, object]) -> list[str]:
    """Render the bridge for the plain-text CLI report."""

    detected_surfaces = cast(list[str], bridge["detectedSurfaces"])
    harnesses = cast(list[dict[str, Any]], bridge["harnesses"])
    lines = [
        "Guard coverage context:",
        f"  Detected runtime surfaces: {', '.join(detected_surfaces)}",
        f"  {bridge['boundary']}",
    ]
    for harness in harnesses:
        for coverage in harness["coverage"]:
            claim_text = (
                "; ".join(
                    f"{claim['event']} ({claim['mode']}; {', '.join(claim['actions']) or 'no actions listed'})"
                    for claim in coverage["claims"]
                )
                or "no matching event claim"
            )
            lines.append(f"  - {harness['displayName']} / {coverage['surface']}: {coverage['status']} via {claim_text}")
    lines.extend(
        [
            f"  Coverage matrix: {bridge['coverageUrl']}",
            f"  Install Guard locally: {bridge['installUrl']}",
            "",
        ]
    )
    return lines


__all__ = [
    "GUARD_CLAIMS_URL",
    "GUARD_COVERAGE_BRIDGE_SCHEMA",
    "GUARD_INSTALL_URL",
    "build_guard_coverage_bridge",
    "guard_coverage_markdown_lines",
    "guard_coverage_text_lines",
]
