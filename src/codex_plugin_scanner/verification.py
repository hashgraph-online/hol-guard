"""Runtime verification engine for plugin readiness checks."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class VerificationCase:
    component: str
    name: str
    passed: bool
    message: str


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verify_pass: bool
    cases: tuple[VerificationCase, ...]


def _check_manifest(plugin_dir: Path) -> VerificationCase:
    manifest = plugin_dir / "plugin.json"
    if not manifest.exists():
        return VerificationCase("manifest", "plugin.json optional", True, "plugin.json not present")
    try:
        json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return VerificationCase("manifest", "plugin.json parses", False, f"Invalid plugin.json: {exc}")
    return VerificationCase("manifest", "plugin.json parses", True, "plugin.json is valid JSON")


def _check_marketplace(plugin_dir: Path) -> VerificationCase:
    marketplace = plugin_dir / "marketplace.json"
    if not marketplace.exists():
        return VerificationCase("marketplace", "marketplace optional", True, "marketplace.json not present")
    try:
        payload = json.loads(marketplace.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return VerificationCase("marketplace", "marketplace.json parses", False, f"Invalid marketplace.json: {exc}")
    plugins = payload.get("plugins", [])
    return VerificationCase("marketplace", "plugins listed", bool(plugins), "plugins found" if plugins else "plugins array missing/empty")


def _check_mcp(plugin_dir: Path, *, online: bool) -> VerificationCase:
    mcp_config = plugin_dir / ".mcp.json"
    if not mcp_config.exists():
        return VerificationCase("mcp", ".mcp.json optional", True, ".mcp.json not present")
    try:
        payload = json.loads(mcp_config.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return VerificationCase("mcp", ".mcp.json parses", False, f"Invalid .mcp.json: {exc}")

    remotes = payload.get("remotes", []) if isinstance(payload, dict) else []
    insecure = []
    for remote in remotes:
        url = remote.get("url", "") if isinstance(remote, dict) else ""
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme != "https":
            insecure.append(url)
    if insecure:
        return VerificationCase("mcp", "remote transport scheme", False, f"Insecure remote URLs: {', '.join(insecure)}")
    if remotes and not online:
        return VerificationCase("mcp", "remote check mode", True, "Remote checks skipped in offline mode")
    return VerificationCase("mcp", "remote transport scheme", True, "MCP configuration passed basic checks")


def verify_plugin(plugin_dir: str | Path, *, online: bool = False) -> VerificationResult:
    resolved = Path(plugin_dir).resolve()
    cases = (
        _check_manifest(resolved),
        _check_marketplace(resolved),
        _check_mcp(resolved, online=online),
    )
    return VerificationResult(verify_pass=all(case.passed for case in cases), cases=cases)


def build_doctor_report(plugin_dir: str | Path, component: str) -> dict[str, object]:
    resolved = Path(plugin_dir).resolve()
    verify = verify_plugin(resolved, online=False)
    component_cases = [
        {"name": case.name, "passed": case.passed, "message": case.message}
        for case in verify.cases
        if component == "all" or case.component == component
    ]
    return {
        "plugin_dir": str(resolved),
        "component": component,
        "verify_pass": verify.verify_pass,
        "cases": component_cases,
    }
