"""Runtime verification engine for plugin readiness checks."""

from __future__ import annotations

import json
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class VerificationCase:
    component: str
    name: str
    passed: bool
    message: str
    classification: str = "pass"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verify_pass: bool
    cases: tuple[VerificationCase, ...]
    workspace: str


def _check_manifest(plugin_dir: Path) -> VerificationCase:
    manifest = plugin_dir / "plugin.json"
    if not manifest.exists():
        return VerificationCase("manifest", "plugin.json optional", True, "plugin.json not present")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return VerificationCase("manifest", "plugin.json parses", False, f"Invalid plugin.json: {exc}", "invalid-json")
    if isinstance(payload, dict) and payload.get("interface") and not isinstance(payload["interface"], dict):
        return VerificationCase("manifest", "interface shape", False, "interface must be an object", "schema")
    return VerificationCase("manifest", "plugin.json parses", True, "plugin.json is valid JSON")


def _check_marketplace(plugin_dir: Path) -> VerificationCase:
    marketplace = plugin_dir / "marketplace.json"
    if not marketplace.exists():
        return VerificationCase("marketplace", "marketplace optional", True, "marketplace.json not present")
    try:
        payload = json.loads(marketplace.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return VerificationCase("marketplace", "marketplace.json parses", False, f"Invalid marketplace.json: {exc}", "invalid-json")
    plugins = payload.get("plugins", []) if isinstance(payload, dict) else []
    if not plugins:
        return VerificationCase("marketplace", "plugins listed", False, "plugins array missing/empty", "schema")
    return VerificationCase("marketplace", "plugins listed", True, "plugins found")


def _check_mcp_http(remotes: list[dict], *, online: bool) -> list[VerificationCase]:
    cases: list[VerificationCase] = []
    for remote in remotes:
        url = str(remote.get("url", ""))
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.scheme != "https":
            cases.append(VerificationCase("mcp", "remote scheme", False, f"Insecure scheme in {url}", "insecure-scheme"))
            continue
        if online:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status in (401, 403):
                        cases.append(VerificationCase("mcp", "remote auth", True, f"Auth required for {url}", "auth-required"))
                    elif 200 <= resp.status < 400:
                        cases.append(VerificationCase("mcp", "remote reachability", True, f"Reachable: {url}"))
                    else:
                        cases.append(VerificationCase("mcp", "remote reachability", False, f"HTTP {resp.status} for {url}", "transport"))
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    cases.append(VerificationCase("mcp", "remote auth", True, f"Auth required for {url}", "auth-required"))
                else:
                    cases.append(VerificationCase("mcp", "remote reachability", False, f"HTTP error for {url}: {exc.code}", "transport"))
            except Exception as exc:  # noqa: BLE001
                cases.append(VerificationCase("mcp", "remote reachability", False, f"Transport failure for {url}: {exc}", "transport"))
        else:
            cases.append(VerificationCase("mcp", "remote reachability", True, f"Offline mode skipped: {url}", "offline-skip"))
    return cases


def _check_mcp_stdio(servers: dict) -> list[VerificationCase]:
    cases: list[VerificationCase] = []
    for name, server in servers.items():
        cmd = server.get("command") if isinstance(server, dict) else None
        args = server.get("args", []) if isinstance(server, dict) else []
        if not cmd:
            continue
        try:
            proc = subprocess.Popen(
                [cmd, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={},
            )
        except Exception as exc:  # noqa: BLE001
            cases.append(VerificationCase("mcp", f"stdio spawn:{name}", False, str(exc), "spawn-failure"))
            continue
        try:
            if proc.stdin:
                proc.stdin.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
                proc.stdin.flush()
            stdout, stderr = proc.communicate(timeout=2)
            if proc.returncode not in (0, None):
                cases.append(VerificationCase("mcp", f"stdio run:{name}", False, stderr or "non-zero exit", "spawn-failure"))
            elif "error" in stdout.lower():
                cases.append(VerificationCase("mcp", f"stdio handshake:{name}", False, stdout.strip(), "protocol-failure"))
            else:
                cases.append(VerificationCase("mcp", f"stdio handshake:{name}", True, "initialize attempted"))
        except subprocess.TimeoutExpired:
            proc.kill()
            cases.append(VerificationCase("mcp", f"stdio timeout:{name}", False, "process timed out", "timeout"))
    return cases


def _check_mcp(plugin_dir: Path, *, online: bool) -> list[VerificationCase]:
    mcp_config = plugin_dir / ".mcp.json"
    if not mcp_config.exists():
        return [VerificationCase("mcp", ".mcp.json optional", True, ".mcp.json not present")]
    try:
        payload = json.loads(mcp_config.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [VerificationCase("mcp", ".mcp.json parses", False, f"Invalid .mcp.json: {exc}", "invalid-json")]

    remotes = payload.get("remotes", []) if isinstance(payload, dict) else []
    servers = payload.get("mcpServers", {}) if isinstance(payload, dict) else {}
    cases = _check_mcp_http(remotes, online=online)
    cases.extend(_check_mcp_stdio(servers if isinstance(servers, dict) else {}))
    if not cases:
        cases.append(VerificationCase("mcp", "mcp config", True, "No remote or stdio MCP surfaces declared"))
    return cases


def _check_skills(plugin_dir: Path) -> VerificationCase:
    skills_dir = plugin_dir / "skills"
    if not skills_dir.exists():
        return VerificationCase("skills", "skills optional", True, "skills directory not present")
    has_skill = any(path.name == "SKILL.md" for path in skills_dir.rglob("SKILL.md"))
    return VerificationCase("skills", "skill manifests", has_skill, "SKILL.md files found" if has_skill else "No SKILL.md found", "missing-skill" if not has_skill else "pass")


def _check_apps(plugin_dir: Path) -> VerificationCase:
    app_config = plugin_dir / ".app.json"
    if not app_config.exists():
        return VerificationCase("apps", "apps optional", True, ".app.json not present")
    try:
        json.loads(app_config.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return VerificationCase("apps", ".app.json parses", False, f"Invalid .app.json: {exc}", "invalid-json")
    return VerificationCase("apps", ".app.json parses", True, ".app.json valid")


def _check_assets(plugin_dir: Path) -> VerificationCase:
    assets = plugin_dir / "assets"
    if not assets.exists():
        return VerificationCase("assets", "assets optional", True, "assets directory not present")
    zero = [path.name for path in assets.rglob("*") if path.is_file() and path.stat().st_size == 0]
    if zero:
        return VerificationCase("assets", "asset size", False, f"Zero-byte assets: {', '.join(zero)}", "zero-byte")
    return VerificationCase("assets", "asset size", True, "asset files are non-empty")


def verify_plugin(plugin_dir: str | Path, *, online: bool = False) -> VerificationResult:
    resolved = Path(plugin_dir).resolve()
    with tempfile.TemporaryDirectory(prefix="codex-verify-") as workspace:
        cases: list[VerificationCase] = [
            _check_manifest(resolved),
            _check_marketplace(resolved),
            *_check_mcp(resolved, online=online),
            _check_skills(resolved),
            _check_apps(resolved),
            _check_assets(resolved),
        ]
        return VerificationResult(
            verify_pass=all(case.passed for case in cases),
            cases=tuple(cases),
            workspace=workspace,
        )


def build_doctor_report(plugin_dir: str | Path, component: str) -> dict[str, object]:
    resolved = Path(plugin_dir).resolve()
    verify = verify_plugin(resolved, online=False)
    component_cases = [
        {"name": case.name, "passed": case.passed, "message": case.message, "classification": case.classification}
        for case in verify.cases
        if component == "all" or case.component == component
    ]
    return {
        "plugin_dir": str(resolved),
        "component": component,
        "verify_pass": verify.verify_pass,
        "workspace": verify.workspace,
        "cases": component_cases,
    }
