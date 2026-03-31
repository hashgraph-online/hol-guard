"""Runtime verification engine for plugin readiness checks."""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .checks.manifest import load_manifest
from .checks.marketplace import _is_safe_source

MARKDOWN_LINK_RE = re.compile(r"\[[^]]+\]\(([^)]+)\)")
INTERFACE_REQUIRED_FIELDS = (
    "type",
    "displayName",
    "shortDescription",
    "developerName",
    "category",
)


@dataclass(frozen=True, slots=True)
class VerificationCase:
    component: str
    name: str
    passed: bool
    message: str
    classification: str = "pass"


@dataclass(frozen=True, slots=True)
class RuntimeTrace:
    component: str
    name: str
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verify_pass: bool
    cases: tuple[VerificationCase, ...]
    workspace: str
    traces: tuple[RuntimeTrace, ...] = ()


def _read_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _is_safe_relative_asset(plugin_dir: Path, value: str) -> bool:
    candidate = Path(value)
    if candidate.is_absolute():
        return False
    resolved = (plugin_dir / candidate).resolve()
    try:
        resolved.relative_to(plugin_dir.resolve())
    except ValueError:
        return False
    return resolved.exists() and resolved.is_file()


def _check_manifest(plugin_dir: Path) -> list[VerificationCase]:
    manifest_path = plugin_dir / ".codex-plugin" / "plugin.json"
    if not manifest_path.exists():
        return [
            VerificationCase(
                "manifest",
                "plugin.json exists",
                False,
                ".codex-plugin/plugin.json is missing",
                "missing-manifest",
            )
        ]

    payload = _read_json(manifest_path)
    if payload is None:
        return [
            VerificationCase(
                "manifest",
                "plugin.json parses",
                False,
                "Invalid .codex-plugin/plugin.json",
                "invalid-json",
            )
        ]
    if not isinstance(payload, dict):
        return [
            VerificationCase(
                "manifest",
                "plugin.json shape",
                False,
                ".codex-plugin/plugin.json must be an object",
                "schema",
            )
        ]

    cases = [
        VerificationCase("manifest", "plugin.json parses", True, ".codex-plugin/plugin.json is valid JSON"),
    ]
    missing_required = [
        field
        for field in ("name", "version", "description")
        if not isinstance(payload.get(field), str) or not payload.get(field)
    ]
    cases.append(
        VerificationCase(
            "manifest",
            "required fields",
            not missing_required,
            "All required manifest fields are present"
            if not missing_required
            else f"Missing required manifest fields: {', '.join(missing_required)}",
            "schema" if missing_required else "pass",
        )
    )

    interface = payload.get("interface")
    if interface is None:
        cases.append(
            VerificationCase(
                "manifest",
                "interface metadata",
                True,
                "interface metadata not declared",
                "optional",
            )
        )
        return cases

    if not isinstance(interface, dict):
        cases.append(
            VerificationCase(
                "manifest",
                "interface metadata",
                False,
                "interface must be an object",
                "schema",
            )
        )
        return cases

    missing_interface = [
        field
        for field in INTERFACE_REQUIRED_FIELDS
        if not isinstance(interface.get(field), str) or not interface.get(field)
    ]
    cases.append(
        VerificationCase(
            "manifest",
            "interface metadata",
            not missing_interface,
            "interface metadata is publishable"
            if not missing_interface
            else f"Missing interface fields: {', '.join(missing_interface)}",
            "schema" if missing_interface else "pass",
        )
    )

    capabilities = interface.get("capabilities")
    capabilities_valid = (
        isinstance(capabilities, list)
        and bool(capabilities)
        and all(isinstance(item, str) and item for item in capabilities)
    )
    cases.append(
        VerificationCase(
            "manifest",
            "capability enumeration",
            capabilities_valid,
            "Capabilities are declared for discovery"
            if capabilities_valid
            else "interface.capabilities must be a non-empty string array",
            "schema" if not capabilities_valid else "pass",
        )
    )

    asset_refs: list[str] = []
    for field in ("composerIcon", "logo"):
        value = interface.get(field)
        if isinstance(value, str) and value:
            asset_refs.append(value)
    screenshots = interface.get("screenshots")
    if isinstance(screenshots, list):
        asset_refs.extend(value for value in screenshots if isinstance(value, str) and value)
    missing_assets = [value for value in asset_refs if not _is_safe_relative_asset(plugin_dir, value)]
    cases.append(
        VerificationCase(
            "manifest",
            "interface assets",
            not missing_assets,
            "Declared interface assets resolve inside the plugin"
            if not missing_assets
            else f"Missing or unsafe interface assets: {', '.join(missing_assets)}",
            "asset-missing" if missing_assets else "pass",
        )
    )
    return cases


def _check_marketplace(plugin_dir: Path) -> list[VerificationCase]:
    marketplace = plugin_dir / "marketplace.json"
    if not marketplace.exists():
        return [
            VerificationCase(
                "marketplace",
                "marketplace optional",
                True,
                "marketplace.json not present",
                "optional",
            )
        ]

    payload = _read_json(marketplace)
    if payload is None:
        return [
            VerificationCase(
                "marketplace",
                "marketplace.json parses",
                False,
                "Invalid marketplace.json",
                "invalid-json",
            )
        ]
    if not isinstance(payload, dict):
        return [
            VerificationCase(
                "marketplace",
                "marketplace.json shape",
                False,
                "marketplace.json must be an object",
                "schema",
            )
        ]

    cases = [
        VerificationCase("marketplace", "marketplace.json parses", True, "marketplace.json is valid JSON"),
    ]
    has_name = isinstance(payload.get("name"), str) and bool(payload.get("name"))
    cases.append(
        VerificationCase(
            "marketplace",
            "marketplace name",
            has_name,
            "Marketplace name is declared" if has_name else 'marketplace.json must declare a string "name"',
            "schema" if not has_name else "pass",
        )
    )

    plugins = payload.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        cases.append(
            VerificationCase(
                "marketplace",
                "plugins listed",
                False,
                "plugins array missing/empty",
                "schema",
            )
        )
        return cases

    cases.append(VerificationCase("marketplace", "plugins listed", True, "plugins found"))
    discovery_issues: list[str] = []
    policy_issues: list[str] = []
    for index, plugin in enumerate(plugins):
        if not isinstance(plugin, dict):
            discovery_issues.append(f"plugin[{index}] must be an object")
            continue
        source = plugin.get("source")
        if not isinstance(source, str) or not source:
            discovery_issues.append(f"plugin[{index}] missing source")
        elif not _is_safe_source(plugin_dir, source):
            discovery_issues.append(f"plugin[{index}] unsafe source {source}")
        policy = plugin.get("policy")
        if not isinstance(policy, dict):
            policy_issues.append(f"plugin[{index}] missing policy object")
            continue
        if not isinstance(policy.get("installation"), str) or not policy.get("installation"):
            policy_issues.append(f"plugin[{index}] missing policy.installation")
        if not isinstance(policy.get("authentication"), str) or not policy.get("authentication"):
            policy_issues.append(f"plugin[{index}] missing policy.authentication")

    cases.append(
        VerificationCase(
            "marketplace",
            "discovery simulation",
            not discovery_issues,
            "Marketplace entries are discoverable" if not discovery_issues else "; ".join(discovery_issues),
            "schema" if discovery_issues else "pass",
        )
    )
    cases.append(
        VerificationCase(
            "marketplace",
            "policy metadata",
            not policy_issues,
            "Marketplace policy metadata is complete" if not policy_issues else "; ".join(policy_issues),
            "schema" if policy_issues else "pass",
        )
    )
    return cases


def _check_mcp_http(remotes: list[dict], *, online: bool) -> list[VerificationCase]:
    cases: list[VerificationCase] = []
    for remote in remotes:
        url = str(remote.get("url", ""))
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.scheme != "https":
            cases.append(
                VerificationCase("mcp", "remote scheme", False, f"Insecure scheme in {url}", "insecure-scheme")
            )
            continue
        if online:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status in (401, 403):
                        cases.append(
                            VerificationCase(
                                "mcp",
                                "remote auth",
                                True,
                                f"Auth required for {url}",
                                "auth-required",
                            )
                        )
                    elif 200 <= resp.status < 400:
                        cases.append(VerificationCase("mcp", "remote reachability", True, f"Reachable: {url}"))
                    else:
                        cases.append(
                            VerificationCase(
                                "mcp",
                                "remote reachability",
                                False,
                                f"HTTP {resp.status} for {url}",
                                "transport",
                            )
                        )
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    cases.append(
                        VerificationCase(
                            "mcp",
                            "remote auth",
                            True,
                            f"Auth required for {url}",
                            "auth-required",
                        )
                    )
                else:
                    cases.append(
                        VerificationCase(
                            "mcp",
                            "remote reachability",
                            False,
                            f"HTTP error for {url}: {exc.code}",
                            "transport",
                        )
                    )
            except Exception as exc:
                cases.append(
                    VerificationCase(
                        "mcp",
                        "remote reachability",
                        False,
                        f"Transport failure for {url}: {exc}",
                        "transport",
                    )
                )
        else:
            cases.append(
                VerificationCase(
                    "mcp",
                    "remote reachability",
                    True,
                    f"Offline mode skipped: {url}",
                    "offline-skip",
                )
            )
    return cases


def _check_mcp_stdio(servers: dict) -> tuple[list[VerificationCase], list[RuntimeTrace]]:
    cases: list[VerificationCase] = []
    traces: list[RuntimeTrace] = []
    for name, server in servers.items():
        cmd = server.get("command") if isinstance(server, dict) else None
        args = server.get("args", []) if isinstance(server, dict) and isinstance(server.get("args", []), list) else []
        if not cmd:
            continue
        command = [str(cmd), *[str(arg) for arg in args]]
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=os.environ.copy(),
            )
        except Exception as exc:
            cases.append(VerificationCase("mcp", f"stdio spawn:{name}", False, str(exc), "spawn-failure"))
            traces.append(
                RuntimeTrace(
                    component="mcp",
                    name=f"stdio spawn:{name}",
                    command=tuple(command),
                    returncode=None,
                    stdout="",
                    stderr=str(exc),
                )
            )
            continue
        try:
            if proc.stdin:
                proc.stdin.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
                proc.stdin.flush()
            stdout, stderr = proc.communicate(timeout=2)
            traces.append(
                RuntimeTrace(
                    component="mcp",
                    name=f"stdio handshake:{name}",
                    command=tuple(command),
                    returncode=proc.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
            )
            if proc.returncode not in (0, None):
                cases.append(
                    VerificationCase(
                        "mcp",
                        f"stdio run:{name}",
                        False,
                        stderr or "non-zero exit",
                        "spawn-failure",
                    )
                )
            elif "error" in stdout.lower():
                cases.append(
                    VerificationCase(
                        "mcp",
                        f"stdio handshake:{name}",
                        False,
                        stdout.strip(),
                        "protocol-failure",
                    )
                )
            else:
                cases.append(VerificationCase("mcp", f"stdio handshake:{name}", True, "initialize attempted"))
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            traces.append(
                RuntimeTrace(
                    component="mcp",
                    name=f"stdio timeout:{name}",
                    command=tuple(command),
                    returncode=None,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=True,
                )
            )
            cases.append(VerificationCase("mcp", f"stdio timeout:{name}", False, "process timed out", "timeout"))
        except Exception as exc:
            proc.kill()
            traces.append(
                RuntimeTrace(
                    component="mcp",
                    name=f"stdio run:{name}",
                    command=tuple(command),
                    returncode=proc.returncode,
                    stdout="",
                    stderr=str(exc),
                )
            )
            cases.append(VerificationCase("mcp", f"stdio run:{name}", False, str(exc), "spawn-failure"))
    return cases, traces


def _check_mcp(plugin_dir: Path, *, online: bool) -> tuple[list[VerificationCase], list[RuntimeTrace]]:
    mcp_config = plugin_dir / ".mcp.json"
    if not mcp_config.exists():
        return [VerificationCase("mcp", ".mcp.json optional", True, ".mcp.json not present", "optional")], []

    payload = _read_json(mcp_config)
    if payload is None:
        return [VerificationCase("mcp", ".mcp.json parses", False, "Invalid .mcp.json", "invalid-json")], []
    if not isinstance(payload, dict):
        return [VerificationCase("mcp", ".mcp.json shape", False, ".mcp.json must be an object", "schema")], []

    remotes = payload.get("remotes", [])
    servers = payload.get("mcpServers", {})
    cases = [VerificationCase("mcp", ".mcp.json parses", True, ".mcp.json is valid JSON")]
    if not isinstance(remotes, list):
        cases.append(VerificationCase("mcp", "remote list", False, "remotes must be an array", "schema"))
        remotes = []
    if not isinstance(servers, dict):
        cases.append(VerificationCase("mcp", "server registry", False, "mcpServers must be an object", "schema"))
        servers = {}
    cases.extend(_check_mcp_http(remotes, online=online))
    stdio_cases, traces = _check_mcp_stdio(servers)
    cases.extend(stdio_cases)
    if len(cases) == 1:
        cases.append(VerificationCase("mcp", "mcp config", True, "No remote or stdio MCP surfaces declared"))
    return cases, traces


def _check_skills(plugin_dir: Path) -> list[VerificationCase]:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return [
            VerificationCase(
                "skills",
                "skills optional",
                True,
                "Manifest unavailable; skills verification skipped",
                "optional",
            )
        ]
    skills_root = manifest.get("skills")
    if not isinstance(skills_root, str) or not skills_root:
        return [VerificationCase("skills", "skills optional", True, "No skills field declared", "optional")]

    skills_dir = plugin_dir / skills_root
    if not skills_dir.exists():
        return [
            VerificationCase(
                "skills",
                "skills directory",
                False,
                f'Skills directory "{skills_root}" not found',
                "missing-skill",
            )
        ]

    skill_files = sorted(skills_dir.rglob("SKILL.md"))
    if not skill_files:
        return [VerificationCase("skills", "skill manifests", False, "No SKILL.md found", "missing-skill")]

    frontmatter_issues: list[str] = []
    reference_issues: list[str] = []
    for skill_file in skill_files:
        try:
            content = skill_file.read_text(encoding="utf-8")
        except OSError as exc:
            frontmatter_issues.append(f"{skill_file.relative_to(plugin_dir)} unreadable: {exc}")
            continue
        parts = content.split("---", 2)
        if len(parts) < 3:
            frontmatter_issues.append(str(skill_file.relative_to(plugin_dir)))
        else:
            frontmatter = parts[1]
            if "name:" not in frontmatter or "description:" not in frontmatter:
                frontmatter_issues.append(str(skill_file.relative_to(plugin_dir)))
        for match in MARKDOWN_LINK_RE.finditer(content):
            target = match.group(1).strip()
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            candidate = (skill_file.parent / target).resolve()
            try:
                candidate.relative_to(plugin_dir.resolve())
            except ValueError:
                reference_issues.append(f"{skill_file.relative_to(plugin_dir)} -> {target}")
                continue
            if not candidate.exists():
                reference_issues.append(f"{skill_file.relative_to(plugin_dir)} -> {target}")

    return [
        VerificationCase(
            "skills",
            "skill manifests",
            True,
            f"{len(skill_files)} skill manifest(s) found",
        ),
        VerificationCase(
            "skills",
            "skill frontmatter",
            not frontmatter_issues,
            "All skill manifests contain frontmatter" if not frontmatter_issues else "; ".join(frontmatter_issues),
            "frontmatter" if frontmatter_issues else "pass",
        ),
        VerificationCase(
            "skills",
            "skill references",
            not reference_issues,
            "Skill references resolve within the plugin" if not reference_issues else "; ".join(reference_issues),
            "reference" if reference_issues else "pass",
        ),
    ]


def _check_apps(plugin_dir: Path) -> list[VerificationCase]:
    app_config = plugin_dir / ".app.json"
    if not app_config.exists():
        return [VerificationCase("apps", "apps optional", True, ".app.json not present", "optional")]
    payload = _read_json(app_config)
    if payload is None:
        return [VerificationCase("apps", ".app.json parses", False, "Invalid .app.json", "invalid-json")]
    if not isinstance(payload, dict):
        return [VerificationCase("apps", ".app.json shape", False, ".app.json must be an object", "schema")]

    apps = payload.get("apps")
    if apps is None:
        return [VerificationCase("apps", ".app.json parses", True, ".app.json valid")]
    if not isinstance(apps, list):
        return [VerificationCase("apps", "apps registry", False, ".app.json apps must be an array", "schema")]
    invalid_entries = [
        str(index)
        for index, entry in enumerate(apps)
        if not isinstance(entry, dict)
        or not isinstance(entry.get("name"), str)
        or not entry.get("name")
        or not any(isinstance(entry.get(field), str) and entry.get(field) for field in ("command", "url"))
    ]
    return [
        VerificationCase("apps", ".app.json parses", True, ".app.json valid"),
        VerificationCase(
            "apps",
            "apps registry",
            not invalid_entries,
            "App entries are valid" if not invalid_entries else f"Invalid app entries: {', '.join(invalid_entries)}",
            "schema" if invalid_entries else "pass",
        ),
    ]


def _check_assets(plugin_dir: Path) -> list[VerificationCase]:
    assets = plugin_dir / "assets"
    if not assets.exists():
        return [VerificationCase("assets", "assets optional", True, "assets directory not present", "optional")]
    zero = [path.name for path in assets.rglob("*") if path.is_file() and path.stat().st_size == 0]
    return [
        VerificationCase(
            "assets",
            "asset size",
            not zero,
            "asset files are non-empty" if not zero else f"Zero-byte assets: {', '.join(zero)}",
            "zero-byte" if zero else "pass",
        )
    ]


def verify_plugin(plugin_dir: str | Path, *, online: bool = False) -> VerificationResult:
    resolved = Path(plugin_dir).resolve()
    mcp_cases, traces = _check_mcp(resolved, online=online)
    cases: list[VerificationCase] = [
        *_check_manifest(resolved),
        *_check_marketplace(resolved),
        *mcp_cases,
        *_check_skills(resolved),
        *_check_apps(resolved),
        *_check_assets(resolved),
    ]
    return VerificationResult(
        verify_pass=all(case.passed for case in cases),
        cases=tuple(cases),
        workspace=str(resolved),
        traces=tuple(traces),
    )


def build_doctor_report(plugin_dir: str | Path, component: str) -> dict[str, object]:
    resolved = Path(plugin_dir).resolve()
    verify = verify_plugin(resolved, online=False)
    component_cases = [
        {
            "name": case.name,
            "passed": case.passed,
            "message": case.message,
            "classification": case.classification,
        }
        for case in verify.cases
        if component == "all" or case.component == component
    ]
    trace_entries = [
        {
            "name": trace.name,
            "command": list(trace.command),
            "returncode": trace.returncode,
            "stdout": trace.stdout,
            "stderr": trace.stderr,
            "timed_out": trace.timed_out,
        }
        for trace in verify.traces
        if component in {"all", "mcp"} or trace.component == component
    ]
    stdout_log = "\n\n".join(
        f"[{trace['name']}]\n$ {' '.join(trace['command'])}\n{trace['stdout']}".rstrip()
        for trace in trace_entries
        if trace["stdout"]
    )
    stderr_log = "\n\n".join(
        f"[{trace['name']}]\n$ {' '.join(trace['command'])}\n{trace['stderr']}".rstrip()
        for trace in trace_entries
        if trace["stderr"]
    )
    timeout_names = [trace["name"] for trace in trace_entries if trace["timed_out"]]
    return {
        "plugin_dir": str(resolved),
        "component": component,
        "verify_pass": verify.verify_pass,
        "workspace": verify.workspace,
        "cases": component_cases,
        "runtime_traces": trace_entries,
        "stdout_log": f"{stdout_log}\n" if stdout_log else "",
        "stderr_log": f"{stderr_log}\n" if stderr_log else "",
        "timeout_markers": "none\n" if not timeout_names else "\n".join(timeout_names) + "\n",
    }
