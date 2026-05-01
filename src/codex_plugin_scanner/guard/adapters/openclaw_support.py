"""OpenClaw adapter support helpers."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from .base import HarnessContext

_MAX_FILE_READ = 64 * 1024
_SKILL_SUBDIRS = ("references", "templates", "scripts", "assets")
_SCANNABLE_EXTENSIONS = {".md", ".txt", ".py", ".sh", ".bash", ".js", ".ts", ".yaml", ".yml", ".json", ".toml"}
_SCANNABLE_NAMES = {".env", "Dockerfile", "Makefile", "Procfile"}


def config_path(context: HarnessContext) -> Path:
    return context.home_dir / ".openclaw" / "openclaw.json"


def managed_root(context: HarnessContext) -> Path:
    return context.guard_home / "openclaw"


def config_artifacts(context: HarnessContext, path: Path, payload: dict[str, object]) -> list[GuardArtifact]:
    artifacts = [_gateway_artifact(context, path, payload)]
    artifacts.extend(_channel_artifacts(path, payload))
    artifacts.extend(_mcp_artifacts(path, payload))
    return artifacts


def skill_artifacts(
    context: HarnessContext,
    payload: dict[str, object],
    found_paths: list[str],
) -> list[GuardArtifact]:
    artifacts: list[GuardArtifact] = []
    seen: set[Path] = set()
    for root in _skill_roots(context, payload):
        if root in seen or not root.is_dir():
            continue
        seen.add(root)
        for skill_md in sorted(root.rglob("SKILL.md")):
            if skill_md.is_symlink() or not skill_md.is_file():
                continue
            found_paths.append(str(skill_md))
            artifacts.extend(_artifacts_for_skill(root, skill_md))
    return artifacts


def overlay_payload(detection: HarnessDetection) -> dict[str, object]:
    return {
        "harness": "openclaw",
        "config_paths": list(detection.config_paths),
        "artifact_count": len(detection.artifacts),
        "artifact_ids": [artifact.artifact_id for artifact in detection.artifacts],
    }


def pretool_payload(*, context: HarnessContext) -> dict[str, object]:
    command = [
        str(Path(sys.executable)),
        "-m",
        "codex_plugin_scanner.cli",
        "hook",
        "--harness",
        "openclaw",
        "--guard-home",
        str(context.guard_home),
        "--home",
        str(context.home_dir),
        "--json",
    ]
    if context.workspace_dir is not None:
        command.extend(["--workspace", str(context.workspace_dir)])
    return {"command": command, "harness": "openclaw"}


def install_state(
    *,
    existing_manifest: dict[str, object],
    overlay_path: Path,
    pretool_path: Path,
) -> str:
    if len(existing_manifest) == 0:
        return "installed"
    if overlay_path.exists() and pretool_path.exists():
        return "already_managed"
    return "repaired_managed_install"


def _gateway_artifact(context: HarnessContext, path: Path, payload: dict[str, object]) -> GuardArtifact:
    gateway = _dict_value(payload.get("gateway"))
    agents = _dict_value(payload.get("agents"))
    defaults = _dict_value(agents.get("defaults"))
    workspace_path = _workspace_path(context, payload)
    sandbox = _dict_value(defaults.get("sandbox"))
    hooks = _dict_value(payload.get("hooks"))
    metadata = {
        "workspace_path": str(workspace_path),
        "gateway_mode": _string_value(gateway.get("mode")),
        "gateway_bind": _string_value(gateway.get("bind")),
        "auth_mode": _string_value(_dict_value(gateway.get("auth")).get("mode")),
        "sandbox_mode": _string_value(sandbox.get("mode")),
        "hooks_enabled": bool(hooks),
        "channel_names": sorted(_channels(payload)),
        "mcp_server_names": sorted(_mcp_servers(payload)),
    }
    args = (
        f"gateway bind {metadata['gateway_bind'] or 'loopback'}",
        f"auth mode {metadata['auth_mode'] or 'token'}",
        f"sandbox {metadata['sandbox_mode'] or 'unset'}",
    )
    return GuardArtifact(
        artifact_id="openclaw:config:global",
        name="OpenClaw gateway config",
        harness="openclaw",
        artifact_type="gateway_config",
        source_scope="global",
        config_path=str(path),
        args=args,
        metadata=metadata,
    )


def _channel_artifacts(path: Path, payload: dict[str, object]) -> list[GuardArtifact]:
    artifacts: list[GuardArtifact] = []
    for name, config in _channels(payload).items():
        dm = _dict_value(config.get("dm"))
        dm_policy = _string_value(config.get("dmPolicy")) or _string_value(dm.get("policy"))
        allow_from = _string_list(config.get("allowFrom")) or _string_list(dm.get("allowFrom"))
        enabled = config.get("enabled", True) is not False
        signals: list[str] = []
        if enabled and dm_policy == "open" and "*" in allow_from:
            signals.append("network traffic from open chat channel can reach the agent without sender pairing")
        artifacts.append(
            GuardArtifact(
                artifact_id=f"openclaw:channel:{name}",
                name=name,
                harness="openclaw",
                artifact_type="channel",
                source_scope="global",
                config_path=str(path),
                args=(f"channel {name}", f"dmPolicy {dm_policy or 'default'}", f"allowFrom {','.join(allow_from)}"),
                metadata={
                    "channel": name,
                    "enabled": enabled,
                    "dm_policy": dm_policy,
                    "allow_from": allow_from,
                    "runtime_request_signals": signals,
                },
            )
        )
    return artifacts


def _mcp_artifacts(path: Path, payload: dict[str, object]) -> list[GuardArtifact]:
    artifacts: list[GuardArtifact] = []
    for name, config in _mcp_servers(payload).items():
        command = config.get("command")
        url = config.get("url")
        env = _dict_value(config.get("env"))
        headers = _dict_value(config.get("headers"))
        args = _string_list(config.get("args"))
        artifacts.append(
            GuardArtifact(
                artifact_id=f"openclaw:mcp:{name}",
                name=name,
                harness="openclaw",
                artifact_type="mcp_server",
                source_scope="global",
                config_path=str(path),
                command=command if isinstance(command, str) else None,
                args=tuple(args),
                url=url if isinstance(url, str) else None,
                transport="http" if isinstance(url, str) else "stdio",
                metadata={
                    "env_keys": sorted(str(key) for key in env if isinstance(key, str)),
                    "header_keys": sorted(str(key) for key in headers if isinstance(key, str)),
                    "env": env,
                    "headers": headers,
                },
            )
        )
    return artifacts


def _artifacts_for_skill(root: Path, skill_md: Path) -> list[GuardArtifact]:
    content = _safe_read(skill_md)
    skill_dir = skill_md.parent
    skill_name = _frontmatter_name(content) or skill_dir.name
    root_id = _path_digest(root)
    skill_dir_id = _path_digest(skill_dir)
    source_scope = f"skill-root:{root_id}"
    artifacts = [
        GuardArtifact(
            artifact_id=f"openclaw:skill:{root_id}:{skill_dir_id}:{skill_name}",
            name=skill_name,
            harness="openclaw",
            artifact_type="skill",
            source_scope=source_scope,
            config_path=str(skill_md),
            command=str(skill_md),
            args=_risk_args(content),
            metadata={
                "content_hash": _content_hash(content),
                "skill_root": str(root),
                "skill_root_id": root_id,
                "skill_dir": str(skill_dir),
                "skill_dir_id": skill_dir_id,
                "env_mentions": sorted(_extract_env_mentions(content)),
            },
        )
    ]
    for subdir_name in _SKILL_SUBDIRS:
        subdir = skill_dir / subdir_name
        if not subdir.is_dir():
            continue
        for file_path in sorted(subdir.rglob("*")):
            if file_path.is_symlink() or not file_path.is_file() or not _is_scannable(file_path):
                continue
            file_content = _safe_read(file_path)
            if not file_content:
                continue
            rel_path = file_path.relative_to(skill_dir)
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"openclaw:skill:{root_id}:{skill_dir_id}:{skill_name}:{rel_path}",
                    name=f"{skill_name}/{rel_path}",
                    harness="openclaw",
                    artifact_type="skill_file",
                    source_scope=source_scope,
                    config_path=str(file_path),
                    command=str(file_path),
                    args=_risk_args(file_content),
                    metadata={
                        "parent_skill": skill_name,
                        "content_hash": _content_hash(file_content),
                        "skill_root_id": root_id,
                        "skill_dir_id": skill_dir_id,
                        "env_mentions": sorted(_extract_env_mentions(file_content)),
                    },
                )
            )
    return artifacts


def _skill_roots(context: HarnessContext, payload: dict[str, object]) -> tuple[Path, ...]:
    workspace_path = _workspace_path(context, payload)
    roots = [
        workspace_path / "skills",
        workspace_path / ".agents" / "skills",
        context.home_dir / ".agents" / "skills",
        context.home_dir / ".openclaw" / "skills",
    ]
    skills = _dict_value(payload.get("skills"))
    load = _dict_value(skills.get("load"))
    for extra_dir in _string_list(load.get("extraDirs")):
        stripped = extra_dir.strip()
        if stripped:
            roots.append(_expand_home(context.home_dir, stripped))
    return tuple(roots)


def _workspace_path(context: HarnessContext, payload: dict[str, object]) -> Path:
    agents = _dict_value(payload.get("agents"))
    defaults = _dict_value(agents.get("defaults"))
    workspace = defaults.get("workspace")
    if isinstance(workspace, str) and workspace:
        return _expand_home(context.home_dir, workspace)
    return context.home_dir / ".openclaw" / "workspace"


def _expand_home(home_dir: Path, value: str) -> Path:
    if value == "~":
        return home_dir
    if value.startswith("~/"):
        return home_dir / value[2:]
    path = Path(value)
    return path if path.is_absolute() else home_dir / path


def _channels(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    channels = _dict_value(payload.get("channels"))
    return {
        str(name): config for name, config in channels.items() if isinstance(name, str) and isinstance(config, dict)
    }


def _mcp_servers(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    mcp = _dict_value(payload.get("mcp"))
    candidates = (mcp.get("servers"), mcp.get("mcpServers"), payload.get("mcpServers"))
    for candidate in candidates:
        server_map = _dict_value(candidate)
        if not server_map:
            continue
        enabled_servers = {
            str(name): config
            for name, config in server_map.items()
            if isinstance(name, str) and isinstance(config, dict) and config.get("enabled", True) is not False
        }
        if enabled_servers:
            return enabled_servers
    return {}


def _dict_value(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float, bool))]


def _risk_args(content: str) -> tuple[str, ...]:
    blocks = _extract_code_blocks(content)
    plain = _plain_markdown(content)
    if plain:
        return (*blocks, plain)
    return blocks


def _extract_code_blocks(content: str) -> tuple[str, ...]:
    blocks = []
    for match in re.finditer(r"```[^\n]*\n(.*?)\n?```", content, re.DOTALL):
        block = match.group(1).strip()
        if block:
            blocks.append(block)
    return tuple(blocks)


def _plain_markdown(content: str, max_len: int = 2048) -> str:
    stripped = re.sub(r"```[^\n]*\n.*?\n?```", "", content, flags=re.DOTALL)
    if stripped.startswith("---"):
        parts = stripped[3:].split("---", 1)
        if len(parts) == 2:
            stripped = parts[1]
    return stripped.strip()[:max_len]


def _frontmatter_name(content: str) -> str | None:
    if not content.startswith("---"):
        return None
    parts = content[3:].split("---", 1)
    if len(parts) != 2:
        return None
    for line in parts[0].splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "name" and value.strip():
            return value.strip().strip("\"'")
    return None


def _extract_env_mentions(content: str) -> set[str]:
    mentions: set[str] = set()
    for match in re.finditer(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", content):
        mentions.add(match.group(1))
    for match in re.finditer(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)", content):
        mentions.add(match.group(1))
    return mentions


def _is_scannable(file_path: Path) -> bool:
    if file_path.suffix.lower() in _SCANNABLE_EXTENSIONS:
        return True
    if not file_path.suffix:
        return file_path.name in _SCANNABLE_NAMES or "scripts" in file_path.parts
    return False


def _safe_read(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8") as file:
            return file.read(_MAX_FILE_READ)
    except (OSError, UnicodeDecodeError):
        return ""


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _path_digest(path: Path) -> str:
    try:
        value = str(path.resolve())
    except (OSError, RuntimeError):
        value = str(path)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
