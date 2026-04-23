"""Claude Code harness adapter."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlencode

from ...path_support import iter_safe_matching_files, resolves_within_root
from ..daemon import guard_daemon_url_for_home, load_guard_daemon_url
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _ensure_path_within_root, _json_payload, _run_command_probe

CLAUDE_GUARD_TOOL_MATCHER = "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*"
CLAUDE_GUARD_NOTIFICATION_MATCHER = "permission_prompt"
CLAUDE_GUARD_SESSION_START_MATCHERS = ("startup", "resume", "clear", "compact")
CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS = 30
CLAUDE_GUARD_PROMPT_TIMEOUT_SECONDS = 20
CLAUDE_GUARD_NOTIFICATION_TIMEOUT_SECONDS = 10
CLAUDE_GUARD_SESSION_START_TIMEOUT_SECONDS = 10
CLAUDE_SETTINGS_FILES = ("settings.json", "settings.local.json")
CLAUDE_GUARD_DAEMON_HOOK_MARKER = "HOL_GUARD_CLAUDE_DAEMON_HOOK"


def _guard_command_handler(command: str, *, timeout: int) -> dict[str, object]:
    return {"type": "command", "command": command, "timeout": timeout}


def _shell_command(command: tuple[str, ...], *, windows: bool | None = None) -> str:
    is_windows = os.name == "nt" if windows is None else windows
    if is_windows:
        return subprocess.list2cmdline(list(command))
    return shlex.join(command)


def _sync_runtime_hook_groups(hooks: dict[str, object], hook_command: str) -> None:
    for key, matcher, timeout in (
        ("PreToolUse", CLAUDE_GUARD_TOOL_MATCHER, CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS),
        ("PostToolUse", CLAUDE_GUARD_TOOL_MATCHER, CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS),
        ("UserPromptSubmit", None, CLAUDE_GUARD_PROMPT_TIMEOUT_SECONDS),
        ("Notification", CLAUDE_GUARD_NOTIFICATION_MATCHER, CLAUDE_GUARD_NOTIFICATION_TIMEOUT_SECONDS),
    ):
        existing_entries = hooks.get(key)
        hooks[key] = _merge_hook_group(
            _prune_guard_hook_entries(existing_entries if isinstance(existing_entries, list) else []),
            matcher,
            _guard_command_handler(hook_command, timeout=timeout),
        )


def _guard_hook_group(matcher: str | None, handler: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {"hooks": [handler]}
    if isinstance(matcher, str) and matcher.strip():
        payload["matcher"] = matcher
    return payload


def _is_guard_hook_command(command: object) -> bool:
    if not isinstance(command, str):
        return False
    if CLAUDE_GUARD_DAEMON_HOOK_MARKER in command:
        return True
    if "codex_plugin_scanner.cli" in command:
        return "guard hook" in command or "'guard', 'hook'" in command or '"guard", "hook"' in command
    return "ensure_guard_daemon(" in command and "HOL Guard protection is active for this workspace." in command


def _handler_identity(handler: dict[str, object]) -> tuple[str, str]:
    handler_type = str(handler.get("type", ""))
    if handler_type == "http":
        return (handler_type, str(handler.get("url", "")))
    return (handler_type, str(handler.get("command", "")))


def _is_guard_hook_url(url: object) -> bool:
    if not isinstance(url, str):
        return False
    return url.startswith("http://127.0.0.1:") and "/v1/hooks/claude-code" in url


def _is_guard_hook_handler(handler: object) -> bool:
    if not isinstance(handler, dict):
        return False
    handler_type = handler.get("type")
    if handler_type == "command":
        return _is_guard_hook_command(handler.get("command"))
    if handler_type == "http":
        return _is_guard_hook_url(handler.get("url"))
    return False


def _merge_hook_group(
    entries: list[object],
    matcher: str | None,
    handler: dict[str, object],
) -> list[object]:
    normalized = [entry for entry in entries if isinstance(entry, dict)]
    matcher_key = matcher.strip() if isinstance(matcher, str) and matcher.strip() else None
    handler_identity = _handler_identity(handler)
    for index, entry in enumerate(normalized):
        entry_matcher = entry.get("matcher")
        entry_matcher_key = entry_matcher.strip() if isinstance(entry_matcher, str) and entry_matcher.strip() else None
        if entry_matcher_key != matcher_key:
            continue
        hooks = entry.get("hooks")
        if not isinstance(hooks, list):
            hooks = []
        if any(isinstance(item, dict) and _handler_identity(item) == handler_identity for item in hooks):
            updated_entry = dict(entry)
            updated_entry["hooks"] = [
                handler if isinstance(item, dict) and _handler_identity(item) == handler_identity else item
                for item in hooks
            ]
            normalized[index] = updated_entry
            return normalized
        hooks.append(handler)
        updated_entry = dict(entry)
        updated_entry["hooks"] = hooks
        normalized[index] = updated_entry
        return normalized
    normalized.append(_guard_hook_group(matcher_key, handler))
    return normalized


def _group_has_handler(entry: object, handler: dict[str, object]) -> bool:
    if not isinstance(entry, dict):
        return False
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return False
    handler_identity = _handler_identity(handler)
    return any(isinstance(hook, dict) and _handler_identity(hook) == handler_identity for hook in hooks)


def _prune_guard_hook_entries(entries: list[object]) -> list[object]:
    remaining: list[object] = []
    for entry in entries:
        if not isinstance(entry, dict):
            remaining.append(entry)
            continue
        if _is_guard_hook_command(entry.get("command")):
            continue
        hooks = entry.get("hooks")
        if not isinstance(hooks, list):
            remaining.append(entry)
            continue
        filtered_hooks = [item for item in hooks if not _is_guard_hook_handler(item)]
        if filtered_hooks:
            updated_entry = dict(entry)
            updated_entry["hooks"] = filtered_hooks
            remaining.append(updated_entry)
    return remaining


def _remove_hook_entry(entries: list[object], handler: dict[str, object]) -> list[object]:
    remaining: list[object] = []
    for entry in entries:
        if not isinstance(entry, dict):
            remaining.append(entry)
            continue
        if _is_guard_hook_command(entry.get("command")):
            continue
        if _group_has_handler(entry, handler):
            hooks = entry.get("hooks")
            if not isinstance(hooks, list):
                continue
            filtered_hooks = [
                item
                for item in hooks
                if not (isinstance(item, dict) and _handler_identity(item) == _handler_identity(handler))
            ]
            if filtered_hooks:
                updated_entry = dict(entry)
                updated_entry["hooks"] = filtered_hooks
                remaining.append(updated_entry)
            continue
        remaining.append(entry)
    return remaining


def _claude_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metadata_with_digest(path: Path) -> dict[str, object]:
    try:
        digest = _claude_digest(path)
    except OSError:
        return {}
    return {"content_digest": digest}


def _discover_project_markdown_artifacts(
    *,
    root_dir: Path,
    base_dir: Path,
    pattern: str,
    harness: str,
    artifact_type: str,
    artifact_id_prefix: str,
    name_for_path: Callable[[Path, Path], str],
) -> list[GuardArtifact]:
    if not base_dir.is_dir():
        return []
    artifacts: list[GuardArtifact] = []
    for artifact_path in iter_safe_matching_files(root_dir, base_dir, pattern):
        artifact_name = name_for_path(artifact_path, base_dir)
        artifacts.append(
            GuardArtifact(
                artifact_id=f"claude-code:project:{artifact_id_prefix}:{artifact_name}",
                name=artifact_name,
                harness=harness,
                artifact_type=artifact_type,
                source_scope="project",
                config_path=str(artifact_path),
                metadata=_metadata_with_digest(artifact_path),
            )
        )
    return artifacts


class ClaudeCodeHarnessAdapter(HarnessAdapter):
    """Discover Claude Code settings, hooks, and workspace agents."""

    harness = "claude-code"
    executable = "claude"
    aliases = ("claude",)
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard uses Claude hooks first and falls back to the local approval center when the shell cannot prompt."
    )
    fallback_hint = "Claude is the best current harness for deferred Guard approvals."
    approval_prompt_channel = "hook"
    approval_auto_open_browser = False

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return (Path.home() / ".claude" / "local" / "claude",)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".claude" / "settings.local.json"
        return context.home_dir / ".claude" / "settings.json"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_candidates = [context.home_dir / ".claude" / name for name in CLAUDE_SETTINGS_FILES]
        if context.workspace_dir is not None:
            config_candidates.extend(
                (
                    *(context.workspace_dir / ".claude" / name for name in CLAUDE_SETTINGS_FILES),
                    context.workspace_dir / ".mcp.json",
                )
            )
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_candidates:
            payload = _json_payload(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            mcp_servers = payload.get("mcpServers")
            if isinstance(mcp_servers, dict):
                for name, server_config in mcp_servers.items():
                    if not isinstance(name, str) or not isinstance(server_config, dict):
                        continue
                    command = server_config.get("command")
                    url = server_config.get("url")
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"claude-code:{scope}:{name}",
                            name=name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command if isinstance(command, str) else None,
                            args=tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str)),
                            url=url if isinstance(url, str) else None,
                            transport="http" if isinstance(server_config.get("url"), str) else "stdio",
                            metadata={
                                "env_keys": sorted(key for key in server_config.get("env", {}))
                                if isinstance(server_config.get("env"), dict)
                                else [],
                                "headers_keys": sorted(key for key in server_config.get("headers", {}))
                                if isinstance(server_config.get("headers"), dict)
                                else [],
                            },
                        )
                    )
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                for hook_name, hook_entries in hooks.items():
                    if not isinstance(hook_name, str) or not isinstance(hook_entries, list):
                        continue
                    normalized_event = hook_name.strip().lower()
                    for group_index, entry in enumerate(hook_entries):
                        if not isinstance(entry, dict):
                            continue
                        flat_command = entry.get("command")
                        if isinstance(flat_command, str):
                            artifacts.append(
                                GuardArtifact(
                                    artifact_id=f"claude-code:{scope}:{normalized_event}:{group_index}",
                                    name=hook_name,
                                    harness=self.harness,
                                    artifact_type="hook",
                                    source_scope=scope,
                                    config_path=str(config_path),
                                    command=flat_command,
                                )
                            )
                            continue
                        matcher = entry.get("matcher")
                        handlers = entry.get("hooks")
                        if not isinstance(handlers, list):
                            continue
                        for handler_index, handler in enumerate(handlers):
                            if not isinstance(handler, dict):
                                continue
                            command = handler.get("command")
                            metadata: dict[str, object] = {}
                            if isinstance(matcher, str):
                                metadata["matcher"] = matcher
                            handler_type = handler.get("type")
                            if isinstance(handler_type, str):
                                metadata["type"] = handler_type
                            url = handler.get("url")
                            if isinstance(url, str):
                                metadata["url"] = url
                            timeout = handler.get("timeout")
                            if isinstance(timeout, int):
                                metadata["timeout"] = timeout
                            condition = handler.get("if")
                            if isinstance(condition, str):
                                metadata["if"] = condition
                            artifacts.append(
                                GuardArtifact(
                                    artifact_id=f"claude-code:{scope}:{normalized_event}:{group_index}:{handler_index}",
                                    name=hook_name,
                                    harness=self.harness,
                                    artifact_type="hook",
                                    source_scope=scope,
                                    config_path=str(config_path),
                                    command=command if isinstance(command, str) else None,
                                    url=url if isinstance(url, str) else None,
                                    metadata=metadata,
                                )
                            )
        if context.workspace_dir is not None:
            agents_dir = context.workspace_dir / ".claude" / "agents"
            if agents_dir.is_dir() and resolves_within_root(context.workspace_dir, agents_dir, require_exists=True):
                found_paths.append(str(agents_dir))
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        root_dir=context.workspace_dir,
                        base_dir=agents_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="agent",
                        artifact_id_prefix="agent",
                        name_for_path=lambda artifact_path, _base_dir: artifact_path.stem,
                    )
                )
            skills_dir = context.workspace_dir / ".claude" / "skills"
            if skills_dir.is_dir() and resolves_within_root(context.workspace_dir, skills_dir, require_exists=True):
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        root_dir=context.workspace_dir,
                        base_dir=skills_dir,
                        pattern="**/SKILL.md",
                        harness=self.harness,
                        artifact_type="skill",
                        artifact_id_prefix="skill",
                        name_for_path=lambda artifact_path, base_dir: (
                            artifact_path.parent.relative_to(base_dir).as_posix() or artifact_path.parent.name
                        ),
                    )
                )
            commands_dir = context.workspace_dir / ".claude" / "commands"
            if commands_dir.is_dir() and resolves_within_root(context.workspace_dir, commands_dir, require_exists=True):
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        root_dir=context.workspace_dir,
                        base_dir=commands_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="command",
                        artifact_id_prefix="command",
                        name_for_path=lambda artifact_path, _base_dir: artifact_path.stem,
                    )
                )
            rules_dir = context.workspace_dir / ".claude" / "rules"
            if rules_dir.is_dir() and resolves_within_root(context.workspace_dir, rules_dir, require_exists=True):
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        root_dir=context.workspace_dir,
                        base_dir=rules_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="instruction",
                        artifact_id_prefix="instruction",
                        name_for_path=lambda artifact_path, _base_dir: artifact_path.stem,
                    )
                )
            project_claude_md = context.workspace_dir / "CLAUDE.md"
            if project_claude_md.is_file() and resolves_within_root(
                context.workspace_dir,
                project_claude_md,
                require_exists=True,
            ):
                artifacts.append(
                    GuardArtifact(
                        artifact_id="claude-code:project:instruction:claude-md",
                        name="CLAUDE.md",
                        harness=self.harness,
                        artifact_type="instruction",
                        source_scope="project",
                        config_path=str(project_claude_md),
                        metadata=_metadata_with_digest(project_claude_md),
                    )
                )
        resolved_executable = self.resolved_executable(context)
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or resolved_executable is not None,
            command_available=resolved_executable is not None,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )

    @staticmethod
    def _hook_command(context: HarnessContext) -> str:
        command = ClaudeCodeHarnessAdapter._hook_command_parts(context)
        return subprocess.list2cmdline(list(command))

    @staticmethod
    def _daemon_hook_command(context: HarnessContext) -> str:
        command = ClaudeCodeHarnessAdapter._daemon_hook_command_parts(context)
        return _shell_command(command)

    @staticmethod
    def _session_start_command(context: HarnessContext) -> str:
        command = ClaudeCodeHarnessAdapter._session_start_command_parts(context)
        return subprocess.list2cmdline(list(command))

    @staticmethod
    def _hook_http_url(context: HarnessContext) -> str:
        daemon_url = load_guard_daemon_url(context.guard_home) or guard_daemon_url_for_home(context.guard_home)
        query: dict[str, str] = {"guard-home": str(context.guard_home)}
        if context.home_dir.resolve() != Path.home().resolve():
            query["home"] = str(context.home_dir)
        if context.workspace_dir is not None:
            query["workspace"] = str(context.workspace_dir)
        return f"{daemon_url}/v1/hooks/claude-code?{urlencode(query)}"

    @staticmethod
    def _daemon_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        fallback_daemon_url = load_guard_daemon_url(context.guard_home) or guard_daemon_url_for_home(context.guard_home)
        state_path = context.guard_home / "daemon-state.json"
        query: dict[str, str] = {"guard-home": str(context.guard_home)}
        if context.home_dir.resolve() != Path.home().resolve():
            query["home"] = str(context.home_dir)
        if context.workspace_dir is not None:
            query["workspace"] = str(context.workspace_dir)
        js = (
            f"const MARKER={CLAUDE_GUARD_DAEMON_HOOK_MARKER!r};"
            "void MARKER;"
            "const fs=require('fs');"
            "const http=require('http');"
            "const {URL}=require('url');"
            f"const statePath={str(state_path)!r};"
            f"const fallbackUrl={fallback_daemon_url!r};"
            f"const query={urlencode(query)!r};"
            "function daemonUrl(){"
            "try{"
            "const payload=JSON.parse(fs.readFileSync(statePath,'utf8'));"
            "if(Number.isInteger(payload.port))return `http://127.0.0.1:${payload.port}`;"
            "}catch(_error){}"
            "return fallbackUrl;"
            "}"
            "function fail(reason){"
            "const message=`HOL Guard could not evaluate this action: ${reason}`;"
            "process.stdout.write(JSON.stringify({decision:'block',reason:message}));"
            "process.exit(0);"
            "}"
            "let body='';"
            "process.stdin.setEncoding('utf8');"
            "process.stdin.on('data',chunk=>{body+=chunk;});"
            "process.stdin.on('end',()=>{"
            "let endpoint;"
            "try{endpoint=new URL('/v1/hooks/claude-code?'+query,daemonUrl());}"
            "catch(error){fail(error.message);return;}"
            "const data=body.trim()?body:'{}';"
            "const headers={'content-type':'application/json','content-length':Buffer.byteLength(data)};"
            "const request=http.request(endpoint,{method:'POST',headers},response=>{"
            "let responseBody='';"
            "response.setEncoding('utf8');"
            "response.on('data',chunk=>{responseBody+=chunk;});"
            "response.on('end',()=>{"
            "if(response.statusCode>=200&&response.statusCode<300){process.stdout.write(responseBody);process.exit(0);}"
            "fail(`daemon returned HTTP ${response.statusCode||0}`);"
            "});"
            "});"
            "request.on('error',error=>{fail(error.message);});"
            "request.end(data);"
            "});"
        )
        return ("node", "-e", js)

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        guard_args = [
            "guard",
            "hook",
            "--guard-home",
            str(context.guard_home),
        ]
        if context.home_dir.resolve() != Path.home().resolve():
            guard_args.extend(["--home", str(context.home_dir)])
        if context.workspace_dir is not None:
            guard_args.extend(["--workspace", str(context.workspace_dir)])
        package_root = Path(__file__).resolve().parents[3]
        code = (
            "import sys;"
            f"sys.path.insert(0, {str(package_root)!r});"
            "from codex_plugin_scanner.cli import main;"
            f"raise SystemExit(main({guard_args!r}))"
        )
        return (sys.executable, "-c", code)

    @staticmethod
    def _session_start_command_parts(context: HarnessContext) -> tuple[str, ...]:
        package_root = Path(__file__).resolve().parents[3]
        code = (
            "import sys;"
            f"sys.path.insert(0, {str(package_root)!r});"
            "import json;"
            "from pathlib import Path;"
            "from codex_plugin_scanner.guard.daemon import ensure_guard_daemon;"
            "from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter;"
            f"ensure_guard_daemon(Path({str(context.guard_home)!r}));"
            f"ClaudeCodeHarnessAdapter.refresh_installed_hook_urls(home_dir=Path({str(context.home_dir)!r}), "
            f"workspace_dir=Path({str(context.workspace_dir)!r}), guard_home=Path({str(context.guard_home)!r}));"
            "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'SessionStart', "
            "'additionalContext': 'HOL Guard protection is active for this workspace.'}}, "
            "separators=(',', ':')))"
        )
        return (sys.executable, "-c", code)

    @classmethod
    def refresh_installed_hook_urls(cls, *, home_dir: Path, workspace_dir: Path, guard_home: Path) -> None:
        cls().refresh_runtime_hook_urls(
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
        )

    def refresh_runtime_hook_urls(self, context: HarnessContext) -> None:
        if context.workspace_dir is None:
            return
        settings_path = context.workspace_dir / ".claude" / "settings.local.json"
        payload = _json_payload(settings_path)
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            return
        _sync_runtime_hook_groups(hooks, self._daemon_hook_command(context))
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        resolved_executable = self.resolved_executable(context)
        if resolved_executable is None:
            return None
        return _run_command_probe([resolved_executable, "--help"], timeout_seconds=5)

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name="claude",
            display_name="claude",
        )
        if context.workspace_dir is None:
            return {
                "harness": self.harness,
                "active": True,
                "config_path": shim_manifest["shim_path"],
                **shim_manifest,
            }
        settings_path = context.workspace_dir / ".claude" / "settings.local.json"
        _ensure_path_within_root(context.workspace_dir, settings_path, label="Claude Code")
        payload = _json_payload(settings_path)
        session_start_command = self._session_start_command(context)
        hook_command = self._daemon_hook_command(context)
        hooks = payload.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            hooks = {}
            payload["hooks"] = hooks
        session_start_entries = _prune_guard_hook_entries(
            hooks.get("SessionStart") if isinstance(hooks.get("SessionStart"), list) else []
        )
        session_start_handler = _guard_command_handler(
            session_start_command,
            timeout=CLAUDE_GUARD_SESSION_START_TIMEOUT_SECONDS,
        )
        for matcher in CLAUDE_GUARD_SESSION_START_MATCHERS:
            session_start_entries = _merge_hook_group(session_start_entries, matcher, session_start_handler)
        hooks["SessionStart"] = session_start_entries
        _sync_runtime_hook_groups(hooks, hook_command)
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries added to .claude/settings.local.json",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name="claude",
            display_name="claude",
            legacy_launcher_names=("claude-code",),
        )
        if context.workspace_dir is None:
            return {
                "harness": self.harness,
                "active": False,
                "config_path": shim_manifest["shim_path"],
                **shim_manifest,
            }
        settings_path = context.workspace_dir / ".claude" / "settings.local.json"
        _ensure_path_within_root(context.workspace_dir, settings_path, label="Claude Code")
        payload = _json_payload(settings_path)
        hooks = payload.get("hooks")
        if isinstance(hooks, dict):
            for key in ("SessionStart", "PreToolUse", "PostToolUse", "UserPromptSubmit", "Notification"):
                entries = hooks.get(key)
                hooks[key] = _prune_guard_hook_entries(entries if isinstance(entries, list) else [])
            settings_path.parent.mkdir(parents=True, exist_ok=True)
            settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries removed from .claude/settings.local.json",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }
