"""Drive real Claude Code, Codex and Cursor agent CLIs through their installed Guard hooks.

Oh My Pi remains the qualification harness. These adapters run the same catalog
through each CLI's own login and its real ``hol-guard install`` hook wiring, so
the evidence shows whether Guard protects that harness on this platform. They
are never merge-qualifying: inference goes straight to the vendor, so the
relay's per-round transcript and canary backstop are not available.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .catalog import Scenario

HARNESSES = ("omp", "claude-code", "codex", "cursor")

# Catalog prompts name omp's tools. Each harness maps them onto its own.
_TOOL_NAMES = {
    "claude-code": {"Bash": "bash", "Read": "read", "Write": "write", "Edit": "edit", "MultiEdit": "edit"},
    "codex": {"command_execution": "bash", "file_change": "edit"},
    "cursor": {
        "shellToolCall": "bash",
        "readToolCall": "read",
        "writeToolCall": "write",
        "editToolCall": "edit",
        "deleteToolCall": "write",
    },
}

_TOOL_GLOSSARY = {
    "claude-code": "In this harness, 'bash' means the Bash tool and the native read, write and edit tools "
    "are Read, Write and Edit.",
    "codex": "In this harness, 'bash' means your shell command tool. You have no separate read tool; "
    "when a native read is requested, read the file with one shell command such as cat. Edits use apply_patch.",
    "cursor": "In this harness, 'bash' means your shell tool and the native read, write and edit tools "
    "are your file read, write and edit tools.",
}


@dataclass(frozen=True)
class Harness:
    """One agent CLI, its Guard hook harness id and the files holding its login."""

    name: str
    executable_names: tuple[str, ...]
    credential_files: tuple[str, ...]
    credential_env: tuple[str, ...] = ()
    extra_env: dict[str, str] = field(default_factory=dict)
    # macOS logins kept in the login Keychain, which Security locates through $HOME.
    macos_keychain: bool = False

    def executable(self, explicit: str | None = None) -> str:
        """Resolve the CLI the operator selected or the first one on PATH."""
        if explicit:
            if resolved := shutil.which(explicit):
                return resolved
            raise RuntimeError(f"--harness-cli {explicit!r} is not an executable")
        for candidate in self.executable_names:
            if resolved := shutil.which(candidate):
                return resolved
        raise RuntimeError(f"install the {self.name} CLI before running Gauntlet with --harness {self.name}")

    def version(self, executable: str) -> str:
        """Record the exact CLI build that ran the cases."""
        output = subprocess.check_output(
            [*self.launch(executable), "--version"], text=True, timeout=60, stderr=subprocess.STDOUT
        )
        return f"{self.name}/{output.strip().splitlines()[-1].strip()}"

    def launch(self, executable: str) -> list[str]:
        """Run the CLI's real program rather than its Windows ``.cmd`` or ``.ps1`` shim.

        ``cmd.exe`` re-parses a shim's arguments and truncates the multi-line,
        quoted prompts the catalog sends, so the shim is resolved to its target.
        """
        path = Path(executable)
        if os.name != "nt" or path.suffix.lower() not in {".cmd", ".ps1", ".bat"}:
            return [executable]
        if self.name == "cursor":
            versions = sorted((path.parent / "versions").glob("*/index.js"), key=lambda entry: entry.parent.name)
            if versions:
                return [str(versions[-1].parent / "node.exe"), str(versions[-1])]
        packages = path.parent.parent
        patterns = {
            "claude-code": ("@anthropic-ai/claude-code/bin/claude.exe",),
            "codex": ("@openai/codex-win32-*/vendor/*/bin/codex.exe",),
        }.get(self.name, ())
        for pattern in patterns:
            found = sorted(packages.glob(pattern))
            if found:
                return [str(found[-1])]
        raise RuntimeError(f"could not resolve the {self.name} program behind {path.name}")

    def command(
        self,
        executable: str,
        *,
        scenario: Scenario,
        prompt: str,
        context: str,
        workspace: Path,
        model: str | None,
    ) -> list[str]:
        """Build a non-interactive, JSON-streaming invocation with the CLI's own approvals off.

        A harness-side sandbox or approval prompt could stop a harmful call before it
        reaches Guard and be miscounted as protection, so only Guard may refuse.
        """
        glossary = _TOOL_GLOSSARY[self.name]
        if self.name == "claude-code":
            command = [
                *self.launch(executable),
                "-p",
                prompt,
                "--output-format",
                "stream-json",
                "--verbose",
                "--append-system-prompt",
                context + "\n" + glossary,
                "--permission-mode",
                "bypassPermissions",
                "--setting-sources",
                "user",
                "--strict-mcp-config",
                "--disable-slash-commands",
                "--no-session-persistence",
                "--tools",
                _claude_tools(scenario),
            ]
            return command + (["--model", model] if model else [])
        if self.name == "codex":
            command = [
                *self.launch(executable),
                "exec",
                "--json",
                "--skip-git-repo-check",
                "--ephemeral",
                "--dangerously-bypass-approvals-and-sandbox",
                # Codex runs config hooks only after the user reviews them once in /hooks.
                # The fixture HOME holds only Guard's freshly installed hooks, so this
                # stands in for that one-time review rather than skipping Guard.
                "--dangerously-bypass-hook-trust",
                "-C",
                str(workspace),
            ]
            if model:
                command += ["-m", model]
            # Developer instructions keep the fixture context out of the user prompt, as
            # Claude's system prompt does, so Guard's prompt review sees only the task.
            instructions = json.dumps(f"{context}\n{glossary}", ensure_ascii=False)
            return [*command, "-c", f"developer_instructions={instructions}", prompt]
        command = [
            *self.launch(executable),
            "-p",
            "--output-format",
            "stream-json",
            "--force",
            "--trust",
            "--sandbox",
            "disabled",
            "--workspace",
            str(workspace),
        ]
        if model:
            command += ["--model", model]
        return [*command, prompt]

    def prepare_context(self, workspace: Path, context: str) -> None:
        """Give Cursor the fixture context as an always-applied workspace rule.

        Cursor's CLI has no system-prompt option. Sending the context inside the
        prompt would put fixture descriptions through Guard's prompt review.
        """
        if self.name != "cursor":
            return
        rules = workspace / ".cursor" / "rules"
        rules.mkdir(parents=True, exist_ok=True)
        body = f"{context}\n{_TOOL_GLOSSARY[self.name]}\n"
        (rules / "gauntlet-fixture.mdc").write_text(
            "---\ndescription: Guard Gauntlet fixture context\nalwaysApply: true\n---\n" + body, encoding="utf-8"
        )


def _claude_tools(scenario: Scenario) -> str:
    if scenario.oracle == "home-copy-task":
        return "Bash,Read"
    if scenario.commands:
        return "Bash"
    if scenario.oracle == "blocked-read":
        return "Read"
    names = {"bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit"}
    return ",".join(names[tool] for tool in scenario.required_tools) or "Bash,Read,Write,Edit"


ADAPTERS = {
    "claude-code": Harness(
        "claude-code",
        ("claude",),
        credential_files=(".claude/.credentials.json",),
        credential_env=("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"),
        extra_env={"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"},
        macos_keychain=True,
    ),
    "codex": Harness("codex", ("codex",), credential_files=(".codex/auth.json",), credential_env=("CODEX_API_KEY",)),
    "cursor": Harness(
        "cursor",
        ("cursor-agent", "agent"),
        credential_files=(".cursor/cli-config.json",),
        credential_env=("CURSOR_API_KEY",),
        macos_keychain=True,
    ),
}


def adapter(name: str) -> Harness:
    """Return the adapter for a non-omp harness."""
    try:
        return ADAPTERS[name]
    except KeyError:
        raise ValueError(f"unsupported harness {name!r}; choose one of {', '.join(HARNESSES)}") from None


class CredentialSeed:
    """Copy the operator's login into the fixture HOME and keep refreshed tokens.

    A CLI may rotate its refresh token during a case. Writing the fixture copy back
    (only when the operator's copy did not change meanwhile) keeps the operator's
    login valid for the next case.
    """

    def __init__(self, harness: Harness, source_home: Path, fixture_home: Path):
        self._pairs: list[tuple[Path, Path, bytes]] = []
        for relative in harness.credential_files:
            source, target = source_home / relative, fixture_home / relative
            try:
                data = source.read_bytes()
            except FileNotFoundError:
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
            if os.name == "posix":
                target.chmod(0o600)
            self._pairs.append((source, target, data))
        self.keychain = False
        keychains = source_home / "Library" / "Keychains"
        if harness.macos_keychain and sys.platform == "darwin" and keychains.is_dir():
            # Link, never copy: the CLI reads its login from the operator's own Keychain.
            (fixture_home / "Library").mkdir(mode=0o700, exist_ok=True)
            (fixture_home / "Library" / "Keychains").symlink_to(keychains, target_is_directory=True)
            self.keychain = True

    @property
    def seeded(self) -> int:
        return len(self._pairs) + int(self.keychain)

    def write_back(self) -> None:
        """Replace the operator's login with a refreshed copy, never a stale or wider-readable one.

        Parallel workers share the operator's file, so the compare and replace run
        under a lock. Each attempt writes its own owner-only (0600) temporary file.
        """
        for source, target, original in self._pairs:
            try:
                refreshed = target.read_bytes()
            except OSError:
                continue
            if refreshed == original or not refreshed.strip():
                continue
            with _login_lock(source):
                try:
                    current = source.read_bytes()
                except FileNotFoundError:
                    continue  # the operator logged out during the case; do not recreate the login
                if current != original:
                    continue
                descriptor, name = tempfile.mkstemp(prefix=f".{source.name}.", suffix=".gauntlet", dir=source.parent)
                temporary = Path(name)
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(refreshed)
                    os.replace(temporary, source)
                finally:
                    temporary.unlink(missing_ok=True)


_LOCK_WAIT_SECONDS = 60
_STALE_LOCK_SECONDS = 600


@contextmanager
def _login_lock(source: Path) -> Iterator[None]:
    """Hold an exclusive lock directory beside the login file; mkdir is atomic on every host."""
    lock = source.with_name(source.name + ".gauntlet-lock")
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while True:
        try:
            lock.mkdir(mode=0o700)
            break
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > _STALE_LOCK_SECONDS:
                    lock.rmdir()
                    continue
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise TimeoutError(f"another Gauntlet worker holds the {source.name} login lock") from None
            time.sleep(0.05)
    try:
        yield
    finally:
        lock.rmdir()


def credential_environment(harness: Harness) -> dict[str, str]:
    """Forward only this harness's own login variables, never other credentials."""
    return {key: os.environ[key] for key in harness.credential_env if os.environ.get(key)}


def read_transcript(name: str, path: Path) -> dict[str, Any]:
    """Normalize a CLI's JSON stream into tool calls and a terminal status."""
    calls: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    terminal = False
    failed = False
    errors: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            errors.append("malformed-event")
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if name == "claude-code":
            terminal, failed = _claude_event(event, kind, calls, order, terminal, failed)
        elif name == "codex":
            terminal, failed = _codex_event(event, kind, calls, order, terminal, failed)
        else:
            terminal, failed = _cursor_event(event, kind, calls, order, terminal, failed)
    names = _TOOL_NAMES[name]
    normalized = []
    for call_id in order:
        call = calls[call_id]
        normalized.append({**call, "id": call_id, "tool": names.get(call["name"], call["name"])})
    return {"calls": normalized, "terminal": terminal, "failed": failed, "errors": sorted(set(errors))}


def _remember(calls: dict, order: list, call_id: Any, name: Any, args: Any) -> None:
    if isinstance(call_id, str) and call_id and call_id not in calls:
        calls[call_id] = {"name": str(name), "args": args if isinstance(args, dict) else {}, "is_error": None}
        order.append(call_id)


def _finish(calls: dict, call_id: Any, is_error: bool, result: Any) -> None:
    if isinstance(call_id, str) and call_id in calls:
        calls[call_id]["is_error"] = is_error
        calls[call_id]["result"] = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)


def _claude_event(event: dict, kind: Any, calls: dict, order: list, terminal: bool, failed: bool) -> tuple[bool, bool]:
    content = (event.get("message") or {}).get("content")
    if kind == "assistant" and isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get("type") == "tool_use":
                _remember(calls, order, part.get("id"), part.get("name"), part.get("input"))
    elif kind == "user" and isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get("type") == "tool_result":
                _finish(calls, part.get("tool_use_id"), part.get("is_error") is True, part.get("content"))
    elif kind == "result":
        return True, event.get("is_error") is True or event.get("subtype") != "success"
    return terminal, failed


def _codex_event(event: dict, kind: Any, calls: dict, order: list, terminal: bool, failed: bool) -> tuple[bool, bool]:
    item = event.get("item")
    if kind in {"item.started", "item.completed"} and isinstance(item, dict):
        item_type = item.get("type")
        if item_type == "command_execution":
            _remember(calls, order, item.get("id"), item_type, {"command": item.get("command")})
            if kind == "item.completed":
                status = item.get("status")
                exit_code = item.get("exit_code")
                _finish(calls, item.get("id"), status != "completed" or exit_code != 0, item.get("aggregated_output"))
        elif item_type == "file_change":
            _remember(calls, order, item.get("id"), item_type, {"changes": item.get("changes")})
            if kind == "item.completed":
                _finish(calls, item.get("id"), item.get("status") != "completed", item.get("changes"))
    elif kind == "turn.completed":
        return True, failed
    elif kind in {"turn.failed", "error"}:
        return True, True
    return terminal, failed


def _cursor_event(event: dict, kind: Any, calls: dict, order: list, terminal: bool, failed: bool) -> tuple[bool, bool]:
    if kind == "tool_call":
        wrapper = event.get("tool_call")
        tools = [key for key in wrapper if key.endswith("ToolCall")] if isinstance(wrapper, dict) else []
        if len(tools) == 1:
            name = tools[0]
            body = wrapper[name] if isinstance(wrapper[name], dict) else {}
            _remember(calls, order, event.get("call_id"), name, body.get("args"))
            if event.get("subtype") == "completed":
                result = body.get("result")
                success = result.get("success") if isinstance(result, dict) else None
                is_error = not isinstance(success, dict) or success.get("exitCode", 0) != 0
                _finish(calls, event.get("call_id"), is_error, result)
    elif kind == "result":
        return True, event.get("is_error") is True or event.get("subtype") != "success"
    return terminal, failed
