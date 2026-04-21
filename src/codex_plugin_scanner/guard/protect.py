"""Install-time Guard protection helpers."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from .models import GuardReceipt
from .receipts import build_receipt
from .store import GuardStore

ProtectAction = Literal["allow", "review", "block"]
SeverityLabel = Literal["low", "medium", "high", "critical"]

_SEVERITY_ORDER: dict[SeverityLabel, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}
_DEFAULT_PROTECT_TIMEOUT_SECONDS = 300
_MAX_PROTECT_TIMEOUT_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class ProtectTarget:
    """A requested install or registration target."""

    artifact_id: str
    artifact_name: str
    artifact_type: str
    ecosystem: str
    package_name: str | None
    raw_spec: str | None
    version: str | None
    source_url: str | None
    harness: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "artifact_type": self.artifact_type,
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "raw_spec": self.raw_spec,
            "version": self.version,
            "source_url": self.source_url,
            "harness": self.harness,
        }


@dataclass(frozen=True, slots=True)
class ProtectRequest:
    """Parsed install-time command."""

    command: tuple[str, ...]
    install_kind: str
    executor: str
    package_manager: str | None
    harness: str | None
    targets: tuple[ProtectTarget, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "command": list(self.command),
            "install_kind": self.install_kind,
            "executor": self.executor,
            "package_manager": self.package_manager,
            "harness": self.harness,
            "targets": [target.to_dict() for target in self.targets],
        }


@dataclass(frozen=True, slots=True)
class ProtectVerdict:
    """Decision returned before install execution."""

    action: ProtectAction
    reason: str
    risk_signals: tuple[str, ...]
    matched_advisories: tuple[dict[str, object], ...]

    @property
    def blocking(self) -> bool:
        return self.action != "allow"

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "reason": self.reason,
            "risk_signals": list(self.risk_signals),
            "matched_advisories": list(self.matched_advisories),
            "blocking": self.blocking,
        }


def build_protect_payload(
    *,
    command: list[str],
    store: GuardStore,
    workspace_dir: Path,
    dry_run: bool,
    now: str,
) -> tuple[dict[str, object], int]:
    """Evaluate and optionally execute an install command."""

    if len(command) == 0:
        raise ValueError("Guard protect requires a command to wrap.")
    request = parse_protect_command(command)
    advisories = store.list_cached_advisories(limit=None)
    verdict = evaluate_protect_request(request, advisories)
    receipt = _build_install_receipt(request, verdict)
    payload: dict[str, object] = {
        "generated_at": now,
        "request": request.to_dict(),
        "targets": [target.to_dict() for target in request.targets],
        "verdict": verdict.to_dict(),
        "executed": False,
        "dry_run": dry_run,
        "receipt": receipt.to_dict(),
        "matched_advisories": list(verdict.matched_advisories),
    }
    if verdict.blocking or dry_run:
        store.add_receipt(receipt)
        store.add_event(
            f"install_time_{verdict.action}",
            {
                "artifact_id": request.targets[0].artifact_id,
                "artifact_name": request.targets[0].artifact_name,
                "executor": request.executor,
                "install_kind": request.install_kind,
                "action": verdict.action,
                "risk_signals": list(verdict.risk_signals),
            },
            now,
        )
        return (payload, 2 if verdict.blocking else 0)
    execution = subprocess.run(
        list(request.command),
        cwd=workspace_dir,
        capture_output=True,
        check=False,
        text=True,
        timeout=_protect_command_timeout_seconds(),
    )
    payload["executed"] = True
    payload["execution"] = {
        "returncode": execution.returncode,
        "stdout": execution.stdout,
        "stderr": execution.stderr,
    }
    if execution.returncode == 0:
        store.add_receipt(receipt)
        store.add_event(
            "install_time_allow",
            {
                "artifact_id": request.targets[0].artifact_id,
                "artifact_name": request.targets[0].artifact_name,
                "executor": request.executor,
                "install_kind": request.install_kind,
                "action": verdict.action,
                "risk_signals": list(verdict.risk_signals),
            },
            now,
        )
    else:
        store.add_event(
            "install_time_execution_failed",
            {
                "artifact_id": request.targets[0].artifact_id,
                "artifact_name": request.targets[0].artifact_name,
                "executor": request.executor,
                "install_kind": request.install_kind,
                "action": verdict.action,
                "returncode": execution.returncode,
                "risk_signals": list(verdict.risk_signals),
            },
            now,
        )
    return (payload, int(execution.returncode))


def _protect_command_timeout_seconds() -> int:
    raw_timeout = os.getenv("GUARD_PROTECT_TIMEOUT_SECONDS")
    if raw_timeout is None:
        return _DEFAULT_PROTECT_TIMEOUT_SECONDS
    try:
        parsed_timeout = int(raw_timeout)
    except ValueError:
        return _DEFAULT_PROTECT_TIMEOUT_SECONDS
    if parsed_timeout < 1:
        return _DEFAULT_PROTECT_TIMEOUT_SECONDS
    return min(parsed_timeout, _MAX_PROTECT_TIMEOUT_SECONDS)


def parse_protect_command(command: list[str]) -> ProtectRequest:
    """Parse a package install or harness registration command."""

    executable = Path(command[0]).name.lower()
    handlers = {
        "npm": _parse_npm_request,
        "pnpm": _parse_pnpm_request,
        "yarn": _parse_yarn_request,
        "pip": _parse_pip_request,
        "uv": _parse_uv_request,
        "go": _parse_go_request,
        "claude": _parse_claude_request,
        "codex": _parse_codex_request,
        "cursor": _parse_cursor_request,
        "antigravity": _parse_antigravity_request,
        "gemini": _parse_gemini_request,
        "opencode": _parse_opencode_request,
    }
    handler = handlers.get(executable, _parse_custom_request)
    return handler(command)


def evaluate_protect_request(
    request: ProtectRequest,
    advisories: list[dict[str, object]],
) -> ProtectVerdict:
    """Calculate the local install-time verdict."""

    risk_signals = _request_risk_signals(request)
    matched_advisories = _matching_advisories(request, advisories)
    blocking_advisories = [item for item in matched_advisories if _advisory_action(item) == "block"]
    review_advisories = [item for item in matched_advisories if _advisory_action(item) == "review"]
    if blocking_advisories:
        headline = _advisory_headline(blocking_advisories[0])
        reason = f"{headline} Guard blocked the install before the artifact landed locally."
        return ProtectVerdict("block", reason, risk_signals, tuple(matched_advisories))
    if len(risk_signals) > 0 or review_advisories:
        reason = _review_reason(request, risk_signals, review_advisories)
        return ProtectVerdict("review", reason, risk_signals, tuple(matched_advisories))
    return ProtectVerdict(
        "allow",
        "Guard found no blocking advisory or risky install signal for this request.",
        risk_signals,
        tuple(matched_advisories),
    )


def _parse_npm_request(command: list[str]) -> ProtectRequest:
    specs = _collect_package_specs(command[2:]) if len(command) > 1 and command[1] in {"install", "add", "i"} else ()
    return _package_manager_request(command, "npm", specs)


def _parse_pnpm_request(command: list[str]) -> ProtectRequest:
    specs = _collect_package_specs(command[2:]) if len(command) > 1 and command[1] in {"add", "install"} else ()
    return _package_manager_request(command, "pnpm", specs)


def _parse_yarn_request(command: list[str]) -> ProtectRequest:
    specs = _collect_package_specs(command[2:]) if len(command) > 1 and command[1] == "add" else ()
    return _package_manager_request(command, "yarn", specs)


def _parse_pip_request(command: list[str]) -> ProtectRequest:
    specs = _collect_package_specs(command[2:]) if len(command) > 1 and command[1] == "install" else ()
    return _package_manager_request(command, "pip", specs)


def _parse_uv_request(command: list[str]) -> ProtectRequest:
    specs = _collect_uv_specs(command)
    return _package_manager_request(command, "uv", specs)


def _parse_go_request(command: list[str]) -> ProtectRequest:
    specs = _collect_package_specs(command[2:]) if len(command) > 1 and command[1] in {"get", "install"} else ()
    return _package_manager_request(command, "go", specs)


def _parse_codex_request(command: list[str]) -> ProtectRequest:
    if len(command) >= 4 and command[1:3] == ["mcp", "add"]:
        name = command[3]
        target = ProtectTarget(
            artifact_id=f"install:codex:{name}",
            artifact_name=name,
            artifact_type="mcp_server",
            ecosystem="codex",
            package_name=name,
            raw_spec=name,
            version=None,
            source_url=_option_value(command, "--url"),
            harness="codex",
        )
        return ProtectRequest(tuple(command), "harness_registration", "codex", None, "codex", (target,))
    return _parse_custom_request(command)


def _parse_claude_request(command: list[str]) -> ProtectRequest:
    if len(command) >= 5 and command[1:3] == ["mcp", "add"]:
        positional = _remaining_positionals(command[3:])
        if len(positional) < 2:
            return _parse_custom_request(command)
        name = positional[0]
        command_or_url = positional[1]
        target = ProtectTarget(
            artifact_id=f"install:claude-code:mcp:{name}",
            artifact_name=name,
            artifact_type="mcp_server",
            ecosystem="claude-code",
            package_name=name,
            raw_spec=command_or_url,
            version=None,
            source_url=command_or_url if command_or_url.startswith(("http://", "https://")) else None,
            harness="claude-code",
        )
        return ProtectRequest(tuple(command), "harness_registration", "claude", None, "claude-code", (target,))
    if len(command) >= 5 and command[1:3] == ["mcp", "add-json"]:
        positional = _remaining_positionals(command[3:])
        if len(positional) < 2:
            return _parse_custom_request(command)
        name = positional[0]
        target = _parse_claude_mcp_target(name, positional[1])
        return ProtectRequest(tuple(command), "harness_registration", "claude", None, "claude-code", (target,))
    return _parse_custom_request(command)


def _parse_cursor_request(command: list[str]) -> ProtectRequest:
    if len(command) >= 4 and command[1:3] == ["mcp", "add"]:
        name = command[3]
        target = ProtectTarget(
            artifact_id=f"install:cursor:{name}",
            artifact_name=name,
            artifact_type="mcp_server",
            ecosystem="cursor",
            package_name=name,
            raw_spec=name,
            version=None,
            source_url=_option_value(command, "--url"),
            harness="cursor",
        )
        return ProtectRequest(tuple(command), "harness_registration", "cursor", None, "cursor", (target,))
    return _parse_custom_request(command)


def _parse_gemini_request(command: list[str]) -> ProtectRequest:
    if len(command) >= 4 and command[1:3] == ["extensions", "install"]:
        name = command[3]
        target = ProtectTarget(
            artifact_id=f"install:gemini:{name}",
            artifact_name=name,
            artifact_type="extension",
            ecosystem="gemini",
            package_name=name,
            raw_spec=name,
            version=None,
            source_url=_option_value(command, "--url"),
            harness="gemini",
        )
        return ProtectRequest(tuple(command), "harness_registration", "gemini", None, "gemini", (target,))
    if len(command) >= 4 and tuple(command[1:3]) in {
        ("extensions", "link"),
        ("skills", "install"),
        ("skills", "link"),
    }:
        spec = command[3]
        name = _target_name_from_spec(spec)
        artifact_type = "extension" if command[1] == "extensions" else "skill"
        target = ProtectTarget(
            artifact_id=f"install:gemini:{artifact_type}:{name}",
            artifact_name=name,
            artifact_type=artifact_type,
            ecosystem="gemini",
            package_name=name if artifact_type == "extension" else None,
            raw_spec=spec,
            version=None,
            source_url=_spec_url(spec),
            harness="gemini",
        )
        return ProtectRequest(tuple(command), "harness_registration", "gemini", None, "gemini", (target,))
    if len(command) >= 5 and command[1:3] == ["mcp", "add"]:
        name = command[3]
        command_or_url = command[4]
        transport = _option_value(command, "--transport") or _option_value(command, "--type")
        source_url = command_or_url if _is_remote_transport(command_or_url, transport) else None
        target = ProtectTarget(
            artifact_id=f"install:gemini:mcp:{name}",
            artifact_name=name,
            artifact_type="mcp_server",
            ecosystem="gemini",
            package_name=name,
            raw_spec=command_or_url,
            version=None,
            source_url=source_url,
            harness="gemini",
        )
        return ProtectRequest(tuple(command), "harness_registration", "gemini", None, "gemini", (target,))
    return _parse_custom_request(command)


def _parse_antigravity_request(command: list[str]) -> ProtectRequest:
    extension_name = _option_value(command, "--install-extension")
    if extension_name is not None:
        target = ProtectTarget(
            artifact_id=f"install:antigravity:extension:{extension_name}",
            artifact_name=extension_name,
            artifact_type="extension",
            ecosystem="antigravity",
            package_name=extension_name,
            raw_spec=extension_name,
            version=None,
            source_url=_spec_url(extension_name),
            harness="antigravity",
        )
        return ProtectRequest(tuple(command), "harness_registration", "antigravity", None, "antigravity", (target,))
    raw_mcp_payload = _option_value(command, "--add-mcp")
    if raw_mcp_payload is not None:
        target = _parse_antigravity_mcp_target(raw_mcp_payload)
        return ProtectRequest(tuple(command), "harness_registration", "antigravity", None, "antigravity", (target,))
    return _parse_custom_request(command)


def _parse_opencode_request(command: list[str]) -> ProtectRequest:
    if len(command) >= 4 and command[1] in {"plugin", "skill"} and command[2] in {"add", "install"}:
        name = command[3]
        target = ProtectTarget(
            artifact_id=f"install:opencode:{name}",
            artifact_name=name,
            artifact_type="plugin" if command[1] == "plugin" else "skill",
            ecosystem="opencode",
            package_name=name,
            raw_spec=name,
            version=None,
            source_url=_option_value(command, "--url"),
            harness="opencode",
        )
        return ProtectRequest(tuple(command), "harness_registration", "opencode", None, "opencode", (target,))
    return _parse_custom_request(command)


def _parse_custom_request(command: list[str]) -> ProtectRequest:
    executable = Path(command[0]).name
    target = ProtectTarget(
        artifact_id=f"install:custom:{_command_fingerprint(command)[:16]}",
        artifact_name=executable,
        artifact_type="custom_command",
        ecosystem="custom",
        package_name=None,
        raw_spec=shlex.join(command),
        version=None,
        source_url=_first_url(command),
        harness=None,
    )
    return ProtectRequest(tuple(command), "custom", executable, None, None, (target,))


def _package_manager_request(command: list[str], ecosystem: str, specs: tuple[str, ...]) -> ProtectRequest:
    targets = tuple(_package_target(ecosystem, spec) for spec in specs)
    if len(targets) == 0:
        targets = (
            ProtectTarget(
                artifact_id=f"install:{ecosystem}:{_command_fingerprint(command)[:16]}",
                artifact_name=ecosystem,
                artifact_type="package_request",
                ecosystem=ecosystem,
                package_name=None,
                raw_spec=shlex.join(command),
                version=None,
                source_url=_first_url(command),
                harness=None,
            ),
        )
    return ProtectRequest(tuple(command), "package_install", ecosystem, ecosystem, None, targets)


def _package_target(ecosystem: str, spec: str) -> ProtectTarget:
    package_name, version = _parse_package_identity(ecosystem, spec)
    source_url = _spec_url(spec)
    identity = package_name or spec
    return ProtectTarget(
        artifact_id=f"install:{ecosystem}:{identity}",
        artifact_name=identity,
        artifact_type=f"{ecosystem}_package",
        ecosystem=ecosystem,
        package_name=package_name,
        raw_spec=spec,
        version=version,
        source_url=source_url,
        harness=None,
    )


def _collect_package_specs(values: list[str]) -> tuple[str, ...]:
    specs: list[str] = []
    skip_next = False
    for index, value in enumerate(values):
        if skip_next:
            skip_next = False
            continue
        if value.startswith("-"):
            if value in {"-r", "--requirement", "--index-url", "--extra-index-url", "--registry"}:
                skip_next = True
            continue
        if index > 0 and values[index - 1] in {"-r", "--requirement"}:
            continue
        specs.append(value)
    return tuple(specs)


def _collect_uv_specs(command: list[str]) -> tuple[str, ...]:
    if len(command) >= 3 and command[1:3] == ["pip", "install"]:
        return _collect_package_specs(command[3:])
    if len(command) >= 2 and command[1] == "add":
        return _collect_package_specs(command[2:])
    return ()


def _parse_package_identity(ecosystem: str, spec: str) -> tuple[str | None, str | None]:
    if ecosystem in {"pip", "uv"} and "==" in spec:
        name, version = spec.split("==", 1)
        return (name, version)
    if ecosystem == "go" and "@" in spec:
        name, version = spec.rsplit("@", 1)
        return (name, version)
    if spec.startswith("@") and spec.count("@") >= 2:
        name, version = spec.rsplit("@", 1)
        return (name, version)
    if "@" in spec and not spec.startswith(("http://", "https://", "git+", "file:")):
        name, version = spec.rsplit("@", 1)
        return (name, version)
    return (_spec_name(spec), None)


def _spec_name(spec: str) -> str | None:
    if spec.startswith(("http://", "https://", "git+", "file:")):
        parsed = urlparse(spec)
        candidate = Path(parsed.path or spec).name
        return candidate or spec
    if spec.startswith(("./", "../", "/")):
        return Path(spec).name or spec
    return spec or None


def _spec_url(spec: str) -> str | None:
    if spec.startswith(("http://", "https://", "git+", "file:")):
        return spec
    return None


def _target_name_from_spec(spec: str) -> str:
    parsed_name = _spec_name(spec)
    if parsed_name is None:
        return spec
    return parsed_name.removesuffix(".git")


def _option_value(command: list[str], option: str) -> str | None:
    for index, value in enumerate(command):
        if value == option and index + 1 < len(command):
            return command[index + 1]
    return None


def _remaining_positionals(args: list[str]) -> list[str]:
    positionals: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            positionals.extend(args[index + 1 :])
            break
        if token.startswith("--"):
            if "=" not in token and index + 1 < len(args) and not args[index + 1].startswith("-"):
                index += 2
                continue
            index += 1
            continue
        if token.startswith("-") and token != "-":
            if len(token) == 2 and index + 1 < len(args) and not args[index + 1].startswith("-"):
                index += 2
                continue
            index += 1
            continue
        positionals.append(token)
        index += 1
    return positionals


def _first_url(command: list[str]) -> str | None:
    for value in command:
        if value.startswith(("http://", "https://", "git+", "file:")):
            return value
    return None


def _parse_antigravity_mcp_target(raw_payload: str) -> ProtectTarget:
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    name = payload.get("name") if isinstance(payload.get("name"), str) else "antigravity-mcp"
    command_or_url = payload.get("url") if isinstance(payload.get("url"), str) else None
    if command_or_url is None and isinstance(payload.get("command"), str):
        command_or_url = payload["command"]
    source_url = (
        command_or_url if isinstance(command_or_url, str) and _is_remote_transport(command_or_url, None) else None
    )
    return ProtectTarget(
        artifact_id=f"install:antigravity:mcp:{name}",
        artifact_name=name,
        artifact_type="mcp_server",
        ecosystem="antigravity",
        package_name=name,
        raw_spec=raw_payload,
        version=None,
        source_url=source_url,
        harness="antigravity",
    )


def _parse_claude_mcp_target(name: str, raw_payload: str) -> ProtectTarget:
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    transport = payload.get("transport") if isinstance(payload.get("transport"), str) else None
    command_or_url = payload.get("url") if isinstance(payload.get("url"), str) else None
    if command_or_url is None and isinstance(payload.get("command"), str):
        command_or_url = payload["command"]
    source_url = (
        command_or_url if isinstance(command_or_url, str) and _is_remote_transport(command_or_url, transport) else None
    )
    return ProtectTarget(
        artifact_id=f"install:claude-code:mcp:{name}",
        artifact_name=name,
        artifact_type="mcp_server",
        ecosystem="claude-code",
        package_name=name,
        raw_spec=raw_payload,
        version=None,
        source_url=source_url,
        harness="claude-code",
    )


def _is_remote_transport(command_or_url: str, transport: str | None) -> bool:
    if transport == "stdio":
        return False
    if transport in {"http", "sse"}:
        return command_or_url.startswith(("http://", "https://"))
    return command_or_url.startswith(("http://", "https://"))


def _matching_advisories(
    request: ProtectRequest,
    advisories: list[dict[str, object]],
) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    for advisory in advisories:
        for target in request.targets:
            if _advisory_matches_target(advisory, target):
                matches.append(advisory)
                break
    matches.sort(key=lambda item: _SEVERITY_ORDER.get(_advisory_severity(item), 0), reverse=True)
    return matches


def _advisory_matches_target(advisory: dict[str, object], target: ProtectTarget) -> bool:
    advisory_id = advisory.get("artifact_id")
    if isinstance(advisory_id, str) and advisory_id == target.artifact_id:
        return True
    advisory_ecosystem = advisory.get("ecosystem")
    if isinstance(advisory_ecosystem, str) and advisory_ecosystem not in {target.ecosystem, "*"}:
        return False
    advisory_package = advisory.get("package") or advisory.get("name")
    if isinstance(advisory_package, str):
        return advisory_package == target.package_name or advisory_package == target.artifact_name
    advisory_publisher = advisory.get("publisher")
    return isinstance(advisory_publisher, str) and advisory_publisher == target.package_name


def _advisory_severity(advisory: dict[str, object]) -> SeverityLabel:
    value = advisory.get("severity")
    if isinstance(value, str) and value in _SEVERITY_ORDER:
        return value
    return "medium"


def _advisory_action(advisory: dict[str, object]) -> ProtectAction:
    value = advisory.get("action")
    if isinstance(value, str) and value in {"allow", "review", "block"}:
        return value
    return "block" if _SEVERITY_ORDER[_advisory_severity(advisory)] >= _SEVERITY_ORDER["high"] else "review"


def _advisory_headline(advisory: dict[str, object]) -> str:
    headline = advisory.get("headline")
    if isinstance(headline, str) and headline.strip():
        return headline.strip()
    artifact = advisory.get("package") or advisory.get("name") or advisory.get("artifact_id") or "Artifact"
    return f"{artifact} matched a Guard advisory."


def _request_risk_signals(request: ProtectRequest) -> tuple[str, ...]:
    signals: list[str] = []
    joined = " ".join(request.command).lower()
    if request.install_kind == "harness_registration":
        if any(target.source_url is not None for target in request.targets):
            signals.append("registers a remote server endpoint")
        if any(target.artifact_type in {"extension", "plugin", "skill"} for target in request.targets):
            signals.append("registers executable harness code")
        if any(value in joined for value in ("http://", "https://", "curl ", "wget ")):
            signals.append("can fetch or talk to a remote server during registration")
    if any(value in joined for value in (".env", "printenv", "process.env", "os.environ", "getenv(")):
        signals.append("references local environment secrets")
    if any(value in joined for value in (".ssh", ".npmrc", ".pypirc", ".gitconfig", "id_rsa", "credentials")):
        signals.append("mentions sensitive local files")
    if any(value in joined for value in ("bash -c", "bash -lc", "sh -c", "zsh -c", "powershell -command")):
        signals.append("runs through a shell wrapper")
    for target in request.targets:
        spec = target.raw_spec or ""
        if target.artifact_type == "custom_command":
            continue
        if spec.startswith(("http://", "https://", "git+", "file:", "./", "../", "/")):
            signals.append("installs from a non-registry source")
    return tuple(_dedupe(signals))


def _review_reason(
    request: ProtectRequest,
    risk_signals: tuple[str, ...],
    review_advisories: list[dict[str, object]],
) -> str:
    if len(review_advisories) > 0:
        return f"{_advisory_headline(review_advisories[0])} Guard paused this install for review."
    if "registers a remote server endpoint" in risk_signals:
        return "This request registers a remote server endpoint. Guard paused it until you review the target."
    if "installs from a non-registry source" in risk_signals:
        return "This request pulls code from a non-registry source. Guard paused it for review before install."
    return "Guard found install-time risk signals that should be reviewed before this command runs."


def _build_install_receipt(request: ProtectRequest, verdict: ProtectVerdict) -> GuardReceipt:
    primary_target = request.targets[0]
    artifact_hash = _command_fingerprint(list(request.command))
    capabilities_summary = f"{request.executor} {request.install_kind.replace('_', ' ')}"
    provenance_summary = shlex.join(request.command)
    return build_receipt(
        harness=request.harness or request.package_manager or request.executor,
        artifact_id=primary_target.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=verdict.action,
        capabilities_summary=capabilities_summary,
        changed_capabilities=list(verdict.risk_signals),
        provenance_summary=provenance_summary,
        artifact_name=primary_target.artifact_name,
        source_scope="install",
    )


def _command_fingerprint(command: list[str]) -> str:
    payload = "\u0000".join(command).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
