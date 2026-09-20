"""Install-time Guard protection helpers."""

from __future__ import annotations

# Retain facade dependencies for live lookups from the helper modules.
import hashlib  # noqa: F401
import json  # noqa: F401
import os  # noqa: F401
import shlex  # noqa: F401
import subprocess  # noqa: F401
from collections.abc import Callable  # noqa: F401
from dataclasses import dataclass, replace  # noqa: F401
from datetime import datetime, timezone  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import Any, Literal  # noqa: F401
from urllib.parse import urlparse  # noqa: F401
from uuid import uuid4  # noqa: F401

from .action_lattice import normalize_guard_action  # noqa: F401
from .advisory_model import ProtectTargetIdentity, advisory_matches_target, build_package_url  # noqa: F401
from .collections_support import dedupe_preserving_order
from .config import GuardConfig  # noqa: F401
from .models import GuardReceipt  # noqa: F401
from .redaction import redact_text  # noqa: F401
from .runtime.decisions import decision_from_legacy_policy_action  # noqa: F401
from .runtime.package_manager_command import strip_package_manager_global_options  # noqa: F401

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
    package_url: str | None
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
            "package_url": self.package_url,
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


from . import protect_execution as _protect_execution  # noqa: E402

build_protect_payload = _protect_execution.build_protect_payload


_observe_only_verdict = _protect_execution._observe_only_verdict


_cached_advisory_policy_context = _protect_execution._cached_advisory_policy_context


_package_payload_uses_saved_approval = _protect_execution._package_payload_uses_saved_approval


_merge_cached_advisory_into_package_payload = _protect_execution._merge_cached_advisory_into_package_payload


_protect_command_timeout_seconds = _protect_execution._protect_command_timeout_seconds


from . import protect_command_parsing as _protect_command_parsing  # noqa: E402

parse_protect_command = _protect_command_parsing.parse_protect_command


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


_parse_npm_request = _protect_command_parsing._parse_npm_request


_parse_pnpm_request = _protect_command_parsing._parse_pnpm_request


_parse_yarn_request = _protect_command_parsing._parse_yarn_request


_parse_pip_request = _protect_command_parsing._parse_pip_request


_parse_uv_request = _protect_command_parsing._parse_uv_request


_parse_go_request = _protect_command_parsing._parse_go_request


_parse_codex_request = _protect_command_parsing._parse_codex_request


_parse_claude_request = _protect_command_parsing._parse_claude_request


_parse_cursor_request = _protect_command_parsing._parse_cursor_request


_parse_gemini_request = _protect_command_parsing._parse_gemini_request


_parse_antigravity_request = _protect_command_parsing._parse_antigravity_request


_parse_opencode_request = _protect_command_parsing._parse_opencode_request


_parse_custom_request = _protect_command_parsing._parse_custom_request


from . import protect_target_parsing as _protect_target_parsing  # noqa: E402

_package_manager_request = _protect_target_parsing._package_manager_request


_package_target = _protect_target_parsing._package_target


_collect_package_specs = _protect_target_parsing._collect_package_specs


_collect_uv_specs = _protect_target_parsing._collect_uv_specs


_parse_package_identity = _protect_target_parsing._parse_package_identity


_spec_name = _protect_target_parsing._spec_name


_spec_url = _protect_target_parsing._spec_url


_target_name_from_spec = _protect_target_parsing._target_name_from_spec


_option_value = _protect_target_parsing._option_value


_remaining_positionals = _protect_target_parsing._remaining_positionals


_first_url = _protect_target_parsing._first_url


_parse_antigravity_mcp_target = _protect_target_parsing._parse_antigravity_mcp_target


_parse_claude_mcp_target = _protect_target_parsing._parse_claude_mcp_target


_is_remote_transport = _protect_target_parsing._is_remote_transport


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
    return advisory_matches_target(
        advisory,
        ProtectTargetIdentity(
            artifact_id=target.artifact_id,
            artifact_name=target.artifact_name,
            ecosystem=target.ecosystem,
            package_name=target.package_name,
            package_url=target.package_url,
            source_url=target.source_url,
        ),
    )


def _advisory_severity(advisory: dict[str, object]) -> SeverityLabel:
    value = advisory.get("severity")
    if isinstance(value, str) and value in _SEVERITY_ORDER:
        return value
    return "medium"


def _advisory_action(advisory: dict[str, object]) -> ProtectAction:
    value = advisory.get("action")
    if value == "allow":
        return "allow"
    if value == "review":
        return "review"
    if value == "block":
        return "block"
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


from . import protect_receipts as _protect_receipts  # noqa: E402

_build_install_receipt = _protect_receipts._build_install_receipt


_is_package_tool_request = _protect_receipts._is_package_tool_request


_command_fingerprint = _protect_receipts._command_fingerprint


_dedupe = dedupe_preserving_order
