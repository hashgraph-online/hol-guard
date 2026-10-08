"""Resolve package install and execute shell intents via the resident authority.

The resident ``package_intent_parse`` op owns install/execute detection for
every supported ecosystem (npm/npx/pnpm/yarn/bun/pip/pipx/uv/poetry/pipenv/
cargo/go/mvn/gradle/composer/bundle/gem/brew/apt/yum/dnf/apk/pacman/zypper/
helm). This module only shapes requests and decodes results; when the
resident is unreachable or returns nothing, ``parse_package_intent`` returns
``None`` — callers treat that as "no package intent".
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .command_model import CanonicalCommand
from .package_intent_common import (
    IntentKind,
    LocalPackageExecutionEvidence,
    PackageExecutionFileEvidence,
    PackageIntent,
    PackageIntentTarget,
)
from .secret_file_requests import _SHELL_TOOL_NAMES, _candidate_command_texts, _normalize_tool_name

__all__ = [
    "IntentKind",
    "LocalPackageExecutionEvidence",
    "PackageExecutionFileEvidence",
    "PackageIntent",
    "PackageIntentTarget",
    "extract_package_intent_request",
    "parse_package_intent",
]


def _canonical_command_mapping(canonical_command: object) -> Mapping[str, object] | None:
    """Project the caller's canonical command onto the native payload shape.

    The native parser takes a mapping, so a structured command is reduced with
    its own ``to_dict``; anything else that is not already a mapping has no
    representation to send and is reported as absent.
    """

    to_dict = getattr(canonical_command, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        return payload if isinstance(payload, dict) else None
    return canonical_command if isinstance(canonical_command, dict) else None


def _native_package_intent(
    command_text: str,
    *,
    workspace: Path | None,
    home_dir: Path | None,
    guard_home: Path | None,
    canonical_command: CanonicalCommand | None,
    environment: Mapping[str, str] | None,
    deadline: float | None = None,
) -> PackageIntent | None:
    """Resolve ``package_intent_parse`` through the resident authority.

    Returns ``None`` only for transport failure (feature unsupported, binary
    unreachable, or no verified executable) or when the resident finds no
    intent. A decoded-but-malformed payload is rejected to ``None`` rather
    than returning garbage intent.
    """

    try:
        from ..config import resolve_guard_home
        from ..native_package_authority import package_intent_parse_native

        intent = package_intent_parse_native(
            command_text,
            workspace=workspace,
            home_dir=home_dir,
            canonical_command=_canonical_command_mapping(canonical_command),
            environment=environment,
            guard_home=guard_home if guard_home is not None else resolve_guard_home(),
            deadline_monotonic=deadline,
        )
    except Exception:
        return None
    return intent if isinstance(intent, PackageIntent) else None


def parse_package_intent(
    command_text: str,
    *,
    workspace: Path | None = None,
    home_dir: Path | None = None,
    canonical_command: CanonicalCommand | None = None,
    environment: Mapping[str, str] | None = None,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> PackageIntent | None:
    """Parse a shell command for package install/execute intent.

    Resident-sole-authority: a ``None`` result from the resident is terminal
    (transport failure or no intent) — no Python re-parse is attempted.
    """

    return _native_package_intent(
        command_text,
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        canonical_command=canonical_command,
        environment=environment,
        deadline=deadline,
    )


def extract_package_intent_request(
    tool_name: object,
    arguments: object,
    *,
    action_envelope_command: str | None,
    workspace: Path | None = None,
    home_dir: Path | None = None,
    guard_home: Path | None = None,
) -> PackageIntent | None:
    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name in _SHELL_TOOL_NAMES:
        for command_text in _candidate_command_texts(arguments):
            intent = parse_package_intent(command_text, workspace=workspace, home_dir=home_dir, guard_home=guard_home)
            if intent is not None:
                return intent
    if action_envelope_command:
        return parse_package_intent(
            action_envelope_command, workspace=workspace, home_dir=home_dir, guard_home=guard_home
        )
    return None
