"""Homebrew package intent parsing."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .package_intent_common import (
    IntentKind,
    PackageIntent,
    PackageIntentTarget,
    existing_relative_paths,
    first_positional,
    flag_tokens,
    homebrew_tap_target,
    homebrew_target,
    option_value,
    redacted_command,
)
from .package_manager_command import strip_package_manager_global_options


def parse_brew_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) < 2:
        return None
    verb = working_tokens[1].lower()
    if verb in {"install", "reinstall", "upgrade"}:
        return _parse_brew_install_intent(tokens, working_tokens=working_tokens)
    if verb == "tap":
        return _parse_brew_tap_intent(tokens, working_tokens=working_tokens)
    if verb == "bundle":
        return _parse_brew_bundle_intent(tokens, working_tokens=working_tokens, workspace=workspace)
    return None


def _parse_brew_install_intent(
    tokens: tuple[str, ...],
    *,
    working_tokens: tuple[str, ...],
) -> PackageIntent:
    targets = tuple(
        homebrew_target(spec, cask=_brew_command_uses_cask(working_tokens))
        for spec in _collect_brew_specs(working_tokens[2:])
    )
    return _build_brew_intent("install", tokens, targets)


def _parse_brew_tap_intent(
    tokens: tuple[str, ...],
    *,
    working_tokens: tuple[str, ...],
) -> PackageIntent | None:
    tap_name = first_positional(working_tokens[2:], skip_value_options={"--custom-remote", "--repair"})
    if tap_name is None:
        return None
    source_url = _brew_tap_source_url(working_tokens, tap_name)
    return _build_brew_intent(
        "install",
        tokens,
        (homebrew_tap_target(tap_name, source_url=source_url),),
    )


def _parse_brew_bundle_intent(
    tokens: tuple[str, ...],
    *,
    working_tokens: tuple[str, ...],
    workspace: Path | None,
) -> PackageIntent | None:
    if (
        len(working_tokens) >= 3
        and working_tokens[2] not in {"install", "upgrade"}
        and not working_tokens[2].startswith("-")
    ):
        return None
    manifest_paths = existing_relative_paths(workspace, (_brew_bundle_file(working_tokens),))
    targets = _brewfile_targets(workspace, manifest_paths)
    return _build_brew_intent("sync", tokens, targets, manifest_paths=manifest_paths)


def _build_brew_intent(
    intent_kind: IntentKind,
    tokens: tuple[str, ...],
    targets: tuple[PackageIntentTarget, ...],
    *,
    manifest_paths: tuple[str, ...] = (),
) -> PackageIntent:
    return PackageIntent(
        package_manager="brew",
        intent_kind=intent_kind,
        command_tokens=tokens,
        redacted_command=redacted_command(tokens),
        targets=targets,
        manifest_paths=manifest_paths,
        lockfile_paths=(),
        flags=flag_tokens(tokens[1:]),
        notes=("brew-bundle",) if intent_kind == "sync" else (),
    )


def _collect_brew_specs(tokens: tuple[str, ...]) -> tuple[str, ...]:
    skip_value_options = {
        "--appdir",
        "--caskroom",
        "--display-times",
        "--env",
        "--language",
        "--prefix",
        "--requirement",
    }
    specs: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in skip_value_options and index + 1 < len(tokens):
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        specs.append(token)
        index += 1
    return tuple(specs)


def _brew_command_uses_cask(tokens: tuple[str, ...]) -> bool:
    return any(token == "--cask" or token.startswith("--cask=") for token in tokens[2:])


def _brew_tap_source_url(tokens: tuple[str, ...], tap_name: str) -> str | None:
    seen_tap = False
    for token in tokens[2:]:
        if token == tap_name and not seen_tap:
            seen_tap = True
            continue
        if seen_tap and not token.startswith("-"):
            return token
    return option_value(tokens, "--custom-remote")


def _brew_bundle_file(tokens: tuple[str, ...]) -> str:
    return option_value(tokens, "--file") or "Brewfile"


def _brewfile_targets(workspace: Path | None, manifest_paths: tuple[str, ...]) -> tuple[PackageIntentTarget, ...]:
    if workspace is None:
        return ()
    targets: list[PackageIntentTarget] = []
    for manifest_path in manifest_paths:
        candidate = (workspace / manifest_path).resolve()
        try:
            candidate.relative_to(workspace.resolve())
            text = candidate.read_text(encoding="utf-8")
        except (OSError, ValueError):
            continue
        targets.extend(_brewfile_line_targets(text))
    return tuple(targets)


def _brewfile_line_targets(text: str) -> tuple[PackageIntentTarget, ...]:
    targets: list[PackageIntentTarget] = []
    for line in text.splitlines():
        parsed = _parse_brewfile_literal_call(line)
        if parsed is None:
            continue
        command, args = parsed
        if command == "brew" and args:
            targets.append(homebrew_target(args[0]))
        elif command == "cask" and args:
            targets.append(homebrew_target(args[0], cask=True))
        elif command == "tap" and args:
            targets.append(homebrew_tap_target(args[0], source_url=_brewfile_tap_source_url(args)))
    return tuple(targets)


def _parse_brewfile_literal_call(line: str) -> tuple[str, tuple[str, ...]] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = re.match(r"^(brew|cask|tap)\s+(.+)$", stripped)
    if match is None:
        return None
    try:
        tokens = shlex.split(match.group(2), posix=True)
    except ValueError:
        return None
    args = tuple(token.rstrip(",") for token in tokens if _brewfile_token_is_dependency_arg(token))
    return (match.group(1), args) if args else None


def _brewfile_token_is_dependency_arg(token: str) -> bool:
    if token == "," or token.startswith((",", ":")):
        return False
    return not token.startswith(("args:", "postinstall:", "restart_service:"))


def _brewfile_tap_source_url(args: tuple[str, ...]) -> str | None:
    if len(args) < 2:
        return None
    candidate = args[1]
    return candidate if "://" in candidate or candidate.startswith(("git@", "ssh:")) else None
