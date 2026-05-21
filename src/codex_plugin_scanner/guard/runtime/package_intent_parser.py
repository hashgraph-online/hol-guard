"""Parse package install and execute shell intents."""

from __future__ import annotations

import re
import shlex
from dataclasses import replace
from pathlib import Path

from ..protect import _collect_package_specs
from .mcp_protection import _command_name, _package_token
from .package_intent_common import (
    PackageIntent,
    PackageIntentTarget,
    composer_target,
    coordinate_target,
    existing_relative_paths,
    first_positional,
    flag_tokens,
    js_target,
    option_value,
    property_value,
    python_target,
    redacted_command,
    version_target,
)
from .secret_file_requests import _SHELL_TOOL_NAMES, _candidate_command_texts, _normalize_tool_name

_CONTROL_TOKENS = {"&&", "||", ";", "|", "|&"}
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_PYTHON_EXECUTABLES = {"py", "python", "python3", "python3.11", "python3.12", "python3.13", "python3.14"}


def parse_package_intent(command_text: str, *, workspace: Path | None = None) -> PackageIntent | None:
    command_tokens = _normalized_command_tokens(command_text)
    if not command_tokens:
        return None
    command_name = _command_name(command_tokens[0])
    handlers = {
        "npm": _parse_npm_intent,
        "npx": _parse_exec_intent,
        "pnpm": _parse_pnpm_intent,
        "yarn": _parse_yarn_intent,
        "bun": _parse_bun_intent,
        "bunx": _parse_exec_intent,
        "pip": _parse_pip_intent,
        "pipx": _parse_pipx_intent,
        "uv": _parse_uv_intent,
        "uvx": _parse_exec_intent,
        "poetry": _parse_poetry_intent,
        "pipenv": _parse_pipenv_intent,
        "cargo": _parse_cargo_intent,
        "go": _parse_go_intent,
        "mvn": _parse_maven_intent,
        "mvnw": _parse_maven_intent,
        "gradle": _parse_gradle_intent,
        "gradlew": _parse_gradle_intent,
        "composer": _parse_composer_intent,
        "bundle": _parse_bundle_intent,
        "bundler": _parse_bundle_intent,
        "gem": _parse_gem_intent,
    }
    handler = handlers.get(command_name)
    if handler is None:
        return None
    intent = handler(command_tokens, workspace=workspace)
    if intent is None:
        return None
    return replace(intent, redacted_command=_redacted_command_text(command_text))


def extract_package_intent_request(
    tool_name: object,
    arguments: object,
    *,
    action_envelope_command: str | None,
    workspace: Path | None = None,
) -> PackageIntent | None:
    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name in _SHELL_TOOL_NAMES:
        for command_text in _candidate_command_texts(arguments):
            intent = parse_package_intent(command_text, workspace=workspace)
            if intent is not None:
                return intent
    if action_envelope_command:
        return parse_package_intent(action_envelope_command, workspace=workspace)
    return None


def _parse_npm_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2:
        return None
    if tokens[1] in {"install", "i", "add", "update"}:
        return _build_intent(
            "npm",
            "install",
            tokens,
            tuple(js_target(spec) for spec in _collect_package_specs(list(tokens[2:]))),
            workspace=workspace,
            manifest_candidates=("package.json",),
            lockfile_candidates=("package-lock.json",),
        )
    if tokens[1] == "ci" or (len(tokens) >= 3 and tokens[1:3] == ("audit", "fix")):
        return _build_intent(
            "npm",
            "sync",
            tokens,
            (),
            workspace=workspace,
            manifest_candidates=("package.json",),
            lockfile_candidates=("package-lock.json",),
        )
    if tokens[1] in {"exec", "x"}:
        return _parse_exec_intent(tokens, workspace=workspace)
    return None


def _parse_pnpm_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2:
        return None
    if tokens[1] in {"add", "install"}:
        return _build_intent(
            "pnpm",
            "install",
            tokens,
            tuple(js_target(spec) for spec in _collect_specs(tokens[2:], skip_value_options={"--filter", "-F"})),
            workspace=workspace,
            manifest_candidates=("package.json", "pnpm-workspace.yaml"),
            lockfile_candidates=("pnpm-lock.yaml",),
        )
    if tokens[1] == "dlx":
        return _parse_exec_intent(tokens, workspace=workspace)
    return None


def _parse_yarn_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    notes: tuple[str, ...] = ()
    working_tokens = tokens
    if len(tokens) >= 4 and tokens[1] == "workspace":
        notes = (f"workspace:{tokens[2]}",)
        working_tokens = (tokens[0], *tokens[3:])
    if len(working_tokens) < 2:
        return None
    if working_tokens[1] in {"add", "install", "up"}:
        return _build_intent(
            "yarn",
            "install",
            tokens,
            tuple(js_target(spec) for spec in _collect_package_specs(list(working_tokens[2:]))),
            workspace=workspace,
            manifest_candidates=("package.json",),
            lockfile_candidates=("yarn.lock",),
            notes=notes,
        )
    if working_tokens[1] == "dlx":
        return _parse_exec_intent(working_tokens, workspace=workspace)
    return None


def _parse_bun_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2 or tokens[1] not in {"add", "install"}:
        return None
    return _build_intent(
        "bun",
        "install",
        tokens,
        tuple(js_target(spec) for spec in _collect_package_specs(list(tokens[2:]))),
        workspace=workspace,
        manifest_candidates=("package.json",),
        lockfile_candidates=("bun.lock", "bun.lockb"),
    )


def _parse_exec_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    package_token = _exec_package_spec(tokens)
    if package_token is None:
        return None
    ecosystem = "pypi" if _command_name(tokens[0]) in {"uvx", "pipx"} else "npm"
    target = python_target(package_token) if ecosystem == "pypi" else js_target(package_token)
    return _build_intent(_command_name(tokens[0]), "execute", tokens, (target,), workspace=workspace)


def _parse_pip_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2 or tokens[1] != "install":
        return None
    targets: list[PackageIntentTarget] = []
    manifest_paths: list[str] = []
    index = 2
    while index < len(tokens):
        token = tokens[index]
        if token in {"-r", "--requirement", "-c", "--constraint"} and index + 1 < len(tokens):
            manifest_paths.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--requirement=") or token.startswith("--constraint="):
            manifest_paths.append(token.partition("=")[2])
            index += 1
            continue
        if token.startswith("-r") and token != "-r":
            manifest_paths.append(token[2:])
            index += 1
            continue
        if token.startswith("-c") and token != "-c":
            manifest_paths.append(token[2:])
            index += 1
            continue
        if token in {"-e", "--editable"} and index + 1 < len(tokens):
            targets.append(python_target(tokens[index + 1], editable=True))
            index += 2
            continue
        if token in {"--index-url", "--extra-index-url", "--hash"} and index + 1 < len(tokens):
            index += 2
            continue
        if token.startswith("--hash=") or token.startswith("-"):
            index += 1
            continue
        targets.append(python_target(token))
        index += 1
    return _build_intent(
        "pip",
        "install",
        tokens,
        tuple(targets),
        workspace=workspace,
        manifest_paths=tuple(existing_relative_paths(workspace, manifest_paths)),
    )


def _parse_pipx_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 3 or tokens[1] not in {"install", "run"}:
        return None
    target_spec = first_positional(tokens[2:], skip_value_options={"--python"})
    if target_spec is None:
        return None
    return _build_intent(
        "pipx",
        "execute" if tokens[1] == "run" else "install",
        tokens,
        (python_target(target_spec),),
        workspace=workspace,
    )


def _parse_uv_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2:
        return None
    if tokens[1] == "add":
        return _build_intent(
            "uv",
            "install",
            tokens,
            tuple(python_target(spec) for spec in _collect_package_specs(list(tokens[2:]))),
            workspace=workspace,
            manifest_candidates=("pyproject.toml",),
            lockfile_candidates=("uv.lock",),
        )
    if len(tokens) >= 3 and tokens[1:3] == ("pip", "install"):
        return _build_intent(
            "uv",
            "install",
            tokens,
            tuple(python_target(spec) for spec in _collect_package_specs(list(tokens[3:]))),
            workspace=workspace,
            manifest_candidates=("pyproject.toml",),
            lockfile_candidates=("uv.lock",),
        )
    if tokens[1] == "sync":
        return _build_intent(
            "uv",
            "sync",
            tokens,
            (),
            workspace=workspace,
            manifest_candidates=("pyproject.toml",),
            lockfile_candidates=("uv.lock",),
        )
    return None


def _parse_poetry_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2:
        return None
    if tokens[1] == "install":
        return _build_intent(
            "poetry",
            "sync",
            tokens,
            (),
            workspace=workspace,
            manifest_candidates=("pyproject.toml",),
            lockfile_candidates=("poetry.lock",),
        )
    if tokens[1] != "add":
        return None
    group = option_value(tokens, "--group") or option_value(tokens, "-G")
    extras_value = option_value(tokens, "--extras")
    extras = tuple(item for item in (extras_value or "").split(",") if item)
    targets = tuple(
        python_target(spec, dependency_group=group, extras=extras) for spec in _collect_package_specs(list(tokens[2:]))
    )
    return _build_intent(
        "poetry",
        "install",
        tokens,
        targets,
        workspace=workspace,
        manifest_candidates=("pyproject.toml",),
        lockfile_candidates=("poetry.lock",),
    )


def _parse_pipenv_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2:
        return None
    if tokens[1] == "sync":
        return _build_intent(
            "pipenv",
            "sync",
            tokens,
            (),
            workspace=workspace,
            manifest_candidates=("Pipfile",),
            lockfile_candidates=("Pipfile.lock",),
        )
    if tokens[1] != "install":
        return None
    return _build_intent(
        "pipenv",
        "install",
        tokens,
        tuple(python_target(spec) for spec in _collect_package_specs(list(tokens[2:]))),
        workspace=workspace,
        manifest_candidates=("Pipfile",),
        lockfile_candidates=("Pipfile.lock",),
    )


def _parse_cargo_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2 or tokens[1] not in {"add", "install"}:
        return None
    source_url = option_value(tokens, "--git")
    targets = tuple(
        version_target("cargo", spec, source_url=source_url) for spec in _collect_package_specs(list(tokens[2:]))
    )
    return _build_intent(
        "cargo",
        "install",
        tokens,
        targets,
        workspace=workspace,
        manifest_candidates=("Cargo.toml",),
        lockfile_candidates=("Cargo.lock",),
    )


def _parse_go_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2 or tokens[1] not in {"get", "install"}:
        return None
    return _build_intent(
        "go",
        "install",
        tokens,
        tuple(version_target("go", spec) for spec in _collect_package_specs(list(tokens[2:]))),
        workspace=workspace,
        manifest_candidates=("go.mod",),
    )


def _parse_maven_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    artifact_value = property_value(tokens, "artifact")
    if artifact_value is None:
        includes = property_value(tokens, "includes")
        dep_version = property_value(tokens, "depVersion")
        artifact_value = f"{includes}:{dep_version}" if includes and dep_version else None
    if artifact_value is None:
        return None
    return _build_intent(
        "maven",
        "install",
        tokens,
        (coordinate_target("maven", artifact_value),),
        workspace=workspace,
        manifest_candidates=("pom.xml",),
    )


def _parse_gradle_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    dependency_value = option_value(tokens, "--dependency")
    if dependency_value is None:
        return None
    return _build_intent(
        "gradle",
        "install",
        tokens,
        (coordinate_target("maven", dependency_value),),
        workspace=workspace,
        manifest_candidates=("build.gradle", "build.gradle.kts"),
    )


def _parse_composer_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2 or tokens[1] not in {"require", "install", "update"}:
        return None
    return _build_intent(
        "composer",
        "install",
        tokens,
        tuple(composer_target(spec) for spec in _collect_package_specs(list(tokens[2:]))),
        workspace=workspace,
        manifest_candidates=("composer.json",),
        lockfile_candidates=("composer.lock",),
    )


def _parse_bundle_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2:
        return None
    if tokens[1] == "install":
        return _build_intent(
            "bundle",
            "sync",
            tokens,
            (),
            workspace=workspace,
            manifest_candidates=("Gemfile",),
            lockfile_candidates=("Gemfile.lock",),
        )
    if tokens[1] != "add" or len(tokens) < 3:
        return None
    version = option_value(tokens, "--version")
    return _build_intent(
        "bundle",
        "install",
        tokens,
        (PackageIntentTarget("rubygems", tokens[2], tokens[2], version),),
        workspace=workspace,
        manifest_candidates=("Gemfile",),
        lockfile_candidates=("Gemfile.lock",),
    )


def _parse_gem_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 3 or tokens[1] != "install":
        return None
    version = option_value(tokens, "-v") or option_value(tokens, "--version")
    return _build_intent(
        "gem",
        "install",
        tokens,
        (PackageIntentTarget("rubygems", tokens[2], tokens[2], version),),
        workspace=workspace,
    )


def _build_intent(
    package_manager: str,
    intent_kind: str,
    command_tokens: tuple[str, ...],
    targets: tuple[PackageIntentTarget, ...],
    *,
    workspace: Path | None,
    manifest_candidates: tuple[str, ...] = (),
    lockfile_candidates: tuple[str, ...] = (),
    manifest_paths: tuple[str, ...] = (),
    notes: tuple[str, ...] = (),
) -> PackageIntent:
    return PackageIntent(
        package_manager=package_manager,
        intent_kind=intent_kind,  # type: ignore[arg-type]
        command_tokens=command_tokens,
        redacted_command=redacted_command(command_tokens),
        targets=targets,
        manifest_paths=manifest_paths or existing_relative_paths(workspace, manifest_candidates),
        lockfile_paths=existing_relative_paths(workspace, lockfile_candidates),
        flags=flag_tokens(command_tokens[1:]),
        notes=notes,
    )


def _collect_specs(tokens: tuple[str, ...], *, skip_value_options: set[str]) -> tuple[str, ...]:
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


def _exec_package_spec(tokens: tuple[str, ...]) -> str | None:
    command_name = _command_name(tokens[0])
    if command_name == "npm" and len(tokens) >= 2 and tokens[1] in {"exec", "x"}:
        explicit_package = option_value(tokens, "--package")
        positional_package = first_positional(tokens[2:], skip_value_options={"--package"})
        if positional_package and explicit_package:
            positional_target = js_target(positional_package)
            explicit_target = js_target(explicit_package)
            if positional_target.package_name == explicit_target.package_name:
                positional_specifier = positional_target.requested_specifier or positional_target.source_url
                explicit_specifier = explicit_target.requested_specifier or explicit_target.source_url
                if positional_specifier is None and explicit_specifier is not None:
                    return explicit_package
                return positional_package
            return explicit_package
        return explicit_package or positional_package
    if command_name == "pipx" and len(tokens) >= 2 and tokens[1] == "run":
        return first_positional(tokens[2:], skip_value_options={"--python"})
    if command_name in {"pnpm", "yarn"} and len(tokens) >= 2 and tokens[1] == "dlx":
        return first_positional(tokens[2:], skip_value_options=set())
    if command_name in {"npx", "bunx", "uvx"}:
        return first_positional(tokens[1:], skip_value_options=set())
    return _package_token(command_name=command_name, args=tokens[1:])


def _normalized_command_tokens(command_text: str) -> tuple[str, ...]:
    try:
        tokens = shlex.split(command_text, posix=True)
    except ValueError:
        return ()
    segment: list[str] = []
    for token in tokens:
        if token in _CONTROL_TOKENS:
            break
        segment.append(token)
    segment = _strip_wrapper_tokens(segment)
    if len(segment) >= 3 and _command_name(segment[0]) in _PYTHON_EXECUTABLES and segment[1] == "-m":
        segment = [segment[2], *segment[3:]]
    return tuple(segment)


def _redacted_command_text(command_text: str) -> str:
    try:
        tokens = shlex.split(command_text, posix=True)
    except ValueError:
        return ""
    segment: list[str] = []
    for token in tokens:
        if token in _CONTROL_TOKENS:
            break
        segment.append(token)
    segment = _strip_redaction_wrappers(segment)
    if len(segment) >= 3 and _command_name(segment[0]) in _PYTHON_EXECUTABLES and segment[1] == "-m":
        segment = [segment[2], *segment[3:]]
    return redacted_command(tuple(segment))


def _strip_redaction_wrappers(segment: list[str]) -> list[str]:
    while segment:
        command_name = _command_name(segment[0])
        if command_name == "sudo":
            segment = _strip_sudo_prefix(segment[1:])
            continue
        if command_name == "env":
            segment = _strip_env_prefix(segment[1:])
            continue
        if command_name in {"command", "time"}:
            segment = _strip_plain_wrapper_flags(segment[1:])
            continue
        break
    return segment


def _strip_wrapper_tokens(segment: list[str]) -> list[str]:
    while segment:
        if _ENV_ASSIGNMENT_RE.match(segment[0]):
            segment.pop(0)
            continue
        command_name = _command_name(segment[0])
        if command_name == "sudo":
            segment = _strip_sudo_prefix(segment[1:])
            continue
        if command_name == "env":
            segment = _strip_env_prefix(segment[1:])
            continue
        if command_name in {"command", "time"}:
            segment = _strip_plain_wrapper_flags(segment[1:])
            continue
        break
    return segment


def _strip_sudo_prefix(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("-"):
            break
        if token in {"-u", "-g", "-h", "-p", "-r", "-t", "-C"} and index + 1 < len(tokens):
            index += 2
            continue
        index += 1
    return tokens[index:]


def _strip_env_prefix(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _ENV_ASSIGNMENT_RE.match(token):
            index += 1
            continue
        if not token.startswith("-"):
            break
        if token in {"-u", "-C", "-S"} and index + 1 < len(tokens):
            index += 2
            continue
        index += 1
    return tokens[index:]


def _strip_plain_wrapper_flags(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens) and tokens[index].startswith("-"):
        index += 1
    return tokens[index:]
