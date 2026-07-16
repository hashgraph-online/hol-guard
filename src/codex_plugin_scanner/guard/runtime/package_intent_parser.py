"""Parse package install and execute shell intents."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from ..protect import _collect_package_specs
from .command_model import CanonicalCommand
from .homebrew_intent import parse_brew_intent
from .mcp_protection import _command_name, _package_token
from .package_intent_common import (
    IntentKind,
    LocalPackageExecutionEvidence,
    PackageExecutionFileEvidence,
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
from .package_manager_command import strip_package_manager_global_options
from .secret_file_requests import _SHELL_TOOL_NAMES, _candidate_command_texts, _normalize_tool_name

_CONTROL_TOKENS = {"&&", "||", ";", "|", "|&", "&"}
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_LOCAL_EXECUTION_COMMANDS = frozenset({"bunx", "npx"})
_LOCAL_EXECUTION_FLAGS_BY_COMMAND = {
    "bunx": frozenset({"--bun", "--no-install"}),
    "npx": frozenset({"--no", "--no-install"}),
}
_JS_LOCKFILE_NAMES = ("bun.lock", "bun.lockb", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")
_PYTHON_EXECUTABLES = {"py", "python", "python3", "python3.11", "python3.12", "python3.13", "python3.14"}
_PACKAGE_SOURCE_ENV_NAMES = frozenset(
    {
        "PIP_EXTRA_INDEX_URL",
        "PIP_INDEX_URL",
        "PIP_FIND_LINKS",
        "UV_DEFAULT_INDEX",
        "UV_EXTRA_INDEX_URL",
        "UV_INDEX",
        "UV_INDEX_URL",
        "NPM_CONFIG_REGISTRY",
        "YARN_NPM_REGISTRY_SERVER",
    }
)


@dataclass(frozen=True, slots=True)
class _CommandSegment:
    tokens: tuple[str, ...]
    redacted_tokens: tuple[str, ...]
    effective_path: str | None
    path_source: str
    effective_cwd: Path
    cwd_source: str
    context_hash: str


def parse_package_intent(
    command_text: str,
    *,
    workspace: Path | None = None,
    canonical_command: CanonicalCommand | None = None,
) -> PackageIntent | None:
    handlers = {
        "npm": _parse_npm_intent,
        "npx": _parse_exec_intent,
        "pnpm": _parse_pnpm_intent,
        "yarn": _parse_yarn_intent,
        "bun": _parse_bun_intent,
        "bunx": _parse_exec_intent,
        "pip": _parse_pip_intent,
        "pip3": _parse_pip_intent,
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
        "brew": parse_brew_intent,
        "apt": _parse_system_package_intent,
        "apt-get": _parse_system_package_intent,
        "yum": _parse_system_package_intent,
        "dnf": _parse_system_package_intent,
        "apk": _parse_system_package_intent,
        "pacman": _parse_system_package_intent,
        "zypper": _parse_system_package_intent,
        "helm": _parse_helm_intent,
    }
    intents: list[PackageIntent] = []
    for segment in _normalized_command_segments(command_text, workspace=workspace):
        if not segment.tokens:
            continue
        command_name = _command_name(segment.tokens[0])
        handler = handlers.get(command_name)
        if handler is None:
            continue
        if command_name in _LOCAL_EXECUTION_COMMANDS:
            intent = _parse_exec_intent(
                segment.tokens,
                workspace=workspace,
                effective_path=segment.effective_path,
                path_source=segment.path_source,
                effective_cwd=segment.effective_cwd,
                cwd_source=segment.cwd_source,
                execution_context_hash=segment.context_hash,
            )
        else:
            intent = handler(segment.tokens, workspace=workspace)
        if intent is not None:
            intents.append(replace(intent, redacted_command=redacted_command(segment.redacted_tokens)))
    return _combine_package_intents(tuple(intents))


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
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) < 2:
        return None
    if working_tokens[1] in {"install", "i", "add", "update"}:
        return _build_intent(
            "npm",
            "install",
            tokens,
            tuple(js_target(spec) for spec in _collect_package_specs(list(working_tokens[2:]))),
            workspace=workspace,
            manifest_candidates=("package.json",),
            lockfile_candidates=("package-lock.json",),
        )
    if working_tokens[1] == "ci" or (len(working_tokens) >= 3 and working_tokens[1:3] == ("audit", "fix")):
        return _build_intent(
            "npm",
            "sync",
            tokens,
            (),
            workspace=workspace,
            manifest_candidates=("package.json",),
            lockfile_candidates=("package-lock.json",),
        )
    if working_tokens[1] in {"exec", "x"}:
        return _parse_exec_intent(working_tokens, workspace=workspace)
    return None


def _parse_pnpm_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) < 2:
        return None
    if working_tokens[1] in {"add", "install", "i"}:
        return _build_intent(
            "pnpm",
            "install",
            tokens,
            tuple(
                js_target(spec) for spec in _collect_specs(working_tokens[2:], skip_value_options={"--filter", "-F"})
            ),
            workspace=workspace,
            manifest_candidates=("package.json", "pnpm-workspace.yaml"),
            lockfile_candidates=("pnpm-lock.yaml",),
        )
    if working_tokens[1] == "dlx":
        return _parse_exec_intent(working_tokens, workspace=workspace)
    return None


def _parse_yarn_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    notes: tuple[str, ...] = ()
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) >= 4 and working_tokens[1] == "workspace":
        notes = (f"workspace:{working_tokens[2]}",)
        working_tokens = (working_tokens[0], *working_tokens[3:])
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


def _parse_exec_intent(
    tokens: tuple[str, ...],
    *,
    workspace: Path | None,
    effective_path: str | None = None,
    path_source: str = "not_applicable",
    effective_cwd: Path | None = None,
    cwd_source: str = "not_applicable",
    execution_context_hash: str = "not_applicable",
) -> PackageIntent | None:
    package_token = _exec_package_spec(tokens)
    if package_token is None:
        return None
    command = _command_name(tokens[0])
    ecosystem = "pypi" if command in {"uvx", "pipx"} else "npm"
    target = python_target(package_token) if ecosystem == "pypi" else js_target(package_token)
    manifest_candidates = ("package.json",) if command in _LOCAL_EXECUTION_COMMANDS else ()
    lockfile_candidates = _JS_LOCKFILE_NAMES if command in _LOCAL_EXECUTION_COMMANDS else ()
    intent = _build_intent(
        command,
        "execute",
        tokens,
        (target,),
        workspace=workspace,
        manifest_candidates=manifest_candidates,
        lockfile_candidates=lockfile_candidates,
    )
    if command not in _LOCAL_EXECUTION_COMMANDS:
        return intent
    return replace(
        intent,
        local_executions=(
            _local_package_execution_evidence(
                command,
                tokens,
                workspace=workspace,
                effective_path=effective_path,
                path_source=path_source,
                effective_cwd=effective_cwd or workspace or Path.cwd(),
                cwd_source=cwd_source,
                execution_context_hash=execution_context_hash,
                manifest_paths=intent.manifest_paths,
                lockfile_paths=intent.lockfile_paths,
            ),
        ),
        notes=(*intent.notes, "local-execution-requires-review"),
    )


def _local_execution_disables_install(tokens: tuple[str, ...]) -> bool:
    command = _command_name(tokens[0]) if tokens else ""
    local_only_flags = _LOCAL_EXECUTION_FLAGS_BY_COMMAND.get(command, frozenset())
    for token in tokens[1:]:
        if not token.startswith("-"):
            return False
        if token not in local_only_flags:
            return False
        if token in {"--no", "--no-install"}:
            return True
    return False


def _local_executable_name(
    tokens: tuple[str, ...],
    *,
    package_name: str | None,
    workspace: Path | None,
    effective_cwd: Path,
) -> str | None:
    command = _command_name(tokens[0]) if tokens else ""
    allowed_flags = _LOCAL_EXECUTION_FLAGS_BY_COMMAND.get(command, frozenset())
    index = 1
    while index < len(tokens) and tokens[index].startswith("-"):
        if tokens[index] not in allowed_flags:
            return None
        index += 1
    if index >= len(tokens):
        return None
    executable = tokens[index]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", executable):
        return executable
    if package_name is None:
        return None
    return _installed_package_bin_name(
        workspace=workspace,
        effective_cwd=effective_cwd,
        package_name=package_name,
    )


def _workspace_js_dependency_version(
    workspace: Path,
    effective_cwd: Path,
    package_name: str,
) -> str | None:
    for root in _node_resolution_roots(workspace, effective_cwd):
        try:
            payload = json.loads((root / "package.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            dependencies = payload.get(key)
            if isinstance(dependencies, dict) and isinstance(dependencies.get(package_name), str):
                version = dependencies[package_name].strip()
                return version or None
    return None


def _local_package_execution_evidence(
    command: str,
    tokens: tuple[str, ...],
    *,
    workspace: Path | None,
    effective_path: str | None,
    path_source: str,
    effective_cwd: Path,
    cwd_source: str,
    execution_context_hash: str,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
) -> LocalPackageExecutionEvidence:
    package_spec = _exec_package_spec(tokens)
    package_name = js_target(package_spec).package_name if package_spec is not None else None
    executable_name = _local_executable_name(
        tokens,
        package_name=package_name,
        workspace=workspace,
        effective_cwd=effective_cwd,
    )
    manager_path = shutil.which(command, path=effective_path) if effective_path is not None else None
    manager = (
        _execution_file_evidence(Path(manager_path), display_path=manager_path) if manager_path is not None else None
    )
    manager_is_guard_shim = _manager_evidence_is_guard_shim(command, manager)
    local_executable = (
        _local_executable_evidence(workspace, effective_cwd, executable_name)
        if workspace is not None and executable_name is not None
        else None
    )
    declared_version = (
        _workspace_js_dependency_version(workspace, effective_cwd, package_name)
        if workspace is not None and package_name is not None
        else None
    )
    return LocalPackageExecutionEvidence(
        manager_name=command,
        path_source=path_source,
        effective_cwd=str(effective_cwd),
        cwd_source=cwd_source,
        manager_is_guard_shim=manager_is_guard_shim,
        local_only_requested=_local_execution_disables_install(tokens),
        context_hash=execution_context_hash,
        package_name=package_name,
        executable_name=executable_name,
        declared_version=declared_version,
        manager=manager,
        local_executable=local_executable,
        manifests=_local_context_file_evidence(
            workspace,
            effective_cwd,
            declared_paths=manifest_paths,
            candidate_names=("package.json",),
        ),
        lockfiles=_local_context_file_evidence(
            workspace,
            effective_cwd,
            declared_paths=lockfile_paths,
            candidate_names=_JS_LOCKFILE_NAMES,
        ),
    )


def _manager_evidence_is_guard_shim(
    command: str,
    manager: PackageExecutionFileEvidence | None,
) -> bool:
    if manager is None or manager.resolved_path is None:
        return False
    try:
        expected_shim = (Path.home() / ".hol-guard" / "package-shims" / "bin" / command).resolve()
        return Path(manager.resolved_path) == expected_shim
    except (OSError, RuntimeError):
        return False


def _local_executable_evidence(
    workspace: Path,
    effective_cwd: Path,
    executable_name: str,
) -> PackageExecutionFileEvidence:
    suffixes = ("", ".cmd", ".ps1") if os.name == "nt" else ("",)
    for root in _node_resolution_roots(workspace, effective_cwd):
        executable_dir = root / "node_modules" / ".bin"
        for suffix in suffixes:
            candidate = executable_dir / f"{executable_name}{suffix}"
            if os.path.lexists(candidate):
                return _execution_file_evidence(
                    candidate,
                    display_path=_execution_display_path(workspace, candidate),
                )
    expected = effective_cwd / "node_modules" / ".bin" / executable_name
    return PackageExecutionFileEvidence(
        path=_execution_display_path(workspace, expected),
        resolved_path=None,
        status="missing",
    )


def _installed_package_bin_name(
    *,
    workspace: Path | None,
    effective_cwd: Path,
    package_name: str,
) -> str | None:
    if workspace is None:
        return None
    for root in _node_resolution_roots(workspace, effective_cwd):
        manifest = root / "node_modules" / Path(*package_name.split("/")) / "package.json"
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        bin_value = payload.get("bin")
        fallback = package_name.rsplit("/", 1)[-1]
        if isinstance(bin_value, str) and bin_value.strip():
            return fallback
        if isinstance(bin_value, dict):
            names = tuple(str(name) for name, value in bin_value.items() if isinstance(value, str) and value.strip())
            if fallback in names:
                return fallback
            if len(names) == 1:
                return names[0]
    fallback = package_name.rsplit("/", 1)[-1]
    return fallback if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", fallback) else None


def _node_resolution_roots(workspace: Path, effective_cwd: Path) -> tuple[Path, ...]:
    workspace_root = workspace.expanduser().resolve()
    current = effective_cwd.expanduser().resolve()
    boundary = (
        workspace_root if current == workspace_root or workspace_root in current.parents else Path(current.anchor)
    )
    roots: list[Path] = []
    while True:
        roots.append(current)
        if current == boundary:
            break
        current = current.parent
    return tuple(roots)


def _execution_display_path(workspace: Path, path: Path) -> str:
    try:
        return path.relative_to(workspace.expanduser().resolve()).as_posix()
    except ValueError:
        return str(path)


def _local_context_file_evidence(
    workspace: Path | None,
    effective_cwd: Path,
    *,
    declared_paths: tuple[str, ...],
    candidate_names: tuple[str, ...],
) -> tuple[PackageExecutionFileEvidence, ...]:
    if workspace is None:
        return ()
    candidates: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for relative_path in declared_paths:
        candidate = workspace / relative_path
        normalized = candidate.absolute()
        if normalized not in seen:
            seen.add(normalized)
            candidates.append((candidate, relative_path))
    for root in _node_resolution_roots(workspace, effective_cwd):
        for name in candidate_names:
            candidate = root / name
            normalized = candidate.absolute()
            if normalized in seen or not os.path.lexists(candidate):
                continue
            seen.add(normalized)
            candidates.append((candidate, _execution_display_path(workspace, candidate)))
    return tuple(
        _execution_file_evidence(candidate, display_path=display_path) for candidate, display_path in candidates
    )


def _execution_file_evidence(path: Path, *, display_path: str) -> PackageExecutionFileEvidence:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return PackageExecutionFileEvidence(
            path=display_path,
            resolved_path=None,
            status="missing",
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError:
        identity = _path_identity(resolved)
        return PackageExecutionFileEvidence(
            path=display_path,
            resolved_path=str(resolved),
            status="unreadable",
            file_identity=identity,
        )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return PackageExecutionFileEvidence(
                path=display_path,
                resolved_path=str(resolved),
                status="not_regular",
                file_identity=_stat_identity(before),
            )
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError:
        return PackageExecutionFileEvidence(
            path=display_path,
            resolved_path=str(resolved),
            status="unreadable",
        )
    finally:
        os.close(descriptor)

    identity_before = _stat_identity(before)
    identity_after = _stat_identity(after)
    if identity_before != identity_after:
        return PackageExecutionFileEvidence(
            path=display_path,
            resolved_path=str(resolved),
            status="unstable",
            file_identity=identity_after,
        )
    return PackageExecutionFileEvidence(
        path=display_path,
        resolved_path=str(resolved),
        status="available",
        file_identity=identity_after,
        content_hash=f"sha256:{digest.hexdigest()}",
    )


def _stat_identity(result: os.stat_result) -> str:
    return ":".join(
        str(value)
        for value in (
            result.st_dev,
            result.st_ino,
            stat.S_IMODE(result.st_mode),
            result.st_size,
            result.st_mtime_ns,
            result.st_ctime_ns,
        )
    )


def _path_identity(path: Path) -> str | None:
    try:
        return _stat_identity(path.stat())
    except OSError:
        return None


def _parse_pip_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) < 2 or working_tokens[1] != "install":
        return None
    targets: list[PackageIntentTarget] = []
    manifest_paths: list[str] = []
    index = 2
    while index < len(working_tokens):
        token = working_tokens[index]
        if token in {"-r", "--requirement", "-c", "--constraint"} and index + 1 < len(working_tokens):
            manifest_paths.append(working_tokens[index + 1])
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
        if token in {"-e", "--editable"} and index + 1 < len(working_tokens):
            targets.append(python_target(working_tokens[index + 1], editable=True))
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
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) < 3 or working_tokens[1] not in {"install", "run"}:
        return None
    target_spec = first_positional(working_tokens[2:], skip_value_options={"--python"})
    if target_spec is None:
        return None
    return _build_intent(
        "pipx",
        "execute" if working_tokens[1] == "run" else "install",
        tokens,
        (python_target(target_spec),),
        workspace=workspace,
    )


def _parse_uv_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) < 2:
        return None
    if working_tokens[1] == "add":
        return _build_intent(
            "uv",
            "install",
            tokens,
            tuple(python_target(spec) for spec in _collect_package_specs(list(working_tokens[2:]))),
            workspace=workspace,
            manifest_candidates=("pyproject.toml",),
            lockfile_candidates=("uv.lock",),
        )
    if len(working_tokens) >= 3 and working_tokens[1:3] == ("pip", "install"):
        return _build_intent(
            "uv",
            "install",
            tokens,
            tuple(python_target(spec) for spec in _collect_package_specs(list(working_tokens[3:]))),
            workspace=workspace,
            manifest_candidates=("pyproject.toml",),
            lockfile_candidates=("uv.lock",),
        )
    if working_tokens[1] == "sync":
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
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) < 2:
        return None
    if working_tokens[1] == "install":
        return _build_intent(
            "poetry",
            "sync",
            tokens,
            (),
            workspace=workspace,
            manifest_candidates=("pyproject.toml",),
            lockfile_candidates=("poetry.lock",),
        )
    if working_tokens[1] != "add":
        return None
    group = option_value(working_tokens, "--group") or option_value(working_tokens, "-G")
    extras_value = option_value(working_tokens, "--extras")
    extras = tuple(item for item in (extras_value or "").split(",") if item)
    targets = tuple(
        python_target(spec, dependency_group=group, extras=extras)
        for spec in _collect_package_specs(list(working_tokens[2:]))
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
    working_tokens = strip_package_manager_global_options(tokens)
    if len(working_tokens) < 2:
        return None
    if working_tokens[1] == "sync":
        return _build_intent(
            "pipenv",
            "sync",
            tokens,
            (),
            workspace=workspace,
            manifest_candidates=("Pipfile",),
            lockfile_candidates=("Pipfile.lock",),
        )
    if working_tokens[1] != "install":
        return None
    return _build_intent(
        "pipenv",
        "install",
        tokens,
        tuple(python_target(spec) for spec in _collect_package_specs(list(working_tokens[2:]))),
        workspace=workspace,
        manifest_candidates=("Pipfile",),
        lockfile_candidates=("Pipfile.lock",),
    )


def _parse_cargo_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2 or tokens[1] not in {"add", "install"}:
        return None
    source_url = option_value(tokens, "--path")
    if source_url is not None:
        source_url = f"file:{source_url}"
    if source_url is None:
        source_url = option_value(tokens, "--git")
    targets = tuple(
        version_target(
            "cargo",
            spec,
            source_url=source_url,
        )
        for spec in _collect_specs(
            tokens[2:],
            skip_value_options={"--branch", "--git", "--index", "--path", "--registry", "--rev", "--tag"},
        )
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


def _parse_system_package_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 2:
        return None
    command_name = _command_name(tokens[0])
    install_verbs = {
        "apk": {"add"},
        "apt": {"install"},
        "apt-get": {"install"},
        "brew": {"install"},
        "dnf": {"install"},
        "pacman": {"-s", "-sy", "-syu", "-suy"},
        "yum": {"install"},
        "zypper": {"install", "in"},
    }
    verb = tokens[1].lower()
    if verb not in install_verbs.get(command_name, set()):
        return None
    targets = tuple(
        PackageIntentTarget("system", package_name=spec, raw_spec=spec, requested_specifier=None)
        for spec in _collect_specs(tokens[2:], skip_value_options={"--repo", "--repository", "-c"})
    )
    return _build_intent(command_name, "install", tokens, targets, workspace=workspace)


def _parse_helm_intent(tokens: tuple[str, ...], *, workspace: Path | None) -> PackageIntent | None:
    if len(tokens) < 4 or tokens[1] != "install":
        return None
    chart = first_positional(tokens[3:], skip_value_options={"--version", "--repo", "-n", "--namespace"})
    if chart is None:
        chart = tokens[3]
    version = option_value(tokens, "--version")
    target = PackageIntentTarget("unsupported", package_name=chart, raw_spec=chart, requested_specifier=version)
    return _build_intent("helm", "install", tokens, (target,), workspace=workspace)


def _build_intent(
    package_manager: str,
    intent_kind: IntentKind,
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
    segments = _normalized_command_segments(command_text)
    return segments[0].tokens if segments else ()


def _normalized_command_segments(
    command_text: str,
    *,
    workspace: Path | None = None,
) -> tuple[_CommandSegment, ...]:
    try:
        tokens = _split_shell_tokens(command_text)
    except ValueError:
        return ()
    segments: list[_CommandSegment] = []
    effective_shell_cwd = (workspace or Path.cwd()).expanduser().resolve()
    shell_cwd_source = "workspace" if workspace is not None else "process"
    for segment_index, (raw_segment, following_operator) in enumerate(_raw_command_segments_with_operators(tokens)):
        normalized_tokens = _normalize_segment(raw_segment)
        if not normalized_tokens:
            continue
        redacted_tokens = _redacted_segment(raw_segment)
        effective_path, path_source, effective_cwd, cwd_source = _effective_execution_context(
            raw_segment,
            workspace=workspace,
            initial_cwd=effective_shell_cwd,
            initial_cwd_source=shell_cwd_source,
        )
        segments.append(
            _CommandSegment(
                tuple(normalized_tokens),
                tuple(redacted_tokens),
                effective_path,
                path_source,
                effective_cwd,
                cwd_source,
                _execution_context_hash(command_text, segment_index),
            )
        )
        if following_operator in {"&&", ";"}:
            effective_shell_cwd, shell_cwd_source = _cwd_after_shell_cd(
                raw_segment,
                current_cwd=effective_shell_cwd,
                current_source=shell_cwd_source,
            )
    return tuple(segments)


def _execution_context_hash(command_text: str, segment_index: int) -> str:
    payload = json.dumps(
        {"command": command_text, "segment_index": segment_index},
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _raw_command_segments(tokens: list[str]) -> tuple[list[str], ...]:
    return tuple(segment for segment, _operator in _raw_command_segments_with_operators(tokens))


def _raw_command_segments_with_operators(
    tokens: list[str],
) -> tuple[tuple[list[str], str | None], ...]:
    segments: list[tuple[list[str], str | None]] = []
    segment: list[str] = []
    for token in tokens:
        if token in _CONTROL_TOKENS:
            if segment:
                segments.append((segment, token))
            segment = []
            continue
        segment.append(token)
    if segment:
        segments.append((segment, None))
    return tuple(segments)


def _cwd_after_shell_cd(
    raw_segment: list[str],
    *,
    current_cwd: Path,
    current_source: str,
) -> tuple[Path, str]:
    segment = _normalize_segment(raw_segment)
    if not segment or _command_name(segment[0]) != "cd":
        return current_cwd, current_source
    arguments = list(segment[1:])
    while arguments and arguments[0] in {"-L", "-P"}:
        arguments.pop(0)
    if arguments and arguments[0] == "--":
        arguments.pop(0)
    if len(arguments) > 1:
        return current_cwd, "shell_cd_unresolved"
    value = arguments[0] if arguments else str(Path.home())
    expanded = os.path.expandvars(value)
    if not expanded or "$" in expanded or "\x00" in expanded:
        return current_cwd, "shell_cd_unresolved"
    candidate = Path(expanded).expanduser()
    if not candidate.is_absolute():
        candidate = current_cwd / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return current_cwd, "shell_cd_failed"
    if not resolved.is_dir():
        return current_cwd, "shell_cd_failed"
    return resolved, "shell_cd"


def _normalize_segment(raw_segment: list[str]) -> list[str]:
    segment = _strip_wrapper_tokens(list(raw_segment))
    if len(segment) >= 3 and _command_name(segment[0]) in _PYTHON_EXECUTABLES and segment[1] == "-m":
        segment = [segment[2], *segment[3:]]
    return segment


def _effective_execution_context(
    raw_segment: list[str],
    *,
    workspace: Path | None,
    initial_cwd: Path | None = None,
    initial_cwd_source: str | None = None,
) -> tuple[str | None, str, Path, str]:
    effective_cwd = (initial_cwd or workspace or Path.cwd()).expanduser().resolve()
    cwd_source = initial_cwd_source or ("workspace" if workspace is not None else "process")
    effective_path = os.environ.get("PATH")
    path_source = "inherited" if effective_path is not None else "inherited_unset"
    index, effective_path, path_source = _consume_path_assignments(
        raw_segment,
        0,
        effective_path,
        path_source,
        direct_source="inline",
    )
    if index >= len(raw_segment):
        return _path_for_resolution(effective_path, effective_cwd), path_source, effective_cwd, cwd_source

    command_name = _command_name(raw_segment[index])
    if command_name == "sudo":
        return None, "sudo_unresolved", effective_cwd, cwd_source
    while command_name in {"command", "time"}:
        index += 1
        if command_name == "command":
            while index < len(raw_segment) and raw_segment[index].startswith("-"):
                if "p" in raw_segment[index][1:]:
                    effective_path = os.defpath
                    path_source = "command_default"
                index += 1
        elif index < len(raw_segment) and raw_segment[index].startswith("-"):
            return None, "time_options_unresolved", effective_cwd, cwd_source
        index, effective_path, path_source = _consume_path_assignments(
            raw_segment,
            index,
            effective_path,
            path_source,
            direct_source="inline",
        )
        if index >= len(raw_segment):
            return _path_for_resolution(effective_path, effective_cwd), path_source, effective_cwd, cwd_source
        command_name = _command_name(raw_segment[index])
    if command_name != "env":
        return _path_for_resolution(effective_path, effective_cwd), path_source, effective_cwd, cwd_source

    index += 1
    parsing_options = True
    split_expansions = 0
    while index < len(raw_segment):
        token = raw_segment[index]
        if _ENV_ASSIGNMENT_RE.match(token):
            name, _, value = token.partition("=")
            if name == "PATH":
                effective_path = _expanded_path_assignment(value, effective_path)
                path_source = "env" if effective_path is not None else "env_unresolved"
            index += 1
            parsing_options = False
            continue
        if not parsing_options:
            break
        if token == "--":
            index += 1
            parsing_options = False
            continue
        if token in {"-i", "--ignore-environment"}:
            effective_path = os.defpath
            path_source = "env_default"
            index += 1
            continue
        if token in {"-u", "--unset"} and index + 1 < len(raw_segment):
            if raw_segment[index + 1] == "PATH":
                effective_path = os.defpath
                path_source = "env_default"
            index += 2
            continue
        if token.startswith("--unset="):
            if token.partition("=")[2] == "PATH":
                effective_path = os.defpath
                path_source = "env_default"
            index += 1
            continue
        if token.startswith("-u") and token != "-u":
            if token[2:] == "PATH":
                effective_path = os.defpath
                path_source = "env_default"
            index += 1
            continue
        if token in {"-C", "--chdir"} and index + 1 < len(raw_segment):
            effective_cwd, cwd_source = _updated_effective_cwd(
                effective_cwd,
                raw_segment[index + 1],
            )
            index += 2
            continue
        if token.startswith("--chdir="):
            effective_cwd, cwd_source = _updated_effective_cwd(
                effective_cwd,
                token.partition("=")[2],
            )
            index += 1
            continue
        if token.startswith("-C") and token != "-C":
            effective_cwd, cwd_source = _updated_effective_cwd(
                effective_cwd,
                token[2:],
            )
            index += 1
            continue
        if token == "-P" and index + 1 < len(raw_segment):
            effective_path = _expanded_path_assignment(raw_segment[index + 1], effective_path)
            path_source = "env_search_path" if effective_path is not None else "env_search_path_unresolved"
            index += 2
            continue
        if token.startswith("-P") and token != "-P":
            effective_path = _expanded_path_assignment(token[2:], effective_path)
            path_source = "env_search_path" if effective_path is not None else "env_search_path_unresolved"
            index += 1
            continue
        split_value, consumed = _env_split_value(raw_segment, index)
        if split_value is not None:
            if split_expansions >= 4:
                return None, "env_split_unresolved", effective_cwd, cwd_source
            try:
                split_tokens = shlex.split(split_value)
            except ValueError:
                return None, "env_split_unresolved", effective_cwd, cwd_source
            raw_segment = [*raw_segment[:index], *split_tokens, *raw_segment[index + consumed :]]
            split_expansions += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return _path_for_resolution(effective_path, effective_cwd), path_source, effective_cwd, cwd_source


def _consume_path_assignments(
    tokens: list[str],
    index: int,
    current_path: str | None,
    current_source: str,
    *,
    direct_source: str,
) -> tuple[int, str | None, str]:
    path_source = current_source
    while index < len(tokens) and _ENV_ASSIGNMENT_RE.match(tokens[index]):
        name, _, value = tokens[index].partition("=")
        if name == "PATH":
            current_path = _expanded_path_assignment(value, current_path)
            path_source = direct_source if current_path is not None else f"{direct_source}_unresolved"
        index += 1
    return index, current_path, path_source


def _path_for_resolution(path_value: str | None, effective_cwd: Path) -> str | None:
    if path_value is None:
        return None
    entries: list[str] = []
    for entry in path_value.split(os.pathsep):
        candidate = Path(entry) if entry else effective_cwd
        if not candidate.is_absolute():
            candidate = effective_cwd / candidate
        entries.append(str(candidate.resolve()))
    return os.pathsep.join(entries)


def _updated_effective_cwd(current_cwd: Path, value: str) -> tuple[Path, str]:
    expanded = os.path.expandvars(value)
    if not expanded or "$" in expanded or "\x00" in expanded:
        return current_cwd, "env_chdir_unresolved"
    candidate = Path(expanded).expanduser()
    if not candidate.is_absolute():
        candidate = current_cwd / candidate
    try:
        return candidate.resolve(), "env_chdir"
    except (OSError, RuntimeError):
        return current_cwd, "env_chdir_unresolved"


def _expanded_path_assignment(value: str, current_path: str | None) -> str | None:
    expanded = value.replace("${PATH}", current_path or "").replace("$PATH", current_path or "")
    expanded = os.path.expandvars(expanded)
    if "$" in expanded or "\x00" in expanded:
        return None
    return expanded


def _redacted_command_text(command_text: str) -> str:
    try:
        tokens = _split_shell_tokens(command_text)
    except ValueError:
        return ""
    raw_segments = _raw_command_segments(tokens)
    if not raw_segments:
        return ""
    segment = _redacted_segment(raw_segments[0])
    return redacted_command(tuple(segment))


def _redacted_segment(raw_segment: list[str]) -> list[str]:
    segment = _strip_redaction_wrappers(list(raw_segment))
    if len(segment) >= 3 and _command_name(segment[0]) in _PYTHON_EXECUTABLES and segment[1] == "-m":
        segment = [segment[2], *segment[3:]]
    return _redact_local_source_tokens(segment)


def _split_shell_tokens(command_text: str) -> list[str]:
    lexer = shlex.shlex(command_text, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _strip_redaction_wrappers(segment: list[str]) -> list[str]:
    preserved_env: list[str] = []
    while segment:
        if _ENV_ASSIGNMENT_RE.match(segment[0]):
            if _package_source_env_assignment(segment[0]):
                preserved_env.append(segment[0])
            segment.pop(0)
            continue
        command_name = _command_name(segment[0])
        if command_name == "sudo":
            segment = _strip_sudo_prefix(segment[1:])
            continue
        if command_name == "env":
            env_preserved, segment = _strip_env_prefix_for_redaction(segment[1:])
            preserved_env.extend(env_preserved)
            continue
        if command_name in {"command", "time"}:
            segment = _strip_plain_wrapper_flags(segment[1:])
            continue
        break
    return [*preserved_env, *segment]


def _combine_package_intents(intents: tuple[PackageIntent, ...]) -> PackageIntent | None:
    if not intents:
        return None
    if len(intents) == 1:
        return intents[0]
    return PackageIntent(
        package_manager=_combined_package_manager(intents),
        intent_kind=_combined_intent_kind(intents),
        command_tokens=_unique_joined_tokens(intent.command_tokens for intent in intents),
        redacted_command=" ; ".join(intent.redacted_command for intent in intents if intent.redacted_command),
        targets=tuple(target for intent in intents for target in intent.targets),
        manifest_paths=_unique_joined_strings(intent.manifest_paths for intent in intents),
        lockfile_paths=_unique_joined_strings(intent.lockfile_paths for intent in intents),
        flags=_unique_joined_strings(intent.flags for intent in intents),
        notes=_unique_joined_strings((*[intent.notes for intent in intents], ("multiple-package-segments",))),
        local_executions=tuple(evidence for intent in intents for evidence in intent.local_executions),
    )


def _combined_package_manager(intents: tuple[PackageIntent, ...]) -> str:
    managers = {intent.package_manager for intent in intents}
    if len(managers) == 1:
        return intents[0].package_manager
    return "multiple"


def _combined_intent_kind(intents: tuple[PackageIntent, ...]) -> IntentKind:
    kinds = {intent.intent_kind for intent in intents}
    if len(kinds) == 1:
        return intents[0].intent_kind
    if "install" in kinds:
        return "install"
    if "execute" in kinds:
        return "execute"
    return "sync"


def _unique_joined_tokens(groups: Iterable[Iterable[str]]) -> tuple[str, ...]:
    tokens: list[str] = []
    for group in groups:
        if tokens:
            tokens.append(";")
        tokens.extend(str(token) for token in group)
    return tuple(tokens)


def _unique_joined_strings(groups: Iterable[Iterable[str]]) -> tuple[str, ...]:
    values: list[str] = []
    for group in groups:
        for value in group:
            if value not in values:
                values.append(value)
    return tuple(values)


def _package_source_env_assignment(token: str) -> bool:
    name, separator, value = token.partition("=")
    return bool(separator and value and name.upper() in _PACKAGE_SOURCE_ENV_NAMES)


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


def _redact_local_source_tokens(segment: list[str]) -> list[str]:
    redacted: list[str] = []
    path_flags = {"--path"}
    index = 0
    while index < len(segment):
        token = segment[index]
        if token in path_flags and index + 1 < len(segment):
            redacted.extend((token, "<local-path>"))
            index += 2
            continue
        if token.startswith("--path="):
            redacted.append("--path=<local-path>")
            index += 1
            continue
        if token.startswith("file:"):
            redacted.append("file:<local-path>")
            index += 1
            continue
        redacted.append(token)
        index += 1
    return redacted


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
    parsing_options = True
    while index < len(tokens):
        token = tokens[index]
        if _ENV_ASSIGNMENT_RE.match(token):
            index += 1
            parsing_options = False
            continue
        if not parsing_options:
            break
        if not token.startswith("-"):
            break
        if token == "--":
            index += 1
            break
        split_value, consumed = _env_split_value(tokens, index)
        if split_value is not None:
            try:
                split_tokens = shlex.split(split_value)
            except ValueError:
                return tokens[index + consumed :]
            return _strip_env_prefix([*split_tokens, *tokens[index + consumed :]])
        if token in {"-u", "--unset", "-C", "--chdir", "-P", "-S", "--split-string"} and index + 1 < len(tokens):
            index += 2
            continue
        index += 1
    return tokens[index:]


def _strip_env_prefix_for_redaction(tokens: list[str]) -> tuple[list[str], list[str]]:
    preserved_env: list[str] = []
    index = 0
    parsing_options = True
    while index < len(tokens):
        token = tokens[index]
        if _ENV_ASSIGNMENT_RE.match(token):
            if _package_source_env_assignment(token):
                preserved_env.append(token)
            index += 1
            parsing_options = False
            continue
        if not parsing_options:
            break
        if not token.startswith("-"):
            break
        if token == "--":
            index += 1
            break
        split_value, consumed = _env_split_value(tokens, index)
        if split_value is not None:
            try:
                split_tokens = shlex.split(split_value)
            except ValueError:
                return preserved_env, tokens[index + consumed :]
            nested_preserved, nested_tokens = _strip_env_prefix_for_redaction(
                [*split_tokens, *tokens[index + consumed :]]
            )
            return [*preserved_env, *nested_preserved], nested_tokens
        if token in {"-u", "--unset", "-C", "--chdir", "-P", "-S", "--split-string"} and index + 1 < len(tokens):
            index += 2
            continue
        index += 1
    return preserved_env, tokens[index:]


def _env_split_value(tokens: list[str], index: int) -> tuple[str | None, int]:
    token = tokens[index]
    if token in {"-S", "--split-string"}:
        return (tokens[index + 1], 2) if index + 1 < len(tokens) else (None, 1)
    if token.startswith("--split-string="):
        return token.partition("=")[2], 1
    if token.startswith("-S") and token != "-S":
        return token[2:], 1
    return None, 0


def _strip_plain_wrapper_flags(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens) and tokens[index].startswith("-"):
        index += 1
    return tokens[index:]
