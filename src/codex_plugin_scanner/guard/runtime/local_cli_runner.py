"""Unwrap package-runner invocations such as ``npx wrangler`` to the CLI they run.

A runner command is bound to the project's ``node_modules/.bin`` binary only
when the resident package-intent parser proves the bin resolves locally and
content-hashes it. Registry and cache fetches keep a package-keyed identity
that never carries a persistent allow.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

LOCAL_BIN_RUNNERS = frozenset({"npx", "bunx", "pnpm", "pnpx", "yarn", "npm"})
# Runners that fetch a missing package from the registry instead of failing.
REGISTRY_FETCH_RUNNERS = frozenset({"npx", "bunx", "pnpx"})
# Only these options may precede a runner target. Package selectors such as
# ``--package``/``-p`` or ``--call``/``-c`` make the runner execute something
# other than the named bin, so any other pre-target option is not unwrapped.
RUNNER_PRETARGET_OPTIONS = frozenset({"-y", "--yes"})
RUNNER_EXEC_SUBCOMMANDS = frozenset({"exec", "x"})
_EXEC_SUBCOMMAND_RUNNERS = frozenset({"npm", "pnpm", "yarn"})
_MAX_PACKAGE_MANIFEST_BYTES = 1_048_576
_MAX_MANIFEST_ANCESTORS = 32
_PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True, slots=True)
class RunnerInvocation:
    """The CLI a package runner launches and the arguments passed to it."""

    runner: str
    target: str
    package_name: str
    inner_arguments: tuple[str, ...]
    local_bin: dict[str, object] | None = None
    direct_dependency: bool = False


def runner_name(executable: str | None) -> str | None:
    if not executable:
        return None
    base = Path(executable.replace("\\", "/")).name.lower()
    if base.endswith((".cmd", ".exe")):
        base = base.rsplit(".", 1)[0]
    return base if base in LOCAL_BIN_RUNNERS else None


def runner_target(runner: str, arguments: list[str] | tuple[str, ...]) -> str | None:
    """Return the bin a runner launches, or ``None`` for any selector form."""

    split = _split_runner_arguments(runner, arguments)
    return split[0] if split is not None else None


def runner_local_bin(
    command: str,
    runner: str,
    arguments: list[str] | tuple[str, ...],
    *,
    cwd: Path,
    home_dir: Path | None,
    reject_target: Callable[[str], bool] | None = None,
) -> dict[str, object] | None:
    """Return content-hashed local-bin evidence for a runner command, or ``None``."""

    from .package_intent_parser import parse_package_intent

    try:
        intent = parse_package_intent(command, workspace=cwd, home_dir=home_dir)
    except Exception:
        return None
    executions = getattr(intent, "local_executions", None) if intent is not None else None
    if not executions or len(executions) != 1:
        return None
    evidence = executions[0]
    local = getattr(evidence, "local_executable", None)
    manager = getattr(evidence, "manager", None)
    if local is None or manager is None or getattr(evidence, "manager_is_guard_shim", False):
        return None
    resolved = getattr(local, "resolved_path", None)
    content_hash = getattr(local, "content_hash", None)
    if getattr(local, "status", None) != "available" or not resolved or not content_hash:
        return None
    # A versioned or aliased spec (``wrangler@3``) can make the runner fetch a
    # different release than the local bin, so only the bare bin name binds.
    target = runner_target(runner, arguments)
    if target is None or target != getattr(evidence, "executable_name", None):
        return None
    if reject_target is not None and reject_target(target.lower()):
        return None
    package_name = getattr(evidence, "package_name", None)
    version = installed_package_version(Path(resolved), package_name)
    if version is None:
        return None
    bin_target = None
    if _is_bin_shim(Path(resolved)):
        # A shim only launches the package's bin script, so its own hash says
        # nothing about the code that runs; bind the script it launches too.
        bin_target = shim_bin_target(Path(resolved).parent.parent, package_name, target)
        if bin_target is None:
            return None
    record: dict[str, object] = {
        "package_name": package_name,
        "executable_name": getattr(evidence, "executable_name", None),
        "installed_version": version,
        "resolved_path": resolved,
        "content_hash": content_hash,
        "manager": {
            "resolved_path": getattr(manager, "resolved_path", None),
            "content_hash": getattr(manager, "content_hash", None),
        },
        "manifests": file_hashes(getattr(evidence, "manifests", ())),
        "lockfiles": file_hashes(getattr(evidence, "lockfiles", ())),
    }
    if bin_target is not None:
        record["bin_target"] = bin_target
    return record


def unwrap_local_runner(
    command: str,
    executable: str | None,
    arguments: list[str] | tuple[str, ...],
    *,
    cwd: Path,
    home_dir: Path | None,
) -> RunnerInvocation | None:
    """Return the CLI a runner command launches, with local-bin evidence when proven."""

    runner = runner_name(executable)
    if runner is None:
        return None
    split = _split_runner_arguments(runner, arguments)
    if split is None:
        return None
    spec, inner = split
    package_name, _, version_spec = spec.rpartition("@") if spec.rfind("@") > 0 else (spec, "", "")
    if not _PACKAGE_NAME.fullmatch(package_name):
        return None
    target = package_name.rsplit("/", 1)[-1]
    local_bin = None
    if not version_spec:
        local_bin = runner_local_bin(command, runner, arguments, cwd=cwd, home_dir=home_dir)
    if local_bin is None and runner not in REGISTRY_FETCH_RUNNERS:
        # pnpm/yarn/npm only launch installed bins; without proof this is not a CLI call.
        return None
    if local_bin is not None:
        package_name = str(local_bin.get("package_name") or package_name)
    return RunnerInvocation(
        runner=runner,
        target=target,
        package_name=package_name,
        inner_arguments=tuple(inner),
        local_bin=local_bin,
        direct_dependency=local_bin is not None and is_direct_dependency(cwd, package_name),
    )


def runner_inner_arguments(runner: str, arguments: list[str] | tuple[str, ...]) -> list[str] | None:
    """Return the arguments passed through to the runner's target CLI."""

    split = _split_runner_arguments(runner, arguments)
    return split[1] if split is not None else None


def installed_package_version(resolved_bin: Path, package_name: object) -> str | None:
    """Read the installed package version that owns the resolved bin."""

    if not isinstance(package_name, str) or not package_name:
        return None
    if _is_bin_shim(resolved_bin):
        # npm on Windows and pnpm write regular-file shims into ``.bin``
        # instead of symlinks, so the owning package sits beside ``.bin``.
        return _shim_package_version(resolved_bin.parent.parent, package_name)
    for parent in resolved_bin.parents:
        if parent.name == "node_modules":
            return None
        data = _read_manifest(parent / "package.json")
        if data is _UNREADABLE:
            return None
        if isinstance(data, dict) and data.get("name") == package_name:
            version = data.get("version")
            return version if isinstance(version, str) and version else None
    return None


def shim_bin_target(node_modules: Path, package_name: object, executable_name: str) -> dict[str, object] | None:
    """Hash the package bin script a ``node_modules/.bin`` shim launches."""

    if not isinstance(package_name, str) or not _PACKAGE_NAME.fullmatch(package_name):
        return None
    package_dir = node_modules.joinpath(*package_name.split("/"))
    data = _read_manifest(package_dir / "package.json")
    if not isinstance(data, dict) or data.get("name") != package_name:
        return None
    bin_field = data.get("bin")
    if isinstance(bin_field, str) and executable_name == package_name.rsplit("/", 1)[-1]:
        entry: object = bin_field
    elif isinstance(bin_field, dict):
        entry = bin_field.get(executable_name)
    else:
        return None
    if not isinstance(entry, str) or not entry.strip():
        return None
    try:
        root = package_dir.resolve(strict=True)
        script = (root / entry).resolve(strict=True)
        if not script.is_relative_to(root) or not script.is_file():
            return None
        digest = hashlib.sha256()
        with script.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, RuntimeError):
        return None
    return {"resolved_path": str(script), "content_hash": f"sha256:{digest.hexdigest()}"}


def _is_bin_shim(resolved_bin: Path) -> bool:
    return resolved_bin.parent.name == ".bin" and resolved_bin.parent.parent.name == "node_modules"


def _shim_package_version(node_modules: Path, package_name: str) -> str | None:
    if not _PACKAGE_NAME.fullmatch(package_name):
        return None
    data = _read_manifest(node_modules.joinpath(*package_name.split("/"), "package.json"))
    if not isinstance(data, dict) or data.get("name") != package_name:
        return None
    version = data.get("version")
    return version if isinstance(version, str) and version else None


def is_direct_dependency(cwd: Path, package_name: str) -> bool:
    """Return whether the nearest ``package.json`` declares the package directly."""

    for index, parent in enumerate((cwd, *cwd.parents)):
        if index >= _MAX_MANIFEST_ANCESTORS:
            return False
        data = _read_manifest(parent / "package.json")
        if data is None:
            continue
        if not isinstance(data, dict):
            return False
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            section = data.get(field)
            if isinstance(section, dict) and package_name in section:
                return True
        return False
    return False


def file_hashes(entries: object) -> list[dict[str, object]]:
    if not isinstance(entries, (list, tuple)):
        return []
    return [
        {
            "path": getattr(entry, "path", None),
            "status": getattr(entry, "status", None),
            "content_hash": getattr(entry, "content_hash", None),
        }
        for entry in entries
    ]


_UNREADABLE = object()


def _read_manifest(manifest: Path) -> object:
    try:
        if not manifest.is_file():
            return None
        if manifest.stat().st_size > _MAX_PACKAGE_MANIFEST_BYTES:
            return _UNREADABLE
        return json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return _UNREADABLE


def _split_runner_arguments(
    runner: str,
    arguments: list[str] | tuple[str, ...],
) -> tuple[str, list[str]] | None:
    exec_subcommand_allowed = runner in _EXEC_SUBCOMMAND_RUNNERS
    for index, argument in enumerate(arguments):
        if argument == "--" or argument in RUNNER_PRETARGET_OPTIONS:
            continue
        if argument.startswith("-"):
            return None
        if exec_subcommand_allowed and argument in RUNNER_EXEC_SUBCOMMANDS:
            exec_subcommand_allowed = False
            continue
        return argument, list(arguments[index + 1 :])
    return None


__all__ = [
    "LOCAL_BIN_RUNNERS",
    "REGISTRY_FETCH_RUNNERS",
    "RunnerInvocation",
    "file_hashes",
    "installed_package_version",
    "is_direct_dependency",
    "runner_inner_arguments",
    "runner_local_bin",
    "runner_name",
    "runner_target",
    "shim_bin_target",
    "unwrap_local_runner",
]
