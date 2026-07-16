"""Security-complete identities for reusable package approvals.

Package approvals are reusable only when Guard can bind the request to a Git
repository and to every local input that can materially change package-manager
execution.  The evidence representation contains digests and stable labels,
never registry credentials or configuration contents.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .models import GuardArtifact
from .runtime.workspace_path_guard import resolve_path_within_workspace

PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND: Final = "package_execution_context"
PACKAGE_EXECUTION_CONTEXT_VERSION: Final = 2

_SUPPORTED_PORTABLE_MANAGERS = frozenset(
    {
        "bun",
        "bunx",
        "bundle",
        "bundler",
        "cargo",
        "composer",
        "gem",
        "go",
        "gradle",
        "gradlew",
        "mvn",
        "mvnw",
        "npm",
        "npx",
        "pip",
        "pip3",
        "pipenv",
        "pipx",
        "pnpm",
        "poetry",
        "uv",
        "uvx",
        "yarn",
    }
)
_JS_MANAGERS = frozenset({"bun", "bunx", "npm", "npx", "pnpm", "yarn"})
_PYTHON_MANAGERS = frozenset({"pip", "pip3", "pipenv", "pipx", "poetry", "uv", "uvx"})
_RUBY_MANAGERS = frozenset({"bundle", "bundler", "gem"})
_MAX_CONFIG_FILE_BYTES = 2 * 1024 * 1024
_MAX_DEPENDENCY_FILE_BYTES = 32 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_MAX_CONTEXT_BYTES = 96 * 1024 * 1024
_MAX_TREE_FILES = 512
_MAX_GIT_POINTER_BYTES = 16 * 1024

_GENERIC_ENVIRONMENT_NAMES = frozenset(
    {
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)
_MANAGER_ENVIRONMENT_NAMES: dict[str, frozenset[str]] = {
    "js": frozenset(
        {
            "BUN_CONFIG_REGISTRY",
            "NODE_AUTH_TOKEN",
            "NPM_CONFIG_CAFILE",
            "NPM_CONFIG_HTTPS_PROXY",
            "NPM_CONFIG_PROXY",
            "NPM_CONFIG_REGISTRY",
            "NPM_CONFIG_STRICT_SSL",
            "NPM_CONFIG_USERCONFIG",
            "NPM_TOKEN",
            "YARN_ENABLE_NETWORK",
            "YARN_ENABLE_SCRIPTS",
            "YARN_HTTP_PROXY",
            "YARN_HTTPS_PROXY",
            "YARN_NPM_AUTH_TOKEN",
            "YARN_NPM_REGISTRY_SERVER",
            "YARN_RC_FILENAME",
        }
    ),
    "python": frozenset(
        {
            "PIP_CERT",
            "PIP_CLIENT_CERT",
            "PIP_CONFIG_FILE",
            "PIP_EXTRA_INDEX_URL",
            "PIP_FIND_LINKS",
            "PIP_INDEX_URL",
            "PIP_NO_INDEX",
            "PIP_TRUSTED_HOST",
            "UV_DEFAULT_INDEX",
            "UV_EXTRA_INDEX_URL",
            "UV_INDEX",
            "UV_INDEX_URL",
            "UV_NO_INDEX",
        }
    ),
    "go": frozenset({"GONOPROXY", "GONOSUMDB", "GOPRIVATE", "GOPROXY", "GOSUMDB"}),
    "jvm": frozenset({"GRADLE_OPTS", "MAVEN_ARGS", "MAVEN_OPTS"}),
    "php": frozenset({"COMPOSER_AUTH", "COMPOSER_HOME", "COMPOSER_REPO_PACKAGIST"}),
}
_DYNAMIC_CODE_LOAD_RE = re.compile(r"(?:require\s*\(|import\s*\()")
_ENV_REFERENCE_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_NPM_DYNAMIC_CONFIG_RE = re.compile(r"^\s*(?:globalconfig|userconfig)\s*=", re.IGNORECASE | re.MULTILINE)


@dataclass(frozen=True, slots=True)
class PackageExecutionContextComponent:
    """One safely displayable component of a package execution identity."""

    name: str
    digest: str


@dataclass(frozen=True, slots=True)
class PackageExecutionContext:
    """Versioned package-manager execution context."""

    digest: str
    portable: bool
    components: tuple[PackageExecutionContextComponent, ...]
    non_portable_reason: str | None = None
    version: int = PACKAGE_EXECUTION_CONTEXT_VERSION

    def to_evidence(self, *, changed_components: Sequence[str] = ()) -> dict[str, object]:
        payload: dict[str, object] = {
            "kind": PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND,
            "schema_version": self.version,
            "portable": self.portable,
            "context_digest": self.digest,
            "components": [{"name": component.name, "digest": component.digest} for component in self.components],
            "portable_summary": (
                "Reusable only across linked Git worktrees when every package execution input matches."
                if self.portable
                else "Bound to this retry because Guard could not prove a complete portable package context."
            ),
        }
        if self.non_portable_reason is not None:
            payload["non_portable_reason"] = self.non_portable_reason
        normalized_changes = tuple(dict.fromkeys(item for item in changed_components if item))
        if normalized_changes:
            payload["changed_components"] = list(normalized_changes)
        return payload


@dataclass(slots=True)
class _ContextFiles:
    total_bytes: int = 0
    count: int = 0

    def read(self, path: Path, *, maximum_bytes: int, allow_symlink: bool = False) -> bytes:
        descriptor: int | None = None
        try:
            if path.is_symlink() and not allow_symlink:
                raise _ContextUnavailableError("symlinked_configuration")
            resolved = path.resolve(strict=True) if allow_symlink else path
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(resolved, flags)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise _ContextUnavailableError("unsupported_configuration")
            if before.st_size > maximum_bytes or self.total_bytes + before.st_size > _MAX_CONTEXT_BYTES:
                raise _ContextUnavailableError("oversized_configuration")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
        except _ContextUnavailableError:
            raise
        except (OSError, RuntimeError):
            raise _ContextUnavailableError("unreadable_configuration") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
        stable_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        final_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if len(payload) != before.st_size or stable_identity != final_identity:
            raise _ContextUnavailableError("configuration_changed_during_review")
        self.total_bytes += len(payload)
        self.count += 1
        if self.count > _MAX_TREE_FILES:
            raise _ContextUnavailableError("oversized_configuration")
        return payload


class _ContextUnavailableError(RuntimeError):
    reason: str

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def build_package_execution_context(
    *,
    workspace_dir: Path,
    artifact: GuardArtifact,
    executable: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> PackageExecutionContext:
    """Build a fail-closed package execution context for an approval request."""

    workspace = workspace_dir.expanduser().resolve()
    env = dict(os.environ if environment is None else environment)
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    manager = _string_value(metadata.get("package_manager")) or "unknown"
    components: list[PackageExecutionContextComponent] = []
    files = _ContextFiles()
    first_failure: str | None = None

    repository_root, repository_material, repository_failure = _repository_material(workspace, files=files)
    if repository_failure is not None:
        first_failure = repository_failure
    components.append(_component("repository_identity", repository_material))
    workspace_material = _workspace_material(workspace, repository_root, portable=repository_failure is None)
    components.append(_component("workspace_identity", workspace_material))

    if manager not in _SUPPORTED_PORTABLE_MANAGERS:
        first_failure = first_failure or "unsupported_package_manager"
    if _is_global_request(metadata):
        first_failure = first_failure or "global_package_request"

    executable_material, executable_failure = _executable_material(
        workspace=workspace,
        repository_root=repository_root,
        manager=manager,
        executable=executable or _string_value(metadata.get("package_executable")),
        environment=env,
        files=files,
    )
    if executable_failure is not None:
        first_failure = first_failure or executable_failure
    components.append(_component("package_manager_executable", executable_material))

    dependency_material, dependency_failure = _dependency_material(
        workspace=workspace,
        metadata=metadata,
        files=files,
    )
    if dependency_failure is not None:
        first_failure = first_failure or dependency_failure
    components.append(_component("manifests_and_lockfiles", dependency_material))

    try:
        configuration = _configuration_material(
            workspace=workspace,
            repository_root=repository_root,
            manager=manager,
            environment=env,
            files=files,
        )
    except _ContextUnavailableError as error:
        first_failure = first_failure or error.reason
        configuration = {
            "registry_proxy": {"status": error.reason},
            "workspace": {"status": error.reason},
            "hooks_overrides_patches": {"status": error.reason},
            "referenced_environment_names": [],
        }
    components.extend(
        (
            _component("registry_and_proxy_configuration", configuration["registry_proxy"]),
            _component("workspace_configuration", configuration["workspace"]),
            _component("lifecycle_hooks_overrides_and_patches", configuration["hooks_overrides_patches"]),
        )
    )

    referenced_names = configuration.get("referenced_environment_names")
    environment_material = _environment_material(
        manager,
        env,
        referenced_names if isinstance(referenced_names, list) else [],
    )
    components.append(_component("environment_policy", environment_material))

    portable = first_failure is None
    if not portable:
        components.append(_component("exact_workspace", {"path": str(workspace)}))
    digest = _digest_json(
        {
            "components": [{"name": item.name, "digest": item.digest} for item in components],
            "portable": portable,
            "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
        }
    )
    return PackageExecutionContext(
        digest=digest,
        portable=portable,
        components=tuple(components),
        non_portable_reason=first_failure,
    )


def package_execution_context_from_evidence(value: object) -> PackageExecutionContext | None:
    """Load and strictly validate a package context from persisted safe evidence."""

    if not isinstance(value, Mapping):
        return None
    if value.get("kind") != PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND:
        return None
    if value.get("schema_version") != PACKAGE_EXECUTION_CONTEXT_VERSION:
        return None
    digest = _sha256_value(value.get("context_digest"))
    if digest is None or not isinstance(value.get("portable"), bool):
        return None
    raw_components = value.get("components")
    if not isinstance(raw_components, list):
        return None
    components: list[PackageExecutionContextComponent] = []
    seen: set[str] = set()
    for item in raw_components:
        if not isinstance(item, Mapping):
            return None
        name = _string_value(item.get("name"))
        component_digest = _sha256_value(item.get("digest"))
        if name is None or component_digest is None or name in seen:
            return None
        seen.add(name)
        components.append(PackageExecutionContextComponent(name=name, digest=component_digest))
    if not components:
        return None
    portable = bool(value["portable"])
    expected_digest = _digest_json(
        {
            "components": [{"name": item.name, "digest": item.digest} for item in components],
            "portable": portable,
            "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
        }
    )
    if digest != expected_digest:
        return None
    reason = _string_value(value.get("non_portable_reason"))
    return PackageExecutionContext(
        digest=digest,
        portable=portable,
        components=tuple(components),
        non_portable_reason=reason,
    )


def package_execution_context_from_scanner_evidence(value: object) -> PackageExecutionContext | None:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return None
    for item in value:
        context = package_execution_context_from_evidence(item)
        if context is not None:
            return context
    return None


def changed_package_execution_context_components(
    previous: PackageExecutionContext,
    current: PackageExecutionContext,
) -> tuple[str, ...]:
    previous_components = {item.name: item.digest for item in previous.components}
    current_components = {item.name: item.digest for item in current.components}
    return tuple(
        sorted(
            name
            for name in previous_components.keys() | current_components.keys()
            if previous_components.get(name) != current_components.get(name)
        )
    )


def _repository_material(
    workspace: Path,
    *,
    files: _ContextFiles,
) -> tuple[Path | None, dict[str, object], str | None]:
    for candidate_root in (workspace, *workspace.parents):
        marker = candidate_root / ".git"
        if not marker.exists():
            continue
        try:
            git_dir = _resolve_git_dir(marker, files=files)
            common_dir = _resolve_git_common_dir(git_dir, files=files)
            remotes = _git_remote_urls(common_dir / "config", files=files)
        except _ContextUnavailableError as error:
            return None, {"workspace_path": str(workspace)}, error.reason
        return (
            candidate_root,
            {
                "common_git_dir": str(common_dir),
                "remote_urls": list(remotes),
            },
            None,
        )
    return None, {"workspace_path": str(workspace)}, "repository_identity_unavailable"


def _resolve_git_dir(marker: Path, *, files: _ContextFiles) -> Path:
    if marker.is_dir():
        return marker.resolve()
    payload = files.read(marker, maximum_bytes=_MAX_GIT_POINTER_BYTES)
    try:
        text = payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise _ContextUnavailableError("repository_identity_unavailable") from None
    if not text.startswith("gitdir:"):
        raise _ContextUnavailableError("repository_identity_unavailable")
    raw_path = text.partition(":")[2].strip()
    if not raw_path:
        raise _ContextUnavailableError("repository_identity_unavailable")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = marker.parent / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise _ContextUnavailableError("repository_identity_unavailable") from None
    if not resolved.is_dir():
        raise _ContextUnavailableError("repository_identity_unavailable")
    return resolved


def _resolve_git_common_dir(git_dir: Path, *, files: _ContextFiles) -> Path:
    marker = git_dir / "commondir"
    if not marker.exists():
        return git_dir.resolve()
    payload = files.read(marker, maximum_bytes=_MAX_GIT_POINTER_BYTES)
    try:
        raw_path = payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise _ContextUnavailableError("repository_identity_unavailable") from None
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = git_dir / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise _ContextUnavailableError("repository_identity_unavailable") from None
    if not resolved.is_dir():
        raise _ContextUnavailableError("repository_identity_unavailable")
    return resolved


def _git_remote_urls(config_path: Path, *, files: _ContextFiles) -> tuple[str, ...]:
    if not config_path.exists():
        return ()
    payload = files.read(config_path, maximum_bytes=_MAX_CONFIG_FILE_BYTES)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise _ContextUnavailableError("repository_identity_unavailable") from None
    in_remote = False
    urls: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_remote = stripped.lower().startswith('[remote "')
            continue
        if not in_remote or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.strip().lower() == "url" and value.strip():
            urls.append(value.strip())
    return tuple(sorted(dict.fromkeys(urls)))


def _workspace_material(workspace: Path, repository_root: Path | None, *, portable: bool) -> dict[str, object]:
    if portable and repository_root is not None:
        try:
            relative = workspace.relative_to(repository_root).as_posix() or "."
        except ValueError:
            relative = str(workspace)
        return {"repository_relative_path": relative}
    return {"exact_path": str(workspace)}


def _executable_material(
    *,
    workspace: Path,
    repository_root: Path | None,
    manager: str,
    executable: str | None,
    environment: Mapping[str, str],
    files: _ContextFiles,
) -> tuple[dict[str, object], str | None]:
    requested = executable or manager
    if not requested or requested == "unknown" or any(token in requested for token in (";", "&&", "||", "|")):
        return {"manager": manager, "status": "unavailable"}, "package_manager_executable_unavailable"
    candidate: Path | None
    if "/" in requested or "\\" in requested:
        raw_path = Path(requested).expanduser()
        candidate = raw_path if raw_path.is_absolute() else workspace / raw_path
        try:
            candidate = candidate.resolve(strict=True)
        except OSError:
            candidate = None
    else:
        resolved = shutil.which(requested, path=environment.get("PATH"))
        candidate = Path(resolved).resolve() if resolved is not None else None
    if candidate is None:
        return {"manager": manager, "requested": Path(requested).name, "status": "unavailable"}, (
            "package_manager_executable_unavailable"
        )
    try:
        payload = files.read(candidate, maximum_bytes=_MAX_EXECUTABLE_BYTES, allow_symlink=True)
    except _ContextUnavailableError as error:
        return {"manager": manager, "requested": Path(requested).name, "status": error.reason}, error.reason
    location = _canonical_executable_location(candidate, workspace=workspace, repository_root=repository_root)
    return {
        "content_digest": hashlib.sha256(payload).hexdigest(),
        "location": location,
        "manager": manager,
        "requested": Path(requested).name,
    }, None


def _canonical_executable_location(candidate: Path, *, workspace: Path, repository_root: Path | None) -> str:
    for label, root in (("workspace", workspace), ("repository", repository_root)):
        if root is None:
            continue
        try:
            return f"{label}:{candidate.relative_to(root).as_posix()}"
        except ValueError:
            continue
    return f"external:{candidate}"


def _dependency_material(
    *,
    workspace: Path,
    metadata: Mapping[str, object],
    files: _ContextFiles,
) -> tuple[dict[str, object], str | None]:
    entries: list[dict[str, str]] = []
    failure: str | None = None
    for kind, key in (("manifest", "manifest_paths"), ("lockfile", "lockfile_paths")):
        for relative_path in _string_items(metadata.get(key)):
            resolved = resolve_path_within_workspace(workspace, relative_path)
            if resolved is None or not resolved.exists():
                entries.append({"kind": kind, "path": relative_path, "status": "missing"})
                failure = failure or "dependency_file_unavailable"
                continue
            try:
                payload = files.read(resolved, maximum_bytes=_MAX_DEPENDENCY_FILE_BYTES)
            except _ContextUnavailableError as error:
                entries.append({"kind": kind, "path": relative_path, "status": error.reason})
                failure = failure or error.reason
                continue
            entries.append(
                {
                    "digest": hashlib.sha256(payload).hexdigest(),
                    "kind": kind,
                    "path": relative_path,
                }
            )
    return {"files": entries}, failure


def _configuration_material(
    *,
    workspace: Path,
    repository_root: Path | None,
    manager: str,
    environment: Mapping[str, str],
    files: _ContextFiles,
) -> dict[str, object]:
    roots = _configuration_roots(workspace, repository_root)
    registry_entries: list[dict[str, str]] = []
    workspace_entries: list[dict[str, str]] = []
    hook_entries: list[dict[str, str]] = []
    referenced_environment_names: set[str] = set()

    registry_names, workspace_names, hook_names = _manager_configuration_names(manager)
    for root in roots:
        for name in registry_names:
            _append_optional_config(
                root / name,
                root_label=_root_label(root, workspace=workspace, repository_root=repository_root),
                entries=registry_entries,
                files=files,
                referenced_environment_names=referenced_environment_names,
                normalize_npmrc=name.endswith("npmrc"),
            )
        for name in workspace_names:
            _append_optional_config(
                root / name,
                root_label=_root_label(root, workspace=workspace, repository_root=repository_root),
                entries=workspace_entries,
                files=files,
                referenced_environment_names=referenced_environment_names,
            )
        for name in hook_names:
            _append_optional_config(
                root / name,
                root_label=_root_label(root, workspace=workspace, repository_root=repository_root),
                entries=hook_entries,
                files=files,
                referenced_environment_names=referenced_environment_names,
                inspect_dynamic_code=True,
            )
        package_json = root / "package.json"
        if manager in _JS_MANAGERS and package_json.exists():
            _append_package_json_security_sections(
                package_json,
                root_label=_root_label(root, workspace=workspace, repository_root=repository_root),
                workspace_entries=workspace_entries,
                hook_entries=hook_entries,
                files=files,
            )

    for path, label, normalize_npmrc in _user_configuration_paths(manager, environment):
        _append_optional_config(
            path,
            root_label=label,
            entries=registry_entries,
            files=files,
            referenced_environment_names=referenced_environment_names,
            normalize_npmrc=normalize_npmrc,
        )

    if manager in _JS_MANAGERS:
        for root in roots:
            root_label = _root_label(root, workspace=workspace, repository_root=repository_root)
            for relative_tree in (".yarn/plugins", ".yarn/patches", "patches"):
                _append_tree(
                    root / relative_tree,
                    root_label=f"{root_label}/{relative_tree}",
                    entries=hook_entries,
                    files=files,
                )

    return {
        "registry_proxy": {"files": sorted(registry_entries, key=_entry_sort_key)},
        "workspace": {"files": sorted(workspace_entries, key=_entry_sort_key)},
        "hooks_overrides_patches": {"files": sorted(hook_entries, key=_entry_sort_key)},
        "referenced_environment_names": sorted(referenced_environment_names),
    }


def _configuration_roots(workspace: Path, repository_root: Path | None) -> tuple[Path, ...]:
    if repository_root is None:
        return (workspace,)
    roots: list[Path] = []
    current = workspace
    while True:
        roots.append(current)
        if current == repository_root:
            break
        if repository_root not in current.parents:
            return (workspace,)
        current = current.parent
    roots.reverse()
    return tuple(roots)


def _manager_configuration_names(manager: str) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if manager in _JS_MANAGERS:
        return (
            (".npmrc",),
            (".yarnrc", ".yarnrc.yml", "pnpm-workspace.yaml", "pnpm-workspace.yml"),
            (".pnpmfile.cjs", "pnpmfile.cjs", ".pnp.cjs"),
        )
    if manager in _PYTHON_MANAGERS:
        return (
            ("pip.conf", "pip.ini"),
            ("Pipfile", "pyproject.toml", "uv.toml"),
            (),
        )
    if manager == "cargo":
        return ((".cargo/config", ".cargo/config.toml"), ("Cargo.toml",), ("build.rs",))
    if manager == "go":
        return ((), ("go.work", "go.mod"), ())
    if manager in {"mvn", "mvnw"}:
        return (("settings.xml",), ("pom.xml", ".mvn/maven.config"), ())
    if manager in {"gradle", "gradlew"}:
        return (("gradle.properties",), ("settings.gradle", "settings.gradle.kts"), ("init.gradle",))
    if manager == "composer":
        return (("auth.json",), ("composer.json",), ("composer.patches.json",))
    if manager in _RUBY_MANAGERS:
        return ((".gemrc", ".bundle/config"), ("Gemfile",), ())
    return ((), (), ())


def _append_optional_config(
    path: Path,
    *,
    root_label: str,
    entries: list[dict[str, str]],
    files: _ContextFiles,
    referenced_environment_names: set[str],
    normalize_npmrc: bool = False,
    inspect_dynamic_code: bool = False,
) -> None:
    if not path.exists():
        return
    payload = files.read(path, maximum_bytes=_MAX_CONFIG_FILE_BYTES)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if normalize_npmrc:
        if _NPM_DYNAMIC_CONFIG_RE.search(text):
            raise _ContextUnavailableError("dynamic_manager_configuration")
        normalized_payload = _normalize_npmrc(text).encode("utf-8")
    else:
        normalized_payload = payload
    if inspect_dynamic_code and _DYNAMIC_CODE_LOAD_RE.search(text):
        raise _ContextUnavailableError("dynamic_manager_configuration")
    referenced_environment_names.update(_ENV_REFERENCE_RE.findall(text))
    entries.append(
        {
            "digest": hashlib.sha256(normalized_payload).hexdigest(),
            "path": f"{root_label}/{path.name}",
        }
    )


def _append_package_json_security_sections(
    path: Path,
    *,
    root_label: str,
    workspace_entries: list[dict[str, str]],
    hook_entries: list[dict[str, str]],
    files: _ContextFiles,
) -> None:
    payload = files.read(path, maximum_bytes=_MAX_CONFIG_FILE_BYTES)
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _ContextUnavailableError("unsupported_configuration") from None
    if not isinstance(parsed, dict):
        raise _ContextUnavailableError("unsupported_configuration")
    workspace_sections = {key: parsed[key] for key in ("packageManager", "workspaces") if key in parsed}
    lifecycle_names = {
        "install",
        "postinstall",
        "preinstall",
        "prepare",
        "prepublish",
        "prepublishOnly",
    }
    scripts = parsed.get("scripts")
    lifecycle_scripts = (
        {key: value for key, value in scripts.items() if key in lifecycle_names} if isinstance(scripts, dict) else {}
    )
    hook_sections = {
        "lifecycle_scripts": lifecycle_scripts,
        **{key: parsed[key] for key in ("overrides", "pnpm", "resolutions") if key in parsed},
    }
    label = f"{root_label}/package.json"
    workspace_entries.append({"digest": _digest_json(workspace_sections), "path": label})
    hook_entries.append({"digest": _digest_json(hook_sections), "path": label})
    if lifecycle_scripts:
        raise _ContextUnavailableError("dynamic_lifecycle_hook")


def _append_tree(
    root: Path,
    *,
    root_label: str,
    entries: list[dict[str, str]],
    files: _ContextFiles,
) -> None:
    if not root.exists():
        return
    if root.is_symlink() or not root.is_dir():
        raise _ContextUnavailableError("unsupported_configuration")
    try:
        paths = sorted(root.rglob("*"))
    except OSError:
        raise _ContextUnavailableError("unreadable_configuration") from None
    file_paths = [path for path in paths if path.is_file() or path.is_symlink()]
    if len(file_paths) > _MAX_TREE_FILES:
        raise _ContextUnavailableError("oversized_configuration")
    for path in file_paths:
        payload = files.read(path, maximum_bytes=_MAX_CONFIG_FILE_BYTES)
        if path.suffix in {".cjs", ".js", ".mjs"}:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                text = ""
            if _DYNAMIC_CODE_LOAD_RE.search(text):
                raise _ContextUnavailableError("dynamic_manager_configuration")
        relative = path.relative_to(root).as_posix()
        entries.append({"digest": hashlib.sha256(payload).hexdigest(), "path": f"{root_label}/{relative}"})


def _user_configuration_paths(
    manager: str,
    environment: Mapping[str, str],
) -> tuple[tuple[Path, str, bool], ...]:
    home_value = environment.get("HOME")
    home = Path(home_value).expanduser() if home_value else Path.home()
    paths: list[tuple[Path, str, bool]] = []
    if manager in _JS_MANAGERS:
        user_config = environment.get("NPM_CONFIG_USERCONFIG")
        paths.append((Path(user_config).expanduser() if user_config else home / ".npmrc", "user", True))
    elif manager in _PYTHON_MANAGERS:
        pip_config = environment.get("PIP_CONFIG_FILE")
        if pip_config:
            paths.append((Path(pip_config).expanduser(), "user", False))
        else:
            paths.extend(
                (
                    (home / ".config" / "pip" / "pip.conf", "user", False),
                    (home / ".config" / "uv" / "uv.toml", "user", False),
                )
            )
    elif manager == "cargo":
        cargo_home = Path(environment.get("CARGO_HOME", str(home / ".cargo"))).expanduser()
        paths.extend(((cargo_home / "config", "user", False), (cargo_home / "config.toml", "user", False)))
    elif manager == "composer":
        composer_home = Path(environment.get("COMPOSER_HOME", str(home / ".composer"))).expanduser()
        paths.extend(((composer_home / "config.json", "user", False), (composer_home / "auth.json", "user", False)))
    elif manager in _RUBY_MANAGERS:
        paths.extend(((home / ".gemrc", "user", False), (home / ".bundle" / "config", "user", False)))
    return tuple(dict.fromkeys(paths))


def _environment_material(
    manager: str,
    environment: Mapping[str, str],
    referenced_names: Sequence[str],
) -> dict[str, object]:
    names = set(_GENERIC_ENVIRONMENT_NAMES)
    manager_names: set[str] = set()
    if manager in _JS_MANAGERS:
        manager_names.update(_MANAGER_ENVIRONMENT_NAMES["js"])
    elif manager in _PYTHON_MANAGERS:
        manager_names.update(_MANAGER_ENVIRONMENT_NAMES["python"])
    elif manager == "go":
        manager_names.update(_MANAGER_ENVIRONMENT_NAMES["go"])
    elif manager in {"gradle", "gradlew", "mvn", "mvnw"}:
        manager_names.update(_MANAGER_ENVIRONMENT_NAMES["jvm"])
    elif manager == "composer":
        manager_names.update(_MANAGER_ENVIRONMENT_NAMES["php"])
    names.update(manager_names)
    names.update(name.lower() for name in manager_names)
    names.update(referenced_names)
    values = {
        name: hashlib.sha256(environment[name].encode("utf-8")).hexdigest() if name in environment else None
        for name in sorted(names)
    }
    return {"variables": values}


def _normalize_npmrc(text: str) -> str:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip().lower()] = value.strip()
    return json.dumps(values, sort_keys=True, separators=(",", ":"))


def _root_label(root: Path, *, workspace: Path, repository_root: Path | None) -> str:
    if repository_root is not None:
        try:
            relative = root.relative_to(repository_root).as_posix() or "."
            return f"repository/{relative}"
        except ValueError:
            pass
    if root == workspace:
        return "workspace"
    return "configuration"


def _entry_sort_key(value: Mapping[str, str]) -> tuple[str, str]:
    return value.get("path", ""), value.get("digest", "")


def _component(name: str, material: object) -> PackageExecutionContextComponent:
    return PackageExecutionContextComponent(name=name, digest=_digest_json(material))


def _digest_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _string_value(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())


def _sha256_value(value: object) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        return None
    return value


def _is_global_request(metadata: Mapping[str, object]) -> bool:
    flags = _string_items(metadata.get("flags"))
    return any(flag in {"-g", "--global", "--location=global"} or flag.startswith("--global=") for flag in flags)


__all__ = [
    "PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND",
    "PACKAGE_EXECUTION_CONTEXT_VERSION",
    "PackageExecutionContext",
    "PackageExecutionContextComponent",
    "build_package_execution_context",
    "changed_package_execution_context_components",
    "package_execution_context_from_evidence",
    "package_execution_context_from_scanner_evidence",
]
