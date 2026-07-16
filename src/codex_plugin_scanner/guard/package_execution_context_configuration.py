"""Package-manager configuration and environment context collection."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from .package_execution_context_inputs import ContextFiles, ContextUnavailableError

_JS_MANAGERS = frozenset({"bun", "bunx", "npm", "npx", "pnpm", "yarn"})
_PYTHON_MANAGERS = frozenset({"pip", "pip3", "pipenv", "pipx", "poetry", "uv", "uvx"})
_RUBY_MANAGERS = frozenset({"bundle", "bundler", "gem"})
_MAX_CONFIG_FILE_BYTES = 2 * 1024 * 1024
_MAX_TREE_FILES = 512

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


def configuration_material(
    *,
    workspace: Path,
    repository_root: Path | None,
    manager: str,
    environment: Mapping[str, str],
    files: ContextFiles,
) -> dict[str, object]:
    """Collect configuration inputs that can alter package execution."""

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
    files: ContextFiles,
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
            raise ContextUnavailableError("dynamic_manager_configuration")
        normalized_payload = _normalize_npmrc(text).encode("utf-8")
    else:
        normalized_payload = payload
    if inspect_dynamic_code and _DYNAMIC_CODE_LOAD_RE.search(text):
        raise ContextUnavailableError("dynamic_manager_configuration")
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
    files: ContextFiles,
) -> None:
    payload = files.read(path, maximum_bytes=_MAX_CONFIG_FILE_BYTES)
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ContextUnavailableError("unsupported_configuration") from None
    if not isinstance(parsed, dict):
        raise ContextUnavailableError("unsupported_configuration")
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
        raise ContextUnavailableError("dynamic_lifecycle_hook")


def _append_tree(
    root: Path,
    *,
    root_label: str,
    entries: list[dict[str, str]],
    files: ContextFiles,
) -> None:
    if not root.exists():
        return
    if root.is_symlink() or not root.is_dir():
        raise ContextUnavailableError("unsupported_configuration")
    try:
        paths = sorted(root.rglob("*"))
    except OSError:
        raise ContextUnavailableError("unreadable_configuration") from None
    file_paths = [path for path in paths if path.is_file() or path.is_symlink()]
    if len(file_paths) > _MAX_TREE_FILES:
        raise ContextUnavailableError("oversized_configuration")
    for path in file_paths:
        payload = files.read(path, maximum_bytes=_MAX_CONFIG_FILE_BYTES)
        if path.suffix in {".cjs", ".js", ".mjs"}:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                text = ""
            if _DYNAMIC_CODE_LOAD_RE.search(text):
                raise ContextUnavailableError("dynamic_manager_configuration")
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


def environment_material(
    manager: str,
    environment: Mapping[str, str],
    referenced_names: Sequence[str],
) -> dict[str, object]:
    """Hash policy-relevant environment values without persisting secrets."""

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


def _digest_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


__all__ = ["configuration_material", "environment_material"]
