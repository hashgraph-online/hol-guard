"""Shared execution-safety checks for Git inspection commands."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from .executable_resolution import which_for_execution_cwd

_GIT_CONFIG_ROUTING_ENV = frozenset(
    {
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_NAMESPACE",
        "GIT_WORK_TREE",
    }
)
_GIT_FETCH_EXECUTION_ENV = frozenset(
    {
        "GIT_ASKPASS",
        "GIT_EXEC_PATH",
        "GIT_PROXY_COMMAND",
        "GIT_SSL_CAINFO",
        "GIT_SSL_CAPATH",
        "GIT_SSL_CERT",
        "GIT_SSL_CIPHER_LIST",
        "GIT_SSL_KEY",
        "GIT_SSL_NO_VERIFY",
        "GIT_SSL_VERSION",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "SSH_ASKPASS",
    }
)
_GIT_LOCAL_CHECKOUT_EXECUTION_ENV = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_EXEC_PATH",
        "GIT_OBJECT_DIRECTORY",
    }
)
_SAFE_GITHUB_REPOSITORY_PATH = re.compile(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?")
_SAFE_GITHUB_SCP_REMOTE = re.compile(r"^git@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$")
_SAFE_GIT_HELPER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_GIT_PROBE_TIMEOUT_SECONDS = 1.0
_READ_ONLY_GIT_STATUS_FLAGS = frozenset(
    {
        "--ahead-behind",
        "--branch",
        "--ignored",
        "--long",
        "--no-ahead-behind",
        "--no-renames",
        "--porcelain",
        "--renames",
        "--short",
        "--show-stash",
        "--untracked-files",
        "-b",
        "-s",
        "-u",
        "-z",
    }
)
_READ_ONLY_GIT_STATUS_VALUE_FLAGS = frozenset(
    {
        "--column",
        "--find-renames",
        "--ignored",
        "--porcelain",
        "--untracked-files",
    }
)


def git_binary_path_is_trusted(git_path: Path, *, cwd: Path) -> bool:
    """Reject Git executables from user-controlled or broadly writable roots."""

    try:
        resolved_cwd = cwd.resolve()
        untrusted_roots = (
            *((resolved_cwd,) if resolved_cwd != Path(resolved_cwd.anchor) else ()),
            Path.home().resolve(),
            Path("/tmp").resolve(),
            Path("/private/tmp").resolve(),
        )
    except (OSError, RuntimeError):
        return False
    for untrusted_root in untrusted_roots:
        try:
            _ = git_path.relative_to(untrusted_root)
        except ValueError:
            continue
        return False
    getuid = getattr(os, "getuid", None)
    current_uid = cast(Callable[[], int], getuid)() if getuid is not None else -1
    getgroups = getattr(os, "getgroups", None)
    current_groups: set[int] = set(cast(Callable[[], list[int]], getgroups)()) if getgroups is not None else set()
    try:
        for candidate in (git_path, *git_path.parents):
            metadata = candidate.stat()
            if metadata.st_mode & stat.S_IWOTH:
                return False
            if metadata.st_mode & stat.S_IWGRP and metadata.st_gid not in current_groups:
                return False
            if candidate == git_path and current_uid >= 0 and metadata.st_uid not in {0, current_uid}:
                return False
    except OSError:
        return False
    return True


def git_config_routing_environment_is_clean() -> bool:
    """Return whether Git configuration discovery follows its default routes."""

    return not any(os.environ.get(key, "").strip() for key in _GIT_CONFIG_ROUTING_ENV)


def trusted_git_binary_for_cwd(cwd: Path) -> Path | None:
    """Resolve Git using the execution cwd and reject user-controlled binaries."""

    try:
        execution_cwd = cwd.resolve()
        path_entries: list[str] = []
        for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
            candidate = Path(entry or ".").expanduser()
            if not candidate.is_absolute():
                candidate = execution_cwd / candidate
            path_entries.append(str(candidate))
        git_path = shutil.which("git", path=os.pathsep.join(path_entries))
        if git_path is None:
            return None
        resolved_git = Path(git_path).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved_git if git_binary_path_is_trusted(resolved_git, cwd=execution_cwd) else None


def git_status_args_are_read_only(args: list[str]) -> bool:
    """Accept only status flags that cannot configure or invoke helpers."""

    if not args or args[0].casefold() != "status":
        return False
    after_option_terminator = False
    for token in args[1:]:
        if after_option_terminator:
            continue
        if token == "--":
            after_option_terminator = True
            continue
        normalized = token.casefold()
        if normalized in _READ_ONLY_GIT_STATUS_FLAGS:
            continue
        if "=" in normalized and normalized.split("=", 1)[0] in _READ_ONLY_GIT_STATUS_VALUE_FLAGS:
            continue
        if (
            normalized.startswith("-")
            and len(normalized) > 2
            and not normalized.startswith("--")
            and all(f"-{flag}" in _READ_ONLY_GIT_STATUS_FLAGS for flag in normalized[1:])
        ):
            continue
        return False
    return True


def git_status_has_execution_free_config(
    cwd: Path,
    *,
    git_binary: Path | None = None,
) -> bool:
    """Reject status when Git configuration could execute a pager or fsmonitor helper."""

    if not git_config_routing_environment_is_clean():
        return False
    resolved_git = git_binary or trusted_git_binary_for_cwd(cwd)
    if resolved_git is None:
        return False
    git_pager = os.environ.get("GIT_PAGER")
    if git_pager is not None:
        if git_pager not in {"", "cat"}:
            return False
    else:
        if os.environ.get("PAGER", "") not in {"", "cat"}:
            return False
        for key in ("core.pager", "pager.status"):
            try:
                result = subprocess.run(
                    [str(resolved_git), "config", "--null", "--get-all", key],
                    cwd=cwd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=1,
                )
            except (OSError, subprocess.SubprocessError):
                return False
            if result.returncode == 1 and not result.stdout:
                continue
            if result.returncode != 0:
                return False
            values = [value for value in result.stdout.split("\0") if value]
            if any(value != "cat" for value in values):
                return False
    try:
        result = subprocess.run(
            [str(resolved_git), "config", "--null", "--get-all", "core.fsmonitor"],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode == 1 and not result.stdout:
        return True
    if result.returncode != 0:
        return False
    values = [value.strip().casefold() for value in result.stdout.split("\0") if value.strip()]
    return bool(values) and all(value in {"0", "false", "no", "off"} for value in values)


def git_object_query_has_no_lazy_fetch(
    cwd: Path,
    *,
    git_binary: Path | None = None,
) -> bool:
    """Reject object queries when repository configuration can fetch missing objects."""

    if not git_config_routing_environment_is_clean():
        return False
    resolved_git = git_binary or trusted_git_binary_for_cwd(cwd)
    if resolved_git is None:
        return False
    try:
        repository_cwd = cwd.resolve()
        repository = subprocess.run(
            [str(resolved_git), "rev-parse", "--is-inside-work-tree"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        config = subprocess.run(
            [str(resolved_git), "config", "--null", "--list"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if repository.returncode != 0 or repository.stdout.strip() != "true" or config.returncode != 0:
        return False
    parsed_config = _parse_null_git_config(config.stdout)
    return parsed_config is not None and not _git_checkout_config_can_fetch(parsed_config)


def git_fetch_origin_has_execution_free_config(
    cwd: Path,
    *,
    git_binary: Path | None = None,
) -> bool:
    """Reject fetch when repository or process state can route execution."""

    if not git_config_routing_environment_is_clean():
        return False
    if any(os.environ.get(key, "").strip() for key in _GIT_FETCH_EXECUTION_ENV):
        return False
    resolved_git = git_binary or trusted_git_binary_for_cwd(cwd)
    if resolved_git is None:
        return False
    try:
        repository_cwd = cwd.resolve()
        repository = subprocess.run(
            [str(resolved_git), "rev-parse", "--is-inside-work-tree"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        if repository.returncode != 0 or repository.stdout.strip().casefold() != "true":
            return False
        config = subprocess.run(
            [str(resolved_git), "config", "--null", "--list"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        if config.returncode != 0:
            return False
        parsed_config = _parse_null_git_config(config.stdout)
        if parsed_config is None or _git_fetch_config_routes_execution(parsed_config):
            return False
        urls = parsed_config.get("remote.origin.url", ())
        if not urls or not all(_safe_github_remote_url(value) for value in urls):
            return False
        git_exec_path = subprocess.run(
            [str(resolved_git), "--exec-path"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        if git_exec_path.returncode != 0:
            return False
        hook_paths = subprocess.run(
            [
                str(resolved_git),
                "rev-parse",
                "--git-path",
                "hooks/post-fetch",
                "--git-path",
                "hooks/pre-auto-gc",
                "--git-path",
                "hooks/reference-transaction",
            ],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    try:
        exec_path = Path(git_exec_path.stdout.strip()).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    helpers = [
        value.strip()
        for key, values in parsed_config.items()
        if key == "credential.helper" or (key.startswith("credential.") and key.endswith(".helper"))
        for value in values
        if value.strip()
    ]
    if not all(_trusted_credential_helper(value, git_exec_path=exec_path, cwd=repository_cwd) for value in helpers):
        return False
    if hook_paths.returncode != 0:
        return False
    resolved_hook_paths = hook_paths.stdout.splitlines()
    if len(resolved_hook_paths) != 3:
        return False
    for value in resolved_hook_paths:
        hook_path = Path(value)
        if not hook_path.is_absolute():
            hook_path = repository_cwd / hook_path
        try:
            if hook_path.exists() and (os.name == "nt" or os.access(hook_path, os.X_OK)):
                return False
        except OSError:
            return False
    return True


def git_push_origin_has_execution_free_config(
    cwd: Path,
    *,
    branch: str,
    git_binary: Path | None = None,
) -> bool:
    """Verify a configured-origin push cannot redirect execution or change branches."""

    resolved_git = git_binary or trusted_git_binary_for_cwd(cwd)
    if (
        resolved_git is None
        or not _git_global_config_environment_is_stable()
        or not git_fetch_origin_has_execution_free_config(cwd, git_binary=resolved_git)
    ):
        return False
    try:
        repository_cwd = cwd.resolve()
        branch_check = subprocess.run(
            [str(resolved_git), "check-ref-format", "--branch", branch],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        current_branch = subprocess.run(
            [str(resolved_git), "symbolic-ref", "--quiet", "--short", "HEAD"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        config = subprocess.run(
            [str(resolved_git), "config", "--null", "--list"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        hook_path = subprocess.run(
            [str(resolved_git), "rev-parse", "--git-path", "hooks/pre-push"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        local_config = subprocess.run(
            [str(resolved_git), "config", "--local", "--null", "--list"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        worktree_config = subprocess.run(
            [str(resolved_git), "config", "--worktree", "--null", "--list"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    parsed_config = _parse_null_git_config(config.stdout) if config.returncode == 0 else None
    parsed_local_config = _parse_optional_scoped_git_config(local_config)
    parsed_worktree_config = _parse_optional_scoped_git_config(worktree_config)
    if (
        branch_check.returncode != 0
        or branch_check.stdout.strip() != branch
        or current_branch.returncode != 0
        or current_branch.stdout.strip() != branch
        or parsed_config is None
        or parsed_local_config is None
        or parsed_worktree_config is None
        or _git_push_config_routes_execution(parsed_config, branch=branch)
        or _git_push_effective_config_weakens_transport(parsed_config)
        or _git_push_scoped_config_routes_transport(parsed_local_config)
        or _git_push_scoped_config_routes_transport(parsed_worktree_config)
        or hook_path.returncode != 0
        or bool(parsed_local_config.get("core.hookspath"))
        or bool(parsed_worktree_config.get("core.hookspath"))
        or len(parsed_config.get("remote.origin.url", ())) != 1
    ):
        return False
    candidate_hook = Path(hook_path.stdout.strip())
    if not candidate_hook.is_absolute():
        candidate_hook = repository_cwd / candidate_hook
    try:
        if not candidate_hook.exists() or (os.name != "nt" and not os.access(candidate_hook, os.X_OK)):
            return True
        if not parsed_config.get("core.hookspath") or candidate_hook.is_symlink():
            return False
        resolved_hook = candidate_hook.resolve(strict=True)
    except OSError:
        return False
    if resolved_hook != candidate_hook.absolute():
        return False
    return _trusted_global_push_hook(resolved_hook, repository_cwd=repository_cwd)


def git_worktree_add_has_execution_free_config(
    cwd: Path,
    *,
    git_binary: Path | None = None,
    ref: str = "HEAD",
) -> bool:
    """Reject worktree creation when checkout can invoke configured code."""

    resolved_git = git_binary or trusted_git_binary_for_cwd(cwd)
    if (
        resolved_git is None
        or any(os.environ.get(key, "") != "" for key in _GIT_LOCAL_CHECKOUT_EXECUTION_ENV)
        or not git_status_has_execution_free_config(cwd, git_binary=resolved_git)
    ):
        return False
    try:
        repository_cwd = cwd.resolve()
        config = subprocess.run(
            [str(resolved_git), "config", "--null", "--list"],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        hook_paths = subprocess.run(
            [
                str(resolved_git),
                "rev-parse",
                "--git-path",
                "hooks/post-checkout",
                "--git-path",
                "hooks/reference-transaction",
            ],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    parsed_config = _parse_null_git_config(config.stdout) if config.returncode == 0 else None
    configured_filters = (
        (
            key.startswith("filter.") and key.endswith((".clean", ".smudge", ".process"))
            for key, values in parsed_config.items()
            if any(value.strip() for value in values)
        )
        if parsed_config is not None
        else ()
    )
    if (
        parsed_config is None
        or _git_checkout_config_can_fetch(parsed_config)
        or (any(configured_filters) and _git_ref_uses_checkout_filter(resolved_git, repository_cwd, ref))
    ):
        return False
    if hook_paths.returncode != 0:
        return False
    paths = hook_paths.stdout.splitlines()
    if len(paths) != 2:
        return False
    for value in paths:
        hook_path = Path(value)
        if not hook_path.is_absolute():
            hook_path = repository_cwd / hook_path
        try:
            if hook_path.exists() and (os.name == "nt" or os.access(hook_path, os.X_OK)):
                return False
        except OSError:
            return False
    return True


def _git_checkout_config_can_fetch(config: dict[str, tuple[str, ...]]) -> bool:
    """Reject partial-clone configuration that can lazily fetch checkout objects."""

    return any(
        (
            (key == "extensions.partialclone" or key.endswith(".partialclonefilter"))
            and any(value != "" for value in values)
        )
        or (
            key.endswith(".promisor")
            and any(value.strip().casefold() not in {"", "0", "false", "no", "off"} for value in values)
        )
        for key, values in config.items()
    )


def _git_ref_uses_checkout_filter(git_binary: Path, cwd: Path, ref: str) -> bool:
    if ref.startswith("-"):
        return True
    try:
        files = subprocess.run(
            [str(git_binary), "ls-tree", "-r", "--name-only", "-z", ref],
            cwd=cwd,
            check=False,
            capture_output=True,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
        if files.returncode != 0:
            return True
        attributes = subprocess.run(
            [str(git_binary), "check-attr", "-z", "--stdin", f"--source={ref}", "filter"],
            cwd=cwd,
            check=False,
            capture_output=True,
            input=files.stdout,
            timeout=_GIT_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return True
    if attributes.returncode != 0:
        return True
    fields = attributes.stdout.split(b"\0")
    if fields and fields[-1] == b"":
        _ = fields.pop()
    if len(fields) % 3 != 0:
        return True
    return any(value not in {b"unspecified", b"unset"} for value in fields[2::3])


def _parse_null_git_config(output: str) -> dict[str, tuple[str, ...]] | None:
    parsed: dict[str, list[str]] = {}
    for entry in output.split("\0"):
        if not entry:
            continue
        key, separator, value = entry.partition("\n")
        if not separator or not key:
            return None
        parsed.setdefault(key.casefold(), []).append(value)
    return {key: tuple(values) for key, values in parsed.items()}


def _parse_optional_scoped_git_config(
    completed: subprocess.CompletedProcess[str],
) -> dict[str, tuple[str, ...]] | None:
    if completed.returncode not in {0, 1}:
        return None
    return _parse_null_git_config(completed.stdout)


def _git_fetch_config_routes_execution(config: dict[str, tuple[str, ...]]) -> bool:
    if config.get("remote.origin.uploadpack"):
        return True
    if any(value.strip() for value in config.get("core.askpass", ())):
        return True
    if any(value.strip() for value in config.get("core.sshcommand", ())):
        return True
    for key, values in config.items():
        if not (key.startswith("url.") and key.endswith(".insteadof")):
            continue
        if key != "url.https://github.com/.insteadof" or not values:
            return True
        if any(value.strip() != "git@github.com:" for value in values):
            return True
    if not all(_safe_origin_fetch_refspec(value) for value in config.get("remote.origin.fetch", ())):
        return True
    boolean_keys = {
        "remote.origin.mirror",
        "remote.origin.prune",
        "remote.origin.prunetags",
        "remote.origin.recursesubmodules",
        "fetch.prune",
        "fetch.prunetags",
        "fetch.recursesubmodules",
        "submodule.recurse",
    }
    if any(_git_config_values_enable_behavior(config.get(key, ())) for key in boolean_keys):
        return True
    return any(value.strip() != "--no-tags" for value in config.get("remote.origin.tagopt", ()))


def _git_push_config_routes_execution(config: dict[str, tuple[str, ...]], *, branch: str) -> bool:
    if config.get("core.gitproxy"):
        return True
    if any((key.startswith("url.") and key.endswith(".pushinsteadof")) or key.startswith("hook.") for key in config):
        return True
    if any(
        config.get(key)
        for key in (
            "remote.origin.push",
            "remote.origin.pushurl",
            "remote.origin.receivepack",
            "remote.origin.vcs",
            "remote.pushdefault",
            f"branch.{branch.casefold()}.pushremote",
        )
    ):
        return True
    boolean_keys = {
        "push.followtags",
        "push.gpgsign",
        "remote.origin.mirror",
    }
    if any(_git_config_values_enable_behavior(config.get(key, ())) for key in boolean_keys):
        return True
    return any(
        value.strip().casefold() not in {"", "0", "false", "no", "off", "check"}
        for value in config.get("push.recursesubmodules", ())
    )


def _git_push_scoped_config_routes_transport(config: dict[str, tuple[str, ...]]) -> bool:
    return any(
        key.startswith(("http.", "credential."))
        or key
        in {
            "core.askpass",
            "core.gitproxy",
            "remote.origin.proxy",
            "remote.origin.proxyauthmethod",
        }
        for key in config
    )


def _git_push_effective_config_weakens_transport(config: dict[str, tuple[str, ...]]) -> bool:
    unsafe_suffixes = (
        ".cookiefile",
        ".extraheader",
        ".followredirects",
        ".pinnedpubkey",
        ".proxy",
        ".proxyauthmethod",
        ".schannelcheckrevoke",
        ".schannelusesslcainfo",
        ".sslbackend",
        ".sslcainfo",
        ".sslcapath",
        ".sslcert",
        ".sslcipherlist",
        ".sslkey",
        ".sslverify",
        ".sslversion",
    )
    return any(key.startswith("http.") and key.endswith(unsafe_suffixes) for key in config)


def _git_global_config_environment_is_stable() -> bool:
    if os.name == "nt" or not hasattr(os, "getuid"):
        return False
    try:
        import pwd

        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        configured_home = Path(os.environ.get("HOME", "")).resolve(strict=True)
        configured_xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
        return configured_home == account_home and (
            not configured_xdg or Path(configured_xdg).resolve() == account_home / ".config"
        )
    except (KeyError, OSError, RuntimeError):
        return False


def _trusted_global_push_hook(path: Path, *, repository_cwd: Path) -> bool:
    """Accept a stable global hook while rejecting repository-controlled hooks."""

    if os.name == "nt":
        return False
    try:
        _ = path.relative_to(repository_cwd)
        return False
    except ValueError:
        pass
    try:
        metadata = path.stat()
        current_uid = os.getuid() if hasattr(os, "getuid") else -1
        return bool(
            path.is_file()
            and not path.is_symlink()
            and metadata.st_uid in {0, current_uid}
            and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        )
    except OSError:
        return False


def _git_config_values_enable_behavior(values: tuple[str, ...]) -> bool:
    return any(value.strip().casefold() not in {"", "0", "false", "no", "off"} for value in values)


def _safe_github_https_remote_url(value: str) -> bool:
    if any(character in value for character in ("\0", "\r", "\n")):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    path_parts = parsed.path.removesuffix(".git").split("/")
    return bool(
        parsed.scheme.casefold() == "https"
        and parsed.hostname is not None
        and parsed.hostname.casefold() == "github.com"
        and port in {None, 443}
        and not parsed.query
        and not parsed.fragment
        and len(path_parts) == 3
        and all(part not in {"", ".", ".."} for part in path_parts[1:])
        and _SAFE_GITHUB_REPOSITORY_PATH.fullmatch(parsed.path)
    )


def _safe_github_ssh_remote_url(value: str) -> bool:
    if any(character in value for character in ("\0", "\r", "\n", " ")):
        return False
    if _SAFE_GITHUB_SCP_REMOTE.fullmatch(value) is not None:
        return True
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    path_parts = parsed.path.removesuffix(".git").split("/")
    return bool(
        parsed.scheme.casefold() == "ssh"
        and parsed.username == "git"
        and parsed.password is None
        and parsed.hostname is not None
        and parsed.hostname.casefold() == "github.com"
        and port in {None, 22}
        and not parsed.query
        and not parsed.fragment
        and len(path_parts) == 3
        and all(part not in {"", ".", ".."} for part in path_parts[1:])
        and _SAFE_GITHUB_REPOSITORY_PATH.fullmatch(parsed.path)
    )


def _safe_github_remote_url(value: str) -> bool:
    return _safe_github_https_remote_url(value) or _safe_github_ssh_remote_url(value)


def _safe_origin_fetch_refspec(value: str) -> bool:
    normalized = value.strip()
    if normalized.startswith("+"):
        normalized = normalized[1:]
    return normalized == "refs/heads/*:refs/remotes/origin/*"


def _trusted_credential_helper(value: str, *, git_exec_path: Path, cwd: Path) -> bool:
    if value.startswith("!"):
        try:
            helper_command = shlex.split(value[1:])
        except ValueError:
            return False
        if len(helper_command) != 3 or helper_command[1:] != ["auth", "git-credential"]:
            return False
        helper_binary = helper_command[0]
        if helper_binary == "gh":
            gh_path = _path_command_for_cwd("gh", cwd=cwd)
        elif Path(helper_binary).is_absolute() and Path(helper_binary).name == "gh":
            gh_path = helper_binary
        else:
            return False
        try:
            resolved_gh = Path(gh_path).resolve(strict=True) if gh_path is not None else None
        except (OSError, RuntimeError):
            return False
        return resolved_gh is not None and git_binary_path_is_trusted(resolved_gh, cwd=cwd)
    if _SAFE_GIT_HELPER_NAME.fullmatch(value) is None:
        return False
    try:
        helper = (git_exec_path / f"git-credential-{value}").resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return helper.is_file() and git_binary_path_is_trusted(helper, cwd=cwd)


_path_command_for_cwd = which_for_execution_cwd


__all__ = (
    "git_binary_path_is_trusted",
    "git_config_routing_environment_is_clean",
    "git_fetch_origin_has_execution_free_config",
    "git_object_query_has_no_lazy_fetch",
    "git_push_origin_has_execution_free_config",
    "git_status_args_are_read_only",
    "git_status_has_execution_free_config",
    "git_worktree_add_has_execution_free_config",
    "trusted_git_binary_for_cwd",
)
