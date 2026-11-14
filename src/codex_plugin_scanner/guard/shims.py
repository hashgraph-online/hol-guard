"""Local launcher shims for Guard-managed harness execution."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime_transition import TransitionFile

from .launcher import merge_guard_launcher_env
from .native_shim_admin import (
    SUPPORTED_PACKAGE_SHIM_MANAGERS,
    HarnessContextLike,
    activate_package_shims,
    ensure_package_shim_path_in_shell_profile,
    get_path_order_status,
    install_package_shims,
    package_shim_cloud_coverage,
    package_shim_dashboard_status,
    package_shim_protection,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
    remove_guard_profile_blocks,
    repair_package_shims,
    uninstall_package_shims,
)
from .package_shim_frozen import (
    FROZEN_PACKAGE_SHIM_SENTINEL,
    package_shim_interpreter,
    resolve_frozen_package_shim_path,
    run_frozen_package_shim,
)

HarnessContext = HarnessContextLike

_PACKAGE_SHIM_COMMANDS = {manager: manager for manager in SUPPORTED_PACKAGE_SHIM_MANAGERS}
_GUARD_PROFILE_MARKER = "# HOL Guard harness launchers"
_GUARD_SHIM_PROFILE_FEATURE = "native-guard-shim-profile-v1"
_GUARD_SHIM_PROFILE_TIMEOUT_SECONDS = 10.0
# Profile under the home directory for each shell; any other shell uses .zshrc.
_GUARD_SHIM_PROFILE_FILES = {"fish": (".config", "fish", "config.fish"), "bash": (".bashrc",)}
# Path fragments that indicate a shim dir lives in an ephemeral location (a test
# temp dir, the system temp root, etc.). Such paths must never be written into a
# long-lived shell profile: they vanish and leave broken PATH entries behind.
# Kept POSIX-only because the profile writers short-circuit on Windows
# (os.name == "nt") before the transient check can run.
_TRANSIENT_PATH_FRAGMENTS = (
    "/var/folders/",
    "/private/var/folders/",
    "/tmp/",
    "/private/tmp/",
    "/temp/",
    "pytest-of-",
)


@dataclass(frozen=True)
class PreparedGuardShim:
    files: tuple[TransitionFile, ...]
    manifest: dict[str, object]


def prepare_guard_shim(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    display_name: str | None = None,
) -> PreparedGuardShim:
    """Render and snapshot both launchers without creating or changing files."""
    from .adapters.native_harness import ask, planned_files

    answer = ask(
        "prepare_guard_shim",
        context,  # pyright: ignore[reportArgumentType]
        harness=harness,
        launcher_name=launcher_name,
        display_name=display_name,
        interpreter={
            "executable": sys.executable,
            "frozen": bool(getattr(sys, "frozen", False)),
            "package_interpreter": package_shim_interpreter(),
            "python_flags": _trusted_python_flags(),
            "import_root": str(_trusted_import_root()),
            "launcher_env": [list(item) for item in merge_guard_launcher_env().items()],
        },
    )
    return PreparedGuardShim(tuple(planned_files(answer)), json.loads(str(answer["manifest"])))


def install_guard_shim(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    display_name: str | None = None,
) -> dict[str, object]:
    """Publish the same prepared launcher bytes used by runtime transitions."""
    from .codex_hook_integrity import atomic_write_bytes
    from .codex_install_transaction import codex_install_transaction
    from .runtime_transition import assert_transition_mutation_allowed

    with codex_install_transaction(context.guard_home, context.guard_home / "bin", actor="harness-shim.install"):
        assert_transition_mutation_allowed(context.guard_home)
        prepared = prepare_guard_shim(harness, context, launcher_name=launcher_name, display_name=display_name)
        for change in prepared.files:
            assert change.after is not None
            atomic_write_bytes(change.path, change.after, mode=change.after_mode, private=False)
        return prepared.manifest


def remove_guard_shim(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    legacy_launcher_names: tuple[str, ...] = (),
    display_name: str | None = None,
) -> dict[str, object]:
    """Remove a previously installed Guard launcher shim."""
    from .codex_install_transaction import codex_install_transaction
    from .runtime_transition import assert_transition_mutation_allowed

    with codex_install_transaction(context.guard_home, context.guard_home / "bin", actor="harness-shim.uninstall"):
        assert_transition_mutation_allowed(context.guard_home)
        return _remove_guard_shim_owned(
            harness,
            context,
            launcher_name=launcher_name,
            legacy_launcher_names=legacy_launcher_names,
            display_name=display_name,
        )


def _remove_guard_shim_owned(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None,
    legacy_launcher_names: tuple[str, ...],
    display_name: str | None,
) -> dict[str, object]:
    from .runtime_transition import RuntimeTransition

    prepared = prepare_guard_shim_removal(
        harness,
        context,
        launcher_name=launcher_name,
        legacy_launcher_names=legacy_launcher_names,
        display_name=display_name,
    )
    for change in prepared.files:
        RuntimeTransition._write_file(change.payload(), "after")
    return prepared.manifest


def prepare_guard_shim_removal(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    legacy_launcher_names: tuple[str, ...] = (),
    display_name: str | None = None,
) -> PreparedGuardShim:
    """Snapshot every launcher an uninstall deletes, without changing files."""
    from .adapters.native_harness import ask, planned_files

    answer = ask(
        "prepare_guard_shim_removal",
        context,  # pyright: ignore[reportArgumentType]
        harness=harness,
        launcher_name=launcher_name,
        display_name=display_name,
        legacy_launcher_names=list(legacy_launcher_names),
    )
    return PreparedGuardShim(tuple(planned_files(answer)), json.loads(str(answer["manifest"])))


def prepare_guard_shim_shell_profile(context: HarnessContext) -> PreparedGuardShim:
    """Capture the selected shell profile and render its PATH block without writes."""
    from .adapters.base import _ensure_path_within_root
    from .codex_hook_recovery import _snapshot
    from .mdm.runtime_request import runtime_answer
    from .runtime_transition import TransitionFile

    shim_dir = context.guard_home / "bin"
    if os.name == "nt":
        return _manual_guard_shim_profile(shim_dir, "unsupported_shell")
    if _is_transient_path(shim_dir):
        return _manual_guard_shim_profile(shim_dir, "transient_guard_home")
    shell = Path(os.environ.get("SHELL", "")).name
    profile_path = context.home_dir.joinpath(*_GUARD_SHIM_PROFILE_FILES.get(shell, (".zshrc",)))
    _ensure_path_within_root(context.home_dir, profile_path, label="Guard shell profile")
    before = _snapshot(profile_path)
    existing = before.decode("utf-8") if before is not None else ""
    # The runtime renders the block; without it the user adds the PATH entry.
    answer = runtime_answer(
        _GUARD_SHIM_PROFILE_FEATURE,
        "guard-shim-profile",
        {"schema": "guard-shim-profile.v1", "existing": existing, "shim_dir": str(shim_dir), "fish": shell == "fish"},
        output_limit=6 * len(existing) + 64 * 1024,
        timeout_seconds=_GUARD_SHIM_PROFILE_TIMEOUT_SECONDS,
    )
    content = answer.get("content") if answer is not None else None
    if not isinstance(content, str):
        return _manual_guard_shim_profile(shim_dir, "native_runtime_unavailable")
    after = content.encode("utf-8")
    mode = profile_path.stat().st_mode & 0o777 if before is not None else 0o600
    change = TransitionFile(
        profile_path.resolve(strict=False), before, after, before_mode=mode, after_mode=mode, no_follow=True
    )
    change.payload()
    return PreparedGuardShim(
        (change,),
        {
            "changed": before != after,
            "profile_path": str(profile_path),
            "shim_dir": str(shim_dir),
            "restart_shell_required": True,
        },
    )


def _manual_guard_shim_profile(shim_dir: Path, reason: str) -> PreparedGuardShim:
    return PreparedGuardShim(
        (),
        {
            "changed": False,
            "profile_path": None,
            "shim_dir": str(shim_dir),
            "restart_shell_required": False,
            "manual_path_required": True,
            "manual_path_reason": reason,
        },
    )


def ensure_guard_shim_path_in_shell_profile(context: HarnessContext) -> dict[str, object]:
    """Prepend the harness launcher shim dir in the user's normal shell profile."""
    from .codex_install_transaction import codex_install_transaction
    from .runtime_transition import RuntimeTransition, assert_transition_mutation_allowed

    prepared = prepare_guard_shim_shell_profile(context)
    if not prepared.files:
        return prepared.manifest
    assert_transition_mutation_allowed(context.guard_home)
    with codex_install_transaction(context.guard_home, context.guard_home / "bin", actor="harness-profile.install"):
        assert_transition_mutation_allowed(context.guard_home)
        prepared = prepare_guard_shim_shell_profile(context)
        payload: dict[str, object] = {"files": [change.payload() for change in prepared.files]}
        RuntimeTransition._compare(payload, "before")
        for change in prepared.files:
            RuntimeTransition._write_file(change.payload(), "after")
        RuntimeTransition._compare(payload, "after")
        return prepared.manifest


def _is_transient_path(path: Path) -> bool:
    """Return True when *path* lives in an ephemeral temp/test location.

    Such paths must not be persisted into a user shell profile because they are
    cleaned up, leaving broken PATH entries that shadow the real binaries.
    Besides the known static temp roots, any path under the process's own
    ``TMPDIR``/``TEMP``/``TMP`` is treated as transient so non-standard temp
    roots on Linux or CI cannot bypass the guard.
    """

    text = str(path)
    if any(fragment in text for fragment in _TRANSIENT_PATH_FRAGMENTS):
        return True
    for env_name in ("TMPDIR", "TEMP", "TMP"):
        env_value = os.environ.get(env_name, "").strip()
        if env_value:
            try:
                if path.resolve().is_relative_to(Path(env_value).expanduser().resolve()):
                    return True
            except (OSError, ValueError):
                if text.startswith(env_value):
                    return True
    return False


def _trusted_python_flags() -> list[str]:
    flags = ["-I"]
    if tuple(sys.version_info[:2]) >= (3, 11):
        flags.append("-P")
    return flags


def _trusted_import_root() -> Path:
    return Path(__file__).resolve().parents[2]


__all__ = [
    "FROZEN_PACKAGE_SHIM_SENTINEL",
    "activate_package_shims",
    "ensure_guard_shim_path_in_shell_profile",
    "ensure_package_shim_path_in_shell_profile",
    "get_path_order_status",
    "install_guard_shim",
    "install_package_shims",
    "package_shim_cloud_coverage",
    "package_shim_dashboard_status",
    "package_shim_protection",
    "package_shim_status",
    "package_shim_supported_managers",
    "prepare_guard_shim_removal",
    "probe_package_shim_intercepts",
    "remove_guard_profile_blocks",
    "remove_guard_shim",
    "repair_package_shims",
    "resolve_frozen_package_shim_path",
    "run_frozen_package_shim",
    "uninstall_package_shims",
]
