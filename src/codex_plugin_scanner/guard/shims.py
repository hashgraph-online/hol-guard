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
    from .native_harness_client import ask
    from .native_harness_steps import planned_files

    answer = ask(
        "prepare_guard_shim",
        context,  # pyright: ignore[reportArgumentType]
        harness=harness,
        launcher_name=launcher_name,
        display_name=display_name,
        interpreter=shim_interpreter(),
    )
    return PreparedGuardShim(tuple(planned_files(answer)), json.loads(str(answer["manifest"])))


def shim_interpreter() -> dict[str, object]:
    """The interpreter a Guard launcher runs, as this process would launch it."""
    return {
        "executable": sys.executable,
        "frozen": bool(getattr(sys, "frozen", False)),
        "package_interpreter": package_shim_interpreter(),
        "python_flags": _trusted_python_flags(),
        "import_root": str(_trusted_import_root()),
        "launcher_env": [list(item) for item in merge_guard_launcher_env().items()],
    }


def install_guard_shim(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    display_name: str | None = None,
) -> dict[str, object]:
    """Publish the same prepared launcher bytes used by runtime transitions.

    The native runtime holds the installation transaction (or runs as the owner this thread already holds),
    publishes the launcher and journals every write.
    """
    from .cli.native_managed_install import ask_managed

    answer = ask_managed(
        "shim_install",
        context,  # pyright: ignore[reportArgumentType]
        [],
        actor="harness-shim.install",
        harness=harness,
        launcher_name=launcher_name,
        display_name=display_name,
    )
    return json.loads(str(answer["manifest"]))


def shell_profile_facts(context: HarnessContextLike) -> dict[str, object]:
    """The shell whose profile gets the PATH block, and whether the shim dir is temporary."""

    return {
        "shell": Path(os.environ.get("SHELL", "")).name,
        "shim_dir_transient": _is_transient_path(context.guard_home / "bin"),
    }


def remove_guard_shim(
    harness: str,
    context: HarnessContextLike,
    *,
    launcher_name: str | None = None,
    legacy_launcher_names: tuple[str, ...] = (),
    display_name: str | None = None,
) -> dict[str, object]:
    """Remove a previously installed Guard launcher shim."""
    from .native_owned import codex_install_transaction
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
    from .native_harness_client import ask
    from .native_harness_steps import planned_files

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
    from .native_harness_client import ask
    from .native_harness_steps import planned_files

    answer = ask(
        "prepare_guard_shim_shell_profile",
        context,  # pyright: ignore[reportArgumentType]
        shell=Path(os.environ.get("SHELL", "")).name,
        shim_dir_transient=_is_transient_path(context.guard_home / "bin"),
    )
    files = tuple(planned_files(answer))
    for change in files:
        change.checked()
    manifest = answer["manifest"]
    return PreparedGuardShim(files, dict(manifest) if isinstance(manifest, dict) else json.loads(str(manifest)))


def ensure_guard_shim_path_in_shell_profile(context: HarnessContext) -> dict[str, object]:
    """Prepend the harness launcher shim dir in the user's normal shell profile."""
    from .cli.native_managed_install import ask_managed

    answer = ask_managed(
        "profile_install",
        context,  # pyright: ignore[reportArgumentType]
        [],
        actor="harness-profile.install",
    )
    manifest = answer.get("manifest")
    return dict(manifest) if isinstance(manifest, dict) else json.loads(str(manifest))


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
