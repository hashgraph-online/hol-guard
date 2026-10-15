"""Local launcher shims for Guard-managed harness execution."""

from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime_transition import TransitionFile

from .durable_harness_launcher import build_harness_shim, build_windows_script
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
_TRUSTED_CLI_LAUNCHER = (
    "import importlib.util, os, sys; "
    "trusted_root = os.path.realpath(sys.argv.pop(1)); "
    "module_name = sys.argv.pop(1); "
    "package_name = module_name.split('.', 1)[0]; "
    "package_root = os.path.join(trusted_root, package_name); "
    "module_path = os.path.join(package_root, *module_name.split('.')[1:]) + '.py'; "
    "cwd = os.path.realpath(os.getcwd()); "
    "normalize = lambda entry: cwd if entry in ('', '.', os.curdir) else os.path.realpath(entry); "
    "blocked_entries = {cwd, trusted_root}; "
    "sys.path = [trusted_root, *[entry for entry in sys.path if normalize(entry) not in blocked_entries]]; "
    "package_spec = importlib.util.spec_from_file_location("
    "package_name, "
    "os.path.join(package_root, '__init__.py'), "
    "submodule_search_locations=[package_root],"
    "); "
    "package_module = importlib.util.module_from_spec(package_spec); "
    "sys.modules[package_name] = package_module; "
    "package_spec.loader.exec_module(package_module); "
    "module_spec = importlib.util.spec_from_file_location(module_name, module_path); "
    "module = importlib.util.module_from_spec(module_spec); "
    "module.__package__ = package_name; "
    "sys.modules[module_name] = module; "
    "module_spec.loader.exec_module(module); "
    "sys.argv[0] = module_path; "
    "raise SystemExit(module.main(sys.argv[1:]))"
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
    from .codex_hook_recovery import _snapshot
    from .runtime_transition import TransitionFile

    shim_dir = context.guard_home / "bin"
    shim_name = launcher_name or harness
    harness_label = display_name or harness
    posix_path = shim_dir / f"guard-{shim_name}"
    windows_path = shim_dir / f"guard-{shim_name}.cmd"
    workspace_args = []
    if context.workspace_dir is not None:
        workspace_args = ["--workspace", str(context.workspace_dir)]
    posix_source = _build_python_shim(harness, context, workspace_args)
    files = []
    for path, text, executable in (
        (posix_path, posix_source, True),
        (windows_path, _build_windows_script(posix_path, source=posix_source), False),
    ):
        before = _snapshot(path)
        before_mode = path.stat().st_mode & 0o777 if before is not None else 0o644
        change = TransitionFile(
            path.resolve(strict=False),
            before,
            text.replace("\n", os.linesep).encode("utf-8"),
            before_mode=before_mode,
            after_mode=before_mode | 0o755 if executable else before_mode,
        )
        change.payload()  # Reject unsafe modes/targets before any publication.
        files.append(change)
    manifest: dict[str, object] = {
        "shim_path": str(posix_path),
        "shim_dir": str(shim_dir),
        "shim_command": posix_path.name,
        "windows_shim_path": str(windows_path),
        "notes": [
            f"Launch {harness_label} through {posix_path.name} so Guard checks changes before the harness starts.",
            f"Add {shim_dir} to PATH to use the wrapper command from any shell.",
        ],
    }
    return PreparedGuardShim(tuple(files), manifest)


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

    shim_dir = context.guard_home / "bin"
    shim_name = launcher_name or harness
    harness_label = display_name or harness
    shim_paths = [
        shim_dir / f"guard-{name}{suffix}" for name in (shim_name, *legacy_launcher_names) for suffix in ("", ".cmd")
    ]
    removed_paths: list[str] = []
    for path in shim_paths:
        if path.exists():
            path.unlink()
            removed_paths.append(str(path))
    posix_path = shim_dir / f"guard-{shim_name}"
    return {
        "shim_path": str(posix_path),
        "shim_dir": str(shim_dir),
        "removed_paths": removed_paths,
        "shim_command": posix_path.name,
        "notes": [f"Removed the Guard launcher shim for {harness_label}."],
    }


def _build_python_shim(harness: str, context: HarnessContextLike, workspace_args: list[str]) -> str:
    return build_harness_shim(
        sys.executable,
        harness,
        context,
        workspace_args,
        trusted_python_flags=_trusted_python_flags(),
        trusted_launcher=_TRUSTED_CLI_LAUNCHER,
        trusted_import_root=_trusted_import_root(),
        launcher_env=merge_guard_launcher_env(),
        home_override_args=_home_override_args(context),
        is_transient_path=_is_transient_path,
    )


def _build_windows_script(posix_path: Path, *, source: str | None = None) -> str:
    return build_windows_script(package_shim_interpreter(), posix_path, source=source)


def _home_override_args(context: HarnessContextLike) -> list[str]:
    if not context.home_dir:
        return []
    if not bool(getattr(context, "home_override_explicit", False)) and (
        context.home_dir.resolve() == Path.home().resolve()
    ):
        return []
    return ["--home", str(context.home_dir)]


def prepare_guard_shim_shell_profile(context: HarnessContext) -> PreparedGuardShim:
    """Capture the selected shell profile and render its PATH block without writes."""
    from .adapters.base import _ensure_path_within_root
    from .codex_hook_recovery import _snapshot
    from .runtime_transition import TransitionFile

    shim_dir = context.guard_home / "bin"
    if os.name == "nt" or _is_transient_path(shim_dir):
        return PreparedGuardShim(
            (),
            {
                "changed": False,
                "profile_path": None,
                "shim_dir": str(shim_dir),
                "restart_shell_required": False,
                "manual_path_required": True,
            },
        )
    profile_path, export_line = _guard_shim_profile_target(context.home_dir, shim_dir)
    _ensure_path_within_root(context.home_dir, profile_path, label="Guard shell profile")
    before = _snapshot(profile_path)
    existing = before.decode("utf-8") if before is not None else ""
    after = _managed_profile_content(existing, export_line, _GUARD_PROFILE_MARKER).encode("utf-8")
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


def _managed_profile_content(existing: str, export_line: str, marker: str) -> str:
    """Render the same idempotent block for normal and transition publication."""
    export_line = export_line.rstrip("\n")
    marker_line = export_line.split("\n", 1)[0]
    if marker_line.strip() != marker.strip():
        # Defensive: caller always passes a block whose first line is the marker.
        export_line = f"{marker}\n{export_line}"
    desired = f"{export_line}\n"
    if existing == desired:
        return existing
    cleaned = _strip_managed_marker_blocks(existing, marker)
    if cleaned == "":
        new_content = desired
    else:
        prefix = "" if cleaned.endswith("\n") else "\n"
        new_content = f"{cleaned}{prefix}{desired}"
    return new_content


def _strip_managed_marker_blocks(content: str, marker: str) -> str:
    """Remove every Guard-managed block tagged with *marker* from *content*.

    A block is the marker line plus the single line that follows it. To avoid
    leaving a gap where a block sat, a single blank line immediately preceding
    or following a removed block is also dropped. Blank-line runs elsewhere in
    the file (user content) are left untouched.
    """

    if not content:
        return ""
    marker_stripped = marker.strip()
    lines = content.splitlines()
    # First pass: locate index ranges [i, i+1] of each marker block.
    drop_indices: set[int] = set()
    for index, line in enumerate(lines):
        if line.strip() == marker_stripped and index + 1 < len(lines):
            drop_indices.add(index)
            drop_indices.add(index + 1)
    if not drop_indices:
        return content if content.endswith("\n") else content + "\n"
    # Second pass: keep lines, swallowing one blank line adjacent to a dropped
    # block so the removal does not leave a stale blank gap.
    keep: list[str] = []
    for index, line in enumerate(lines):
        if index in drop_indices:
            continue
        is_blank = line.strip() == ""
        if is_blank:
            prev_kept_blank_gap = keep and keep[-1].strip() == ""
            # Drop this blank only if both neighbors were removed (i.e. the blank
            # was sandwiched between two removed block lines or sits at the edge
            # of a removal zone).
            prev_dropped = (index - 1) in drop_indices
            next_dropped = (index + 1) in drop_indices
            edge_of_removal = prev_dropped or next_dropped
            if edge_of_removal and not prev_kept_blank_gap:
                continue
        keep.append(line)
    cleaned = "\n".join(keep)
    if cleaned and not cleaned.endswith("\n"):
        cleaned += "\n"
    return cleaned


def _guard_shim_profile_target(home_dir: Path, shim_dir: Path) -> tuple[Path, str]:
    shell = Path(os.environ.get("SHELL", "")).name
    marker = _GUARD_PROFILE_MARKER
    if shell == "fish":
        return (
            home_dir / ".config" / "fish" / "config.fish",
            f"{marker}\n{_fish_path_prepend(shim_dir)}",
        )
    if shell == "bash":
        return (
            home_dir / ".bashrc",
            f"{marker}\n{_posix_path_export(shim_dir)}",
        )
    return (
        home_dir / ".zshrc",
        f"{marker}\n{_posix_path_export(shim_dir)}",
    )


def _posix_path_export(shim_dir: Path) -> str:
    return f"export PATH={shlex.quote(str(shim_dir))}:$PATH"


def _fish_path_prepend(shim_dir: Path) -> str:
    return f"fish_add_path --prepend -- {shlex.quote(str(shim_dir))}"


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
    "package_shim_status",
    "package_shim_supported_managers",
    "probe_package_shim_intercepts",
    "remove_guard_profile_blocks",
    "remove_guard_shim",
    "repair_package_shims",
    "resolve_frozen_package_shim_path",
    "run_frozen_package_shim",
    "uninstall_package_shims",
]
