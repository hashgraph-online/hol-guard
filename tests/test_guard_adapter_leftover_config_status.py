"""Setup status for Guard configuration left behind by a tool that is no longer installed."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.diagnostics_bridge import artifacts_use_guard, native_diagnostics
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def _detect(
    context: HarnessContext,
    *,
    command_available: bool,
    warnings: tuple[str, ...] = (),
    has_config: bool = True,
) -> HarnessDetection:
    config_path = context.home_dir / ".stubtool" / "config.json"
    return HarnessDetection(
        harness="stubtool",
        installed=True,
        command_available=command_available,
        config_paths=(str(config_path),) if has_config else (),
        artifacts=(
            GuardArtifact(
                artifact_id="stubtool:hook",
                name="guard hook",
                harness="stubtool",
                artifact_type="hook",
                source_scope="global",
                config_path=str(config_path),
                command="hol-guard",
                args=("hook", "stubtool"),
            ),
        ),
        warnings=warnings,
    )


def _diagnostics(
    tmp_path: Path,
    *,
    command_available: bool,
    warnings: tuple[str, ...] = (),
    has_config: bool = True,
    command_absence_proves_uninstalled: bool = True,
    detect: Callable[[HarnessContext], HarnessDetection] | None = None,
) -> dict[str, object]:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    if detect is not None:
        detection = detect(context)
    else:
        detection = _detect(context, command_available=command_available, warnings=warnings, has_config=has_config)
    return native_diagnostics(
        harness="stubtool",
        executable="stubtool",
        command_absence_proves_uninstalled=command_absence_proves_uninstalled,
        guard_home=context.guard_home,
        launcher_names=["stubtool"],
        detection=detection,
        runtime_probe=None,
        warnings=None,
    )


def test_guard_config_for_uninstalled_tool_is_not_reported_broken(tmp_path: Path) -> None:
    diagnostics = _diagnostics(tmp_path, command_available=False)

    assert diagnostics["setup_status"] == "not_found"
    # Configuration left behind is what makes fleet posture report the tool as needing setup.
    assert diagnostics["config_paths"]
    warnings = [str(warning) for warning in diagnostics["warnings"]]  # type: ignore[union-attr]
    assert any("hol-guard uninstall stubtool" in warning for warning in warnings)


def test_guard_config_for_installed_tool_stays_active(tmp_path: Path) -> None:
    diagnostics = _diagnostics(tmp_path, command_available=True)

    assert diagnostics["setup_status"] == "active"
    assert diagnostics["warnings"] == []


@pytest.mark.parametrize(
    "failure",
    [
        "Guard native hooks are disabled for stubtool.",
        "Managed Codex hooks are missing from the stubtool config.",
    ],
)
def test_other_setup_failures_stay_broken_when_tool_is_missing(tmp_path: Path, failure: str) -> None:
    diagnostics = _diagnostics(tmp_path, command_available=False, warnings=(failure,))

    assert diagnostics["setup_status"] == "broken"


def test_other_setup_failures_stay_broken_when_tool_is_installed(tmp_path: Path) -> None:
    diagnostics = _diagnostics(
        tmp_path, command_available=True, warnings=("Guard native hooks are disabled for stubtool.",)
    )

    assert diagnostics["setup_status"] == "broken"


def test_guard_launcher_without_tool_config_stays_broken(tmp_path: Path) -> None:
    diagnostics = _diagnostics(tmp_path, command_available=False, has_config=False)

    assert diagnostics["setup_status"] == "broken"


@pytest.mark.parametrize(
    "fault",
    [
        "The configured stubtool executable was rejected as untrusted.",
        "Stale or duplicate Guard-managed stubtool entries detected.",
    ],
)
def test_a_fault_in_the_adapter_own_words_stays_broken(tmp_path: Path, fault: str) -> None:
    # An adapter words its own faults, and an unavailable command does not explain
    # any of them: a rejected executable may sit beside a working one on PATH, and
    # duplicate managed entries are wrong however the tool was installed.
    diagnostics = _diagnostics(tmp_path, command_available=False, warnings=(fault,))

    assert diagnostics["setup_status"] == "broken"


def test_a_harness_running_without_its_command_stays_broken(tmp_path: Path) -> None:
    diagnostics = _diagnostics(tmp_path, command_available=False, command_absence_proves_uninstalled=False)

    assert diagnostics["setup_status"] == "broken"


def test_a_harness_running_without_its_command_is_not_told_to_uninstall(tmp_path: Path) -> None:
    # Its configuration is in use, so recommending `hol-guard uninstall` would drop live protection.
    diagnostics = _diagnostics(tmp_path, command_available=False, command_absence_proves_uninstalled=False)

    warnings = [str(warning) for warning in diagnostics["warnings"]]  # type: ignore[union-attr]
    assert warnings
    assert not any("uninstall" in warning for warning in warnings)
    assert not any("leftover" in warning.lower() for warning in warnings)
    assert any("runs Guard's hooks without it" in warning for warning in warnings)


def _launcher_only(context: HarnessContext) -> HarnessDetection:
    """A Guard launcher beside a tool config Guard never touched."""
    detection = _detect(context, command_available=False)
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=detection.config_paths,
        artifacts=(
            GuardArtifact(
                artifact_id="stubtool:launcher",
                name="guard launcher",
                harness=detection.harness,
                artifact_type="guard_launcher_shim",
                source_scope="global",
                config_path=str(context.home_dir / ".local" / "bin" / "guard-stubtool"),
            ),
        ),
        warnings=detection.warnings,
    )


def test_a_launcher_beside_an_unmanaged_config_stays_broken(tmp_path: Path) -> None:
    # The launcher is the only thing Guard manages here, so an unmanaged tool
    # config sitting beside it must not make the launcher vanish from doctor.
    diagnostics = _diagnostics(tmp_path, command_available=False, detect=_launcher_only)

    assert diagnostics["setup_status"] == "broken"


_WIDE = 4096 + 5


def _plain_artifact(index: int, config_path: str, args: tuple[str, ...] = ()) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=f"stubtool:server:{index}",
        name=f"server {index}",
        harness="stubtool",
        artifact_type="mcp_server",
        source_scope="global",
        config_path=config_path,
        command="node",
        args=args,
    )


def _wide(context: HarnessContext) -> HarnessDetection:
    """A detection whose every list is wider than one native request array may be."""
    config_dir = context.home_dir / ".stubtool"
    config_paths = tuple(str(config_dir / f"config-{index}.json") for index in range(_WIDE))
    plain = tuple(_plain_artifact(index, config_paths[0]) for index in range(_WIDE))
    # Only the last argument of the last artifact names Guard.
    wide_args = (*(f"--flag-{index}" for index in range(_WIDE)), "hol-guard")
    return HarnessDetection(
        harness="stubtool",
        installed=True,
        command_available=True,
        config_paths=config_paths,
        artifacts=(*plain, _plain_artifact(_WIDE, config_paths[0], wide_args)),
        warnings=tuple(f"note {index}" for index in range(_WIDE)),
    )


def test_a_detection_wider_than_one_native_array_crosses_whole(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    detection = _wide(context)

    diagnostics = _diagnostics(tmp_path, command_available=True, detect=_wide)

    assert diagnostics["setup_status"] == "active"
    assert diagnostics["warnings"] == list(detection.warnings)
    assert artifacts_use_guard(detection.artifacts)
    assert not artifacts_use_guard(detection.artifacts[:-1])
