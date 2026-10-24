"""The baseline risk-action tables Python keeps must match the native ones.

``config.SECURITY_LEVEL_RISK_ACTIONS`` and ``protection_posture.POSTURE_RISK_ACTIONS``
are a second copy of the tables ``guard_command::local_supply_chain`` keeps for
``security_level_risk_actions`` and ``posture_risk_actions``. Both copies decide
what Guard does about a risk class when the user configured nothing, so a row
that drifts in one of them makes the CLI and the resident disagree about the
same configuration without either side failing.

These cases load a real configuration for every level and posture and compare
the baseline Python resolves against the one the native composer returns for
the same configuration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import _effective_risk_actions, load_guard_config
from codex_plugin_scanner.guard.config_constants import VALID_SECURITY_LEVELS
from codex_plugin_scanner.guard.native_policy_effective import effective_native_policy_v3
from codex_plugin_scanner.guard.protection_posture import VALID_PROTECTION_POSTURES

_LEVELS = sorted(VALID_SECURITY_LEVELS)
_POSTURES = sorted(VALID_PROTECTION_POSTURES)


def _config(guard_home: Path, *, level: str, posture: str):
    guard_home.mkdir(parents=True, exist_ok=True)
    mode = "observe" if posture == "watch" else "enforce"
    (guard_home / "config.toml").write_text(
        f'mode = "{mode}"\nsecurity_level = "{level}"\nprotection_posture = "{posture}"\n',
        encoding="utf-8",
    )
    return load_guard_config(guard_home)


@pytest.mark.parametrize("level", _LEVELS)
@pytest.mark.parametrize("posture", _POSTURES)
def test_native_baseline_matches_the_python_table(
    tmp_path: Path, native_hook_force: Path, level: str, posture: str
) -> None:
    config = _config(tmp_path / ".hol-guard", level=level, posture=posture)

    native = effective_native_policy_v3(config)

    assert native["risk_actions"] == _effective_risk_actions(config)


def test_a_configured_override_wins_on_both_sides(tmp_path: Path, native_hook_force: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir(parents=True, exist_ok=True)
    (guard_home / "config.toml").write_text(
        'mode = "enforce"\n'
        'security_level = "balanced"\n'
        'protection_posture = "protected"\n'
        "\n[risk_actions]\n"
        'network_egress = "block"\n',
        encoding="utf-8",
    )
    config = load_guard_config(guard_home)

    native = effective_native_policy_v3(config)

    assert native["risk_actions"]["network_egress"] == "block"
    assert native["risk_actions"] == _effective_risk_actions(config)
