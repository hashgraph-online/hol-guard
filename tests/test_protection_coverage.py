"""Guard must not report a posture as in effect when nothing is registered."""

from __future__ import annotations

from codex_plugin_scanner.guard.protection_coverage import protection_is_in_effect


def test_a_managed_harness_with_registered_artifacts_is_in_effect() -> None:
    assert protection_is_in_effect([{"harness": "claude-code", "managed": True, "artifact_count": 6}]) is True


def test_a_managed_harness_with_no_artifacts_is_not_in_effect() -> None:
    # This is the installed failure seen in the field: Guard still calls the
    # harness managed while every hook array in its settings file is empty.
    assert protection_is_in_effect([{"harness": "claude-code", "managed": True, "artifact_count": 0}]) is False


def test_an_unmanaged_harness_is_not_in_effect() -> None:
    assert protection_is_in_effect([{"harness": "codex", "managed": False, "artifact_count": 119}]) is False


def test_setup_status_wins_over_the_managed_flag_when_the_payload_carries_it() -> None:
    assert protection_is_in_effect([{"harness": "codex", "setup_status": "broken", "artifact_count": 119}]) is False
    assert protection_is_in_effect([{"harness": "codex", "setup_status": "partial"}]) is False
    assert protection_is_in_effect([{"harness": "codex", "setup_status": "active"}]) is True


def test_one_working_harness_keeps_protection_in_effect() -> None:
    assert (
        protection_is_in_effect(
            [
                {"harness": "claude-code", "setup_status": "partial"},
                {"harness": "codex", "setup_status": "broken"},
                {"harness": "omp", "setup_status": "active"},
            ]
        )
        is True
    )


def test_a_payload_without_harness_rows_is_not_treated_as_a_lapse() -> None:
    # Missing evidence is not evidence of a lapse, and a renderer must not raise
    # an alarm it cannot support.
    assert protection_is_in_effect([]) is True
    assert protection_is_in_effect(["not-a-row", None]) is True


def test_a_string_artifact_count_is_read_and_a_boolean_is_not() -> None:
    assert protection_is_in_effect([{"managed": True, "artifact_count": "6"}]) is True
    assert protection_is_in_effect([{"managed": True, "artifact_count": "none"}]) is False
    assert protection_is_in_effect([{"managed": True, "artifact_count": True}]) is False


def test_host_artifacts_do_not_count_as_guard_registration() -> None:
    # A managed install can still have skills or MCP servers after its hook
    # arrays are emptied. Those artifacts keep artifact_count above zero and
    # are not a Guard registration.
    assert (
        protection_is_in_effect(
            [{"harness": "cline", "managed": True, "artifact_count": 4, "guard_registered": False}]
        )
        is False
    )
    assert (
        protection_is_in_effect(
            [{"harness": "cline", "managed": True, "artifact_count": 1, "guard_registered": True}]
        )
        is True
    )


def test_an_unscanned_managed_install_is_not_reported_as_a_lapse() -> None:
    # Desktop bootstrap skips the app scan and hardcodes a zero artifact count.
    # That placeholder is missing evidence, not an empty hook array.
    assert (
        protection_is_in_effect(
            [{"harness": "codex", "managed": True, "artifact_count": 0, "artifacts_scanned": False}]
        )
        is True
    )
