"""Tests for the shared ResourceBudget and applied-control evidence."""

from __future__ import annotations

import sys
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.resource_budget import (
    AppliedControl,
    ResourceBackend,
    ResourceBudget,
    ResourceControlKind,
    applied_controls,
    backend_supports_rlimit,
)


class TestResourceBudget:
    def test_defaults_valid(self) -> None:
        budget = ResourceBudget()
        assert budget.cpu_seconds > 0
        assert len(budget.digest()) == 64

    def test_digest_order_independent(self) -> None:
        assert (
            ResourceBudget(cpu_seconds=10, memory_bytes=1024).digest()
            == ResourceBudget(memory_bytes=1024, cpu_seconds=10).digest()
        )

    def test_digest_changes_on_value(self) -> None:
        assert ResourceBudget(cpu_seconds=10).digest() != ResourceBudget(cpu_seconds=20).digest()

    @pytest.mark.parametrize(
        "field,bad",
        [
            ("cpu_seconds", 0),
            ("memory_bytes", 0),
            ("process_count", 0),
            ("open_file_count", 0),
            ("output_bytes", 0),
            ("wall_clock_seconds", 0),
        ],
    )
    def test_rejects_out_of_range(self, field: str, bad: int) -> None:
        with pytest.raises(ValueError, match=field):
            ResourceBudget(**{field: bad})

    def test_rejects_bool(self) -> None:
        with pytest.raises(ValueError):
            ResourceBudget(cpu_seconds=True)

    def test_rejects_bad_schema_version(self) -> None:
        with pytest.raises(ValueError, match="schema version"):
            ResourceBudget(schema_version="other")


class TestBackendSupport:
    def test_current_platform(self) -> None:
        assert backend_supports_rlimit(sys.platform) is True

    def test_unknown_platform_no_rlimit(self) -> None:
        assert backend_supports_rlimit("plan9") is False


class TestAppliedControls:
    def test_output_bounding_applied_on_all_backends(self) -> None:
        for backend in ResourceBackend:
            controls = {c.kind: c for c in applied_controls(ResourceBudget(), backend, platform=sys.platform)}
            assert controls[ResourceControlKind.OUTPUT_BYTES].applied is True

    def test_rlimit_controls_applied_on_rlimit_backend(self) -> None:
        controls = {
            c.kind: c for c in applied_controls(ResourceBudget(), ResourceBackend.RLIMIT, platform=sys.platform)
        }
        assert controls[ResourceControlKind.CPU].applied is True
        assert controls[ResourceControlKind.MEMORY].applied is True

    def test_unsupported_controls_not_implied(self) -> None:
        # On a backend that cannot enforce RLIMIT, controls must lower guarantees, not be implied.
        controls = {
            c.kind: c for c in applied_controls(ResourceBudget(), ResourceBackend.UNSUPPORTED, platform="plan9")
        }
        assert controls[ResourceControlKind.CPU].applied is False
        assert controls[ResourceControlKind.CPU].limit_value is None
        assert controls[ResourceControlKind.MEMORY].applied is False

    def test_applied_control_limit_value_set_when_applied(self) -> None:
        budget = ResourceBudget(cpu_seconds=99)
        controls = {c.kind: c for c in applied_controls(budget, ResourceBackend.RLIMIT, platform=sys.platform)}
        assert controls[ResourceControlKind.CPU].limit_value == 99

    def test_unapplied_control_limit_value_dropped(self) -> None:
        controls = {
            c.kind: c for c in applied_controls(ResourceBudget(), ResourceBackend.UNSUPPORTED, platform="plan9")
        }
        for control in controls.values():
            if not control.applied:
                assert control.limit_value is None


class TestAppliedControlValidation:
    def test_rejects_non_enum_kind(self) -> None:
        with pytest.raises(ValueError, match="ResourceControlKind"):
            AppliedControl(kind=cast(ResourceControlKind, "cpu"), applied=True, backend="rlimit", limit_value=1)

    def test_rejects_non_bool_applied(self) -> None:
        with pytest.raises(ValueError, match="applied"):
            AppliedControl(
                kind=ResourceControlKind.CPU,
                applied=cast(bool, "yes"),
                backend="rlimit",
                limit_value=1,
            )
