from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.guard_seeded_faults import PARSER_SEEDED_FAULTS, FaultExpectation, SeededFault


def _assert_fault_expectation(fault: SeededFault) -> None:
    parsed = parse_shell_command(fault.command)
    expectation: FaultExpectation = fault.expectation
    if expectation == "exclude_redirect_target":
        assert "--help" not in parsed.segments[0].arguments
        assert parsed.redirects[0].target == "--help"
    elif expectation == "preserve_path_override":
        assert parsed.path_overridden is True
        assert parsed.segments[0].environment_names == ("PATH",)
    elif expectation == "preserve_provenance":
        assert parsed.extraction_provenance == "guard-shell"
    elif expectation == "mark_malformed_uncertain":
        assert parsed.confidence == "fallback"
        assert parsed.uncertainty_reason == "malformed_shell_quoting"
    else:
        assert parsed.confidence == "uncertain"
        assert parsed.uncertainty_reason == "command_byte_limit_exceeded"


@pytest.mark.security_critical
@pytest.mark.regression
@pytest.mark.parser
@pytest.mark.release
@pytest.mark.parametrize("fault", PARSER_SEEDED_FAULTS, ids=lambda fault: fault.fault_id)
def test_seeded_command_parser_faults_remain_rejected_or_visible(fault: SeededFault) -> None:
    _assert_fault_expectation(fault)


def test_seeded_fault_ids_and_guarantees_are_unique_and_nonempty() -> None:
    assert len({fault.fault_id for fault in PARSER_SEEDED_FAULTS}) == len(PARSER_SEEDED_FAULTS)
    assert all(fault.guarantee for fault in PARSER_SEEDED_FAULTS)
