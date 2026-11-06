from __future__ import annotations

import re

from tests.guard_copilot_hook_command_corpus import COPILOT_ENCODED_EXEC_DENY_CASES, COPILOT_NODE_DELETE_DENY_CASES


def test_copilot_encoded_exec_corpus_has_stable_unique_security_cases() -> None:
    assert len(COPILOT_ENCODED_EXEC_DENY_CASES) == 11
    assert len({case.case_id for case in COPILOT_ENCODED_EXEC_DENY_CASES}) == len(COPILOT_ENCODED_EXEC_DENY_CASES)
    assert all(re.fullmatch(r"COPILOT-ENCODED-EXEC-\d{3}", case.case_id) for case in COPILOT_ENCODED_EXEC_DENY_CASES)
    assert all(case.security_reference and case.command for case in COPILOT_ENCODED_EXEC_DENY_CASES)


def test_copilot_node_delete_corpus_has_stable_unique_security_cases() -> None:
    assert len(COPILOT_NODE_DELETE_DENY_CASES) == 24
    assert len({case.case_id for case in COPILOT_NODE_DELETE_DENY_CASES}) == len(COPILOT_NODE_DELETE_DENY_CASES)
    assert all(re.fullmatch(r"COPILOT-NODE-DELETE-\d{3}", case.case_id) for case in COPILOT_NODE_DELETE_DENY_CASES)
    assert all(case.security_reference and case.command for case in COPILOT_NODE_DELETE_DENY_CASES)
