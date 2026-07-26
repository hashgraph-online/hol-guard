"""Stable Copilot hook command cases with one owner integration test."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class CopilotHookCommandCase:
    """A security-relevant Copilot shell payload and its reviewed identity."""

    case_id: str
    command: str
    security_reference: str


COPILOT_ENCODED_EXEC_DENY_CASES: Final[tuple[CopilotHookCommandCase, ...]] = (
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-001",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | bash",
        security_reference="encoded-payload-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-002",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -D | bash",
        security_reference="bsd-base64-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-003",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | /bin/bash",
        security_reference="path-qualified-shell-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-004",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -di | bash",
        security_reference="clustered-base64-flag-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-005",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | dash",
        security_reference="alternate-shell-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-006",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | env bash",
        security_reference="environment-wrapper-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-007",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | env -i bash",
        security_reference="environment-option-wrapper-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-008",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | /usr/bin/env -i bash",
        security_reference="path-qualified-environment-wrapper-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-009",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | env -u FOO bash",
        security_reference="environment-unset-wrapper-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-010",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | env --unset=FOO bash",
        security_reference="environment-unset-equals-wrapper-decode-and-execute",
    ),
    CopilotHookCommandCase(
        case_id="COPILOT-ENCODED-EXEC-011",
        command="echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -i -d | bash",
        security_reference="base64-flag-order-decode-and-execute",
    ),
)
