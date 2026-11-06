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


COPILOT_NODE_DELETE_DENY_CASES: Final[tuple[CopilotHookCommandCase, ...]] = (
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-001", "node -e \"require('fs').unlinkSync('dangerous-marker.json')\"", "node-inline-delete"
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-002",
        "echo ok\nnode -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "newline-chained-node-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-003",
        "node --trace-warnings -e \"require('fs').unlinkSync ('dangerous-marker.json')\"",
        "node-shifted-eval-flag-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-004",
        "stdbuf -o L node -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "stdio-wrapper-node-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-005",
        "node -pe \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "node-combined-print-eval-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-006",
        "node --print \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "node-print-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-007",
        "node --title guard-proof -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "node-option-before-eval-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-008",
        "NODE -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "case-variant-node-delete",
    ),
    CopilotHookCommandCase("COPILOT-NODE-DELETE-009", "unlink dangerous-marker.json", "direct-unlink-delete"),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-010",
        "node -e \"require('fs')['unlinkSync']('dangerous-marker.json')\"",
        "node-bracket-access-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-011",
        "node -e \"(require('fs').unlinkSync)('dangerous-marker.json')\"",
        "node-parenthesized-call-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-012",
        "node -e \"require('fs').unlinkSync?.('dangerous-marker.json')\"",
        "node-optional-call-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-013",
        "node -e \"require('fs').unlinkSync.call(null, 'dangerous-marker.json')\"",
        "node-call-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-014",
        "node -e \"require('fs').unlinkSync.apply(null, ['dangerous-marker.json'])\"",
        "node-apply-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-015",
        "node -e \"require('fs').unlinkSync?.apply(null, ['dangerous-marker.json'])\"",
        "node-optional-apply-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-016",
        'env -S "find . -name dangerous-marker.json -delete"',
        "environment-split-find-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-017",
        "env -S \"node -e \\\"require('fs').unlinkSync('dangerous-marker.json')\\\"\"",
        "environment-split-node-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-018",
        "env -iu FOO find . -name dangerous-marker.json -delete",
        "clustered-environment-find-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-019",
        'env -iS "find . -name dangerous-marker.json -delete"',
        "clustered-environment-split-find-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-020",
        "node --inspect-port 0 -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "node-inspect-option-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-021",
        "node --redirect-warnings /tmp/w.log -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "node-warning-redirection-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-022",
        "echo ok |& node -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "stderr-pipeline-node-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-023",
        "echo ok # note\nnode -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "commented-newline-node-delete",
    ),
    CopilotHookCommandCase(
        "COPILOT-NODE-DELETE-024",
        "node -p -e \"require('fs').unlinkSync('dangerous-marker.json')\"",
        "node-print-eval-delete",
    ),
)
