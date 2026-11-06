"""What a headless OMP agent reads when Guard stops a tool call."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tests.pi_extension_response_source_support import _generated_source

_SIGNATURES = {
    "function approvalRequestId(response: GuardResponse): string | null {": "function approvalRequestId(response) {",
    "function approvalUrlFromResponse(response: GuardResponse): string | null {": (
        "function approvalUrlFromResponse(response) {"
    ),
    "function approvalManualRetryReason(response: GuardResponse, fallbackReason: string): string {": (
        "function approvalManualRetryReason(response, fallbackReason) {"
    ),
}


def _function(source: str, signature: str) -> str:
    start = source.index(signature)
    end = source.index("\n}\n", start) + 2
    return _SIGNATURES[signature] + source[start + len(signature) : end]


def _reasons(tmp_path: Path, responses: list[dict[str, object]]) -> list[str]:
    source = _generated_source(tmp_path)
    helpers = "\n".join(_function(source, signature) for signature in _SIGNATURES)
    script = tmp_path / "fixture.mjs"
    script.write_text(
        f"{helpers}\n"
        f"const responses = {json.dumps(responses)};\n"
        "console.log(JSON.stringify(responses.map(r => approvalManualRetryReason(r, r.reason))));\n",
        encoding="utf-8",
    )
    completed = subprocess.run(["node", str(script)], capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_a_stop_without_an_approval_request_does_not_ask_for_approval(tmp_path: Path) -> None:
    reason = "HOL Guard requires review. Continue with a safe, permitted alternative."
    [stopped, pending] = _reasons(
        tmp_path,
        [
            {"decision": "deny", "reason": reason},
            {
                "decision": "deny",
                "reason": reason,
                "approval_request_id": "req-1",
                "approval_url": "http://127.0.0.1:1/approvals/req-1",
            },
        ],
    )

    assert stopped == reason
    assert pending.startswith(reason)
    assert "Retry the exact original tool call after approving it in HOL Guard." in pending
    assert "HOL Guard approval page: http://127.0.0.1:1/approvals/req-1" in pending
