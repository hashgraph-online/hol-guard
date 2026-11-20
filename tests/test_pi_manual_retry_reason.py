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
    "function desktopUrlFromResponse(response: GuardResponse): string | null {": (
        "function desktopUrlFromResponse(response) {"
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
    assert (
        "Give the user this exact HOL Guard approval link, copied in full: http://127.0.0.1:1/approvals/req-1"
        in pending
    )


def test_the_approval_page_line_keeps_the_signed_link_from_the_reason(tmp_path: Path) -> None:
    page = "http://127.0.0.1:1/requests/" + "a" * 32
    signed = page + "/1794444686-" + "b" * 32
    other = "http://127.0.0.1:1/requests/" + "c" * 32 + "/1794444686-" + "d" * 32
    reason = f"HOL Guard requires review. Open HOL Guard to approve or keep this blocked: {signed}."
    [held, unsigned, foreign] = _reasons(
        tmp_path,
        [
            {"decision": "deny", "reason": reason, "approval_request_id": "a" * 32, "approval_url": page},
            {
                "decision": "deny",
                "reason": "HOL Guard requires review.",
                "approval_request_id": "a" * 32,
                "approval_url": page,
            },
            {
                "decision": "deny",
                "reason": f"HOL Guard requires review: {other}",
                "approval_request_id": "a" * 32,
                "approval_url": page,
            },
        ],
    )

    # The link line repeats the signed link, never the bare page that cannot decide.
    assert f"Give the user this exact HOL Guard approval link, copied in full: {signed}" in held
    assert f"{page}\n" not in held + "\n"
    assert not held.rstrip().endswith(page)
    # Without a signed link for this request in the reason, the page is all there is.
    assert unsigned.endswith(f"copied in full: {page}")
    assert foreign.endswith(f"copied in full: {page}")


def test_the_link_line_asks_for_the_desktop_link_and_the_signed_link(tmp_path: Path) -> None:
    request_id = "a" * 32
    page = f"http://127.0.0.1:1/requests/{request_id}"
    signed = page + "/1794444686-" + "b" * 32
    desktop = f"hol-guard-desktop://requests/{request_id}"
    reason = (
        "HOL Guard requires review. Open HOL Guard to approve or keep this blocked: "
        f"{desktop} (HOL Guard Desktop), or in a browser: {signed}."
    )
    other_desktop = "hol-guard-desktop://requests/" + "c" * 32
    [held, foreign, unlabeled] = _reasons(
        tmp_path,
        [
            {"decision": "deny", "reason": reason, "approval_request_id": request_id, "approval_url": page},
            {
                "decision": "deny",
                "reason": reason.replace(desktop, other_desktop),
                "approval_request_id": request_id,
                "approval_url": page,
            },
            {
                "decision": "deny",
                "reason": f"HOL Guard requires review. See {desktop} and {signed}.",
                "approval_request_id": request_id,
                "approval_url": page,
            },
        ],
    )

    # Desktop handles request links here, so the agent is asked for both links,
    # each on its own line so neither is cut short or merged into prose.
    assert held.endswith(
        "Give the user both HOL Guard approval links, each copied in full:\n"
        f"HOL Guard Desktop: {desktop}\nBrowser: {signed}"
    )
    # Another request's Desktop link, or one Guard did not offer as the Desktop
    # step, never replaces the single signed-link line.
    assert foreign.endswith(f"Give the user this exact HOL Guard approval link, copied in full: {signed}")
    assert unlabeled.endswith(f"Give the user this exact HOL Guard approval link, copied in full: {signed}")
