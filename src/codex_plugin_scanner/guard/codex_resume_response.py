"""Project Codex continuation results into approval-response copy."""

from __future__ import annotations


def project_codex_resume_response(
    *,
    updated: dict[str, object],
    copy: dict[str, str],
    codex_resume: dict[str, object],
) -> dict[str, object]:
    """Attach one continuation result without performing persistence side effects."""

    status = str(codex_resume.get("status") or "")
    message = str(codex_resume.get("message") or "")
    if status == "sent":
        updated["resolution_summary"] = "Decision saved. HOL Guard sent Codex a continue prompt in the original thread."
        copy = {"title": "Decision saved. Codex chat was notified.", "body": message}
    elif status in {"pending", "in_progress"}:
        updated["resolution_summary"] = message or "Decision saved. Codex is still waiting for HOL Guard."
        copy = {
            "title": "Decision saved. Codex is continuing.",
            "body": message or "Return to Codex; the original action should continue automatically.",
        }
    elif status == "already_sent":
        updated["resolution_summary"] = "Decision saved. Codex was already notified for this request."
        copy = {"title": "Decision saved. Codex already notified.", "body": message}
    else:
        updated["resolution_summary"] = message or str(updated.get("resolution_summary") or "Decision saved.")
        copy = {
            "title": (
                "Decision saved. Return to Codex."
                if status == "skipped"
                else "Decision saved. Codex chat could not be notified."
            ),
            "body": message or copy["body"],
        }
    updated["copy"] = copy
    updated["retry_hint"] = copy["body"]
    return updated
