from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/notify_merged_extension_claimants.py"
WORKFLOW = ROOT / ".github/workflows/extension-claim-notice.yml"
SPEC = importlib.util.spec_from_file_location("guard_extension_claim_notice", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

MERGE_SHA = "a" * 40
BEFORE_SHA = "b" * 40


def listing(extension_id: str, ids: list[str]) -> dict[str, Any]:
    return {
        "schemaVersion": "guard.extension-listing.v1",
        "extensionId": extension_id,
        "maintainerGithubIds": ids,
    }


class FakeGitHub:
    def __init__(self) -> None:
        self.default_branch = "main"
        self.merged = True
        self.base_ref = "main"
        self.compare_status = "ahead"
        self.files: list[dict[str, Any]] = []
        self.file_payloads: dict[tuple[str, str], dict[str, Any] | None] = {}
        self.comment_rows: list[dict[str, Any]] = []
        self.logins: dict[str, str | None] = {}
        self.posted: list[tuple[int, str]] = []

    def repo_metadata(self) -> dict[str, Any]:
        return {"default_branch": self.default_branch}

    def pull_request(self, number: int) -> dict[str, Any]:
        return {
            "merged_at": "2026-09-08T00:00:00Z" if self.merged else None,
            "base": {"ref": self.base_ref},
            "merge_commit_sha": MERGE_SHA,
        }

    def compare(self, base: str, head: str) -> dict[str, Any]:
        assert base == MERGE_SHA
        assert head == self.default_branch
        return {"status": self.compare_status}

    def commit(self, sha: str) -> dict[str, Any]:
        assert sha == MERGE_SHA
        return {"parents": [{"sha": BEFORE_SHA}]}

    def pull_request_files(self, number: int) -> list[dict[str, Any]]:
        return self.files

    def file_json(self, path: str, ref: str, *, missing_ok: bool = False) -> dict[str, Any] | None:
        value = self.file_payloads.get((ref, path))
        if value is None and not missing_ok:
            raise AssertionError(f"unexpected missing file: {path}@{ref}")
        return value

    def file_exists(self, path: str, ref: str) -> bool:
        return self.file_payloads.get((ref, path)) is not None

    def comments(self, number: int) -> list[dict[str, Any]]:
        return self.comment_rows

    def user_login(self, account_id: str) -> str | None:
        return self.logins.get(account_id)

    def post_comment(self, number: int, body: str) -> None:
        self.posted.append((number, body))


def test_new_contribution_notifies_only_reviewed_numeric_ids() -> None:
    client = FakeGitHub()
    extension_id = "command.example"
    client.files = [
        {"status": "added", "filename": f"contributions/extensions/{extension_id}.json"},
        {"status": "added", "filename": f"contributions/extension-listings/{extension_id}.json"},
    ]
    client.file_payloads[(MERGE_SHA, f"contributions/extensions/{extension_id}.json")] = {"schemaVersion": "v1"}
    client.file_payloads[(MERGE_SHA, f"contributions/extension-listings/{extension_id}.json")] = listing(
        extension_id, ["200", "100"]
    )
    client.logins = {"200": "second-maintainer", "100": "first-maintainer"}

    assert MODULE.process(client, 42, MODULE.DEFAULT_STUDIO_URL) == 0

    assert len(client.posted) == 1
    body = client.posted[0][1]
    assert MODULE.MARKER in body
    assert "@second-maintainer" in body
    assert "@first-maintainer" in body
    assert "extension=command.example" in body
    assert "PR author" not in body
    assert "runtime trust" in body


def test_pr_authorship_never_creates_claim_authority() -> None:
    client = FakeGitHub()
    extension_id = "command.no-authority"
    client.files = [{"status": "added", "filename": f"contributions/extensions/{extension_id}.json"}]
    client.file_payloads[(MERGE_SHA, f"contributions/extensions/{extension_id}.json")] = {"schemaVersion": "v1"}

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_listing_change_notifies_only_newly_accepted_ids() -> None:
    client = FakeGitHub()
    extension_id = "command.existing"
    listing_path = f"contributions/extension-listings/{extension_id}.json"
    contribution_path = f"contributions/extensions/{extension_id}.json"
    client.files = [{"status": "modified", "filename": listing_path}]
    client.file_payloads[(MERGE_SHA, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(BEFORE_SHA, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(MERGE_SHA, listing_path)] = listing(extension_id, ["100", "200"])
    client.file_payloads[(BEFORE_SHA, listing_path)] = listing(extension_id, ["100"])
    client.logins = {"100": "old-maintainer", "200": "new-maintainer"}

    assert MODULE.process(client, 8, MODULE.DEFAULT_STUDIO_URL) == 0

    body = client.posted[0][1]
    assert "@new-maintainer" in body
    assert "@old-maintainer" not in body


def test_existing_marker_makes_manual_backfill_idempotent() -> None:
    client = FakeGitHub()
    client.comment_rows = [{"body": f"{MODULE.MARKER}\nAlready posted"}]

    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_noncanonical_or_removed_merge_is_not_actionable() -> None:
    client = FakeGitHub()
    client.base_ref = "release/3.2"
    assert MODULE.process(client, 10, MODULE.DEFAULT_STUDIO_URL) == 0

    client.base_ref = "main"
    client.compare_status = "diverged"
    assert MODULE.process(client, 10, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_invalid_authority_metadata_fails_closed() -> None:
    client = FakeGitHub()
    extension_id = "command.invalid-authority"
    listing_path = f"contributions/extension-listings/{extension_id}.json"
    contribution_path = f"contributions/extensions/{extension_id}.json"
    client.files = [
        {"status": "added", "filename": contribution_path},
        {"status": "added", "filename": listing_path},
    ]
    client.file_payloads[(MERGE_SHA, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(MERGE_SHA, listing_path)] = listing(extension_id, ["not-a-number"])

    with pytest.raises(MODULE.ClaimNoticeError, match="invalid numeric GitHub ID"):
        MODULE.collect_notice_items(client, 11)


def test_unresolved_numeric_id_stays_visible_without_guessing_a_username() -> None:
    item = MODULE.NoticeItem(
        extension_id="command.unresolved",
        identities=(("100", "resolved-user"), ("200", None)),
    )
    body = MODULE.build_comment([item], MODULE.DEFAULT_STUDIO_URL)
    assert "@resolved-user" in body
    assert "GitHub ID `200`" in body
    assert "GitHub ID `100`" not in body


def test_changed_extension_ids_ignore_removed_or_unrelated_files() -> None:
    contributions, listings = MODULE.changed_extension_ids(
        [
            {"status": "added", "filename": "contributions/extensions/command.one.json"},
            {
                "status": "modified",
                "filename": "contributions/extension-listings/mcp.two.json",
            },
            {"status": "removed", "filename": "contributions/extensions/command.gone.json"},
            {"status": "modified", "filename": "README.md"},
        ]
    )
    assert contributions == {"command.one"}
    assert listings == {"mcp.two"}


def test_workflow_is_merge_only_and_supports_idempotent_backfill() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request_target:" in text
    assert "types: [closed]" in text
    assert "github.event.pull_request.merged == true" in text
    assert "workflow_dispatch:" in text
    assert "pr_number:" in text
    assert "contributions/extension-listings/**" in text
    assert "pull-requests: write" in text
    assert "issues: write" in text
    assert "persist-credentials: false" in text
    assert "notify_merged_extension_claimants.py" in text
    assert "https://hol.org/guard/extension-studio" in text
