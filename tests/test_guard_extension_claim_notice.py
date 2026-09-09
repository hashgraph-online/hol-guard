from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/notify_merged_extension_claimants.py"
WORKFLOW = ROOT / ".github/workflows/extension-claim-notice.yml"
SCHEMA = ROOT / "contracts/extensions/listing.v1.schema.json"
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
        "tagline": f"Reviewed operation coverage for {extension_id}.",
        "category": "other",
        "limitations": ["Coverage is limited to the reviewed operations and the surrounding Guard policy."],
        "maintainerGithubIds": ids,
    }


class FakeGitHub:
    def __init__(self) -> None:
        self.default_branch = "main"
        self.merged = True
        self.base_ref = "main"
        self.base_sha = BEFORE_SHA
        self.compare_status = "ahead"
        self.baseline_status = "ahead"
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
            "base": {"ref": self.base_ref, "sha": self.base_sha},
            "merge_commit_sha": MERGE_SHA,
        }

    def compare(self, base: str, head: str) -> dict[str, Any]:
        if base == self.base_sha and head == MERGE_SHA:
            return {"status": self.baseline_status}
        if base == MERGE_SHA and head == self.default_branch:
            return {"status": self.compare_status}
        raise AssertionError(f"unexpected comparison: {base}...{head}")

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


def configure_new_contribution(client: FakeGitHub, extension_id: str, ids: list[str]) -> None:
    contribution_path = f"contributions/extensions/{extension_id}.json"
    listing_path = f"contributions/extension-listings/{extension_id}.json"
    client.files = [
        {"status": "added", "filename": contribution_path},
        {"status": "added", "filename": listing_path},
    ]
    client.file_payloads[(MERGE_SHA, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(MERGE_SHA, listing_path)] = listing(extension_id, ids)


def test_new_contribution_notifies_only_reviewed_numeric_ids() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.example", ["200", "100"])
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


def test_pre_pr_base_sha_supports_multi_commit_rebase_merges() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.rebased", ["300"])
    client.logins = {"300": "rebased-maintainer"}

    assert MODULE.process(client, 12, MODULE.DEFAULT_STUDIO_URL) == 0
    assert "@rebased-maintainer" in client.posted[0][1]


def test_existing_marker_from_trusted_actions_identity_is_idempotent() -> None:
    client = FakeGitHub()
    client.comment_rows = [
        {
            "body": f"{MODULE.MARKER}\nAlready posted",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]

    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_contributor_cannot_spoof_notice_marker() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.marker-spoof", ["400"])
    client.logins = {"400": "real-maintainer"}
    client.comment_rows = [{"body": MODULE.MARKER, "user": {"id": 1234, "type": "User"}}]

    assert MODULE.process(client, 13, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1


def test_renamed_contributions_require_explicit_maintainer_backfill() -> None:
    client = FakeGitHub()
    old_id = "command.old-name"
    new_id = "command.new-name"
    old_contribution = f"contributions/extensions/{old_id}.json"
    new_contribution = f"contributions/extensions/{new_id}.json"
    old_listing = f"contributions/extension-listings/{old_id}.json"
    new_listing = f"contributions/extension-listings/{new_id}.json"
    client.files = [
        {"status": "renamed", "filename": new_contribution, "previous_filename": old_contribution},
        {"status": "renamed", "filename": new_listing, "previous_filename": old_listing},
    ]
    client.file_payloads[(BEFORE_SHA, old_contribution)] = {"schemaVersion": "v1"}
    client.file_payloads[(BEFORE_SHA, old_listing)] = listing(old_id, ["700"])
    client.file_payloads[(MERGE_SHA, new_contribution)] = {"schemaVersion": "v1"}
    client.file_payloads[(MERGE_SHA, new_listing)] = listing(new_id, ["700"])
    client.logins = {"700": "renamed-maintainer"}

    assert MODULE.process(client, 15, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []

    assert MODULE.process(client, 15, MODULE.DEFAULT_STUDIO_URL, allow_renames=True) == 0
    assert len(client.posted) == 1
    assert "@renamed-maintainer" in client.posted[0][1]


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
    configure_new_contribution(client, extension_id, ["not-a-number"])

    with pytest.raises(MODULE.ClaimNoticeError, match="invalid numeric GitHub ID"):
        MODULE.collect_notice_items(client, 11)


def test_missing_required_listing_fields_fail_closed() -> None:
    client = FakeGitHub()
    extension_id = "command.invalid-listing"
    configure_new_contribution(client, extension_id, ["500"])
    listing_path = f"contributions/extension-listings/{extension_id}.json"
    client.file_payloads[(MERGE_SHA, listing_path)].pop("tagline")

    with pytest.raises(MODULE.ClaimNoticeError, match="canonical schema"):
        MODULE.collect_notice_items(client, 14)


def test_non_ascii_and_duplicate_github_ids_fail_closed() -> None:
    extension_id = "command.invalid-ids"
    non_ascii_digits = "\uff11\uff12\uff13"
    with pytest.raises(MODULE.ClaimNoticeError, match="invalid numeric GitHub ID"):
        MODULE.accepted_github_ids(listing(extension_id, [non_ascii_digits]), extension_id)
    with pytest.raises(MODULE.ClaimNoticeError, match="must be unique"):
        MODULE.accepted_github_ids(listing(extension_id, ["600", "600"]), extension_id)


def test_worker_authority_constants_match_public_schema() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    required = frozenset(schema["required"])
    allowed = frozenset(schema["properties"])
    categories = frozenset(schema["properties"]["category"]["enum"])
    github_id_pattern = schema["properties"]["maintainerGithubIds"]["items"]["pattern"]
    assert required == MODULE.LISTING_REQUIRED_KEYS
    assert allowed == MODULE.LISTING_ALLOWED_KEYS
    assert categories == MODULE.LISTING_CATEGORIES
    assert github_id_pattern == MODULE.GITHUB_ID_RE.pattern


def test_unresolved_numeric_id_stays_visible_without_guessing_a_username() -> None:
    item = MODULE.NoticeItem(
        extension_id="command.unresolved",
        identities=(("100", "resolved-user"), ("200", None)),
    )
    body = MODULE.build_comment([item], MODULE.DEFAULT_STUDIO_URL)
    assert "@resolved-user" in body
    assert "GitHub ID `200`" in body
    assert "GitHub ID `100`" not in body


def test_changed_extension_ids_track_renames_and_ignore_removed_files() -> None:
    contributions, listings, renamed = MODULE.changed_extension_ids(
        [
            {"status": "added", "filename": "contributions/extensions/command.one.json"},
            {
                "status": "modified",
                "filename": "contributions/extension-listings/mcp.two.json",
            },
            {
                "status": "renamed",
                "filename": "contributions/extensions/command.new.json",
                "previous_filename": "contributions/extensions/command.old.json",
            },
            {"status": "removed", "filename": "contributions/extensions/command.gone.json"},
            {"status": "modified", "filename": "README.md"},
        ]
    )
    assert contributions == {"command.one", "command.new"}
    assert listings == {"mcp.two"}
    assert renamed == {"command.new", "command.old"}


def test_workflow_is_merge_only_and_supports_reviewed_rename_backfill() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request_target:" in text
    assert "types: [closed]" in text
    assert "github.event.pull_request.merged == true" in text
    assert "workflow_dispatch:" in text
    assert "pr_number:" in text
    assert "allow_renames:" in text
    assert "contributions/extension-listings/**" in text
    assert "pull-requests: write" in text
    assert "issues: write" in text
    assert "persist-credentials: false" in text
    assert "--allow-renames" in text
    assert "notify_merged_extension_claimants.py" in text
    assert "https://hol.org/guard/extension-studio" in text
