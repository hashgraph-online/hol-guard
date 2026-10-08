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
SCHEMA_V1 = ROOT / "contracts/extensions/listing.v1.schema.json"
SCHEMA_V2 = ROOT / "contracts/extensions/listing.v2.schema.json"
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


def listing_v2(extension_id: str, ids: list[str]) -> dict[str, Any]:
    result = listing(extension_id, ids)
    result.update(
        {
            "schemaVersion": "guard.extension-listing.v2",
            "summary": "Bounded public credit for the reviewed declarative extension contribution.",
            "contributors": [{"githubId": "900", "githubLogin": "credit-author", "roles": ["author"]}],
            "originalContributions": [
                {"kind": "pull-request", "url": "https://github.com/hashgraph-online/hol-guard/pull/3020"}
            ],
            "upstream": {"name": "Example upstream", "url": "https://github.com/example/project"},
        }
    )
    return result


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
        self.updated: list[tuple[int, str]] = []

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

    def update_comment(self, comment_id: int, body: str) -> None:
        self.updated.append((comment_id, body))


def configure_new_contribution(
    client: FakeGitHub,
    extension_id: str,
    ids: list[str],
    *,
    tip_ids: list[str] | None = None,
) -> None:
    contribution_path = f"contributions/extensions/{extension_id}.json"
    listing_path = f"contributions/extension-listings/{extension_id}.json"
    client.files = [
        {"status": "added", "filename": contribution_path},
        {"status": "added", "filename": listing_path},
    ]
    client.file_payloads[(MERGE_SHA, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(client.default_branch, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(MERGE_SHA, listing_path)] = listing(extension_id, ids)
    # Current canonical state used by the delayed/backfill revalidation pass.
    client.file_payloads[(client.default_branch, listing_path)] = listing(
        extension_id, ids if tip_ids is None else tip_ids
    )


def configure_unmapped_contribution(client: FakeGitHub, extension_id: str) -> str:
    contribution_path = f"contributions/extensions/{extension_id}.json"
    client.files = [{"status": "added", "filename": contribution_path}]
    client.file_payloads[(MERGE_SHA, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(client.default_branch, contribution_path)] = {"schemaVersion": "v1"}
    return contribution_path


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
    assert "claim=command.example" in body
    assert "source_surface=github_claim_notice" in body
    assert "extension=command.example" not in body
    assert "PR author" not in body
    assert "runtime trust" in body
    assert "## Claim your extension" in body
    assert "continue with GitHub" in body
    assert "public publisher page" in body
    assert "launch story" in body
    assert "setup guide and blog content" in body
    assert "verified publisher badge toolkit" in body
    assert "claiming alone does not publish" in body
    assert "trust score" not in body
    assert "installs" not in body


def configure_new_command_source(client: FakeGitHub, extension_id: str) -> str:
    """A command extension contributed as its canonical source only; the
    descriptor under contributions/extensions/ is generated on main later."""
    source_path = f"contributions/command-sources/{extension_id}.json"
    client.files = [
        {"status": "added", "filename": source_path},
        {"status": "added", "filename": f"tests/fixtures/command-source-{extension_id[8:]}.v1.json"},
    ]
    client.file_payloads[(MERGE_SHA, source_path)] = {"schema": "guard.command-extension-source.v1"}
    client.file_payloads[(client.default_branch, source_path)] = {"schema": "guard.command-extension-source.v1"}
    return source_path


def test_source_only_command_contribution_gets_mapping_guidance() -> None:
    client = FakeGitHub()
    configure_new_command_source(client, "command.sourceonly")

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1
    body = client.posted[0][1]
    assert MODULE.GUIDANCE_MARKER in body
    assert "contributions/extension-listings/command.sourceonly.json" in body
    assert MODULE.MARKER not in body


def test_source_only_command_contribution_with_listing_gets_claim_notice() -> None:
    client = FakeGitHub()
    configure_new_command_source(client, "command.sourceonly")
    listing_path = "contributions/extension-listings/command.sourceonly.json"
    client.files.append({"status": "added", "filename": listing_path})
    client.file_payloads[(MERGE_SHA, listing_path)] = listing("command.sourceonly", ["100"])
    client.file_payloads[(client.default_branch, listing_path)] = listing("command.sourceonly", ["100"])
    client.logins = {"100": "source-maintainer"}

    assert MODULE.process(client, 42, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1
    body = client.posted[0][1]
    assert MODULE.MARKER in body
    assert "@source-maintainer" in body
    assert "claim=command.sourceonly" in body


def test_generated_descriptor_for_merged_source_does_not_repeat_guidance() -> None:
    """The post-merge refresh adds the descriptor for a source already on main;
    that maintainer PR is not a new contribution and gets no claim comment."""
    client = FakeGitHub()
    source_path = configure_new_command_source(client, "command.sourceonly")
    descriptor_path = "contributions/extensions/command.sourceonly.json"
    client.files = [{"status": "added", "filename": descriptor_path}]
    client.file_payloads[(BEFORE_SHA, source_path)] = {"schema": "guard.command-extension-source.v1"}
    client.file_payloads[(MERGE_SHA, descriptor_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(client.default_branch, descriptor_path)] = {"schemaVersion": "v1"}

    assert MODULE.process(client, 8, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_updated_existing_command_source_does_not_repeat_guidance() -> None:
    client = FakeGitHub()
    source_path = configure_new_command_source(client, "command.sourceonly")
    client.files[0]["status"] = "modified"
    client.file_payloads[(BEFORE_SHA, source_path)] = {"schema": "guard.command-extension-source.v1"}

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_pr_authorship_never_creates_claim_authority() -> None:
    client = FakeGitHub()
    extension_id = "command.no-authority"
    client.files = [{"status": "added", "filename": f"contributions/extensions/{extension_id}.json"}]
    client.file_payloads[(MERGE_SHA, f"contributions/extensions/{extension_id}.json")] = {"schemaVersion": "v1"}

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_current_unmapped_contribution_gets_reviewed_mapping_instructions() -> None:
    client = FakeGitHub()
    configure_unmapped_contribution(client, "command.unmapped")

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1
    body = client.posted[0][1]
    assert MODULE.GUIDANCE_MARKER in body
    assert "contributions/extension-listings/command.unmapped.json" in body
    assert "publisher-metadata.md" in body
    assert "?claim=" not in body
    assert MODULE.MARKER not in body


def test_updated_existing_unmapped_contribution_does_not_repeat_claim_guidance() -> None:
    client = FakeGitHub()
    contribution_path = configure_unmapped_contribution(client, "command.unmapped")
    client.file_payloads[(BEFORE_SHA, contribution_path)] = {"schemaVersion": "v1"}

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_guidance_is_idempotent_only_for_the_trusted_bot() -> None:
    client = FakeGitHub()
    configure_unmapped_contribution(client, "command.unmapped")
    client.comment_rows = [{"body": MODULE.GUIDANCE_MARKER, "user": {"id": 1234, "type": "User"}}]

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1

    client.comment_rows.append(
        {
            "body": client.posted[0][1],
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    )
    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1


def test_removed_or_later_claimable_source_gets_no_stale_guidance() -> None:
    client = FakeGitHub()
    contribution_path = configure_unmapped_contribution(client, "command.unmapped")
    del client.file_payloads[(client.default_branch, contribution_path)]

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []

    client.file_payloads[(client.default_branch, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(client.default_branch, "contributions/extension-listings/command.unmapped.json")] = listing(
        "command.unmapped", ["100"]
    )
    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_empty_accepted_set_gets_guidance_without_a_claim_link() -> None:
    client = FakeGitHub()
    contribution_path = configure_unmapped_contribution(client, "command.unmapped")
    listing_path = "contributions/extension-listings/command.unmapped.json"
    client.file_payloads[(MERGE_SHA, listing_path)] = listing("command.unmapped", [])
    client.file_payloads[(client.default_branch, listing_path)] = listing("command.unmapped", [])
    assert client.file_payloads[(client.default_branch, contribution_path)] is not None

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1
    assert MODULE.GUIDANCE_MARKER in client.posted[0][1]
    assert "?claim=" not in client.posted[0][1]


def test_invalid_current_listing_skips_guidance_without_a_claim_link() -> None:
    client = FakeGitHub()
    configure_unmapped_contribution(client, "command.unmapped")
    client.file_payloads[(client.default_branch, "contributions/extension-listings/command.unmapped.json")] = {
        "schemaVersion": "invalid"
    }

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
    client.file_payloads[(client.default_branch, contribution_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(MERGE_SHA, listing_path)] = listing(extension_id, ["100", "200"])
    client.file_payloads[(BEFORE_SHA, listing_path)] = listing(extension_id, ["100"])
    client.file_payloads[(client.default_branch, listing_path)] = listing(extension_id, ["100", "200"])
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


def test_explicit_refresh_updates_only_existing_trusted_notice() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.refresh", ["400"])
    client.logins = {"400": "reviewed-maintainer"}
    client.comment_rows = [
        {
            "id": 123,
            "body": f"{MODULE.MARKER}\nOld notice",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]

    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True, dry_run=True) == 0
    assert client.updated == []
    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True) == 0
    assert client.posted == []
    assert len(client.updated) == 1
    assert client.updated[0][0] == 123
    assert "@reviewed-maintainer" in client.updated[0][1]
    assert "launch story" in client.updated[0][1]

    client.comment_rows[0]["body"] = client.updated[0][1]
    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True) == 0
    assert len(client.updated) == 1


def test_refresh_rejects_trusted_comment_without_valid_id() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.refresh", ["400"])
    client.comment_rows = [{"body": MODULE.MARKER, "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"}}]

    with pytest.raises(MODULE.ClaimNoticeError, match="comment ID is invalid"):
        MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True)


def test_refresh_withdraws_link_after_claim_authority_is_removed() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.withdrawn", ["400"], tip_ids=[])
    client.comment_rows = [
        {
            "id": 123,
            "body": f"{MODULE.MARKER}\n[Old claim link](https://example.com)",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]

    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True) == 0
    assert client.posted == []
    assert client.updated == [(123, MODULE.build_withdrawn_comment())]
    assert "no longer current" in client.updated[0][1]
    assert "?claim=" not in client.updated[0][1]


def test_refresh_retains_existing_link_during_portal_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.portal-gated", ["400"])
    client.comment_rows = [
        {
            "id": 123,
            "body": f"{MODULE.MARKER}\nOld claim notice",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]
    monkeypatch.setattr(MODULE, "portal_readiness", lambda _url: ("provider_unavailable", "portal unreachable"))

    assert (
        MODULE.process(
            client,
            9,
            MODULE.DEFAULT_STUDIO_URL,
            refresh_existing=True,
            portal_readiness_url="https://portal.example/ready",
        )
        == 0
    )
    assert client.posted == []
    assert client.updated == []


def test_refresh_does_not_withdraw_rename_backfill_without_opt_in() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.unmapped", [])
    client.files.append(
        {
            "status": "renamed",
            "filename": "contributions/extensions/command.renamed.json",
            "previous_filename": "contributions/extensions/command.old.json",
        }
    )
    client.comment_rows = [
        {
            "id": 123,
            "body": f"{MODULE.MARKER}\nEarlier rename claim link",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]

    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True) == 0
    assert client.updated == []


def test_refresh_keeps_rename_link_when_another_extension_is_eligible() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.eligible", ["400"])
    client.files.append(
        {
            "status": "renamed",
            "filename": "contributions/extensions/command.renamed.json",
            "previous_filename": "contributions/extensions/command.old.json",
        }
    )
    client.comment_rows = [
        {
            "id": 123,
            "body": f"{MODULE.MARKER}\nEarlier rename claim link",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]

    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True) == 0
    assert client.updated == []


def test_refresh_withdraws_link_after_native_contribution_is_removed() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.removed", ["400"])
    client.file_payloads.pop((client.default_branch, "contributions/extensions/command.removed.json"))
    client.comment_rows = [
        {
            "id": 123,
            "body": f"{MODULE.MARKER}\nEarlier claim link",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]

    assert MODULE.process(client, 9, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True) == 0
    assert client.updated == [(123, MODULE.build_withdrawn_comment())]


def test_contributor_cannot_spoof_notice_marker() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.marker-spoof", ["400"])
    client.logins = {"400": "real-maintainer"}
    client.comment_rows = [{"body": MODULE.MARKER, "user": {"id": 1234, "type": "User"}}]

    assert MODULE.process(client, 13, MODULE.DEFAULT_STUDIO_URL, refresh_existing=True) == 0
    assert len(client.posted) == 1
    assert client.updated == []


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
    client.file_payloads[(client.default_branch, new_contribution)] = {"schemaVersion": "v1"}
    client.file_payloads[(MERGE_SHA, new_listing)] = listing(new_id, ["700"])
    client.file_payloads[(client.default_branch, new_listing)] = listing(new_id, ["700"])
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


def test_v2_credit_never_becomes_claim_authority() -> None:
    extension_id = "command.v2-credit"
    v2 = listing_v2(extension_id, [])
    assert MODULE.accepted_github_ids(v2, extension_id) == ()
    v2["maintainerGithubIds"] = ["500"]
    assert MODULE.accepted_github_ids(v2, extension_id) == ("500",)


def test_v2_credit_contract_fails_closed() -> None:
    v2 = listing_v2("command.invalid-v2-credit", ["500"])
    v2["contributors"] = [{"githubId": "900", "githubLogin": "credit-author", "roles": ["owner"]}]
    with pytest.raises(MODULE.ClaimNoticeError, match="contributor roles are invalid"):
        MODULE.accepted_github_ids(v2, "command.invalid-v2-credit")


def test_worker_authority_constants_match_public_schema() -> None:
    v1 = json.loads(SCHEMA_V1.read_text(encoding="utf-8"))
    v2 = json.loads(SCHEMA_V2.read_text(encoding="utf-8"))
    categories = frozenset(v1["properties"]["category"]["enum"])
    github_id_pattern = v1["properties"]["maintainerGithubIds"]["items"]["pattern"]
    assert frozenset(v1["required"]) == MODULE.LISTING_REQUIRED_KEYS
    assert frozenset(v1["properties"]) == MODULE.LISTING_ALLOWED_KEYS
    assert frozenset(v2["required"]) == MODULE.LISTING_V2_REQUIRED_KEYS
    assert frozenset(v2["properties"]) == MODULE.LISTING_V2_ALLOWED_KEYS
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
            {"status": "added", "filename": "contributions/command-sources/command.source.json"},
            {"status": "added", "filename": "tests/fixtures/command-source-source.v1.json"},
            {"status": "modified", "filename": "README.md"},
        ]
    )
    assert contributions == {"command.one", "command.new", "command.source"}
    assert listings == {"mcp.two"}
    assert renamed == {"command.new", "command.old"}


def test_workflow_is_merge_only_and_supports_reviewed_rename_backfill() -> None:
    """Claim notices retain merge checks and PR-comment access without issue-management access."""

    text = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request_target:" in text
    assert "types: [closed]" in text
    assert "github.event.pull_request.merged == true" in text
    assert "workflow_dispatch:" in text
    assert "pr_number:" in text
    assert "allow_renames:" in text
    assert "dry_run:" in text
    assert "refresh_existing:" in text
    assert "contributions/extension-listings/**" in text
    for path in ("contributions/extensions/**", "contributions/command-sources/**", "contributions/mcp-servers/**"):
        assert path in text
    assert "pull-requests: write" in text
    assert "issues: write" not in text
    assert "persist-credentials: false" in text
    assert "--allow-renames" in text
    assert "--dry-run" in text
    assert "--refresh-existing" in text
    assert "notify_merged_extension_claimants.py" in text
    assert "https://hol.org/guard/extension-studio" in text


def test_delayed_backfill_never_reinvites_identity_removed_from_current_main() -> None:
    """A11: an old merged sidecar must not re-invite a since-removed identity."""

    client = FakeGitHub()
    configure_new_contribution(client, "command.revoked", ["100", "200"], tip_ids=["100"])
    client.logins = {"100": "remaining-maintainer", "200": "withdrawn-maintainer"}

    assert MODULE.process(client, 21, MODULE.DEFAULT_STUDIO_URL) == 0

    assert len(client.posted) == 1
    body = client.posted[0][1]
    assert "@remaining-maintainer" in body
    assert "@withdrawn-maintainer" not in body


def test_delayed_backfill_skips_when_whole_accepted_set_was_withdrawn() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.fully-revoked", ["300"], tip_ids=[])

    assert MODULE.process(client, 22, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []
    report = MODULE.readiness_report(client, 22)
    assert report["prStatus"] == "source_not_current"
    assert report["entries"] == [
        {"extensionId": "command.fully-revoked", "status": "source_not_current", "notifiedIds": []}
    ]


def test_delayed_backfill_skips_when_listing_absent_from_current_main() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.delisted", ["400"])
    listing_path = "contributions/extension-listings/command.delisted.json"
    del client.file_payloads[(client.default_branch, listing_path)]

    assert MODULE.process(client, 23, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []
    report = MODULE.readiness_report(client, 23)
    assert report["entries"][0]["status"] == "source_not_current"


def test_invalid_current_listing_reports_source_not_current_instead_of_posting() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.corrupted-tip", ["500"])
    listing_path = "contributions/extension-listings/command.corrupted-tip.json"
    corrupted = listing("command.corrupted-tip", ["500"])
    corrupted["maintainerGithubIds"] = "not-a-list"
    client.file_payloads[(client.default_branch, listing_path)] = corrupted

    assert MODULE.process(client, 24, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []
    report = MODULE.readiness_report(client, 24)
    assert report["entries"][0]["status"] == "source_not_current"


def test_readiness_report_types_not_merged_and_no_mapping() -> None:
    client = FakeGitHub()
    client.merged = False
    report = MODULE.readiness_report(client, 31)
    assert report["prStatus"] == "not_merged"
    assert report["entries"] == []

    client.merged = True
    client.files = [{"status": "added", "filename": "contributions/extensions/command.unmapped.json"}]
    client.file_payloads[(MERGE_SHA, "contributions/extensions/command.unmapped.json")] = {"schemaVersion": "v1"}
    report = MODULE.readiness_report(client, 31)
    assert report["prStatus"] == "no_mapping"
    assert report["entries"] == [{"extensionId": "command.unmapped", "status": "no_mapping", "notifiedIds": []}]


def test_readiness_report_types_empty_mapping_as_no_mapping() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.empty-authority", [])
    report = MODULE.readiness_report(client, 32)
    assert report["entries"] == [{"extensionId": "command.empty-authority", "status": "no_mapping", "notifiedIds": []}]


def test_readiness_report_maps_github_api_errors_to_provider_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()

    def api_failure(number: int) -> list[dict[str, Any]]:
        raise MODULE.ClaimNoticeError("GitHub API request failed")

    monkeypatch.setattr(client, "comments", api_failure)
    report = MODULE.readiness_report(client, 38)

    assert report["prStatus"] == "provider_unavailable"
    assert report["detail"] == "GitHub API request failed"
    assert report["entries"] == []


def test_readiness_report_reraises_non_api_claim_notice_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()

    def invalid_provenance(number: int) -> list[dict[str, Any]]:
        raise MODULE.ClaimNoticeError("invalid comment provenance")

    monkeypatch.setattr(client, "comments", invalid_provenance)
    with pytest.raises(MODULE.ClaimNoticeError, match="invalid comment provenance"):
        MODULE.readiness_report(client, 39)


def test_readiness_report_uses_first_entry_for_mixed_noneligible_statuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeGitHub()

    def mixed_statuses(
        _client: Any,
        _pr_number: int,
        *,
        allow_renames: bool = False,
        records: list[Any] | None = None,
    ) -> tuple[list[Any], str, bool]:
        assert records is not None
        records.extend(
            [
                MODULE.ExtensionReadiness("command.source-not-current", "source_not_current"),
                MODULE.ExtensionReadiness("command.no-mapping", "no_mapping"),
            ]
        )
        return [], "source_not_current", False

    monkeypatch.setattr(MODULE, "_plan_notice_items", mixed_statuses)
    report = MODULE.readiness_report(client, 40)

    assert [entry["status"] for entry in report["entries"]] == ["source_not_current", "no_mapping"]
    assert report["prStatus"] == "source_not_current"


def test_readiness_report_reports_eligible_entry_and_portal_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.ready", ["600"])
    client.logins = {"600": "ready-maintainer"}

    # Portal endpoint unconfigured: neither the entry nor the PR may claim ready.
    report = MODULE.readiness_report(client, 33)
    assert report["portalStatus"] == "not_configured"
    assert report["entries"][0]["status"] == "portal_not_ready"
    assert report["prStatus"] == "portal_not_ready"

    def ok(url: str) -> tuple[str, str]:
        return "ok", "portal reports ready"

    monkeypatch.setattr(MODULE, "portal_readiness", ok)
    report = MODULE.readiness_report(client, 33, portal_readiness_url="https://portal.example/ready")
    assert report["portalStatus"] == "ok"
    assert report["prStatus"] == "eligible_for_notice"
    assert report["entries"][0]["status"] == "eligible_for_notice"
    assert report["entries"][0]["notifiedIds"] == ["600"]


def test_readiness_report_fails_closed_when_portal_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.portal-down", ["700"])

    def unreachable(url: str) -> tuple[str, str]:
        return "provider_unavailable", "portal unreachable: connection refused"

    monkeypatch.setattr(MODULE, "portal_readiness", unreachable)
    report = MODULE.readiness_report(client, 34, portal_readiness_url="https://portal.example/ready")
    assert report["prStatus"] == "provider_unavailable"
    assert report["entries"][0]["status"] == "provider_unavailable"

    def lagging(url: str) -> tuple[str, str]:
        return "portal_not_ready", "portal did not affirm readiness"

    monkeypatch.setattr(MODULE, "portal_readiness", lagging)
    report = MODULE.readiness_report(client, 34, portal_readiness_url="https://portal.example/ready")
    assert report["prStatus"] == "portal_not_ready"
    assert report["entries"][0]["status"] == "portal_not_ready"


def test_process_never_posts_when_configured_portal_is_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.gated", ["800"])
    client.logins = {"800": "gated-maintainer"}

    def not_ready(url: str) -> tuple[str, str]:
        return "portal_not_ready", "projection is stale"

    monkeypatch.setattr(MODULE, "portal_readiness", not_ready)
    assert (
        MODULE.process(
            client,
            35,
            MODULE.DEFAULT_STUDIO_URL,
            portal_readiness_url="https://portal.example/ready",
        )
        == 0
    )
    assert client.posted == []


def test_portal_outage_does_not_suppress_mapping_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_unmapped_contribution(client, "command.unmapped")
    monkeypatch.setattr(MODULE, "portal_readiness", lambda _url: ("portal_not_ready", "projection is stale"))

    assert (
        MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL, portal_readiness_url="https://portal.example/ready") == 0
    )
    assert len(client.posted) == 1
    assert MODULE.GUIDANCE_MARKER in client.posted[0][1]
    assert MODULE.MARKER not in client.posted[0][1]


def test_account_lookup_failure_does_not_suppress_mapping_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.mapped", ["800"])
    unmapped_path = "contributions/extensions/command.unmapped.json"
    client.files.append({"status": "added", "filename": unmapped_path})
    client.file_payloads[(MERGE_SHA, unmapped_path)] = {"schemaVersion": "v1"}
    client.file_payloads[(client.default_branch, unmapped_path)] = {"schemaVersion": "v1"}

    def lookup_failure(_account_id: str) -> str | None:
        raise MODULE.ClaimNoticeError("GitHub API request failed")

    monkeypatch.setattr(client, "user_login", lookup_failure)
    with pytest.raises(MODULE.ClaimNoticeError, match="GitHub API request failed"):
        MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL)
    assert len(client.posted) == 1
    assert MODULE.GUIDANCE_MARKER in client.posted[0][1]
    assert MODULE.MARKER not in client.posted[0][1]


def test_trusted_marker_marks_readiness_already_notified() -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.duplicate", ["900"])
    client.logins = {"900": "dup-maintainer"}
    client.comment_rows = [
        {
            "body": f"{MODULE.MARKER}\nEarlier notice",
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]

    report = MODULE.readiness_report(client, 36)
    assert report["prStatus"] == "already_notified"
    assert report["entries"][0]["status"] == "already_notified"
    assert MODULE.process(client, 36, MODULE.DEFAULT_STUDIO_URL) == 0
    assert client.posted == []


def test_report_only_mode_prints_readiness_json_without_posting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = FakeGitHub()
    configure_new_contribution(client, "command.report-only", ["950"])

    def ok(url: str) -> tuple[str, str]:
        return "ok", "portal reports ready"

    monkeypatch.setattr(MODULE, "portal_readiness", ok)
    assert (
        MODULE.process(
            client,
            37,
            MODULE.DEFAULT_STUDIO_URL,
            report_only=True,
            portal_readiness_url="https://portal.example/ready",
        )
        == 0
    )
    assert client.posted == []
    import json as jsonlib

    payload = jsonlib.loads(capsys.readouterr().out)
    assert payload["schemaVersion"] == "guard.extension-claim-notice-readiness.v1"
    assert payload["entries"][0]["status"] == "eligible_for_notice"


def test_portal_readiness_maps_transport_failures_without_claiming_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    class Response:
        def __init__(self, payload: bytes, status: int = 200) -> None:
            self._payload = payload
            self.status = status

        def read(self, limit: int) -> bytes:
            return self._payload

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def ok(req: object, timeout: float) -> Response:
        return Response(b'{"ok": true}')

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", ok)
    assert MODULE.portal_readiness("https://portal.example/ready") == ("ok", "portal reports ready")

    def ready_only_flag(req: object, timeout: float) -> Response:
        return Response(b'{"ready": true, "entries": 69}')

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", ready_only_flag)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "portal_not_ready"

    def not_affirming(req: object, timeout: float) -> Response:
        return Response(b'{"ok": false}')

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", not_affirming)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "portal_not_ready"

    def non_200(req: object, timeout: float) -> Response:
        return Response(b'{"ok": true}', status=202)

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", non_200)
    assert MODULE.portal_readiness("https://portal.example/ready") == (
        "portal_not_ready",
        "portal returned HTTP 202",
    )

    def http_error(req: object, timeout: float) -> Response:
        raise urllib.error.HTTPError(req.url if hasattr(req, "url") else "x", 503, "unavailable", None, None)  # type: ignore[arg-type]

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", http_error)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "provider_unavailable"

    def http_not_found(req: object, timeout: float) -> Response:
        raise urllib.error.HTTPError(req.url if hasattr(req, "url") else "x", 404, "not found", None, None)  # type: ignore[arg-type]

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", http_not_found)
    assert MODULE.portal_readiness("https://portal.example/ready") == (
        "portal_not_ready",
        "portal returned HTTP 404",
    )

    def os_error(req: object, timeout: float) -> Response:
        raise OSError("connection refused")

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", os_error)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "provider_unavailable"

    def not_json(req: object, timeout: float) -> Response:
        return Response(b"<html>maintenance</html>")

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", not_json)
    assert MODULE.portal_readiness("https://portal.example/ready")[0] == "portal_not_ready"


def test_readyness_reasons_constant_covers_the_reviewed_vocabulary() -> None:
    assert (
        frozenset(
            {
                "no_mapping",
                "not_merged",
                "source_not_current",
                "portal_not_ready",
                "already_notified",
                "eligible_for_notice",
                "provider_unavailable",
            }
        )
        == MODULE.READYNESS_REASONS
    )
