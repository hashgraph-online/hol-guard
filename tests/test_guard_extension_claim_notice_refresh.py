"""Refresh, backfill and fail-closed behaviour of the claim notice."""

from __future__ import annotations

import json

import pytest

from tests.extension_claim_notice_harness import (
    BEFORE_SHA,
    MERGE_SHA,
    MODULE,
    SCHEMA_V1,
    SCHEMA_V2,
    WORKFLOW,
    FakeGitHub,
    configure_new_contribution,
    listing,
    listing_v2,
)


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
