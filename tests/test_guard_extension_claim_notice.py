"""Claim notices and mapping guidance posted for a merged contribution."""

from __future__ import annotations

from tests.extension_claim_notice_harness import (
    BEFORE_SHA,
    MERGE_SHA,
    MODULE,
    FakeGitHub,
    configure_new_command_source,
    configure_new_contribution,
    configure_unmapped_contribution,
    listing,
)


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
