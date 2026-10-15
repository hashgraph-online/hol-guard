from __future__ import annotations

from typing import Any

from tests.test_guard_extension_claim_notice import (
    MERGE_SHA,
    MODULE,
    FakeGitHub,
    configure_new_command_source,
    listing,
)


class VerifiedHistoryGitHub(FakeGitHub):
    def pull_request(self, number: int) -> dict[str, Any]:
        pull = super().pull_request(number)
        pull.update({"merged": self.merged, "user": {"id": 100, "login": "source-author", "type": "User"}})
        pull["base"]["repo"] = {"full_name": self.repo}
        return pull

    def _request(self, url: str) -> Any:
        route = url.removeprefix(self.base_url + "/")
        source_path = self.files[0]["filename"]
        if route.startswith("commits?"):
            return [{"sha": MERGE_SHA}]
        if route == f"commits/{MERGE_SHA}?per_page=100":
            return {"files": [{"filename": source_path, "status": "added"}]}
        if route == f"commits/{MERGE_SHA}/pulls?per_page=100":
            return [{"number": 7}]
        if route == "commits/main":
            return {"sha": MERGE_SHA}
        raise AssertionError(f"Unexpected provenance route: {route}")

    def compare(self, base: str, head: str) -> dict[str, Any]:
        if base == head == MERGE_SHA:
            return {"status": "identical"}
        return super().compare(base, head)


def test_verified_source_only_merge_gets_direct_claim_link_without_listing() -> None:
    client = VerifiedHistoryGitHub()
    configure_new_command_source(client, "command.sourceonly")
    client.logins = {"100": "source-author"}

    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1
    body = client.posted[0][1]
    assert MODULE.MARKER in body
    assert "claim=command.sourceonly" in body
    assert "@source-author" in body
    assert MODULE.GUIDANCE_MARKER not in body
    assert "extension-listings" not in body


def test_explicit_empty_current_authority_revokes_automatic_claim_link() -> None:
    client = VerifiedHistoryGitHub()
    configure_new_command_source(client, "command.revoked")
    client.file_payloads[(client.default_branch, "contributions/extension-listings/command.revoked.json")] = listing(
        "command.revoked", []
    )
    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert not client.posted
def test_removed_historical_empty_override_recovers_original_author_invitation() -> None:
    client = VerifiedHistoryGitHub()
    configure_new_command_source(client, "command.sourceonly")
    client.file_payloads[(MERGE_SHA, "contributions/extension-listings/command.sourceonly.json")] = listing(
        "command.sourceonly", []
    )
    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert len(client.posted) == 1
    assert "claim=command.sourceonly" in client.posted[0][1]


def test_historical_introduction_without_binding_uses_current_external_classification() -> None:
    client = VerifiedHistoryGitHub()
    configure_new_command_source(client, "command.sourceonly")
    client.file_payloads[(MERGE_SHA, "contracts/extensions/trust/command.sourceonly.v1.json")] = None
    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert MODULE.MARKER in client.posted[0][1]


def test_project_reclassification_blocks_an_automatic_invitation() -> None:
    client = VerifiedHistoryGitHub()
    configure_new_command_source(client, "command.sourceonly")
    client.file_payloads[(client.default_branch, "contracts/extensions/trust/command.sourceonly.v1.json")] = {
        "schemaVersion": "guard.extension-trust-binding.v1",
        "extension": "command.sourceonly",
        "trustClass": "first-party",
    }
    assert MODULE.process(client, 7, MODULE.DEFAULT_STUDIO_URL) == 0
    assert not client.posted
