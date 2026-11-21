"""Shared fixtures for the merged-extension claim-notice tests.

The notice script is loaded by path once here so every claim-notice test
module drives the same module object and the same GitHub fixture.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

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
    repo = "hashgraph-online/hol-guard"
    base_url = "https://api.github.com/repos/hashgraph-online/hol-guard"

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

    def _request(self, url: str) -> Any:
        raise MODULE.ClaimProvenanceError("Fixture has no verified introducing history")

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
        if path.startswith("contracts/extensions/trust/") and (ref, path) not in self.file_payloads:
            runtime_id = path.removeprefix("contracts/extensions/trust/").removesuffix(".v1.json")
            return {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": runtime_id,
                "trustClass": "external",
            }
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


def configure_new_command_source(client: FakeGitHub, extension_id: str) -> str:
    """A command extension contributed as its canonical source only; the
    descriptor under contributions/extensions/ is generated on main later."""
    source_path = f"contributions/command-sources/{extension_id}.json"
    client.files = [
        {"status": "added", "filename": source_path},
        {"status": "added", "filename": f"tests/fixtures/command-source-{extension_id[8:]}.v1.json"},
    ]
    source = {"schema": "guard.command-extension-source.v1", "extension": {"extension_id": extension_id}}
    client.file_payloads[(MERGE_SHA, source_path)] = source
    client.file_payloads[(client.default_branch, source_path)] = source
    return source_path
