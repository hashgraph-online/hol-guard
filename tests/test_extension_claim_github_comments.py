from __future__ import annotations

import io
import re

import pytest

from scripts import notify_merged_extension_claimants as notices
from scripts.extension_claim_github_comments import batched_pull_comments


class Client:
    repo = "hashgraph-online/hol-guard"

    def __init__(self) -> None:
        self.requests = 0
        self.incomplete = False
        self.errors = False

    def _request(self, url, *, method, payload):
        assert url == "https://api.github.com/graphql" and method == "POST"
        self.requests += 1
        if self.errors:
            raise OSError("Synthetic API outage")
        return {
            "data": {
                "repository": {
                    alias: {
                        "number": int(number),
                        "comments": {
                            "pageInfo": {"hasPreviousPage": self.incomplete},
                            "nodes": [
                                {
                                    "databaseId": 99,
                                    "body": notices.MARKER,
                                    "author": {"databaseId": 41898282, "__typename": "Bot"},
                                }
                            ],
                        },
                    }
                    for alias, number in re.findall(r"(p\d+): pullRequest\(number:(\d+)\)", payload["query"])
                }
            }
        }


def _credit_listing(contributors: list[dict[str, object]]) -> dict[str, object]:
    return {
        "summary": "Reviews destructive file-transfer operations through a bounded native command contract.",
        "contributors": contributors,
        "originalContributions": [],
        "upstream": None,
    }


def test_contributor_profile_does_not_expand_claim_notice_credit_identity() -> None:
    credit = {"githubId": "123", "githubLogin": "example-author", "roles": ["author"]}
    notices._validate_v2_credit_fields(
        _credit_listing(
            [
                {
                    **credit,
                    "profile": {
                        "description": "Writes bounded file-transfer coverage.",
                        "website": "https://example.com",
                    },
                }
            ]
        ),
        "command.blitcp",
    )
    with pytest.raises(notices.ClaimNoticeError, match="profile"):
        notices._validate_v2_credit_fields(
            _credit_listing([{**credit, "profile": {"email": "person@example.com"}}]),
            "command.blitcp",
        )
    with pytest.raises(notices.ClaimNoticeError, match="canonical schema"):
        notices._validate_v2_credit_fields(
            _credit_listing([{**credit, "email": "person@example.com"}]),
            "command.blitcp",
        )


@pytest.mark.parametrize("field", ["website", "linkedin", "x"])
def test_contributor_profile_rejects_null_links(field: str) -> None:
    credit = {"githubId": "123", "githubLogin": "example-author", "roles": ["author"]}
    with pytest.raises(notices.ClaimNoticeError, match="canonical schema"):
        notices._validate_v2_credit_fields(
            _credit_listing([{**credit, "profile": {field: None}}]),
            "command.blitcp",
        )


def test_comment_queries_are_bounded_and_preserve_trusted_actor_identity() -> None:
    client = Client()
    rows = batched_pull_comments(client, list(range(1, 62)))
    assert len(rows) == 61 and client.requests == 4
    assert notices.trusted_notice_comment(rows[7])["id"] == 99


@pytest.mark.parametrize("failure", ["incomplete", "errors"])
def test_incomplete_comment_evidence_requires_independent_recheck(failure: str) -> None:
    client = Client()
    setattr(client, failure, True)
    assert batched_pull_comments(client, [7]) == {}


def test_oversized_github_response_cannot_be_parsed_or_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        notices.urllib.request,
        "urlopen",
        lambda *args, **kwargs: io.BytesIO(b"x" * (notices.MAX_GITHUB_RESPONSE_BYTES + 1)),
    )
    client = notices.GitHubApi("example", "hashgraph-online/hol-guard")
    with pytest.raises(notices.ClaimNoticeError, match="byte limit"):
        client._request(
            "https://api.github.com/graphql", method="POST", payload={"query": "query { viewer { login } }"}
        )
