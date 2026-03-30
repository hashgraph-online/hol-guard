"""Tests for awesome-list submission helpers."""

from pathlib import Path
from urllib.error import HTTPError

from codex_plugin_scanner.scanner import scan_plugin
from codex_plugin_scanner.submission import (
    SubmissionMetadata,
    build_submission_issue_body,
    build_submission_issue_title,
    build_submission_payload,
    create_submission_issue,
    find_existing_submission_issue,
    resolve_submission_metadata,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_resolve_submission_metadata_prefers_manifest_fields() -> None:
    result = scan_plugin(FIXTURES / "good-plugin")

    metadata = resolve_submission_metadata(
        FIXTURES / "good-plugin",
        result,
        github_repository="hashgraph-online/example-good-plugin",
    )

    assert metadata.plugin_name == "Example Good Plugin"
    assert metadata.plugin_url == "https://github.com/hashgraph-online/codex-plugin-scanner"
    assert metadata.description == "Reusable security-first plugin fixture"
    assert metadata.author == "Hashgraph Online"
    assert metadata.category == "Community Plugins"


def test_resolve_submission_metadata_falls_back_to_github_context() -> None:
    result = scan_plugin(FIXTURES / "minimal-plugin")

    metadata = resolve_submission_metadata(
        FIXTURES / "minimal-plugin",
        result,
        github_repository="hashgraph-online/minimal-plugin",
    )

    assert metadata.plugin_name == "minimal-plugin"
    assert metadata.plugin_url == "https://github.com/hashgraph-online/minimal-plugin"
    assert metadata.author == "hashgraph-online"
    assert metadata.description == "A minimal plugin"


def test_submission_payload_and_issue_body_include_registry_data() -> None:
    result = scan_plugin(FIXTURES / "good-plugin")
    metadata = SubmissionMetadata(
        plugin_name="Example Good Plugin",
        plugin_url="https://github.com/hashgraph-online/example-good-plugin",
        description="Reusable security-first plugin fixture",
        author="Hashgraph Online",
        category="Community Plugins",
    )

    payload = build_submission_payload(
        metadata,
        result,
        source_repository="hashgraph-online/example-good-plugin",
        source_sha="abc123",
        workflow_url="https://github.com/hashgraph-online/example-good-plugin/actions/runs/1",
        scanner_version="1.2.0",
    )
    body = build_submission_issue_body(
        metadata,
        result,
        payload=payload,
        workflow_url="https://github.com/hashgraph-online/example-good-plugin/actions/runs/1",
    )

    assert payload["score"] == 100
    assert payload["grade"] == "A"
    assert payload["pluginUrl"] == metadata.plugin_url
    assert "## Registry Payload" in body
    assert "<!-- codex-plugin-scanner-plugin-url: https://github.com/hashgraph-online/example-good-plugin -->" in body
    assert '"pluginName": "Example Good Plugin"' in body
    assert metadata.plugin_url in body


def test_submission_issue_title_uses_plugin_prefix() -> None:
    metadata = SubmissionMetadata(
        plugin_name="Example Good Plugin",
        plugin_url="https://github.com/hashgraph-online/example-good-plugin",
        description="Reusable security-first plugin fixture",
        author="Hashgraph Online",
        category="Community Plugins",
    )

    assert build_submission_issue_title(metadata) == "[Plugin] Example Good Plugin"
    assert build_submission_issue_title(metadata, prefix="[Registry]") == "[Registry] Example Good Plugin"


def test_find_existing_submission_issue_uses_search_api_and_exact_marker(monkeypatch) -> None:
    captured: dict[str, str] = {}

    def fake_request_json(method: str, url: str, token: str, payload=None):
        captured["method"] = method
        captured["url"] = url
        captured["token"] = token
        return {
            "items": [
                {
                    "number": 42,
                    "html_url": "https://github.com/hashgraph-online/awesome-codex-plugins/issues/42",
                    "body": (
                        "## Plugin Submission\n"
                        "<!-- codex-plugin-scanner-plugin-url: "
                        "https://github.com/hashgraph-online/example-good-plugin -->\n"
                    ),
                },
                {
                    "number": 99,
                    "html_url": "https://github.com/hashgraph-online/awesome-codex-plugins/issues/99",
                    "body": (
                        "## Plugin Submission\n"
                        "<!-- codex-plugin-scanner-plugin-url: "
                        "https://github.com/hashgraph-online/example-good-plugin-extra -->\n"
                    ),
                },
            ]
        }

    monkeypatch.setattr("codex_plugin_scanner.submission._request_json", fake_request_json)

    issue = find_existing_submission_issue(
        "hashgraph-online/awesome-codex-plugins",
        "https://github.com/hashgraph-online/example-good-plugin",
        "token-123",
    )

    assert issue is not None
    assert issue.number == 42
    assert issue.created is False
    assert captured["method"] == "GET"
    assert "/search/issues?" in captured["url"]
    assert captured["token"] == "token-123"


def test_create_submission_issue_retries_without_labels_on_invalid_labels(monkeypatch) -> None:
    calls: list[dict[str, object | None]] = []

    def fake_request_json(method: str, url: str, token: str, payload=None):
        calls.append({"method": method, "url": url, "token": token, "payload": payload})
        if len(calls) == 1:
            raise HTTPError(
                url=url,
                code=422,
                msg="Unprocessable Entity",
                hdrs=None,
                fp=None,
            )
        return {
            "number": 17,
            "html_url": "https://github.com/hashgraph-online/awesome-codex-plugins/issues/17",
        }

    monkeypatch.setattr("codex_plugin_scanner.submission._request_json", fake_request_json)

    issue = create_submission_issue(
        "hashgraph-online/awesome-codex-plugins",
        "[Plugin] Example Good Plugin",
        "Body",
        "token-123",
        labels=("plugin-submission",),
    )

    assert issue.number == 17
    assert issue.created is True
    assert calls[0]["payload"] == {
        "title": "[Plugin] Example Good Plugin",
        "body": "Body",
        "labels": ["plugin-submission"],
    }
    assert calls[1]["payload"] == {
        "title": "[Plugin] Example Good Plugin",
        "body": "Body",
    }


def test_create_submission_issue_rejects_malformed_api_responses(monkeypatch) -> None:
    def fake_request_json(method: str, url: str, token: str, payload=None):
        return []

    monkeypatch.setattr("codex_plugin_scanner.submission._request_json", fake_request_json)

    try:
        create_submission_issue(
            "hashgraph-online/awesome-codex-plugins",
            "[Plugin] Example Good Plugin",
            "Body",
            "token-123",
        )
    except RuntimeError as error:
        assert "unexpected response" in str(error)
    else:
        raise AssertionError("Expected create_submission_issue to reject malformed responses.")


def test_create_submission_issue_rejects_missing_issue_fields(monkeypatch) -> None:
    def fake_request_json(method: str, url: str, token: str, payload=None):
        return {"number": "17"}

    monkeypatch.setattr("codex_plugin_scanner.submission._request_json", fake_request_json)

    try:
        create_submission_issue(
            "hashgraph-online/awesome-codex-plugins",
            "[Plugin] Example Good Plugin",
            "Body",
            "token-123",
        )
    except RuntimeError as error:
        assert "required fields" in str(error)
    else:
        raise AssertionError("Expected create_submission_issue to reject incomplete responses.")
