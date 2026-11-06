"""A reviewed disposition must fail closed if its identity or source evidence drifts."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from scripts.ci import apply_sonar_hook_bridge_review as review


@pytest.fixture
def review_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict, dict, Mock]:
    monkeypatch.chdir(tmp_path)
    source = "value = 1\n"
    manifest = {
        "project": review.PROJECT,
        "branch": review.BRANCH,
        "issue": review.ISSUE,
        "rule": review.RULE,
        "component": review.COMPONENT,
        "reviewed_commit": "a" * 40,
        "reason": "fixture reason",
        "source_sha256": dict.fromkeys(review.REVIEWED_SOURCES, review.fingerprint(source)),
    }
    for name in review.REVIEWED_SOURCES:
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    review.MANIFEST.parent.mkdir(parents=True)
    review.MANIFEST.write_text(json.dumps(manifest))
    issue = {
        "key": review.ISSUE,
        "project": review.PROJECT,
        "rule": review.RULE,
        "component": review.PROJECT + ":" + review.COMPONENT,
        "hash": "fixture",
        "lastChangeAnalysisUuid": "analysis-1",
        "issueStatus": "OPEN",
    }

    def sonar(path: str, **parameters: object):
        if path == "/api/issues/search":
            return {"total": 1, "issues": [dict(issue)]}
        if path == "/api/project_branches/list":
            return {
                "branches": [
                    {"name": "release", "isMain": False, "type": "LONG"},
                    {
                        "name": review.BRANCH,
                        "isMain": True,
                        "type": "LONG",
                        "analysisDate": "2026-10-19T18:03:49+0000",
                        "commit": {"sha": "b" * 40},
                    },
                ]
            }
        if path == "/api/issues/do_transition":
            assert parameters == {"post": True, "issue": review.ISSUE, "transition": "falsepositive"}
            issue["issueStatus"] = "FALSE_POSITIVE"
        return {}

    api = Mock(side_effect=sonar)
    monkeypatch.setattr(review, "sonar", api)
    monkeypatch.setattr(review, "analyzed_source", Mock(return_value=source))
    return manifest, issue, api


def test_dry_run_verifies_all_sources_without_mutation(review_case) -> None:
    _manifest, _issue, api = review_case
    with patch.object(review, "analyzed_source", return_value="value = 1\n") as sources:
        review.main()
    assert not any(call.kwargs.get("post") for call in api.call_args_list)
    assert sources.call_count == len(review.REVIEWED_SOURCES)
    assert {call.args for call in sources.call_args_list} == {("b" * 40, name) for name in review.REVIEWED_SOURCES}
    assert (review.OUTPUT / "review.json").is_file()


def test_apply_changes_only_the_reviewed_issue_and_verifies_result(review_case) -> None:
    _manifest, _issue, api = review_case
    review.main(apply=True)
    writes = [call for call in api.call_args_list if call.kwargs.get("post")]
    assert [call.args[0] for call in writes] == ["/api/issues/add_comment", "/api/issues/do_transition"]
    assert all(call.kwargs["issue"] == review.ISSUE for call in writes)
    after = json.loads((review.OUTPUT / "after.json").read_text())
    assert after["issueStatus"] == "FALSE_POSITIVE"


def test_already_reviewed_issue_is_not_changed_again(review_case) -> None:
    _manifest, issue, api = review_case
    issue["issueStatus"] = "FALSE_POSITIVE"
    review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


@pytest.mark.parametrize("field", ["key", "project", "rule", "component"])
def test_wrong_issue_identity_prevents_every_write(review_case, field: str) -> None:
    _manifest, issue, api = review_case
    issue[field] = "different"
    with pytest.raises(ValueError, match="identity changed"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


def test_a_pull_request_finding_is_never_transitioned(review_case) -> None:
    _manifest, issue, api = review_case
    issue["pullRequest"] = "5276"
    with pytest.raises(ValueError, match="identity changed"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


@pytest.mark.parametrize("field,value", [("isMain", False), ("type", "SHORT"), ("analysisDate", "")])
def test_non_main_analysis_prevents_every_write(review_case, field: str, value: object) -> None:
    _manifest, _issue, api = review_case
    original = api.side_effect

    def sonar(path: str, **parameters):
        payload = original(path, **parameters)
        if path == "/api/project_branches/list":
            payload["branches"][1][field] = value
        return payload

    api.side_effect = sonar
    with pytest.raises(ValueError, match="analysis identity"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


@pytest.mark.parametrize("location", ["local", "analyzed"])
def test_changed_source_prevents_every_write(review_case, location: str) -> None:
    manifest, _issue, api = review_case
    if location == "local":
        Path(next(iter(review.REVIEWED_SOURCES))).write_text("value = 2\n")
    else:
        manifest["source_sha256"] = dict.fromkeys(review.REVIEWED_SOURCES, review.fingerprint("value = 2\n"))
        review.MANIFEST.write_text(json.dumps(manifest))
        for path in review.REVIEWED_SOURCES:
            Path(path).write_text("value = 2\n")
    with pytest.raises(ValueError, match="source changed"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


def test_empty_source_manifest_is_not_accepted(review_case) -> None:
    manifest, _issue, api = review_case
    manifest["source_sha256"] = {}
    review.MANIFEST.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="source set changed"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


@pytest.mark.parametrize("field", ["project", "branch", "issue", "rule", "component"])
def test_manifest_identity_drift_prevents_every_write(review_case, field: str) -> None:
    manifest, _issue, api = review_case
    manifest[field] = "different"
    review.MANIFEST.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="manifest identity changed"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


def test_concurrent_analysis_change_prevents_every_write(review_case, monkeypatch: pytest.MonkeyPatch) -> None:
    _manifest, issue, api = review_case
    reader = Mock(side_effect=[dict(issue), {**issue, "lastChangeAnalysisUuid": "analysis-2"}])
    monkeypatch.setattr(review, "read_issue", reader)
    with pytest.raises(ValueError, match="finding changed"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


@pytest.mark.parametrize("sha", ["", "main", "a" * 39, "a" * 41, "g" * 40, "../untrusted"])
def test_invalid_analyzed_revision_prevents_writes(review_case, sha: str) -> None:
    _manifest, _issue, api = review_case
    original = api.side_effect

    def sonar(path: str, **parameters):
        payload = original(path, **parameters)
        if path == "/api/project_branches/list":
            payload["branches"][1]["commit"]["sha"] = sha
        return payload

    api.side_effect = sonar
    with pytest.raises(ValueError, match="analysis identity"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


def test_analyzed_commit_change_prevents_writes(review_case, monkeypatch: pytest.MonkeyPatch) -> None:
    _manifest, _issue, api = review_case
    reader = Mock(side_effect=[{"sha": "b" * 40, "date": "first"}, {"sha": "c" * 40, "date": "second"}])
    monkeypatch.setattr(review, "read_analysis", reader)
    with pytest.raises(ValueError, match="analyzed revision changed"):
        review.main(apply=True)
    assert not any(call.kwargs.get("post") for call in api.call_args_list)


def test_unapproved_endpoints_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    opener = Mock()
    monkeypatch.setattr(review, "build_opener", opener)
    with pytest.raises(ValueError, match="unapproved Sonar endpoint"):
        review.sonar("/api/issues/bulk_change", post=True, issue=review.ISSUE)
    opener.assert_not_called()


def test_source_fetch_never_sends_sonar_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SONAR_TOKEN", "fixture-sonar-token")
    response = Mock()
    response.read.return_value = b"value = 1\n"
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)
    opener = Mock()
    opener.open.return_value = response
    factory = Mock(return_value=opener)
    monkeypatch.setattr(review, "build_opener", factory)
    path = review.COMPONENT
    assert review.analyzed_source("b" * 40, path) == "value = 1\n"
    request = opener.open.call_args.args[0]
    assert request.full_url == "https://raw.githubusercontent.com/hashgraph-online/hol-guard/" + "b" * 40 + "/" + path
    assert request.header_items() == []
    handler = factory.call_args.args[0]
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://attacker.invalid") is None


@pytest.mark.parametrize(
    "sha,path", [("main", "src/codex_plugin_scanner/guard/native_runtime_durable.py"), ("a" * 40, "../x")]
)
def test_source_fetch_rejects_unapproved_inputs(monkeypatch: pytest.MonkeyPatch, sha: str, path: str) -> None:
    opener = Mock()
    monkeypatch.setattr(review, "build_opener", opener)
    with pytest.raises(ValueError, match="unapproved analyzed source"):
        review.analyzed_source(sha, path)
    opener.assert_not_called()


def test_the_committed_manifest_matches_the_reviewed_sources() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / review.MANIFEST).read_text(encoding="utf-8"))
    assert (manifest["project"], manifest["branch"], manifest["issue"]) == (review.PROJECT, review.BRANCH, review.ISSUE)
    assert (manifest["rule"], manifest["component"]) == (review.RULE, review.COMPONENT)
    assert set(manifest["source_sha256"]) == set(review.REVIEWED_SOURCES)
    for path, expected in manifest["source_sha256"].items():
        assert review.fingerprint((root / path).read_text(encoding="utf-8")) == expected


def test_the_scanner_scope_guardrail_is_untouched() -> None:
    root = Path(__file__).resolve().parents[1]
    properties = (root / "sonar-project.properties").read_text(encoding="utf-8")
    assert "sonar.issue.ignore.multicriteria" not in properties
    assert "sonar.coverage.exclusions" not in properties
