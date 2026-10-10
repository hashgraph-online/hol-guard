from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from scripts import reconcile_extension_claim_notices as notices

SHA = "a" * 40


def fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, changes: dict | None = None, trust_class: str = "external"
) -> Path:
    plan = {
        "schemaVersion": "guard.extension-claim-invitations.v1", "sourceSha": SHA,
        "entries": [{"extensionId": "command.example", "githubId": "100", "pullRequest": 7}],
    }
    if changes:
        plan.update(changes)
    with zipfile.ZipFile(tmp_path / notices.ARCHIVE, "w") as archive:
        archive.writestr(notices.PLAN, json.dumps(plan))
        archive.writestr("docs/guard/extensions/catalog.v1.json", json.dumps({"entries": [{
            "id": "command.example", "claimPolicy": "provenance", "trustClass": trust_class,
            "maintainerGithubIds": ["100"],
        }]}))
    verified = []
    monkeypatch.setattr(notices, "verify_bundle", lambda directory, sha: verified.append((directory, sha)))
    if not changes and trust_class == "external":
        assert notices.planned_pull_requests(tmp_path, SHA) == [7]
        assert verified == [(tmp_path, SHA)]
    return tmp_path


def test_verified_source_bound_plan_selects_only_introducing_pr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = fixture(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(notices, "process", lambda client, number, url, **kwargs: calls.append((number, kwargs)))
    assert notices.reconcile(object(), directory, SHA, dry_run=True) == 0
    assert calls == [(7, {"dry_run": True})]


@pytest.mark.parametrize("changes", [
    {"sourceSha": "b" * 40},
    {"entries": [{"extensionId": "command.example", "githubId": "200", "pullRequest": 7}]},
    {"entries": [{"extensionId": "command.other", "githubId": "100", "pullRequest": 7}]},
    {"entries": [{"extensionId": "command.example", "githubId": "100", "pullRequest": True}]},
    {"entries": [{"extensionId": "command.example", "githubId": "100", "pullRequest": 7}] * 2},
])
def test_plan_rejects_identity_mismatch_before_any_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changes: dict
) -> None:
    directory = fixture(tmp_path, monkeypatch, changes=changes)
    calls = []
    monkeypatch.setattr(notices, "process", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        notices.reconcile(object(), directory, SHA)
    assert not calls


def test_one_failed_notice_is_visible_and_does_not_stop_other_prs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(notices, "planned_pull_requests", lambda *args: [7, 8])
    calls = []
    def send(client, number, url, **kwargs):
        calls.append(number)
        if number == 7:
            raise OSError("Synthetic comment delivery outage")
    monkeypatch.setattr(notices, "process", send)
    assert notices.reconcile(object(), directory, SHA) == 1
    assert calls == [7, 8]


def test_plan_rejects_project_owned_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = fixture(tmp_path, monkeypatch, trust_class="first-party")
    with pytest.raises(ValueError, match="catalog authority"):
        notices.planned_pull_requests(directory, SHA)


def test_plan_rejects_more_jobs_than_actions_supports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notices.sys, "argv", ["reconcile", "--directory", ".", "--source-sha", SHA, "--plan"])
    monkeypatch.setattr(notices, "planned_pull_requests", lambda *args: list(range(1, 258)))
    monkeypatch.setattr(notices, "has_trusted_notice", lambda comments: False)
    class Client:
        def comments(self, number):
            return []
    monkeypatch.setattr(notices, "GitHubApi", lambda *args: Client())
    with pytest.raises(ValueError, match="matrix limit"):
        notices.main()
