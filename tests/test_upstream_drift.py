"""Upstream drift reports name stale proofs and never treat a failed lookup as current."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts import upstream_drift
from scripts.upstream_drift import NotFoundError, Pin, check, gauntlet_scenarios, pack_members, pins, summary

ROOT = Path(__file__).resolve().parents[1]
GWS_SHA = "705fb0ecac6f4249679958f6325b809b63fdde17"


def fake_fetch(responses: dict[str, object]):
    def fetch(url: str) -> object:
        value = responses.get(url)
        if value is None:
            raise NotFoundError(url)
        if isinstance(value, Exception):
            raise value
        return value

    return fetch


def test_repository_pins_cover_business_sources_with_exact_upstreams():
    found = {(pin.extension_id, pin.kind): pin for pin in pins(ROOT)}
    assert found[("command.google-workspace.gws", "github")].pinned == GWS_SHA
    assert found[("command.google-workspace.gws", "github")].project == "googleworkspace/cli"
    assert found[("command.salesforce.sf", "npm")].project == "@salesforce/plugin-data"
    assert found[("command.salesforce.sf", "npm")].pinned == "5.1.10"
    assert all(len(pin.pinned) == 40 for pin in found.values() if pin.kind == "github")


def test_repository_proof_map_links_packs_and_gauntlet_scenarios():
    assert "business.google-workspace" in pack_members(ROOT)["command.google-workspace.gws"]
    scenarios = gauntlet_scenarios(ROOT)
    assert scenarios["command.google-workspace.gws"] == ["explicit-disabled-gws-send-permission"]
    assert scenarios["command.salesforce.sf"] == ["explicit-disabled-salesforce-delete-permission"]


def test_github_pin_compares_against_latest_release_then_default_branch():
    pin = Pin("command.demo", "github", "acme/cli", "a" * 40, "source.json")
    api = "https://api.github.com/repos/acme/cli"
    released = fake_fetch(
        {
            f"{api}/releases/latest": {"tag_name": "v2.0.0"},
            f"{api}/compare/{'a' * 40}...v2.0.0": {"status": "ahead", "ahead_by": 7},
        }
    )
    [finding] = check([pin], released, {"command.demo": ["business.demo"]}, {"command.demo": ["demo-denial"]})
    assert (finding.status, finding.current) == ("drifted", "v2.0.0")
    assert finding.affected_packs == ["business.demo"]
    assert finding.affected_scenarios == ["demo-denial"]

    unreleased = fake_fetch(
        {api: {"default_branch": "main"}, f"{api}/compare/{'a' * 40}...main": {"status": "identical"}}
    )
    [finding] = check([pin], unreleased, {"command.demo": ["business.demo"]}, {})
    assert (finding.status, finding.current, finding.affected_packs) == ("current", "main", [])


def test_malformed_release_is_unknown_not_default_branch():
    pin = Pin("command.demo", "github", "acme/cli", "a" * 40, "source.json")
    api = "https://api.github.com/repos/acme/cli"
    fetch = fake_fetch(
        {
            f"{api}/releases/latest": {"name": "no tag"},
            api: {"default_branch": "main"},
            f"{api}/compare/{'a' * 40}...main": {"status": "identical"},
        }
    )
    [finding] = check([pin], fetch, {}, {})
    assert finding.status == "unknown"
    assert "tag_name" in finding.detail


def test_http_failures_name_endpoint_and_status(monkeypatch):
    url = "https://api.github.com/repos/acme/cli"

    def denied(request, timeout):
        raise upstream_drift.urllib.error.HTTPError(url, 403, "rate limit exceeded", {}, None)

    monkeypatch.setattr(upstream_drift.urllib.request, "urlopen", denied)
    with pytest.raises(RuntimeError, match=r"GET https://api\.github\.com/repos/acme/cli returned HTTP 403"):
        upstream_drift.http_json(url)


def test_npm_pin_compares_against_latest_dist_tag():
    pin = Pin("command.demo", "npm", "@acme/plugin", "1.0.0", "source.json")
    url = "https://registry.npmjs.org/@acme%2Fplugin"
    [finding] = check([pin], fake_fetch({url: {"dist-tags": {"latest": "1.0.0"}}}), {}, {})
    assert finding.status == "current"
    [finding] = check([pin], fake_fetch({url: {"dist-tags": {"latest": "1.1.0"}}}), {}, {})
    assert (finding.status, finding.current) == ("drifted", "1.1.0")


@pytest.mark.parametrize("failure", [OSError("offline"), KeyError("dist-tags")])
def test_upstream_failures_are_unknown_and_still_name_stale_proofs(failure: Exception):
    pin = Pin("command.demo", "npm", "demo", "1.0.0", "source.json")
    [finding] = check([pin], fake_fetch({"https://registry.npmjs.org/demo": failure}), {"command.demo": ["p"]}, {})
    assert finding.status == "unknown"
    assert type(failure).__name__ in finding.detail
    assert finding.affected_packs == ["p"]
    assert "drift" in summary([finding]).lower()


def test_main_exits_nonzero_on_drift_and_writes_report(tmp_path, monkeypatch):
    monkeypatch.setattr(upstream_drift, "http_json", fake_fetch({}))
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    report = tmp_path / "report.json"
    assert upstream_drift.main(["--json", str(report)]) == 1
    data = json.loads(report.read_text())
    assert data["schema"] == "hol.guard.upstream-drift.v1"
    assert {item["status"] for item in data["findings"]} == {"unknown"}
    assert "Stale proofs" in summary_file.read_text()


def test_scheduled_workflow_only_reads():
    workflow = yaml.safe_load((ROOT / ".github/workflows/upstream-drift.yml").read_text())
    assert workflow["permissions"] == {}
    [job] = workflow["jobs"].values()
    assert job["permissions"] == {"contents": "read"}
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
