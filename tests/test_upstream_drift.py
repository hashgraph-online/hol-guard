"""Upstream drift reports name stale proofs and never treat a failed lookup as current."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts import upstream_drift
from scripts.upstream_drift import (
    NotFoundError,
    Pin,
    check,
    discovery_pins,
    discovery_projection,
    gauntlet_scenarios,
    pack_members,
    pins,
    refresh_discovery_pins,
    summary,
)

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


GMAIL_URL = "https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest"
GWS_DEFAULT_VERSIONS = {"gmail": "v1", "drive": "v3", "calendar": "v3"}


def gmail_document(**send_changes) -> dict:
    send = {
        "httpMethod": "POST",
        "path": "gmail/v1/users/{userId}/messages/send",
        "description": "Sends the specified message.",
        "parameters": {"userId": {"location": "path", "type": "string", "required": True}},
        "request": {"$ref": "Message"},
        "scopes": ["https://www.googleapis.com/auth/gmail.send"],
        "supportsMediaUpload": True,
    } | send_changes
    return {
        "name": "gmail",
        "version": "v1",
        "revision": "1",
        "schemas": {
            "Message": {"properties": {"raw": {"type": "string"}, "payload": {"$ref": "MessagePart"}}},
            "MessagePart": {
                "properties": {
                    "filename": {"type": "string", "description": "Name."},
                    "description": {"type": "string", "description": "Body."},
                }
            },
        },
        "resources": {"users": {"resources": {"messages": {"methods": {"send": send, "batchDelete": {}}}}}},
    }


def write_gmail_pins(repository: Path, document: dict, routes=("users.messages.send",)) -> Path:
    folder = repository / "contributions/upstream-schemas"
    folder.mkdir(parents=True, exist_ok=True)
    pins_file = {
        "schema": "hol.guard.upstream-discovery-pins.v1",
        "extension_id": "command.demo",
        "description": "demo",
        "apis": [
            {"name": "gmail", "version": "v1", "revision": "1", "projection": discovery_projection(document, routes)}
        ],
    }
    path = folder / "command.demo.json"
    path.write_text(json.dumps(pins_file), encoding="utf-8")
    return path


def rule_discovery_routes() -> set[tuple[str, str]]:
    source = json.loads((ROOT / "contributions/command-sources/command.google-workspace.gws.json").read_text())
    paths = []

    def walk(node):
        if isinstance(node, dict):
            config = node.get("config") or {}
            if node.get("op") == "executable.v1":
                paths.append(config["subcommands"])
            if node.get("op") == "executable-path-set.v1":
                paths.extend(config["paths"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(source)
    routes = set()
    for service, *route in paths:
        name, _, version = service.partition(":")
        if name in GWS_DEFAULT_VERSIONS and not route[0].startswith("+"):
            routes.add((f"{name}/{version or GWS_DEFAULT_VERSIONS[name]}", ".".join(route)))
    return routes


def test_repository_discovery_pins_cover_every_gws_rule_route():
    pinned = {
        (pin.project, key.split(" ", 1)[1])
        for pin in discovery_pins(ROOT)
        for key, _ in pin.expected
        if key.startswith("methods ")
    }
    assert pinned == rule_discovery_routes()
    assert {pin.extension_id for pin in discovery_pins(ROOT)} == {"command.google-workspace.gws"}
    assert any(pin.extension_id == "command.google-workspace.gws" for pin in pins(ROOT))


def test_repository_discovery_pin_file_round_trips(tmp_path):
    path = ROOT / "contributions/upstream-schemas/command.google-workspace.gws.json"
    pins_file = json.loads(path.read_text(encoding="utf-8"))
    assert upstream_drift._pins_text(pins_file) == path.read_text(encoding="utf-8")
    assert len(path.read_text(encoding="utf-8").splitlines()) <= 500


def nested_change() -> dict:
    document = gmail_document()
    document["schemas"]["MessagePart"]["properties"]["filename"]["type"] = "integer"
    return document


def description_property_change() -> dict:
    document = gmail_document()
    document["schemas"]["MessagePart"]["properties"]["description"]["type"] = "integer"
    return document


@pytest.mark.parametrize(
    ("document", "changed"),
    [
        (gmail_document(), []),
        (gmail_document(description="Sends mail."), []),
        (gmail_document(scopes=["https://mail.google.com/"]), ["methods users.messages.send"]),
        (gmail_document(path="gmail/v2/send"), ["methods users.messages.send"]),
        (nested_change(), ["schemas MessagePart"]),
        (description_property_change(), ["schemas MessagePart"]),
    ],
)
def test_discovery_pin_reports_changed_method_shape(tmp_path, document, changed):
    write_gmail_pins(tmp_path, gmail_document())
    [pin] = discovery_pins(tmp_path)
    [finding] = check([pin], fake_fetch({GMAIL_URL: document}), {"command.demo": ["business.demo"]}, {})
    assert finding.status == ("drifted" if changed else "current")
    if changed:
        assert finding.detail == "changed: " + ", ".join(changed)
        assert finding.affected_packs == ["business.demo"]


def test_discovery_route_lookup_ignores_case(tmp_path):
    write_gmail_pins(tmp_path, gmail_document(), routes=("users.messages.batchdelete",))
    [pin] = discovery_pins(tmp_path)
    assert dict(pin.expected)["methods users.messages.batchdelete"] != upstream_drift._digest(None)


def test_discovery_pin_reports_new_sibling_and_removed_method(tmp_path):
    write_gmail_pins(tmp_path, gmail_document())
    [pin] = discovery_pins(tmp_path)
    added = gmail_document()
    added["resources"]["users"]["resources"]["messages"]["methods"]["sendNow"] = {}
    [finding] = check([pin], fake_fetch({GMAIL_URL: added}), {}, {})
    assert (finding.status, finding.detail) == ("drifted", "changed: resources users.messages")
    removed = gmail_document()
    del removed["resources"]["users"]["resources"]["messages"]["methods"]["send"]
    [finding] = check([pin], fake_fetch({GMAIL_URL: removed}), {}, {})
    assert finding.status == "drifted"
    assert "methods users.messages.send" in finding.detail


def test_discovery_fetch_failure_is_unknown(tmp_path):
    write_gmail_pins(tmp_path, gmail_document())
    [pin] = discovery_pins(tmp_path)
    [finding] = check([pin], fake_fetch({}), {}, {})
    assert finding.status == "unknown"


def test_discovery_summary_names_the_refresh_step(tmp_path):
    write_gmail_pins(tmp_path, gmail_document())
    [pin] = discovery_pins(tmp_path)
    [finding] = check([pin], fake_fetch({GMAIL_URL: nested_change()}), {}, {})
    text = summary([finding])
    assert "--refresh-discovery-pins" in text
    assert "update the command source pin" not in text
    assert "| `1` | `1` |" in text


def test_refresh_discovery_pins_rewrites_reviewed_routes_only(tmp_path):
    write_gmail_pins(tmp_path, gmail_document())
    current = gmail_document(scopes=["https://mail.google.com/"])
    current["revision"] = "2"
    [path] = refresh_discovery_pins(tmp_path, fake_fetch({GMAIL_URL: current}))
    [pin] = discovery_pins(tmp_path)
    [finding] = check([pin], fake_fetch({GMAIL_URL: current}), {}, {})
    assert finding.status == "current"
    api = json.loads(path.read_text())["apis"][0]
    assert api["revision"] == "2"
    assert list(api["projection"]["methods"]) == ["users.messages.send"]
    assert sorted(api["projection"]["schemas"]) == ["Message", "MessagePart"]


def test_refresh_refuses_to_pin_a_removed_method(tmp_path):
    path = write_gmail_pins(tmp_path, gmail_document())
    before = path.read_text()
    removed = gmail_document()
    del removed["resources"]["users"]["resources"]["messages"]["methods"]["send"]
    with pytest.raises(ValueError, match=r"no longer has users\.messages\.send"):
        refresh_discovery_pins(tmp_path, fake_fetch({GMAIL_URL: removed}))
    assert path.read_text() == before


def test_scheduled_workflow_only_reads():
    workflow = yaml.safe_load((ROOT / ".github/workflows/upstream-drift.yml").read_text())
    assert workflow["permissions"] == {}
    [job] = workflow["jobs"].values()
    assert job["permissions"] == {"contents": "read"}
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    # Run as a module: as a script, scripts/ci would shadow the top-level ci package.
    assert any(step.get("run", "").startswith("python -m scripts.upstream_drift ") for step in job["steps"])
