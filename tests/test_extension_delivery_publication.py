"""Publication cannot upload unbound files or regress the selected source."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def publisher(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("extension_delivery_github")


@pytest.fixture
def selector(publisher):
    return importlib.import_module("extension_delivery_selector")


def selection(source="2" * 40, publication="12.1"):
    return {
        "schema": "guard.extension-distribution-selector.v2",
        "source_sha": source,
        "publication_id": publication,
        "root_sha256": "3" * 64,
    }


@pytest.mark.parametrize("state,expected", [("ahead", True), ("behind", False), ("identical", True)])
def test_selector_only_fast_forwards(selector, monkeypatch, state, expected):
    old, new = "1" * 40, "2" * 40
    calls = []

    def github(*args):
        calls.append(args)
        if "/compare/" in args[1]:
            return json.dumps({"status": state})
        if "PATCH" in args:
            assert args[-2:] == ("-F", "force=false")
            return json.dumps({"object": {"type": "commit", "sha": new}})
        return json.dumps({"object": {"type": "commit", "sha": new if state == "identical" else old}})

    monkeypatch.setattr(selector, "github", github)
    candidate = selection(new)
    monkeypatch.setattr(
        selector, "current", lambda: (old, candidate if state == "identical" else selection(old, "11.1"))
    )
    monkeypatch.setattr(selector, "pointer_commit", lambda parent, value: new)
    assert selector.select(candidate) is expected
    assert sum("PATCH" in call for call in calls) == (1 if state == "ahead" else 0)
    assert not any("DELETE" in call or "force=true" in call for call in calls)


def test_selector_race_retains_a_newer_publication(selector, monkeypatch):
    old, candidate, newer = "1" * 40, "2" * 40, "3" * 40
    failed = False

    def github(*args):
        nonlocal failed
        if "PATCH" in args:
            assert "force=false" in args
            failed = True
            raise RuntimeError("Update is not a fast forward (HTTP 422)")
        if "/compare/" in args[1]:
            return json.dumps({"status": "ahead"})
        return json.dumps({"object": {"type": "commit", "sha": newer if failed else old}})

    monkeypatch.setattr(selector, "github", github)
    monkeypatch.setattr(
        selector, "current", lambda: (newer, selection(newer, "13.1")) if failed else (old, selection(old, "11.1"))
    )
    monkeypatch.setattr(selector, "pointer_commit", lambda parent, value: candidate)
    assert selector.select(selection(candidate)) is False


def test_same_source_renewal_and_stale_attempt_ordering(selector, monkeypatch):
    old = selection(publication="12.1")
    monkeypatch.setattr(
        selector, "github", lambda *args: pytest.fail("same-source renewal does not compare code history")
    )
    assert selector.can_advance(old, selection(publication="12.2")) is True
    assert selector.can_advance(old, selection(publication="11.9")) is False
    assert selector.can_advance(old, old) is False
    with pytest.raises(ValueError, match="reused"):
        selector.can_advance(old, {**old, "root_sha256": "4" * 64})


def test_selector_does_not_hide_unrelated_validation_errors(selector, monkeypatch):
    monkeypatch.setattr(selector, "current", lambda: ("1" * 40, selection("1" * 40, "11.1")))
    commits = []
    monkeypatch.setattr(selector, "pointer_commit", lambda *args: commits.append(args) or "2" * 40)

    def github(*args):
        if "PATCH" in args:
            raise RuntimeError("Invalid sha (HTTP 422)")
        return json.dumps({"status": "ahead"})

    monkeypatch.setattr(selector, "github", github)
    with pytest.raises(RuntimeError, match="Invalid sha"):
        selector.select(selection())
    assert len(commits) == 1


def test_draft_lookup_does_not_scan_release_history(publisher, monkeypatch):
    calls = []

    def github(*args):
        calls.append(args)
        if args[1] == "graphql":
            return json.dumps({"data": {"repository": {"release": {"databaseId": 1, "tagName": "tag"}}}})
        return json.dumps({"id": 1, "tag_name": "tag", "draft": True})

    monkeypatch.setattr(publisher, "github", github)
    assert publisher.release("tag")["draft"] is True
    assert len(calls) == 2 and not any("--paginate" in call for call in calls)


def test_asset_plan_rejects_unbound_duplicate_changed_and_missing_files(publisher, monkeypatch, tmp_path):
    from extension_delivery_assets import AssetPlan
    from extension_delivery_inventory import read_plan

    source, publication_id = "1" * 40, "12.1"
    plan = AssetPlan(tmp_path / "assets", source, publication_id=publication_id)
    data = b'{"reviewed":"public"}'
    target = plan.asset(data, "object")
    row = plan.pending[0]
    key = (target["tag"], target["asset"])
    import hashlib

    expected = {
        key: {
            "location": row["location"],
            "kind": "container",
            "members": {
                target["member"]: {"sha256": hashlib.sha256(data).hexdigest(), "length": len(data)},
            },
        }
    }
    path = tmp_path / "asset-plan.jsonl"
    path.write_text(json.dumps(row) + "\n")
    assert read_plan(tmp_path, expected, source, publication_id) == [row]
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="duplicate"):
        read_plan(tmp_path, expected, source, publication_id)
    path.write_text("")
    with pytest.raises(ValueError, match="incomplete"):
        read_plan(tmp_path, expected, source, publication_id)
    path.write_text(json.dumps({**row, "location": {"tag": "../private", "asset": "unbound"}}) + "\n")
    with pytest.raises(ValueError, match="unbound"):
        read_plan(tmp_path, expected, source, publication_id)
    path.write_text(json.dumps(row) + "\n")
    (tmp_path / "assets" / target["tag"] / target["asset"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="bytes differ"):
        read_plan(tmp_path, expected, source, publication_id)


def test_a_full_data_release_still_fits_the_distribution_anchor(publisher, monkeypatch):
    """Every data release also carries the signed root, so a full batch plus
    that pair must stay inside the publisher's release inventory bound."""
    from extension_delivery_assets import ASSETS_PER_RELEASE

    from codex_plugin_scanner.guard.catalog_delivery.transport import PROVENANCE_ASSET, ROOT_ASSET

    def refuse(tag):
        raise RuntimeError("inventory bound accepted")

    monkeypatch.setattr(publisher, "release", refuse)
    inventory = {f"objects-{index:06}.zip": {"sha256": "0" * 64, "length": 1} for index in range(ASSETS_PER_RELEASE)}
    inventory[ROOT_ASSET] = {"sha256": "0" * 64, "length": 1}
    inventory[PROVENANCE_ASSET] = {"sha256": "0" * 64, "length": 1}
    with pytest.raises(RuntimeError, match="inventory bound accepted"):
        publisher.publish_assets("extension-data-" + "1" * 40 + "-12.1-000000", "1" * 40, inventory, inventory)

    inventory["objects-999999.zip"] = {"sha256": "0" * 64, "length": 1}
    with pytest.raises(ValueError, match="asset inventory invalid"):
        publisher.publish_assets("extension-data-" + "1" * 40 + "-12.1-000000", "1" * 40, inventory, inventory)


def test_retries_use_separate_data_releases_without_overwriting_prior_attempt(publisher, tmp_path):
    from extension_delivery_assets import AssetPlan

    first = AssetPlan(tmp_path / "first", "1" * 40, publication_id="12.1")
    second = AssetPlan(tmp_path / "second", "1" * 40, publication_id="12.2")
    one, two = first.asset(b"public", "object"), second.asset(b"public", "object")
    assert one["tag"] != two["tag"] and one["asset"] == two["asset"]


def test_publication_cli_reports_a_root_that_was_not_selected(publisher, monkeypatch, capsys, tmp_path):
    import publish_extension_delivery as command

    result = {"selected": False, "source_sha": "1" * 40, "publication_id": "12.1", "root_sha256": "2" * 64}
    monkeypatch.setattr(command, "publish", lambda *args: result)
    monkeypatch.setattr(
        "sys.argv", ["publisher", "--directory", str(tmp_path), "--source-sha", "1" * 40, "--publication-id", "12.1"]
    )
    command.main()
    assert json.loads(capsys.readouterr().out) == result
