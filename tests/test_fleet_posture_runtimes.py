"""The ``runtimes`` section of fleet posture: projection, privacy, caching and size priority."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime import fleet_posture as fp
from codex_plugin_scanner.guard.runtime import fleet_posture_runtimes as fpr
from codex_plugin_scanner.guard.runtime.fleet_posture_common import keyed_digest
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_fleet_posture_builder import NOW, FakeAdapter, _build, _config, _row, _set_inventory, _validate

KEY = b"k" * 32
EXE = "e" * 64
PATH = "/Users/ada/.nvm/versions/node/v22.11.0/bin/node"


def _posture(rows: list[dict[str, object]], **overrides: object) -> dict[str, object]:
    posture: dict[str, object] = {
        "status": "ok",
        "error": None,
        "coverage": {
            "mode": "observed_only",
            "advisories_available": False,
            "reason": "runtime_advisories_unavailable",
        },
        "candidate_limit_reached": False,
        "unresolved_launches": [{"harness": "codex", "server": "github", "command": "ghx", "lookup": "path"}],
        "runtimes": rows,
    }
    posture.update(overrides)
    return posture


def _runtime(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "location_id": "loc-1",
        "path": PATH,
        "location_state": "present",
        "reason": None,
        "launched_by": [
            {"harness": "codex", "server": "acme-internal-db", "role": "command"},
            {"harness": "claude-code", "server": "acme-internal-db", "role": "command"},
            {"harness": "codex", "server": "other", "role": "command"},
            {"harness": "not-a-harness", "server": "x", "role": "command"},
        ],
        "artifact_id": "art-1",
        "family": "node",
        "version": "22.11.0",
        "identity_assurance": "self_reported",
        "executable_sha256": EXE,
        "os": "macos",
        "arch": "arm64",
        "advisory_matches": [{"advisory_id": "GHSA-aaaa", "status": "affected", "reason": "version"}],
    }
    row.update(overrides)
    return row


@pytest.fixture
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


@pytest.fixture
def context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")


def test_projection_names_no_path_server_or_command() -> None:
    section = fpr.project_runtime_posture(_posture([_runtime()]), hash_key=KEY)

    assert section == {
        "status": "ok",
        "reason": None,
        "coverage": "observed_only",
        "scopeComplete": False,
        "advisoriesAvailable": False,
        "candidateLimitReached": False,
        "unresolvedLaunches": 1,
        "items": [
            {
                "family": "node",
                "version": "22.11.0",
                "identityAssurance": "self_reported",
                "executableHash": f"sha256:{EXE}",
                "os": "macos",
                "arch": "arm64",
                "locationState": "present",
                "reason": None,
                "locationHash": keyed_digest(KEY, PATH),
                "harnesses": ["claude-code", "codex"],
                "advisoryIds": ["GHSA-aaaa"],
            }
        ],
    }
    text = json.dumps(section)
    for private in ("/Users", "ada", "acme-internal-db", "ghx", "github", "loc-1", "art-1"):
        assert private not in text


def test_unexpected_values_fall_back_to_unknown() -> None:
    row = _runtime(
        path=None,
        family="Node JS",
        os=None,
        arch="x86-64",
        identity_assurance="vendor_signed",
        location_state="gone",
        reason="Not A Code",
        executable_sha256="E" * 64,
        version="9" * 80,
        advisory_matches=["GHSA-b", "GHSA-b", {"advisory_id": ""}, 7],
    )

    [item] = fpr.project_runtime_posture(_posture([row]), hash_key=KEY)["items"]  # type: ignore[misc]

    assert item["family"] == item["os"] == item["arch"] == "unknown"
    assert item["identityAssurance"] == item["locationState"] == item["reason"] == "unknown"
    assert item["executableHash"] is None and item["locationHash"] is None
    assert item["version"] == "9" * 64
    assert item["advisoryIds"] == ["GHSA-b"]


def test_more_than_the_limit_is_reported_partial() -> None:
    section = fpr.project_runtime_posture(_posture([_runtime()] * (fpr.MAX_RUNTIMES + 1)), hash_key=KEY)

    assert len(section["items"]) == fpr.MAX_RUNTIMES  # type: ignore[arg-type]
    assert (section["status"], section["reason"], section["candidateLimitReached"]) == (
        "partial",
        "runtime_candidate_limit_reached",
        True,
    )


def test_unavailable_native_probe_is_reported_not_hidden() -> None:
    posture = _posture([], status="unavailable", error="native_runtime_unavailable", unresolved_launches=[])

    section = fpr.project_runtime_posture(posture, hash_key=KEY)

    assert (section["status"], section["reason"], section["items"]) == ("unavailable", "native_runtime_unavailable", [])


def test_posture_carries_runtimes_and_matches_the_contract(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("skill-a")])
    monkeypatch.setattr(fpr, "_observe", lambda *_: _posture([_runtime()]))

    payload = _build(store, context, [FakeAdapter("claude-code")]).payload

    _validate(payload)
    runtimes = payload["runtimes"]
    assert runtimes["items"][0]["harnesses"] == ["claude-code", "codex"]  # type: ignore[index]


def test_minimal_reporting_leaves_runtimes_out(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    monkeypatch.setattr(fpr, "_observe", pytest.fail)

    payload = _build(store, context, [FakeAdapter("claude-code")], reporting_enabled=False).payload

    assert "runtimes" not in payload


def test_runtimes_are_observed_once_per_ttl(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    calls: list[object] = []

    def observe(_context: object, now: object, _advisory: object) -> dict[str, object]:
        calls.append(now)
        return _posture([_runtime()])

    monkeypatch.setattr(fpr, "_observe", observe)
    adapters = [FakeAdapter("claude-code")]

    def build_at(minutes: int) -> dict[str, object]:
        settings = fp.FleetPostureSettings(
            context=context,
            guard_config=_config(),
            now=NOW + timedelta(minutes=minutes),  # type: ignore[arg-type]
        )
        return fp.build_fleet_posture_state(store, adapters, settings).payload

    first = build_at(0)
    second = build_at(59)
    assert len(calls) == 1
    assert second["runtimes"] == first["runtimes"]

    build_at(60)
    assert len(calls) == 2


def test_cached_runtimes_are_bound_to_the_workspace_and_key(
    store: GuardStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[object] = []

    def observe(context: HarnessContext, _now: object, _advisory: object) -> dict[str, object]:
        observed.append(context.workspace_dir)
        return _posture([_runtime(path=f"{context.workspace_dir}/bin/node")])

    monkeypatch.setattr(fpr, "_observe", observe)

    def section(workspace: Path, key: bytes) -> dict[str, object] | None:
        context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=workspace, guard_home=tmp_path / "guard")
        return fpr.runtimes_section(store, context, hash_key=key, now=NOW)

    alpha, beta = tmp_path / "alpha", tmp_path / "beta"
    alpha.mkdir()
    beta.mkdir()
    first = section(alpha, b"k" * 32)
    assert section(alpha, b"k" * 32) == first
    other = section(beta, b"k" * 32)
    rekeyed = section(beta, b"r" * 32)

    assert observed == [alpha, beta, beta]
    assert other is not None and rekeyed is not None and first is not None
    assert other["items"][0]["locationHash"] == keyed_digest(b"k" * 32, f"{beta}/bin/node")
    assert rekeyed["items"][0]["locationHash"] == keyed_digest(b"r" * 32, f"{beta}/bin/node")
    assert json.dumps(store.get_sync_payload(fpr.RUNTIMES_STATE_KEY)).count(str(tmp_path)) == 0


def test_failed_observation_omits_the_section_and_is_retried(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])

    def broken(*_: object) -> dict[str, object]:
        raise OSError("boom")

    monkeypatch.setattr(fpr, "_observe", broken)
    adapters = [FakeAdapter("claude-code")]
    assert "runtimes" not in _build(store, context, adapters).payload

    monkeypatch.setattr(fpr, "_observe", lambda *_: _posture([_runtime()]))
    assert "runtimes" in _build(store, context, adapters).payload


def test_runtimes_give_way_before_inventory_rows(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_row(f"skill-{index}") for index in range(20)]
    _set_inventory(store, monkeypatch, rows)
    adapters = [FakeAdapter("claude-code")]
    monkeypatch.setattr(fpr, "_observe", lambda *_: _posture([]))
    without = _build(store, context, adapters, runtimes_ttl_seconds=0).payload
    del without["runtimes"]
    budget = fp.json_size(without) + 16
    monkeypatch.setattr(fp, "MAX_PAYLOAD_BYTES", budget)
    monkeypatch.setattr(fpr, "_observe", lambda *_: _posture([_runtime()] * fpr.MAX_RUNTIMES))

    payload = _build(store, context, adapters, runtimes_ttl_seconds=0).payload

    assert "runtimes" not in payload
    assert len(payload["inventory"]["items"]) == len(rows)  # type: ignore[index, arg-type]


def _bundle(version: str) -> dict[str, object]:
    return {"response": {"bundle": {"bundleVersion": version}}, "workspace_id": "w", "now": 1.0}


def test_cached_advisory_bundle_reaches_the_observation(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []

    def observe(_context: object, _now: object, advisory: object) -> dict[str, object]:
        seen.append(advisory)
        return _posture([_runtime()], coverage={"mode": "observed_only", "advisories_available": True})

    monkeypatch.setattr(fpr, "_advisory_bundle", lambda _store: (_bundle("v7"), None))
    monkeypatch.setattr(fpr, "_observe", observe)

    section = fpr.runtimes_section(store, context, hash_key=KEY, now=NOW)

    assert seen == [(_bundle("v7"), None)]
    assert section is not None and section["advisoriesAvailable"] is True
    assert section["items"][0]["advisoryIds"] == ["GHSA-aaaa"]


def test_a_newly_synced_bundle_is_rematched_before_the_cache_expires(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    advisory: list[tuple[dict[str, object] | None, str | None]] = [(None, "runtime_advisory_bundle_not_cached")]
    calls: list[object] = []

    def observe(_context: object, _now: object, current: object) -> dict[str, object]:
        calls.append(current)
        return _posture([_runtime()])

    monkeypatch.setattr(fpr, "_advisory_bundle", lambda _store: advisory[0])
    monkeypatch.setattr(fpr, "_observe", observe)

    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW)
    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW + timedelta(minutes=5))
    advisory[0] = (_bundle("v7"), None)
    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW + timedelta(minutes=10))
    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW + timedelta(minutes=15))
    advisory[0] = (_bundle("v8"), None)
    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW + timedelta(minutes=20))

    assert [call[0] for call in calls] == [None, _bundle("v7"), _bundle("v8")]  # type: ignore[index]


def test_cached_matches_lapse_when_their_bundle_does(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    expires = (NOW + timedelta(minutes=10)).timestamp()
    calls: list[object] = []

    def observe(_context: object, now: object, _advisory: object) -> dict[str, object]:
        calls.append(now)
        return _posture([_runtime()], advisory_source={"state": "verified", "valid_until": expires})

    monkeypatch.setattr(fpr, "_advisory_bundle", lambda _store: (_bundle("v7"), None))
    monkeypatch.setattr(fpr, "_observe", observe)

    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW)
    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW + timedelta(minutes=9))
    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW + timedelta(minutes=10))

    assert len(calls) == 2


@pytest.mark.parametrize("field", ["workspace_id", "sync_keyring", "entitlement"])
def test_a_changed_verification_input_is_rematched(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    advisory = [(_bundle("v7"), None)]
    calls: list[object] = []

    def observe(_context: object, _now: object, current: object) -> dict[str, object]:
        calls.append(current)
        return _posture([_runtime()])

    monkeypatch.setattr(fpr, "_advisory_bundle", lambda _store: advisory[0])
    monkeypatch.setattr(fpr, "_observe", observe)

    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW)
    advisory[0] = ({**_bundle("v7"), field: {"changed": True}}, None)
    fpr.runtimes_section(store, context, hash_key=KEY, now=NOW + timedelta(minutes=1))

    assert len(calls) == 2
