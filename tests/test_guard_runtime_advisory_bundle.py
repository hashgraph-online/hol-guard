"""Runtime advisories from the cached, signed supply-chain bundle.

Python only gathers the stored response and its sync context; the native
runtime verifies the bundle before any advisory reaches matching. These tests
cover the loader, the bridge contract and how posture reports coverage,
including the fallback when the native runtime predates bundled advisories.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import runtime_identity_assessment as runtime_identity
from codex_plugin_scanner.guard import runtime_posture
from codex_plugin_scanner.guard.cli.runtime_posture_command import render_runtime_posture
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime_advisory_bundle import (
    NOT_CACHED,
    NOT_CONNECTED,
    cached_advisory_bundle,
)
from codex_plugin_scanner.guard.runtime_identity_assessment import (
    RuntimeAdvisoryVerdict,
    RuntimeIdentityAssessment,
    RuntimeIdentityError,
)
from codex_plugin_scanner.guard.runtime_posture import (
    BUNDLE_ASSESSMENT_FAILED,
    BUNDLE_UNSUPPORTED,
    build_runtime_posture,
)

NOW = "2026-01-01T00:00:00+00:00"
WORKSPACE = "11111111-1111-4111-8111-111111111111"
BUNDLE_INPUT = {"response": {"bundle": {}}, "workspace_id": WORKSPACE, "now": 1.0}


class FakeStore:
    def __init__(self, *, workspace: str | None = WORKSPACE, payloads=None, cached=None) -> None:
        self.workspace = workspace
        self.payloads = payloads or {}
        self.cached = cached

    def get_cloud_workspace_id(self) -> str | None:
        return self.workspace

    def get_sync_payload(self, key: str) -> object:
        return self.payloads.get(key)

    def get_cached_supply_chain_bundle(self, workspace_id: str) -> object:
        assert workspace_id == self.workspace
        return self.cached


def test_loader_hands_over_the_stored_response_and_sync_context() -> None:
    keyring = {"workspace_id": WORKSPACE, "keys": []}
    store = FakeStore(
        payloads={
            "supply_chain_bundle_entitlement": {"workspace_id": WORKSPACE, "bundle_version": "v7"},
            "supply_chain_bundle_keyring": keyring,
        },
        cached={"bundle": {"bundleVersion": "v7"}, "signature": "s", "cached_at": "2026-01-01"},
    )

    bundle, reason = cached_advisory_bundle(store, now=42.0)

    assert reason is None
    assert bundle == {
        "response": {"bundle": {"bundleVersion": "v7"}, "signature": "s"},
        "workspace_id": WORKSPACE,
        "sync_keyring": keyring,
        "entitlement": {"workspace_id": WORKSPACE, "bundle_version": "v7"},
        "now": 42.0,
    }


def test_loader_leaves_the_entitlement_check_to_the_native_runtime() -> None:
    # A record naming another workspace is handed over as stored; the native
    # runtime refuses it with the same check package evaluation applies.
    entitlement = {"workspace_id": "other"}
    store = FakeStore(payloads={"supply_chain_bundle_entitlement": entitlement}, cached={"bundle": {}})

    bundle, reason = cached_advisory_bundle(store)

    assert reason is None and bundle is not None
    assert bundle["entitlement"] == entitlement


@pytest.mark.parametrize(
    ("store", "expected"),
    [
        (FakeStore(workspace=None), NOT_CONNECTED),
        (FakeStore(cached=None), NOT_CACHED),
    ],
)
def test_loader_returns_no_bundle_with_a_reason(store: FakeStore, expected: str) -> None:
    assert cached_advisory_bundle(store) == (None, expected)


def test_bundle_requests_select_the_bundle_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake(feature: str, command: str, request: dict[str, object], **_: object) -> dict[str, object]:
        seen.append(feature)
        return {"ok": False, "error": "runtime_identity_failed"}

    monkeypatch.setattr(runtime_identity, "run_native_identity_command", fake)
    for request in ({"artifacts": []}, {"artifacts": [], "cached_bundle": BUNDLE_INPUT}):
        with pytest.raises(RuntimeIdentityError):
            runtime_identity.assess_runtime_identity(request)

    assert seen == [runtime_identity.RUNTIME_IDENTITY_FEATURE, runtime_identity.RUNTIME_IDENTITY_BUNDLE_FEATURE]


def test_bridge_parses_advisory_source_and_rule_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    reply = {
        "ok": True,
        "result": {
            "schema": runtime_identity.RUNTIME_IDENTITY_SCHEMA,
            "scope_complete": False,
            "artifacts": [],
            "advisories": [
                {
                    "advisory_id": "GHSA-node",
                    "verdict": "affected",
                    "reasons": ["in_range"],
                    "affected_artifact_ids": ["a1"],
                    "affected_instance_ids": [],
                    "replacement_instance_ids": [],
                    "severity": "high",
                    "known_exploited": True,
                    "title": "Node.js permission bypass",
                }
            ],
            "advisory_source": {"state": "verified", "entries": 1},
        },
    }
    monkeypatch.setattr(runtime_identity, "_native_request", lambda request: reply)

    assessment = runtime_identity.assess_runtime_identity({"artifacts": []})

    [row] = assessment.advisories
    assert (row.severity, row.known_exploited, row.title) == ("high", True, "Node.js permission bypass")
    assert assessment.advisory_source == {"state": "verified", "entries": 1}


def _detection(command: str) -> HarnessDetection:
    artifact = GuardArtifact(
        artifact_id="claude-code:files",
        name="files",
        harness="claude-code",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="config.json",
        command=command,
        args=(),
        transport="stdio",
        metadata={"env": {}},
    )
    return HarnessDetection("claude-code", True, True, ("config.json",), (artifact,))


def _node(tmp_path: Path) -> Path:
    path = tmp_path / ".nvm" / "versions" / "node" / "v22.12.0" / "bin" / "node"
    path.parent.mkdir(parents=True)
    path.write_text("binary-not-a-script\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _posture(tmp_path: Path, **kwargs: object) -> dict[str, object]:
    node = _node(tmp_path)
    return build_runtime_posture(
        [_detection("node")], generated_at=NOW, environment={"PATH": str(node.parent)}, **kwargs
    )


@pytest.fixture
def native_runtime(native_hook_force: Path) -> Path:
    return native_hook_force


def _assessment(source: dict[str, object], *advisories: RuntimeAdvisoryVerdict) -> RuntimeIdentityAssessment:
    return RuntimeIdentityAssessment(
        scope_complete=False, artifacts=(), advisories=tuple(advisories), advisory_source=source
    )


def test_older_native_runtime_falls_back_to_observation_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, native_runtime: Path
) -> None:
    seen: list[dict[str, object]] = []

    def assess(request: dict[str, object]) -> RuntimeIdentityAssessment:
        seen.append(request)
        if "cached_bundle" in request:
            raise RuntimeIdentityError("runtime_identity_native_unavailable")
        return _assessment({"state": "absent"})

    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", assess)

    payload = _posture(tmp_path, advisory_bundle=BUNDLE_INPUT)

    assert ["cached_bundle" in request for request in seen] == [True, False]
    assert payload["status"] == "ok"
    assert payload["advisory_source"] == {
        "state": "unsupported",
        "reason": BUNDLE_UNSUPPORTED,
        "coverage_reason": "runtime_advisory_bundle_unsupported",
        "advisories_available": False,
    }
    assert payload["coverage"]["advisories_available"] is False
    assert payload["coverage"]["reason"] == "runtime_advisory_bundle_unsupported"


def test_any_bundle_failure_still_reports_the_runtimes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, native_runtime: Path
) -> None:
    # An oversized or otherwise rejected bundle request costs the advisories,
    # never the observation of the runtimes themselves.
    calls: list[dict[str, object]] = []

    def assess(request: dict[str, object]) -> RuntimeIdentityAssessment:
        calls.append(request)
        if "cached_bundle" in request:
            raise RuntimeIdentityError("runtime_identity_input_too_large")
        return _assessment({"state": "absent"})

    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", assess)

    payload = _posture(tmp_path, advisory_bundle=BUNDLE_INPUT)

    assert ["cached_bundle" in request for request in calls] == [True, False]
    assert payload["status"] == "ok"
    assert payload["runtimes"]
    assert payload["advisory_source"]["reason"] == "runtime_identity_input_too_large"
    assert payload["coverage"] | {"statement": ""} == {
        "mode": "observed_only",
        "instances_enumerated": False,
        "advisories_available": False,
        "reason": BUNDLE_ASSESSMENT_FAILED,
        "statement": "",
    }


def test_assessment_that_fails_without_the_bundle_too_is_partial(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, native_runtime: Path
) -> None:
    def assess(request: dict[str, object]) -> RuntimeIdentityAssessment:
        raise RuntimeIdentityError("runtime_identity_failed")

    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", assess)

    payload = _posture(tmp_path, advisory_bundle=BUNDLE_INPUT)

    assert payload["status"] == "partial"
    assert payload["coverage"]["reason"] == "runtime_assessment_failed"


@pytest.mark.parametrize(
    ("source", "available", "reason"),
    [
        ({"state": "verified", "entries": 2, "advisories_available": True, "coverage_reason": None}, True, None),
        (
            {"state": "verified", "entries": 0, "advisories_available": False, "coverage_reason": "not_in_bundle"},
            False,
            "not_in_bundle",
        ),
        (
            {"state": "invalid", "advisories_available": False, "coverage_reason": "bundle_invalid"},
            False,
            "bundle_invalid",
        ),
        # Only the native report decides availability; a verified state alone is not enough.
        ({"state": "verified", "entries": 3}, False, None),
    ],
)
def test_coverage_relays_the_native_source_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    native_runtime: Path,
    source: dict[str, object],
    available: bool,
    reason: str | None,
) -> None:
    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", lambda request: _assessment(source))

    payload = _posture(tmp_path, advisory_bundle=BUNDLE_INPUT)

    assert payload["coverage"]["advisories_available"] is available
    assert payload["coverage"]["reason"] == reason
    assert payload["advisory_source"] == source


def test_an_empty_inventory_still_reports_the_bundle_source(monkeypatch: pytest.MonkeyPatch) -> None:
    source = {"state": "verified", "entries": 2, "advisories_available": True, "coverage_reason": None}
    seen: list[dict[str, object]] = []

    def assess(request: dict[str, object]) -> RuntimeIdentityAssessment:
        seen.append(request)
        return _assessment(source)

    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", assess)

    payload = build_runtime_posture([], generated_at=NOW, environment={"PATH": ""}, advisory_bundle=BUNDLE_INPUT)

    assert seen[0]["artifacts"] == []
    assert payload["runtimes"] == []
    assert payload["advisory_source"] == source
    assert payload["coverage"]["advisories_available"] is True


def test_loader_reason_is_reported_when_there_is_no_bundle(tmp_path: Path, native_runtime: Path) -> None:
    payload = _posture(tmp_path, advisory_bundle=None, advisory_bundle_reason=NOT_CONNECTED)

    assert payload["coverage"]["advisories_available"] is False
    assert payload["coverage"]["reason"] == NOT_CONNECTED


def test_affected_rows_carry_rule_metadata_and_render(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, native_runtime: Path
) -> None:
    def verdict(advisory_id: str, value: str, reasons: tuple[str, ...]) -> RuntimeAdvisoryVerdict:
        return RuntimeAdvisoryVerdict(advisory_id, value, reasons, (), (), (), "high", value == "affected", "Title")

    source = {"state": "verified", "entries": 3, "bundle_version": "v7", "advisories_available": True}
    rows = (
        verdict("ADV-1", "affected", ("in_range",)),
        verdict("ADV-2", "unknown", ("vendor_unknown",)),
        verdict("ADV-3", "not_affected", ()),
    )
    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", lambda request: _assessment(source, *rows))

    payload = _posture(tmp_path, advisory_bundle=BUNDLE_INPUT)
    text = render_runtime_posture(payload)

    assert payload["advisories"][0] | {"reasons": []} == {
        "advisory_id": "ADV-1",
        "verdict": "affected",
        "reasons": [],
        "affected_artifact_ids": [],
        "severity": "high",
        "known_exploited": True,
        "title": "Title",
    }
    assert "advisories: cached bundle v7." in text
    assert "ADV-1 [high] known exploited affected: Title" in text
    assert "ADV-2 [high] undetermined (vendor_unknown): Title" in text
    assert "ADV-3" not in text
