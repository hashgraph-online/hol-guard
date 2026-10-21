"""Harness version coverage: manifest validation and the compatibility decision.

The 18.4.12 and 18.8.3 records below are regression fixtures for exact-version
matching. They are not production coverage claims.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.harness_versions.compatibility import (
    OBSERVATION_MAX_AGE_SECONDS,
    STATE_COVERAGE_UNAVAILABLE,
    STATE_TESTED,
    STATE_UNTESTED,
    STATE_VERSION_UNKNOWN,
    decide_compatibility,
)
from codex_plugin_scanner.guard.harness_versions.discovery import VersionObservation
from codex_plugin_scanner.guard.harness_versions.manifest import (
    ManifestError,
    ManifestLoad,
    bundled_manifest_path,
    load_manifest,
    parse_manifest,
)
from codex_plugin_scanner.guard.harness_versions.versions import parse_version, parse_version_banner

GUARD = "9.9.9"
PLATFORM = "darwin-arm64"
NOW = 1_800_000_000.0
FULL_EVENTS = ["PostToolUse", "PreToolUse", "UserPromptSubmit"]


def _record(version: str, **overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "harness_version": version,
        "guard_version": GUARD,
        "platforms": [PLATFORM],
        "transport": "managed_extension",
        "events": list(FULL_EVENTS),
        "suite": {"id": "guard-gauntlet-full-task", "result": "passed"},
        "evidence_level": "live_block",
        "evidence_reference": "https://github.com/hashgraph-online/hol-guard/actions/runs/1",
        "observed_at": "2026-10-16T00:00:00Z",
    }
    record.update(overrides)
    return record


def _manifest(*records: dict[str, object], version_source: str = "package-metadata") -> dict[str, object]:
    return {
        "schema_version": "hol-guard-harness-version-coverage.v1",
        "revision": "fixture.1",
        "harnesses": [
            {
                "harness": "omp",
                "version_source": version_source,
                "limitations": ["Exact versions only."],
                "remediation": [{"label": "Releases", "url": "https://github.com/can1357/oh-my-pi/releases"}],
                "records": list(records),
            }
        ],
    }


FIXTURE = _manifest(_record("18.4.12"), _record("18.8.3"))


def _load(payload: dict[str, object] = FIXTURE) -> ManifestLoad:
    return ManifestLoad(parse_manifest(payload), None)


def _observed(version: str, *, at: float = NOW, installation: str | None = "install-a") -> VersionObservation:
    parsed = parse_version(version)
    assert parsed is not None
    return VersionObservation("omp", "observed", parsed, "package-metadata", installation, None, at)


def _decide(observation: VersionObservation, load: ManifestLoad | None = None, **kwargs: object) -> dict[str, object]:
    options: dict[str, object] = {"guard_version": GUARD, "platform": PLATFORM, "now": NOW}
    options.update(kwargs)
    return decide_compatibility(
        harness="omp",
        observation=observation,
        manifest_load=load or _load(),
        **options,  # type: ignore[arg-type]
    )


class TestVersions:
    @pytest.mark.parametrize("text", ["18.4.12", "v18.4.12", "18.4.12-rc.1", "18.4.12+build.5"])
    def test_accepts_exact_semver(self, text: str) -> None:
        assert parse_version(text) is not None

    @pytest.mark.parametrize("text", ["18.x", "^18.4.12", ">=18", "18.4", "18.4.*", "", "018.4.1", "1" * 70, None, 18])
    def test_rejects_ranges_and_malformed(self, text: object) -> None:
        assert parse_version(text) is None

    @pytest.mark.parametrize(
        "banner", ["18.8.3\n", "omp 18.8.3", "oh-my-pi v18.8.3", "@oh-my-pi/pi-coding-agent 18.8.3"]
    )
    def test_banner_accepts_known_prefixes(self, banner: str) -> None:
        version = parse_version_banner("omp", banner)
        assert version is not None and version.canonical == "18.8.3"

    @pytest.mark.parametrize(
        "banner",
        ["", "18.8.3 18.8.4", "omp 18.8.3\nsecond line", "other-tool 18.8.3", "omp 18.8.3 (beta)", "x" * 5000],
    )
    def test_banner_rejects_ambiguous_output(self, banner: str) -> None:
        assert parse_version_banner("omp", banner) is None


class TestManifestValidation:
    def test_bundled_manifest_loads_and_claims_nothing_for_omp(self) -> None:
        load = load_manifest()
        assert load.error is None and load.manifest is not None
        assert load.manifest.harnesses["omp"].records == ()

    @pytest.mark.parametrize("version", ["18.x", "^18.4.12", ">=18.4.12 <19", "18.4.12 - 18.8.3", "*"])
    def test_rejects_ranges(self, version: str) -> None:
        with pytest.raises(ManifestError, match="exact version"):
            parse_manifest(_manifest(_record(version)))

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"suite": {"id": "pi-sdk-pin", "result": "passed"}}, "eligible suite"),
            ({"suite": {"id": "guard-gauntlet-full-task", "result": "failed"}}, "passed"),
            ({"suite": {"id": "pi-exact-continuation", "result": "passed"}}, "suite does not exercise"),
            ({"transport": "hooks"}, "suite does not exercise"),
            ({"evidence_level": "independent_review"}, "evidence_level"),
            ({"evidence_reference": "https://example.com/run/1"}, "retained evidence"),
            ({"observed_at": "2026-10-16T00:00:00"}, "timezone"),
            ({"platforms": ["plan9-mips"]}, "platforms"),
            ({"guard_version": "3.x"}, "Guard release"),
            ({"unexpected": True}, "unsupported keys"),
        ],
    )
    def test_rejects_ineligible_records(self, overrides: dict[str, object], message: str) -> None:
        with pytest.raises(ManifestError, match=message):
            parse_manifest(_manifest(_record("18.4.12", **overrides)))

    def test_contract_suite_cannot_claim_full_events(self) -> None:
        record = _record(
            "18.4.12",
            suite={"id": "pi-exact-continuation", "result": "passed"},
            evidence_level="unit_test",
            events=["PreToolUse"],
        )
        assert parse_manifest(_manifest(record)).harnesses["omp"].records[0].events == ("PreToolUse",)

    def test_rejects_duplicate_claims(self) -> None:
        with pytest.raises(ManifestError, match="duplicate or conflicting"):
            parse_manifest(_manifest(_record("18.4.12"), _record("18.4.12")))

    def test_rejects_records_without_version_source(self) -> None:
        with pytest.raises(ManifestError, match="version source"):
            parse_manifest(_manifest(_record("18.4.12"), version_source="unavailable"))

    @pytest.mark.parametrize("url", ["http://github.com/x", "https://evil.example/x", "javascript:alert(1)"])
    def test_rejects_unreviewed_remediation(self, url: str) -> None:
        payload = copy.deepcopy(FIXTURE)
        payload["harnesses"][0]["remediation"] = [{"label": "x", "url": url}]  # type: ignore[index]
        with pytest.raises(ManifestError, match="https link"):
            parse_manifest(payload)

    def test_rejects_unknown_harness_and_schema(self) -> None:
        payload = copy.deepcopy(FIXTURE)
        payload["harnesses"][0]["harness"] = "not-a-harness"  # type: ignore[index]
        with pytest.raises(ManifestError):
            parse_manifest(payload)
        with pytest.raises(ManifestError, match="schema_version"):
            parse_manifest({**FIXTURE, "schema_version": "v0"})

    def test_load_reports_missing_and_invalid(self, tmp_path: Path) -> None:
        assert load_manifest(tmp_path / "absent.json").error == "manifest_missing"
        broken = tmp_path / "broken.json"
        broken.write_text(json.dumps(_manifest(_record("18.x"))), encoding="utf-8")
        load = load_manifest(broken)
        assert load.manifest is None and load.error == "manifest_invalid"


class TestDecision:
    @pytest.mark.parametrize("version", ["18.4.12", "18.8.3"])
    def test_exact_match_is_tested(self, version: str) -> None:
        payload = _decide(_observed(version))
        assert payload["state"] == STATE_TESTED
        assert payload["tested_scope"] == "all_declared_events"
        assert payload["enforcement_effect"] == "none"
        assert payload["acknowledgement"] == {"eligible": False, "acknowledged": False, "key": None}
        evidence = payload["evidence"]
        assert isinstance(evidence, list) and evidence
        assert all(item["suite"] == {"id": item["suite"]["id"], "result": "passed"} for item in evidence)

    @pytest.mark.parametrize("version", ["18.11.2", "18.4.11", "18.6.0", "18.8.3-rc.1", "19.0.0"])
    def test_newer_lower_and_intermediate_versions_are_untested(self, version: str) -> None:
        payload = _decide(_observed(version))
        assert payload["state"] == STATE_UNTESTED
        assert payload["reason"] == "version_not_in_evidence"
        assert payload["tested_versions"] == ["18.4.12", "18.8.3"]
        assert payload["acknowledgement"]["eligible"] is True  # type: ignore[index]

    def test_build_metadata_does_not_match_plain_version(self) -> None:
        assert _decide(_observed("18.8.3+build.7"))["state"] == STATE_UNTESTED

    def test_prerelease_flag_is_reported(self) -> None:
        assert _decide(_observed("18.9.0-beta.2"))["version_is_prerelease"] is True

    def test_other_guard_build_or_platform_has_no_coverage(self) -> None:
        assert _decide(_observed("18.8.3"), guard_version="9.9.10")["state"] == STATE_COVERAGE_UNAVAILABLE
        payload = _decide(_observed("18.8.3"), platform="linux-x86_64")
        assert payload["state"] == STATE_COVERAGE_UNAVAILABLE
        assert payload["reason"] == "no_evidence_for_this_build"

    def test_partial_event_scope_is_partial(self) -> None:
        record = _record(
            "18.4.12",
            suite={"id": "pi-exact-continuation", "result": "passed"},
            evidence_level="unit_test",
            events=["PreToolUse"],
        )
        payload = _decide(_observed("18.4.12"), _load(_manifest(record)))
        assert payload["state"] == STATE_TESTED
        assert payload["tested_scope"] == "partial"
        assert payload["tested_events"] == ["PreToolUse"]

    def test_unknown_and_ambiguous_versions_are_unknown_and_not_acknowledgeable(self) -> None:
        for observation in (
            VersionObservation("omp", "unavailable", None, "none", None, "executable_missing", NOW),
            VersionObservation("omp", "ambiguous", None, "none", "install-a", "multiple_installations", NOW),
        ):
            payload = _decide(observation)
            assert payload["state"] == STATE_VERSION_UNKNOWN
            assert payload["reason"] == observation.reason
            assert payload["acknowledgement"]["eligible"] is False  # type: ignore[index]

    def test_stale_observation_is_unknown(self) -> None:
        payload = _decide(_observed("18.8.3", at=NOW - OBSERVATION_MAX_AGE_SECONDS - 1))
        assert payload["state"] == STATE_VERSION_UNKNOWN
        assert payload["reason"] == "observation_stale"

    def test_missing_manifest_and_empty_records_are_unavailable(self) -> None:
        missing = _decide(_observed("18.8.3"), ManifestLoad(None, "manifest_missing"))
        assert (missing["state"], missing["reason"]) == (STATE_COVERAGE_UNAVAILABLE, "manifest_missing")
        empty = _decide(_observed("18.8.3"), load_manifest())
        assert (empty["state"], empty["reason"]) == (STATE_COVERAGE_UNAVAILABLE, "harness_not_covered")

    def test_acknowledgement_key_changes_with_every_binding(self) -> None:
        base = _decide(_observed("18.11.2"))["acknowledgement"]["key"]  # type: ignore[index]
        other_version = _decide(_observed("18.11.3"))["acknowledgement"]["key"]  # type: ignore[index]
        other_install = _decide(_observed("18.11.2", installation="install-b"))["acknowledgement"]["key"]  # type: ignore[index]
        revised = copy.deepcopy(FIXTURE)
        revised["revision"] = "fixture.2"
        other_revision = _decide(_observed("18.11.2"), _load(revised))["acknowledgement"]["key"]  # type: ignore[index]
        assert len({base, other_version, other_install, other_revision}) == 4

    def test_acknowledged_key_collapses_only_matching_warning(self) -> None:
        key = _decide(_observed("18.11.2"))["acknowledgement"]["key"]  # type: ignore[index]
        acked = _decide(_observed("18.11.2"), acknowledged_keys=frozenset({key}))
        assert acked["state"] == STATE_UNTESTED
        assert acked["acknowledgement"]["acknowledged"] is True  # type: ignore[index]
        moved = _decide(_observed("18.11.3"), acknowledged_keys=frozenset({key}))
        assert moved["acknowledgement"]["acknowledged"] is False  # type: ignore[index]

    def test_payload_never_exposes_paths(self, tmp_path: Path) -> None:
        payload = json.dumps(_decide(_observed("18.11.2")))
        assert str(Path.home()) not in payload and str(tmp_path) not in payload


def test_documented_schema_accepts_bundled_and_fixture_manifests() -> None:
    import jsonschema

    schema_path = Path(__file__).resolve().parents[1] / "docs/guard/schemas/harness-version-coverage.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    bundled = json.loads(bundled_manifest_path().read_text(encoding="utf-8"))
    for payload in (bundled, FIXTURE):
        assert list(validator.iter_errors(payload)) == []
    assert list(validator.iter_errors(_manifest(_record("18.x"))))
