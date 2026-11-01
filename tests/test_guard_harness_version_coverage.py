"""Harness version coverage: manifest validation and the compatibility decision.

The native runtime owns the decision; its Rust tests hold the full state table.
These tests pin the Python shim, the CI validator, and the bundled manifest.

The 18.4.12 and 18.8.3 records below are regression fixtures for exact-version
matching. They are not production coverage claims.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.harness_versions import compatibility
from codex_plugin_scanner.guard.harness_versions.acknowledgements import (
    clear_acknowledgements,
    record_acknowledgement,
)
from codex_plugin_scanner.guard.harness_versions.compatibility import (
    OBSERVATION_MAX_AGE_SECONDS,
    STATE_COVERAGE_UNAVAILABLE,
    STATE_TESTED,
    STATE_UNTESTED,
    STATE_VERSION_UNKNOWN,
    decide_compatibility,
)
from codex_plugin_scanner.guard.harness_versions.discovery import VersionObservation
from codex_plugin_scanner.guard.harness_versions.service import _manifest_path
from codex_plugin_scanner.guard.harness_versions.versions import parse_version, parse_version_banner
from scripts.ci.harness_version_manifest import ManifestError, bundled_manifest_path, parse_manifest

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


def _observed(version: str, *, at: float = NOW, installation: str | None = "install-a") -> VersionObservation:
    parsed = parse_version(version)
    assert parsed is not None
    return VersionObservation("omp", "observed", parsed, "package-metadata", installation, None, at)


@pytest.fixture
def decide(tmp_path: Path) -> Callable[..., dict[str, object]]:
    def run(
        observation: VersionObservation, manifest: dict[str, object] | None = FIXTURE, **kwargs: object
    ) -> dict[str, object]:
        path = tmp_path / "manifest.json"
        if manifest is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(json.dumps(manifest), encoding="utf-8")
        options: dict[str, object] = {"guard_version": GUARD, "platform": PLATFORM, "now": NOW}
        options.update(kwargs)
        return decide_compatibility(
            harness="omp",
            observation=observation,
            manifest_path=path,
            guard_home=tmp_path / "guard",
            **options,  # type: ignore[arg-type]
        )

    return run


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
    def test_bundled_manifest_loads_with_an_omp_entry(self) -> None:
        # Records are promoted per release, so what they claim is not pinned here.
        manifest = parse_manifest(json.loads(bundled_manifest_path().read_text(encoding="utf-8")))
        assert "omp" in manifest.harnesses
        assert bundled_manifest_path() == _manifest_path

    def test_bundled_manifest_links_to_how_coverage_works(self) -> None:
        # Where no record applies, the card's links are the only guidance it gives.
        manifest = parse_manifest(json.loads(bundled_manifest_path().read_text(encoding="utf-8")))
        link = manifest.harnesses["omp"].remediation[0]
        prefix = "https://github.com/hashgraph-online/hol-guard/blob/main/"
        assert link.url.startswith(prefix)
        assert (Path(__file__).resolve().parents[1] / link.url.removeprefix(prefix)).is_file()

    def test_native_runtime_accepts_the_bundled_manifest(self, decide: Callable[..., dict[str, object]]) -> None:
        bundled = json.loads(bundled_manifest_path().read_text(encoding="utf-8"))
        payload = decide(_observed("0.0.1"), bundled)
        assert payload["reason"] != "manifest_invalid"
        assert payload["coverage_revision"] == bundled["revision"]

    @pytest.mark.parametrize(
        ("observed_at", "accepted"),
        [
            ("2026-10-16T00:00:00Z", True),
            ("2026-10-16 00:00+05:30", True),
            ("2026-10-16T00:00:00.123456-07:00", True),
            ("2026-10-16T00:00:00+0000", False),
            ("20261016T000000Z", False),
            ("2026-10-16T00:00:00.1234567Z", False),
            ("2026-02-30T00:00:00Z", False),
        ],
    )
    def test_ci_and_native_validators_agree_on_timestamps(
        self, decide: Callable[..., dict[str, object]], observed_at: str, accepted: bool
    ) -> None:
        manifest = _manifest(_record("18.4.12", observed_at=observed_at))
        native = decide(_observed("18.4.12"), manifest)
        assert (native["state"] == STATE_TESTED) is accepted
        if accepted:
            parse_manifest(manifest)
        else:
            assert native["state"] == STATE_COVERAGE_UNAVAILABLE
            with pytest.raises(ManifestError, match="observed_at"):
                parse_manifest(manifest)

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


class TestDecision:
    @pytest.mark.parametrize("version", ["18.4.12", "18.8.3"])
    def test_exact_match_is_tested(self, decide: Callable[..., dict[str, object]], version: str) -> None:
        payload = decide(_observed(version))
        assert payload["state"] == STATE_TESTED
        assert payload["tested_scope"] == "all_declared_events"
        assert payload["enforcement_effect"] == "none"
        assert payload["acknowledgement"] == {"eligible": False, "acknowledged": False, "key": None}
        evidence = payload["evidence"]
        assert isinstance(evidence, list) and evidence
        assert all(item["suite"] == {"id": item["suite"]["id"], "result": "passed"} for item in evidence)

    @pytest.mark.parametrize("version", ["18.11.2", "18.4.11", "18.8.3-rc.1", "18.8.3+build.7"])
    def test_neighbouring_versions_are_untested(self, decide: Callable[..., dict[str, object]], version: str) -> None:
        payload = decide(_observed(version))
        assert payload["state"] == STATE_UNTESTED
        assert payload["reason"] == "version_not_in_evidence"
        assert payload["tested_versions"] == ["18.4.12", "18.8.3"]
        assert payload["acknowledgement"]["eligible"] is True  # type: ignore[index]

    def test_uncertain_inputs_are_never_tested(self, decide: Callable[..., dict[str, object]]) -> None:
        unknown = decide(VersionObservation("omp", "unavailable", None, "none", None, "executable_missing", NOW))
        assert (unknown["state"], unknown["reason"]) == (STATE_VERSION_UNKNOWN, "executable_missing")
        stale = decide(_observed("18.8.3", at=NOW - OBSERVATION_MAX_AGE_SECONDS - 1))
        assert (stale["state"], stale["reason"]) == (STATE_VERSION_UNKNOWN, "observation_stale")
        missing = decide(_observed("18.8.3"), None)
        assert (missing["state"], missing["reason"]) == (STATE_COVERAGE_UNAVAILABLE, "manifest_missing")
        broken = decide(_observed("18.8.3"), _manifest(_record("18.x")))
        assert (broken["state"], broken["reason"]) == (STATE_COVERAGE_UNAVAILABLE, "manifest_invalid")
        other = decide(_observed("18.8.3"), platform="linux-x86_64")
        assert (other["state"], other["reason"]) == (STATE_COVERAGE_UNAVAILABLE, "no_evidence_for_this_build")

    def test_acknowledgement_round_trips_through_the_store(
        self, decide: Callable[..., dict[str, object]], tmp_path: Path
    ) -> None:
        key = decide(_observed("18.11.2"))["acknowledgement"]["key"]  # type: ignore[index]
        assert isinstance(key, str)
        entry = record_acknowledgement(tmp_path / "guard", harness="omp", key=key)
        assert entry["key"] == key
        acked = decide(_observed("18.11.2"))
        assert acked["state"] == STATE_UNTESTED
        assert acked["acknowledgement"]["acknowledged"] is True  # type: ignore[index]
        assert decide(_observed("18.11.3"))["acknowledgement"]["acknowledged"] is False  # type: ignore[index]
        assert clear_acknowledgements(tmp_path / "guard", harness="omp") == 1
        assert decide(_observed("18.11.2"))["acknowledgement"]["acknowledged"] is False  # type: ignore[index]

    def test_store_rejects_a_malformed_key(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            record_acknowledgement(tmp_path / "guard", harness="omp", key="../../etc")

    def test_payload_never_exposes_paths(self, decide: Callable[..., dict[str, object]], tmp_path: Path) -> None:
        payload = json.dumps(decide(_observed("18.11.2")))
        assert str(Path.home()) not in payload and str(tmp_path) not in payload

    def test_without_a_runtime_the_version_is_unknown(
        self, decide: Callable[..., dict[str, object]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(compatibility, "runtime_request", lambda *_args, **_kwargs: None)
        payload = decide(_observed("18.8.3"))
        assert (payload["state"], payload["reason"]) == (STATE_VERSION_UNKNOWN, "runtime_unavailable")
        assert payload["enforcement_effect"] == "none"


def test_documented_schema_accepts_bundled_and_fixture_manifests() -> None:
    import jsonschema

    schema_path = Path(__file__).resolve().parents[1] / "docs/guard/schemas/harness-version-coverage.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    bundled = json.loads(bundled_manifest_path().read_text(encoding="utf-8"))
    for payload in (bundled, FIXTURE):
        assert list(validator.iter_errors(payload)) == []
    assert list(validator.iter_errors(_manifest(_record("18.x"))))
