"""Security contracts for the privileged Desktop Core alpha feed."""

from __future__ import annotations

import hashlib
import json
import runpy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "desktop-core-alpha-feed.yml"
TOOL = ROOT / "scripts" / "release" / "desktop_core_alpha_feed.py"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def workflow() -> dict[object, object]:
    value = yaml.safe_load(workflow_text())
    assert isinstance(value, dict)
    return value


def publish_job() -> dict[str, object]:
    jobs = workflow()["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["publish-macos-arm64"]
    assert isinstance(job, dict)
    return job


def test_privileged_feed_runs_only_from_main_and_immutable_workflow_sha() -> None:
    text = workflow_text()
    job = publish_job()
    assert len(text.splitlines()) <= 500
    assert job["permissions"] == {
        "contents": "write",
        "id-token": "write",
        "attestations": "write",
    }
    steps = [step for step in job["steps"] if isinstance(step, dict)]
    invocation_guard = next(
        step for step in steps if step.get("name") == "Require trusted main workflow invocation"
    )
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in invocation_guard["run"]
    checkouts = [
        step
        for step in steps
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    privileged_checkout = next(
        step for step in checkouts if step.get("name") == "Check out immutable release automation"
    )
    assert privileged_checkout["with"]["ref"] == "${{ github.sha }}"
    assert privileged_checkout["with"]["persist-credentials"] is False
    checkout_binding = next(
        step for step in steps if step.get("name") == "Bind automation checkout to workflow source"
    )
    assert "test \"$(git rev-parse 'HEAD^{commit}')\" = \"$GITHUB_SHA\"" in checkout_binding["run"]


def test_candidate_tag_is_not_authority_and_must_match_release_branch() -> None:
    text = workflow_text()
    namespace = runpy.run_path(str(TOOL))
    assert "Authorize exact Core source with release provenance" in text
    assert "refs/tags/${CORE_TAG}^{commit}" in text
    assert "refs/remotes/origin/${RELEASE_BRANCH}" in text
    assert "merge-base --is-ancestor" in text
    assert "discover-release" in text
    assert namespace["SUPPORTED_TRAINS"] == {"3.0", "3.1"}


def test_release_discovery_selects_newest_supported_3x_train(tmp_path: Path, capsys) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text(
        "alpha/v3.0.0a8\nalpha/v3.1.0a10\nalpha/v3.0.0a9\n",
        encoding="utf-8",
    )
    namespace = runpy.run_path(str(TOOL))
    namespace["discover_release"](tags)
    output = capsys.readouterr().out
    assert "available=true" in output
    assert "version=3.1.0a10" in output
    assert "tag=alpha/v3.1.0a10" in output
    assert "train=3.1" in output
    assert "branch=release/3.1" in output


def test_candidate_requires_trusted_publish_workflow_attestation() -> None:
    text = workflow_text()
    assert 'gh attestation verify "${WHEELS[0]}"' in text
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/publish.yml"' in text
    assert '--signer-digest "$SOURCE_SHA"' in text and '--source-digest "$SOURCE_SHA"' in text
    assert '--source-ref "refs/heads/${RELEASE_BRANCH}"' in text
    assert "--deny-self-hosted-runners" in text


def test_existing_assets_are_all_or_nothing() -> None:
    text = workflow_text()
    tool = TOOL.read_text(encoding="utf-8")
    assert "inspect-assets" in text
    assert 'present == set(expected)' in tool
    assert '"signature"' not in tool.split("def inspect_assets", 1)[1].split("def verify_bootstrap", 1)[0]
    assert "repair_signature" not in text
    assert "Refusing partial or ambiguous Core asset set" in tool


def test_reused_binary_requires_prior_feed_provenance() -> None:
    text = workflow_text()
    assert "Verify prior feed provenance before reusing assets" in text
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/desktop-core-alpha-feed.yml"' in text
    assert "--source-ref refs/heads/main" in text
    assert 'for asset in "$BASE" "$BASE.json" "$BASE.attested.json"; do' in text
    assert 'gh attestation verify "$asset"' in text


def test_apple_verification_pins_identity_team_and_notarized_gatekeeper_source() -> None:
    text = workflow_text()
    assert 'grep -Fx "Authority=$APPLE_SIGNING_IDENTITY"' in text
    assert 'grep -Fx "TeamIdentifier=$APPLE_TEAM_ID"' in text
    assert "spctl --assess --type execute --verbose=4" in text
    assert 'grep -F "source=Notarized Developer ID"' in text
    assert 'grep -F "Mach-O 64-bit executable arm64"' in text


def test_complete_apple_trusted_asset_set_is_attested_together() -> None:
    text = workflow_text()
    assert "Attest complete hardened Core asset set" in text
    assert "${{ env.RELEASE_TARGET }}.attested.json" in text
    assert "${{ env.RELEASE_TARGET }}.json.sig" not in text
    assert 'gh release upload "$CORE_TAG" "$BASE" "$BASE.json" "$BASE.attested.json"' in text


def test_final_verification_reloads_published_asset_bytes() -> None:
    text = workflow_text()
    assert 'PUBLISHED="$RUNNER_TEMP/published-assets"' in text
    assert 'gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$asset" --dir "$PUBLISHED"' in text
    assert 'test -f "$PUBLISHED/$asset"' in text
    assert 'gh attestation verify "$PUBLISHED/$asset"' in text
    assert 'gh attestation verify "$RUNNER_TEMP/dist/$asset"' not in text


def test_manifest_and_marker_bind_exact_authorized_source_and_hashes(tmp_path: Path) -> None:
    tool = TOOL.read_text(encoding="utf-8")
    namespace = runpy.run_path(str(TOOL))
    assert 'MARKER_SCHEMA = "hol-guard-core-attestation.v3"' in tool
    assert "signatureSha256" not in tool

    base = tmp_path / "core"
    manifest = Path(f"{base}.json")
    marker = Path(f"{base}.attested.json")
    base.write_bytes(b"binary")
    manifest.write_bytes(b"manifest")
    common = {
        "version": "3.1.0a1",
        "source_commit": "a" * 40,
        "source_tag": "alpha/v3.1.0a1",
        "target": "aarch64-apple-darwin",
        "apple_signing_identity": "Developer ID Application: HOL",
        "apple_team_id": "TEAMID",
    }
    namespace["create_marker"](base, marker, workflow_run="123456", **common)
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["schema"] == "hol-guard-core-attestation.v3"
    assert set(payload) >= {"binarySha256", "manifestSha256", "workflowRun", "attestedAt"}
    assert "signatureSha256" not in payload
    namespace["validate_marker"](base, marker, **common)

    payload["binarySha256"] = "c" * 64
    marker.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SystemExit, match="Marker hash mismatch for binarySha256"):
        namespace["validate_marker"](base, marker, **common)


def test_privileged_inline_python_is_isolated_from_workspace_import_shadowing() -> None:
    text = workflow_text()
    inline_python = [line.strip() for line in text.splitlines() if "python3" in line and "<<" in line]
    assert inline_python
    assert all("python3 -I" in line for line in inline_python)
    assert "python3 -I scripts/release/desktop_core_alpha_feed.py" in text
