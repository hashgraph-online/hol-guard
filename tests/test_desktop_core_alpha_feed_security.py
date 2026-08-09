"""Security contracts for the privileged Desktop Core alpha feed."""

from __future__ import annotations

import hashlib
import json
import runpy
from pathlib import Path

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


def test_feed_is_release_3_0_only_and_wakes_after_publisher() -> None:
    text = workflow_text()
    namespace = runpy.run_path(str(TOOL))
    assert namespace["SUPPORTED_TRAINS"] == {"3.0"}
    assert "branches: [release/3.0]" in text
    assert 'workflows: ["Publish to PyPI"]' in text
    assert "workflow_run.conclusion == 'success'" in text


def test_release_discovery_ignores_3_1(tmp_path: Path, capsys) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text("alpha/v3.0.0a26\nalpha/v3.1.0a99\nalpha/v3.0.0a27\n", encoding="utf-8")
    namespace = runpy.run_path(str(TOOL))
    namespace["discover_release"](tags)
    output = capsys.readouterr().out
    assert "version=3.0.0a27" in output
    assert "tag=alpha/v3.0.0a27" in output
    assert "branch=release/3.0" in output
    assert "3.1" not in output


def test_privileged_feed_is_main_bound_and_pins_candidate_provenance() -> None:
    text = workflow_text()
    job = publish_job()
    assert job["permissions"] == {"contents": "write", "id-token": "write", "attestations": "write"}
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in text
    assert "ref: ${{ github.sha }}" in text
    assert "persist-credentials: false" in text
    assert "refs/tags/${CORE_TAG}^{commit}" in text
    assert "refs/remotes/origin/${RELEASE_BRANCH}" in text
    assert "merge-base --is-ancestor" in text
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/publish.yml"' in text
    assert '--signer-digest "$SOURCE_SHA"' in text
    assert '--source-ref "refs/heads/${RELEASE_BRANCH}"' in text


def test_feed_uses_apple_trust_and_no_redundant_manifest_key() -> None:
    text = workflow_text()
    helper = TOOL.read_text(encoding="utf-8")
    assert "HOL_GUARD_CORE_UPDATE_PRIVATE_KEY" not in text
    assert "HOL_GUARD_CORE_UPDATE_PUBLIC_KEY" not in text
    assert "json.sig" not in text
    assert "minisign" not in helper.lower()
    assert "bunx @tauri-apps/cli" not in text
    assert "IMPORTED_CERTIFICATE_SHA1=$(openssl x509" in text
    assert "-passin env:APPLE_CERTIFICATE_PASSWORD" in text
    assert 'codesign --display --extract-certificates="$RUNNER_TEMP/codesign-cert-"' in text
    assert 'test "$CERTIFICATE_SHA1" = "$IMPORTED_CERTIFICATE_SHA1"' in text
    assert 'grep -Fx "Authority=$APPLE_SIGNING_IDENTITY"' in text
    assert 'test "$CERTIFICATE_SHA1" = "$SELECTOR_SHA1"' in text
    assert 'grep -Fx "TeamIdentifier=$APPLE_TEAM_ID"' in text
    assert 'grep -F "source=Notarized Developer ID"' in text


def test_macos_feed_avoids_bash4_only_builtins_and_binds_mode() -> None:
    text = workflow_text()
    job = publish_job()
    assert "mapfile " not in text
    assert "readarray " not in text
    steps = {step.get("name"): step for step in job["steps"]}
    manifest = steps["Create or validate update manifest"]
    assert manifest["env"]["MODE"] == "${{ steps.existing.outputs.mode }}"
    assert 'test "$WHEEL_COUNT" -eq 1' in text
    assert 'test -f "$WHEEL"' in text


def test_existing_asset_set_is_all_or_nothing(tmp_path: Path, capsys) -> None:
    namespace = runpy.run_path(str(TOOL))
    assets = tmp_path / "assets.txt"
    base = "hol-guard-core-3.0.0a27-aarch64-apple-darwin"
    assets.write_text("", encoding="utf-8")
    namespace["inspect_assets"](assets, base)
    assert "mode=build" in capsys.readouterr().out
    assets.write_text(f"{base}\n{base}.json\n{base}.attested.json\n", encoding="utf-8")
    namespace["inspect_assets"](assets, base)
    assert "mode=verify_existing" in capsys.readouterr().out


def test_manifest_and_marker_bind_source_and_hashes(tmp_path: Path) -> None:
    namespace = runpy.run_path(str(TOOL))
    base = tmp_path / "core"
    manifest = Path(f"{base}.json")
    marker = Path(f"{base}.attested.json")
    base.write_bytes(b"binary")
    common = dict(
        version="3.0.0a27",
        source_commit="a" * 40,
        source_tag="alpha/v3.0.0a27",
        target="aarch64-apple-darwin",
        minimum_desktop_version="0.1.0-alpha.0",
    )
    namespace["create_manifest"](base, manifest, **common)
    namespace["validate_manifest"](base, manifest, **common)
    marker_common = {key: common[key] for key in ("version", "source_commit", "source_tag", "target")}
    marker_common.update(apple_signing_identity="Developer ID Application: HOL", apple_team_id="TEAMID")
    namespace["create_marker"](base, marker, workflow_run="123", **marker_common)
    namespace["validate_marker"](base, marker, **marker_common)
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["binarySha256"] == hashlib.sha256(b"binary").hexdigest()
    assert payload["manifestSha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert "signatureSha256" not in payload


def test_complete_feed_assets_are_attested_uploaded_and_reloaded() -> None:
    text = workflow_text()
    assert "Attest complete hardened Core asset set" in text
    assert "Publish immutable Core assets" in text
    assert 'gh release upload "$CORE_TAG" "$BASE" "$BASE.json" "$BASE.attested.json"' in text
    assert 'for asset in "$BASE" "$BASE.json" "$BASE.attested.json"; do' in text
    assert 'PUBLISHED="$RUNNER_TEMP/published-assets"' in text
    assert 'gh attestation verify "$PUBLISHED/$asset"' in text
