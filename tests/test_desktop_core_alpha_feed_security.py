"""Security contracts for the privileged Desktop Core stable feed."""

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
FROZEN_ENTRYPOINT = ROOT / "scripts" / "mdm" / "hol-guard-entry.py"


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


def test_feed_is_stable_3_0_only_and_wakes_after_main_publisher() -> None:
    text = workflow_text()
    namespace = runpy.run_path(str(TOOL))
    trusted_push = """push:
    branches: [main]
    paths:
      - .github/workflows/desktop-core-alpha-feed.yml
      - scripts/release/desktop_core_alpha_feed.py"""
    assert namespace["SUPPORTED_TRAINS"] == {"3.0"}
    assert trusted_push in text
    assert "branches: [main]" in text
    assert 'workflows: ["Publish to PyPI"]' in text
    assert "workflow_run.conclusion == 'success'" in text


def test_release_discovery_ignores_prereleases_and_3_1(tmp_path: Path, capsys) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text("alpha/v3.0.7a1\nv3.1.0\nv3.0.6\nv3.0.7\n", encoding="utf-8")
    namespace = runpy.run_path(str(TOOL))
    namespace["discover_release"](tags)
    output = capsys.readouterr().out
    assert "version=3.0.7" in output
    assert "tag=v3.0.7" in output
    assert "branch=main" in output
    assert "3.1" not in output


def test_release_discovery_can_backfill_an_exact_stable_version(tmp_path: Path, capsys) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text("v3.0.6\nv3.0.7\n", encoding="utf-8")
    namespace = runpy.run_path(str(TOOL))
    namespace["discover_release"](tags, "3.0.6")
    output = capsys.readouterr().out
    assert "version=3.0.6" in output
    assert "tag=v3.0.6" in output


def test_release_discovery_rejects_unpublished_or_prerelease_backfill(tmp_path: Path) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text("alpha/v3.0.6a1\nv3.0.7\n", encoding="utf-8")
    namespace = runpy.run_path(str(TOOL))
    with pytest.raises(SystemExit, match="not an eligible published release"):
        namespace["discover_release"](tags, "3.0.6")


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
    job = publish_job()
    steps = {step.get("name"): step for step in job["steps"]}
    extraction_line = (
        'codesign --display --extract-certificates "$BINARY" >/dev/null 2> "$RUNNER_TEMP/codesign-certificates.txt"'
    )
    extraction_lines = [
        line.strip() for line in text.splitlines() if "codesign --display --extract-certificates" in line
    ]
    verify = steps["Verify exact Apple identity, notarization, and Core contract"]
    verify_run = verify["run"]
    assert isinstance(verify_run, str)
    assert "HOL_GUARD_CORE_UPDATE_PRIVATE_KEY" not in text
    assert "HOL_GUARD_CORE_UPDATE_PUBLIC_KEY" not in text
    assert "json.sig" not in text
    assert "minisign" not in helper.lower()
    assert "bunx @tauri-apps/cli" not in text
    assert steps["Import Apple signing identity"]["if"] == "steps.release.outputs.available == 'true'"
    assert "security find-identity -v -p codesigning" in text
    assert "apple-signing-fingerprint.txt" in text
    assert 'CERT_DIR="$RUNNER_TEMP/codesign-certs"' in text
    assert 'cd "$CERT_DIR"' in text
    assert extraction_lines == [extraction_line]
    assert '--extract-certificates "$CERT_DIR"' not in text
    assert '--extract-certificates "$CERT_PREFIX"' not in text
    assert 'test -s "$CERT_DIR/codesign0"' in text
    assert 'cat "$RUNNER_TEMP/codesign-certificates.txt" >&2' in text
    assert "openssl x509 -inform DER" in text
    assert 'test "$ACTUAL_FINGERPRINT" = "$EXPECTED_FINGERPRINT"' in text
    assert 'grep -Fx "Authority=$APPLE_SIGNING_IDENTITY"' not in text
    assert 'grep -Fx "TeamIdentifier=$APPLE_TEAM_ID"' in text
    assert verify["env"]["MODE"] == "${{ steps.existing.outputs.mode }}"
    assert "spctl --assess" not in verify_run
    assert 'test -s "$RUNNER_TEMP/notary-result.json"' in verify_run
    assert '.status == "Accepted" and (.id | type == "string" and length > 0)' in verify_run


def test_feed_builds_core_with_multiprocessing_safe_entrypoint() -> None:
    entrypoint = FROZEN_ENTRYPOINT.read_text(encoding="utf-8")
    freeze_dispatch = entrypoint.index("freeze_support()")
    guard_import = entrypoint.index("from codex_plugin_scanner.guard.frozen_daemon_runtime")
    assert freeze_dispatch < guard_import
    assert "scripts/mdm/hol-guard-entry.py" in workflow_text()


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
    assert '--pattern "hol_guard-${CORE_VERSION}-*-macosx_*_arm64.whl"' in text
    assert '-name "hol_guard-${CORE_VERSION}-*-macosx_*_arm64.whl"' in text
    assert '--pattern "hol_guard-${CORE_VERSION}-*.whl"' not in text
    assert '-name "hol_guard-${CORE_VERSION}-*.whl"' not in text


def test_frozen_sidecar_stages_cloud_review_package_data() -> None:
    text = workflow_text()
    assert "python3 -I scripts/release/stage_guard_cloud_review_artifacts.py" in text
    assert '--source-root "$SOURCE"' in text


def test_frozen_sidecar_stages_attested_native_runtime() -> None:
    text = workflow_text()
    build = next(step for step in publish_job()["steps"] if step.get("name") == "Build standalone Core executable")
    run = build["run"]
    assert isinstance(run, str)
    assert 'cp "$WHEEL" "$RUNNER_TEMP/attested-macos-arm64.whl"' in text
    assert "python3 -I scripts/release/stage_native_runtime_for_desktop_core.py" in run
    assert '--wheel "$RUNNER_TEMP/attested-macos-arm64.whl"' in run
    assert '--expected-version "$CORE_VERSION"' in run
    assert '--expected-target "$RELEASE_TARGET"' in run
    assert "--refresh-identity" in run
    assert run.index("stage_native_runtime_for_desktop_core.py") < run.index("uv run --no-sync pyinstaller")
    assert run.index(
        'codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$NATIVE_RUNTIME"'
    ) < run.index("uv run --no-sync pyinstaller")
    assert '--add-data "$NATIVE_RUNTIME:codex_plugin_scanner/_native"' in run
    assert '--add-data "$NATIVE_MANIFEST:codex_plugin_scanner/_native"' in run
    assert "--add-binary" not in run
    assert "python3 -I scripts/release/verify_pyinstaller_native_runtime.py" in run
    native_verify = run.index("verify_pyinstaller_native_runtime.py")
    signing_verify = run.index("verify_pyinstaller_macos_signing.py")
    assert signing_verify < native_verify


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
        version="3.0.7",
        source_commit="a" * 40,
        source_tag="v3.0.7",
        target="aarch64-apple-darwin",
        minimum_desktop_version="0.1.0-beta.0",
    )
    namespace["create_manifest"](base, manifest, **common)
    namespace["validate_manifest"](base, manifest, **common)
    assert json.loads(manifest.read_text(encoding="utf-8"))["channel"] == "stable"
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
