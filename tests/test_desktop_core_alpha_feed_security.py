"""Security contracts for the privileged Desktop Core alpha feed."""

from __future__ import annotations

import base64
import hashlib
import json
import runpy
import subprocess
import sys
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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
    assert namespace["SUPPORTED_TRAINS"] == {"3.0"}


def test_release_discovery_ignores_inactive_3_1_train(tmp_path: Path, capsys) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text(
        "alpha/v3.0.0a8\nalpha/v3.1.0a10\nalpha/v3.0.0a9\n",
        encoding="utf-8",
    )
    namespace = runpy.run_path(str(TOOL))
    namespace["discover_release"](tags)
    output = capsys.readouterr().out
    assert "available=true" in output
    assert "version=3.0.0a9" in output
    assert "tag=alpha/v3.0.0a9" in output
    assert "train=3.0" in output
    assert "branch=release/3.0" in output
    assert "3.1" not in output


def test_candidate_requires_trusted_publish_workflow_attestation() -> None:
    text = workflow_text()
    assert 'gh attestation verify "${WHEELS[0]}"' in text
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/publish.yml"' in text
    assert '--signer-digest "$SOURCE_SHA"' in text and '--source-digest "$SOURCE_SHA"' in text
    assert '--source-ref "refs/heads/${RELEASE_BRANCH}"' in text
    assert "--deny-self-hosted-runners" in text


def test_existing_assets_are_all_or_nothing_except_safe_signature_repair() -> None:
    text = workflow_text()
    tool = TOOL.read_text(encoding="utf-8")
    assert "inspect-assets" in text
    assert 'present == {"binary", "manifest", "marker"}' in tool
    assert '_emit("mode", "repair_signature")' in tool
    assert "Refusing partial or ambiguous Core asset set" in tool
    assert 'if [[ "$MODE" == "repair_signature" ]]; then' in text
    assert 'for asset in "$BASE" "$BASE.json"; do' in text
    assert 'MARKER_SCHEMA=$(jq -r' in text
    assert 'if [[ "$MARKER_SCHEMA" != "hol-guard-core-attestation.v2" ]]' in text
    assert "rebuild legacy assets instead" in text
    assert 'gh attestation verify "$BASE.attested.json"' in text
    assert "validate-marker" in text and "--mode repair" in text
    assert 'gh release upload "$CORE_TAG" "$BASE.json.sig" "$BASE.attested.json" --clobber' in text


def test_reused_binary_requires_prior_feed_provenance() -> None:
    text = workflow_text()
    assert "Verify prior feed provenance before reusing assets" in text
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/desktop-core-alpha-feed.yml"' in text
    assert "--source-ref refs/heads/main" in text
    assert 'for asset in "$BASE" "$BASE.json"; do' in text
    assert 'for asset in "$BASE" "$BASE.json" "$BASE.json.sig" "$BASE.attested.json"; do' in text
    assert 'gh attestation verify "$asset"' in text


def test_apple_verification_pins_identity_team_and_notarized_gatekeeper_source() -> None:
    text = workflow_text()
    assert 'grep -Fx "Authority=$APPLE_SIGNING_IDENTITY"' in text
    assert 'grep -Fx "TeamIdentifier=$APPLE_TEAM_ID"' in text
    assert "spctl --assess --type execute --verbose=4" in text
    assert 'grep -F "source=Notarized Developer ID"' in text
    assert 'grep -F "Mach-O 64-bit executable arm64"' in text


def test_manifest_signature_is_required_and_uses_independent_update_key() -> None:
    text = workflow_text()
    helper_prefix = TOOL.read_text(encoding="utf-8").split("def verify_minisign", maxsplit=1)[0]
    assert "cryptography" not in helper_prefix
    assert "HOL_GUARD_CORE_UPDATE_PRIVATE_KEY" in text
    assert "HOL_GUARD_CORE_UPDATE_PRIVATE_KEY_PASSWORD" in text
    assert "HOL_GUARD_CORE_UPDATE_PUBLIC_KEY" in text
    assert "bunx @tauri-apps/cli@2.11.4 signer sign" in text
    assert "verify-minisign" in text
    assert "uv run --no-project --with cryptography==50.0.0" in text
    assert '--public-key "$CORE_UPDATE_PUBLIC_KEY"' in text
    assert 'test -s "$MANIFEST.sig"' in text
    assert ".json.sig" in text


def test_manifest_signature_verification_binds_bytes_and_public_key(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    signature_path = tmp_path / "manifest.json.sig"
    manifest.write_text('{"version":"3.0.0a1"}\n', encoding="utf-8")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = b"guardkey"
    encoded_key = base64.b64encode(b"Ed" + key_id + public_key).decode()
    message = hashlib.blake2b(manifest.read_bytes(), digest_size=64).digest()
    signature = b"ED" + key_id + private_key.sign(message)
    trusted_comment = "release manifest"
    global_signature = private_key.sign(signature + trusted_comment.encode())
    signature_path.write_text(
        "untrusted comment: signature from minisign secret key\n"
        f"{base64.b64encode(signature).decode()}\n"
        f"trusted comment: {trusted_comment}\n"
        f"{base64.b64encode(global_signature).decode()}\n",
        encoding="utf-8",
    )
    command = [
        sys.executable,
        "-I",
        str(TOOL),
        "verify-minisign",
        "--file",
        str(manifest),
        "--signature",
        str(signature_path),
        "--public-key",
        encoded_key,
    ]
    verified = subprocess.run(command, capture_output=True, text=True, check=False)
    assert verified.returncode == 0, verified.stderr

    manifest.write_text('{"version":"3.0.0a2"}\n', encoding="utf-8")
    tampered = subprocess.run(command, capture_output=True, text=True, check=False)
    assert tampered.returncode != 0
    assert "signature verification failed" in tampered.stderr

    wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    wrong_key_command = [*command[:-1], base64.b64encode(b"Ed" + b"wrongkey" + wrong_key).decode()]
    rejected = subprocess.run(wrong_key_command, capture_output=True, text=True, check=False)
    assert rejected.returncode != 0
    assert "key ID does not match" in rejected.stderr


def test_complete_hardened_asset_set_is_attested_together() -> None:
    text = workflow_text()
    assert "Attest complete hardened Core asset set" in text
    assert "${{ env.RELEASE_TARGET }}.json.sig" in text
    assert "${{ env.RELEASE_TARGET }}.attested.json" in text
    assert 'gh release upload "$CORE_TAG" "$BASE" "$BASE.json" "$BASE.json.sig" "$BASE.attested.json"' in text
    assert 'gh release upload "$CORE_TAG" "$BASE.json.sig" "$BASE.attested.json" --clobber' in text


def test_final_verification_reloads_published_asset_bytes() -> None:
    text = workflow_text()
    assert 'PUBLISHED="$RUNNER_TEMP/published-assets"' in text
    assert 'gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$asset" --dir "$PUBLISHED"' in text
    assert 'test -f "$PUBLISHED/$asset"' in text
    assert 'gh attestation verify "$PUBLISHED/$asset"' in text
    assert 'gh attestation verify "$RUNNER_TEMP/dist/$asset"' not in text


def test_manifest_and_marker_bind_exact_authorized_source_and_hashes(tmp_path: Path) -> None:
    text = workflow_text()
    tool = TOOL.read_text(encoding="utf-8")
    assert "create-manifest" in text
    assert "validate-manifest" in text
    assert "create-marker" in text
    assert 'MARKER_SCHEMA = "hol-guard-core-attestation.v2"' in tool
    assert "LEGACY_MARKER_SCHEMA" not in tool
    assert '"binarySha256": _sha256(base)' in tool
    assert '"manifestSha256": _sha256(manifest)' in tool
    assert '"signatureSha256": _sha256(signature)' in tool

    base = tmp_path / "core"
    manifest = Path(f"{base}.json")
    signature = Path(f"{base}.json.sig")
    marker = Path(f"{base}.attested.json")
    base.write_bytes(b"binary")
    manifest.write_bytes(b"manifest")
    signature.write_bytes(b"replacement-signature")
    marker_payload = {
        "schema": "legacy",
        "version": "3.0.0a1",
        "sourceCommit": "a" * 40,
        "sourceTag": "alpha/v3.0.0a1",
        "target": "aarch64-apple-darwin",
        "binarySha256": hashlib.sha256(base.read_bytes()).hexdigest(),
        "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "signatureSha256": "b" * 64,
        "appleSigningIdentity": "Developer ID Application: HOL",
        "appleTeamId": "TEAMID",
    }
    marker.write_text(json.dumps(marker_payload), encoding="utf-8")
    common = [
        sys.executable,
        str(TOOL),
        "validate-marker",
        "--base",
        str(base),
        "--marker",
        str(marker),
        "--version",
        "3.0.0a1",
        "--source-commit",
        "a" * 40,
        "--source-tag",
        "alpha/v3.0.0a1",
        "--target",
        "aarch64-apple-darwin",
        "--apple-signing-identity",
        "Developer ID Application: HOL",
        "--apple-team-id",
        "TEAMID",
    ]
    rejected = subprocess.run([*common, "--mode", "repair"], capture_output=True, text=True, check=False)
    assert rejected.returncode != 0
    assert "Unsupported marker schema" in rejected.stderr

    marker.write_text(
        json.dumps(
            {
                "schema": "hol-guard-core-attestation.v1",
                "version": "3.0.0a1",
                "sourceCommit": "a" * 40,
                "sourceTag": "alpha/v3.0.0a1",
                "target": "aarch64-apple-darwin",
                "workflowRun": "123456",
                "attestedAt": "2026-08-07T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    legacy_validation = subprocess.run([*common, "--mode", "repair"], capture_output=True, text=True, check=False)
    assert legacy_validation.returncode != 0
    assert "Unsupported marker schema" in legacy_validation.stderr

    marker_payload["schema"] = "hol-guard-core-attestation.v2"
    marker.write_text(json.dumps(marker_payload), encoding="utf-8")
    repair_validation = subprocess.run([*common, "--mode", "repair"], capture_output=True, text=True, check=False)
    assert repair_validation.returncode == 0, repair_validation.stderr

    negative_cases = (
        ({"binarySha256": "c" * 64}, "Marker hash mismatch for binarySha256"),
        ({"manifestSha256": "d" * 64}, "Marker hash mismatch for manifestSha256"),
        ({"sourceCommit": "e" * 40}, "Marker mismatch for sourceCommit"),
        ({"signatureSha256": "not-a-digest"}, "valid prior signatureSha256"),
    )
    for changes, expected_error in negative_cases:
        marker.write_text(json.dumps(marker_payload | changes), encoding="utf-8")
        invalid = subprocess.run([*common, "--mode", "repair"], capture_output=True, text=True, check=False)
        assert invalid.returncode != 0
        assert expected_error in invalid.stderr


def test_privileged_inline_python_is_isolated_from_workspace_import_shadowing() -> None:
    text = workflow_text()
    inline_python = [line.strip() for line in text.splitlines() if "python3" in line and "<<" in line]
    assert inline_python
    assert all("python3 -I" in line for line in inline_python)
    assert "python3 -I scripts/release/desktop_core_alpha_feed.py" in text
