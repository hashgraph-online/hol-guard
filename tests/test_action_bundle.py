"""Regression checks for the GitHub Action bundle and Marketplace packaging."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_action_metadata_includes_marketplace_branding_and_fallback_install() -> None:
    action_text = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")

    assert 'name: "HOL Codex Plugin Scanner"' in action_text
    assert "branding:" in action_text
    assert 'icon: "check-circle"' in action_text
    assert 'color: "blue"' in action_text
    assert "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405" in action_text
    assert 'python3 -m pip install "pypi-attestations==' in action_text
    assert "install_source:" in action_text
    assert 'default: "pypi"' in action_text
    assert "INSTALL_SOURCE: ${{ inputs.install_source }}" in action_text
    assert "INSTALL_CISCO: ${{ inputs.install_cisco }}" in action_text
    assert 'if [ "$INSTALL_SOURCE" = "local" ]; then' in action_text
    assert "install_source=local requires the source repository checkout" in action_text
    assert 'python3 -m pip install "$LOCAL_SOURCE"' in action_text
    assert 'python3 -m pip install "$LOCAL_SOURCE[cisco]"' in action_text
    assert 'elif [ "$INSTALL_SOURCE" = "pypi" ]; then' in action_text
    assert (
        'python3 -m pip download --only-binary=:all: --no-deps --dest "$DIST_DIR" '
        '"codex-plugin-scanner==${SCANNER_VERSION}"'
    ) in action_text
    assert "python3 -m pypi_attestations verify pypi \\" in action_text
    assert 'python3 -m pip install "$DIST_DIR/$DIST_BASENAME"' in action_text
    assert 'python3 -m pip install "cisco-ai-skill-scanner==${CISCO_VERSION}"' in action_text
    assert "scanner-version.txt" in action_text
    assert "cisco-version.txt" in action_text
    assert "pypi-attestations-version.txt" in action_text
    assert 'SCANNER_REPOSITORY="https://github.com/hashgraph-online/codex-plugin-scanner"' in action_text
    assert "write_step_summary:" in action_text
    assert "profile:" in action_text
    assert "config:" in action_text
    assert "baseline:" in action_text
    assert "online:" in action_text
    assert "upload_sarif:" in action_text
    assert "sarif_category:" in action_text
    assert "registry_payload_output:" in action_text
    assert "submission_enabled:" in action_text
    assert "policy_pass:" in action_text
    assert "verify_pass:" in action_text
    assert "grade_label:" in action_text
    assert "max_severity:" in action_text
    assert "findings_total:" in action_text
    assert "report_path:" in action_text
    assert "registry_payload_path:" in action_text
    assert "submission_issue_urls:" in action_text
    assert "python3 -m codex_plugin_scanner.action_runner" in action_text
    assert "MODE: ${{ inputs.mode }}" in action_text
    assert "PROFILE: ${{ inputs.profile }}" in action_text
    assert "CONFIG: ${{ inputs.config }}" in action_text
    assert "BASELINE: ${{ inputs.baseline }}" in action_text
    assert "ONLINE: ${{ inputs.online }}" in action_text
    assert "value: ${{ steps.scan.outputs.score }}" in action_text
    assert "value: ${{ steps.scan.outputs.grade }}" in action_text
    assert "value: ${{ steps.scan.outputs.policy_pass }}" in action_text
    assert "value: ${{ steps.scan.outputs.verify_pass }}" in action_text
    assert "value: ${{ steps.scan.outputs.grade_label }}" in action_text
    assert "value: ${{ steps.scan.outputs.max_severity }}" in action_text
    assert "value: ${{ steps.scan.outputs.findings_total }}" in action_text
    assert "value: ${{ steps.scan.outputs.report_path }}" in action_text
    assert "value: ${{ steps.scan.outputs.registry_payload_path }}" in action_text
    assert "value: ${{ steps.scan.outputs.submission_eligible }}" in action_text
    assert "value: ${{ steps.scan.outputs.submission_performed }}" in action_text
    assert "value: ${{ steps.scan.outputs.submission_issue_urls }}" in action_text
    assert "value: ${{ steps.scan.outputs.submission_issue_numbers }}" in action_text
    assert "GITHUB_STEP_SUMMARY" in action_text
    assert "github/codeql-action/upload-sarif@" in action_text


def test_publish_workflow_attaches_marketplace_action_bundle() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert "Build GitHub Action bundle" in workflow_text
    assert "hol-codex-plugin-scanner-action-v${VERSION}.zip" in workflow_text
    assert "Attest GitHub release assets" in workflow_text
    assert "actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32" in workflow_text
    assert "attestations: write" in workflow_text
    assert "id-token: write" in workflow_text
    assert 'cp action/action.yml "${BUNDLE_ROOT}/action.yml"' in workflow_text
    assert """printf '%s\\n' "${VERSION}" > "${BUNDLE_ROOT}/scanner-version.txt" """[:-1] in workflow_text
    assert 'cp action/cisco-version.txt "${BUNDLE_ROOT}/cisco-version.txt"' in workflow_text
    assert 'cp action/pypi-attestations-version.txt "${BUNDLE_ROOT}/pypi-attestations-version.txt"' in workflow_text
    assert "dist/codex-plugin-scanner-v${VERSION}.intoto.jsonl" in workflow_text
    assert "Collect release asset files" in workflow_text
    assert "find dist -maxdepth 1 -type f -print0 | sort -z" in workflow_text
    assert 'mapfile -t RELEASE_ASSETS <<\'EOF\'' in workflow_text
    assert '"${RELEASE_ASSETS[@]}"' in workflow_text
    assert "subject-path: |" in workflow_text
    assert "dist/*" in workflow_text
    assert "docker pull ghcr.io/hashgraph-online/codex-plugin-scanner:${VERSION}" in workflow_text
    assert "publish-container:" in workflow_text
    assert "packages: write" in workflow_text
    assert "docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2" in workflow_text
    assert "docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567" in workflow_text
    assert "docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83" in workflow_text
    assert "ghcr.io/${{ github.repository }}" in workflow_text
    assert "${IMAGE_NAME}:latest" in workflow_text
    assert "org.opencontainers.image.version=${{ needs.build.outputs.version }}" in workflow_text
    e2e_workflow_text = (ROOT / ".github" / "workflows" / "e2e-test.yml").read_text(encoding="utf-8")
    assert e2e_workflow_text.count("install_source: local") == 5


def test_ci_workflow_covers_cross_platform_runtime() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "windows-latest" in workflow_text
    assert "macos-latest" in workflow_text


def test_publish_action_repo_workflow_syncs_action_repository() -> None:
    workflow_text = (ROOT / ".github" / "workflows" / "publish-action-repo.yml").read_text(encoding="utf-8")

    assert "Publish GitHub Action Repository" in workflow_text
    assert "ACTION_REPO_TOKEN" in workflow_text
    assert "hashgraph-online/hol-codex-plugin-scanner-action" in workflow_text
    assert "Validate publication credentials" in workflow_text
    assert "Compute scanner package version" in workflow_text
    assert "paths:" not in workflow_text
    assert "if: secrets.ACTION_REPO_TOKEN != ''" not in workflow_text
    assert (
        "git status --short -- action.yml README.md scanner-version.txt "
        "cisco-version.txt pypi-attestations-version.txt LICENSE SECURITY.md CONTRIBUTING.md"
    ) in workflow_text
    assert "SOURCE_REF" in workflow_text
    assert 'gh repo clone "$ACTION_REPOSITORY" action-repo -- --depth 1' in workflow_text
    assert "fetch-depth: 0" in workflow_text
    assert (
        'git remote set-url origin "https://x-access-token:${ACTION_REPO_TOKEN}@github.com/$ACTION_REPOSITORY.git"'
    ) in workflow_text
    assert 'cp "${GITHUB_WORKSPACE}/action/action.yml" action.yml' in workflow_text
    assert """printf '%s\\n' "${{ steps.scanner_version.outputs.version }}" > scanner-version.txt""" in workflow_text
    assert 'cp "${GITHUB_WORKSPACE}/action/cisco-version.txt" cisco-version.txt' in workflow_text
    assert (
        'cp "${GITHUB_WORKSPACE}/action/pypi-attestations-version.txt" pypi-attestations-version.txt'
    ) in workflow_text
    assert "git push origin HEAD:main" in workflow_text
    assert 'gh release view "${TAG}" --repo "$ACTION_REPOSITORY"' in workflow_text
    assert 'git ls-remote --tags origin "refs/tags/${TAG}"' in workflow_text
    assert "git push origin refs/tags/v1 --force" in workflow_text
    assert "steps.release_state.outputs.release_exists == 'false'" in workflow_text
    assert "steps.release_state.outputs.tag_exists == 'true'" in workflow_text
    assert 'gh release create "${TAG}"' in workflow_text
    assert "--generate-notes" in workflow_text
    assert "Published automatically from ${SOURCE_SERVER_URL}/${SOURCE_REPOSITORY}/tree/${SOURCE_REF}" in workflow_text


def test_action_bundle_docs_live_in_action_readme() -> None:
    action_readme = (ROOT / "action" / "README.md").read_text(encoding="utf-8")

    assert "Hashgraph-Online.png" in action_readme
    assert "Latest Release" in action_readme
    assert "Marketplace-facing wrapper" in action_readme
    assert "root `action.yml` layout" in action_readme
    assert "published action bundle" in action_readme
    assert "Source of Truth" in action_readme
    assert "verifies its PyPI provenance" in action_readme
    assert "install_source: local" in action_readme
    assert "uses: ./action" in action_readme
    assert "ghcr.io/hashgraph-online/codex-plugin-scanner:<version>" in action_readme
    assert "online`, `submission_enabled`, and `upload_sarif`" in action_readme
    assert "registry_payload_output" in action_readme
    assert "grade_label" in action_readme
    assert "max_severity" in action_readme
    assert "submission issue" in action_readme
    assert "awesome-codex-plugins" in action_readme
    assert "publish-action-repo.yml" in action_readme
    assert "hashgraph-online/hol-codex-plugin-scanner-action@v1" in action_readme
    assert "actions/checkout@v4" in action_readme
    assert "actions/github-script@v7" in action_readme
    assert "opt-in Cisco skill-scanner dependency used by this repo" in action_readme


def test_readme_uses_stable_apache_license_badge() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "https://img.shields.io/badge/license-Apache--2.0-blue.svg" in readme
    assert "https://img.shields.io/github/license/hashgraph-online/codex-plugin-scanner" not in readme
    assert "publish-action-repo.yml" in readme
    assert "docs/github-action-marketplace.md" not in readme
    assert "ghcr.io/hashgraph-online/codex-plugin-scanner:<version>" in readme
    assert "Container Image" in readme


def test_container_files_exist_for_enterprise_distribution() -> None:
    dockerfile_text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    dockerignore_text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    docker_requirements_text = (ROOT / "docker-requirements.txt").read_text(encoding="utf-8")

    assert "FROM python:3.12-slim@sha256:" in dockerfile_text
    assert "cat <<'EOF' >/usr/local/bin/codex-plugin-scanner" in dockerfile_text
    assert 'ENTRYPOINT ["codex-plugin-scanner"]' in dockerfile_text
    assert "COPY docker-requirements.txt LICENSE README.md /app/" in dockerfile_text
    assert "python3 -m pip install --require-hashes -r /app/docker-requirements.txt" in dockerfile_text
    assert dockerfile_text.index("COPY docker-requirements.txt LICENSE README.md /app/") < dockerfile_text.index(
        "RUN python3 -m pip install --require-hashes -r /app/docker-requirements.txt"
    )
    assert dockerfile_text.index("RUN python3 -m pip install --require-hashes -r /app/docker-requirements.txt") < (
        dockerfile_text.index("COPY src /app/src")
    )
    assert "SOURCE_ROOT = \"/app/src\"" in dockerfile_text
    assert "WORKSPACE = \"/workspace\"" in dockerfile_text
    assert "from codex_plugin_scanner.cli import main" in dockerfile_text
    assert "USER scanner" in dockerfile_text
    assert "rich==14.2.0" in docker_requirements_text
    assert "--hash=sha256:" in docker_requirements_text
    assert ".git" in dockerignore_text
    assert "tests" in dockerignore_text


def test_license_declares_spdx_identifier() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

    assert license_text.startswith("SPDX-License-Identifier: Apache-2.0")
