"""Supply chain risk detection for Guard runtime protection."""

from __future__ import annotations

import re

from codex_plugin_scanner.guard.runtime.signals import (
    RiskConfidenceLabel,
    RiskSeverityLabel,
    RiskSignalCategory,
    RiskSignalV2,
)

_NPM_LIFECYCLE_SCRIPT = re.compile(
    r'"(?:preinstall|install|postinstall|prepare|prepublish)"\s*:\s*"(?:[^"\\]|\\.)*(?:curl|wget|bash|sh|python|node|exec|eval)(?:[^"\\]|\\.)*"',
    re.IGNORECASE,
)
_NPM_POSTINSTALL_SECRET = re.compile(
    r'"postinstall"\s*:\s*"(?:[^"\\]|\\.)*(?:\.env|\.ssh|\.aws|\.netrc|password|secret|token|key)(?:[^"\\]|\\.)*"',
    re.IGNORECASE,
)
_NPM_POSTINSTALL_NETWORK = re.compile(
    r'"postinstall"\s*:\s*"(?:[^"\\]|\\.)*(?:curl|wget|fetch|http)(?:[^"\\]|\\.)*"',
    re.IGNORECASE,
)
_NPX_REMOTE = re.compile(
    r"\bnpx\s+(?:--yes\s+)?(?!ts-node|tsc\b|prettier\b|eslint\b|jest\b|mocha\b|vitest\b)[A-Za-z0-9@._/-]{3,}",
    re.IGNORECASE,
)
_UVX_REMOTE = re.compile(
    r"\buvx\s+[A-Za-z0-9._/-]{2,}",
    re.IGNORECASE,
)
_PIP_GIT = re.compile(
    r"\bpip(?:3)?\s+install\s+(?:--[^\s]+\s+)*git\+https?://",
    re.IGNORECASE,
)
_PIP_LOCAL_WITH_BUILD_BACKEND = re.compile(
    r"\bpip(?:3)?\s+install\s+\.",
    re.IGNORECASE,
)
_SETUP_PY_EXEC = re.compile(
    r"\bpython(?:3)?\s+setup\.py\s+(?:install|develop|bdist|sdist|build)\b",
    re.IGNORECASE,
)
_PYPROJECT_BUILD_BACKEND_DRIFT = re.compile(
    r"\[build-system\].*?build-backend\s*=\s*\"[^\"]+\"",
    re.DOTALL,
)
_DOCKERFILE_CURL_SHELL = re.compile(
    r"RUN\s+.*?curl\s+.*?\|\s*(?:bash|sh|python|node)",
    re.IGNORECASE,
)
_SHELL_CURL_PIPE_EXEC = re.compile(
    r"\bcurl\s+.*?\|\s*(?:bash|sh|python|node|ruby)\b",
    re.IGNORECASE,
)
_GH_ACTION_UNPINNED_SHA = re.compile(
    r"uses:\s+[A-Za-z0-9._/-]+@(?!(?:[0-9a-f]{40})\b)[A-Za-z0-9._-]+",
    re.IGNORECASE,
)
_GH_ACTION_MUTABLE_TAG = re.compile(
    r"uses:\s+[A-Za-z0-9._/-]+@v\d+(?:\.\d+)?(?!\.\d)\b",
    re.IGNORECASE,
)
_DOCKER_IMAGE_LATEST = re.compile(
    r"FROM\s+[A-Za-z0-9._/:-]+:latest\b",
    re.IGNORECASE,
)
_DOCKER_BASE_IMAGE = re.compile(
    r"^\s*FROM\s+([A-Za-z0-9._/-]+:[A-Za-z0-9._-]+)\b",
    re.IGNORECASE | re.MULTILINE,
)
_LOCKFILE_SOURCE_DRIFT = re.compile(
    r"\"resolved\"\s*:\s*\"(?!https://registry\.npmjs\.org/)[^\"]+\"",
    re.IGNORECASE,
)
_LOCKFILE_INTEGRITY_MISSING = re.compile(
    r"\"integrity\"\s*:\s*\"\"",
    re.IGNORECASE,
)
_SCRIPT_SHELL_PROFILE = re.compile(
    r"~?/\.(?:bashrc|bash_profile|zshrc|profile|zprofile)\b",
    re.IGNORECASE,
)
_SCRIPT_GIT_HOOKS = re.compile(
    r"\.git/hooks/[a-z\-]+",
    re.IGNORECASE,
)
_SCRIPT_LAUNCH_AGENT = re.compile(
    r"~/Library/LaunchAgents/",
    re.IGNORECASE,
)
_SCRIPT_CRON = re.compile(
    r"\bcrontab\s+-[el]\b|\b/etc/cron\.",
    re.IGNORECASE,
)
_PUBLISH_WITH_TOKEN = re.compile(
    r"(?:NPM_TOKEN|NODE_AUTH_TOKEN)\s*=\s*\S+\s+(?:npm|pnpm|yarn|bun)\s+publish\b"
    r"|(?:npm|pnpm|yarn|bun)\s+publish\b.*?(?:NPM_TOKEN|NODE_AUTH_TOKEN)\s*=\s*\S+",
    re.IGNORECASE | re.DOTALL,
)
_KNOWN_CRITICAL_BASE_IMAGES: dict[str, tuple[str, str]] = {
    "python:3.6.15": (
        "Python 3.6 base image is end-of-life",
        "This exact Python base image tag is end-of-life and no longer receives security fixes.",
    ),
    "node:12.22.12": (
        "Node.js 12 base image is end-of-life",
        "This exact Node.js base image tag is end-of-life and no longer receives security fixes.",
    ),
}


def detect_supply_chain_risk(
    content: str,
    *,
    file_path: str | None = None,
) -> tuple[RiskSignalV2, ...]:
    """Classify supply chain risk patterns and return typed risk signals."""
    signals: list[RiskSignalV2] = []
    _check_npm_lifecycle_scripts(content, signals)
    _check_npx_remote(content, signals)
    _check_uvx_remote(content, signals)
    _check_pip_git(content, signals)
    _check_pip_local_with_build_backend(content, signals)
    _check_setup_py_exec(content, signals)
    _check_dockerfile_curl_shell(content, signals)
    _check_shell_curl_pipe_exec(content, signals)
    _check_gh_action_unpinned(content, signals)
    _check_docker_image_latest(content, signals)
    _check_known_critical_docker_base_image(content, signals)
    _check_lockfile_source_drift(content, signals)
    _check_lockfile_integrity_missing(content, signals)
    _check_script_shell_profile(content, signals)
    _check_script_git_hooks(content, signals)
    _check_script_launch_agent(content, signals)
    _check_script_cron(content, signals)
    _check_publish_with_token(content, signals)
    return tuple(signals)


def _check_npm_lifecycle_scripts(content: str, signals: list[RiskSignalV2]) -> None:
    if _NPM_POSTINSTALL_SECRET.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.postinstall-secret-read",
                "secret",
                "critical",
                "strong",
                "Package postinstall script reads secret paths",
                "This package reads credential files during installation.",
                "postinstall reads secret path",
            )
        )
        return
    if _NPM_POSTINSTALL_NETWORK.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.postinstall-network-send",
                "network",
                "high",
                "strong",
                "Package postinstall script makes network requests",
                "This package sends network traffic during installation.",
                "postinstall uses curl/wget/fetch",
            )
        )
        return
    if _NPM_LIFECYCLE_SCRIPT.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.install-lifecycle-exec",
                "execution",
                "high",
                "likely",
                "Package lifecycle script executes shell commands",
                "This package runs shell commands during install (postinstall/prepare/install).",
                "lifecycle script contains shell exec",
            )
        )


def _check_npx_remote(content: str, signals: list[RiskSignalV2]) -> None:
    if _NPX_REMOTE.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.npx-remote-exec",
                "execution",
                "high",
                "likely",
                "npx executes a remote package without local install",
                "npx fetches and executes packages from npm on demand without pinning.",
                "npx remote execution",
                false_positive_hint="may be a trusted dev tool like prettier or eslint",
            )
        )


def _check_uvx_remote(content: str, signals: list[RiskSignalV2]) -> None:
    if _UVX_REMOTE.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.uvx-remote-exec",
                "execution",
                "high",
                "likely",
                "uvx executes a remote Python package without local install",
                "uvx fetches and runs Python packages from PyPI without pinning.",
                "uvx remote execution",
                false_positive_hint="may be a trusted dev tool",
            )
        )


def _check_pip_git(content: str, signals: list[RiskSignalV2]) -> None:
    if _PIP_GIT.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.pip-install-git",
                "execution",
                "high",
                "strong",
                "pip installs a package directly from a git repository",
                "Installing from git bypasses PyPI integrity checks and can pull arbitrary code.",
                "pip install git+https",
            )
        )


def _check_pip_local_with_build_backend(content: str, signals: list[RiskSignalV2]) -> None:
    if _PIP_LOCAL_WITH_BUILD_BACKEND.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.pip-local-build",
                "execution",
                "medium",
                "likely",
                "pip installs local package which may invoke build backend hooks",
                "Local pip install can run setup.py or pyproject.toml build hooks.",
                "pip install .",
                false_positive_hint="common in dev workflows; verify build backend is trusted",
            )
        )


def _check_setup_py_exec(content: str, signals: list[RiskSignalV2]) -> None:
    if _SETUP_PY_EXEC.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.setup-py-exec",
                "execution",
                "medium",
                "strong",
                "setup.py install/build executes arbitrary Python during packaging",
                "Running setup.py directly can execute arbitrary code in the build script.",
                "python setup.py install/build",
            )
        )


def _check_dockerfile_curl_shell(content: str, signals: list[RiskSignalV2]) -> None:
    if _DOCKERFILE_CURL_SHELL.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.dockerfile-curl-shell",
                "execution",
                "critical",
                "strong",
                "Dockerfile RUN pipes curl output to a shell",
                "This Dockerfile fetches and executes remote code during image build.",
                "Dockerfile RUN curl | bash",
            )
        )


def _check_shell_curl_pipe_exec(content: str, signals: list[RiskSignalV2]) -> None:
    if _SHELL_CURL_PIPE_EXEC.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.curl-pipe-exec",
                "execution",
                "critical",
                "strong",
                "Script pipes curl output directly to a shell interpreter",
                "Piping remote content to bash/sh/python executes untrusted code.",
                "curl | bash/sh pattern",
            )
        )


def _check_gh_action_unpinned(content: str, signals: list[RiskSignalV2]) -> None:
    if _GH_ACTION_MUTABLE_TAG.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.gh-action-mutable-tag",
                "supply_chain",
                "high",
                "strong",
                "GitHub Action uses a mutable version tag (vN or vN.N)",
                "Mutable tags can be moved to different commits by the action author.",
                "uses: action@vN",
                false_positive_hint="acceptable if action author is highly trusted",
            )
        )
    elif _GH_ACTION_UNPINNED_SHA.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.gh-action-unpinned-sha",
                "supply_chain",
                "medium",
                "likely",
                "GitHub Action does not pin to a full commit SHA",
                "Using branch names or short refs risks inadvertent code change pickup.",
                "uses: action@branch/tag",
            )
        )


def _check_docker_image_latest(content: str, signals: list[RiskSignalV2]) -> None:
    if _DOCKER_IMAGE_LATEST.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.docker-image-latest",
                "supply_chain",
                "medium",
                "likely",
                "Docker image uses the mutable :latest tag",
                "The :latest tag resolves to different image digests over time.",
                "FROM image:latest",
            )
        )


def _check_known_critical_docker_base_image(content: str, signals: list[RiskSignalV2]) -> None:
    for match in _DOCKER_BASE_IMAGE.finditer(content):
        image_ref = match.group(1).lower()
        title_reason = _KNOWN_CRITICAL_BASE_IMAGES.get(image_ref)
        if title_reason is None:
            continue
        title, plain_reason = title_reason
        signals.append(
            _sc_signal(
                "supply-chain.docker-base-image-known-critical",
                "supply_chain",
                "high",
                "strong",
                title,
                plain_reason,
                f"FROM {image_ref}",
            )
        )
        return


def _check_lockfile_source_drift(content: str, signals: list[RiskSignalV2]) -> None:
    if _LOCKFILE_SOURCE_DRIFT.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.lockfile-source-drift",
                "supply_chain",
                "high",
                "strong",
                "Lockfile package resolved URL points outside official registry",
                "A non-registry resolved URL may indicate dependency confusion or substitution.",
                "resolved URL not from registry.npmjs.org",
            )
        )


def _check_lockfile_integrity_missing(content: str, signals: list[RiskSignalV2]) -> None:
    if _LOCKFILE_INTEGRITY_MISSING.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.lockfile-integrity-missing",
                "supply_chain",
                "high",
                "strong",
                "Lockfile entry has empty integrity hash",
                "A missing integrity hash removes tamper detection for this dependency.",
                "integrity field is empty string",
            )
        )


def _check_script_shell_profile(content: str, signals: list[RiskSignalV2]) -> None:
    if _SCRIPT_SHELL_PROFILE.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.script-shell-profile",
                "persistence",
                "high",
                "strong",
                "Package script modifies shell profile",
                "This script writes to .bashrc/.zshrc which persists across shell sessions.",
                "shell profile modification in package script",
            )
        )


def _check_script_git_hooks(content: str, signals: list[RiskSignalV2]) -> None:
    if _SCRIPT_GIT_HOOKS.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.script-git-hooks",
                "persistence",
                "high",
                "strong",
                "Package script creates or modifies git hooks",
                "Git hooks can execute arbitrary code on every git operation.",
                ".git/hooks path in package script",
            )
        )


def _check_script_launch_agent(content: str, signals: list[RiskSignalV2]) -> None:
    if _SCRIPT_LAUNCH_AGENT.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.script-launch-agent",
                "persistence",
                "critical",
                "strong",
                "Package script installs a macOS Launch Agent",
                "Launch Agents run on login and provide persistent code execution.",
                "LaunchAgents path in package script",
            )
        )


def _check_script_cron(content: str, signals: list[RiskSignalV2]) -> None:
    if _SCRIPT_CRON.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.script-cron",
                "persistence",
                "high",
                "strong",
                "Package script modifies cron jobs",
                "Cron entries provide persistent scheduled code execution.",
                "crontab or /etc/cron path in package script",
            )
        )


def _check_publish_with_token(content: str, signals: list[RiskSignalV2]) -> None:
    if _PUBLISH_WITH_TOKEN.search(content):
        signals.append(
            _sc_signal(
                "supply-chain.publish-with-token",
                "secret",
                "high",
                "likely",
                "npm publish command uses an auth token",
                "Inline auth tokens in publish commands can be exfiltrated via logs.",
                "NPM_TOKEN or NODE_AUTH_TOKEN inline in publish command",
            )
        )


def _sc_signal(
    signal_id: str,
    category: RiskSignalCategory,
    severity: RiskSeverityLabel,
    confidence: RiskConfidenceLabel,
    title: str,
    plain_reason: str,
    technical_detail: str,
    false_positive_hint: str | None = None,
) -> RiskSignalV2:
    return RiskSignalV2(
        signal_id=signal_id,
        category=category,
        severity=severity,
        confidence=confidence,
        detector="supply-chain.content",
        title=title,
        plain_reason=plain_reason,
        technical_detail=technical_detail,
        evidence_ref="supply_chain_content",
        redaction_level="summary",
        false_positive_hint=false_positive_hint,
        advisory_id=None,
    )
