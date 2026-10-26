"""Cache build output, never the host's sandbox policy or qualification result."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _executable(path: Path, body: str) -> None:
    path.write_text(f"#!/usr/bin/env bash\nset -euo pipefail\n{body}\n")
    path.chmod(0o755)


def _install(tmp_path: Path, mode: str = "") -> tuple[subprocess.CompletedProcess[str], str]:
    if os.name == "nt" or shutil.which("bash") is None or shutil.which("sha256sum") is None:
        pytest.skip("exercises the Ubuntu Bash installer")
    cache = tmp_path / "cache"
    cache.mkdir()
    binary = cache / "bwrap"
    version = "0.9.0" if mode == "wrong-version" else "0.11.0"
    help_text = "--bind" if mode == "no-overlay" else "--overlay"
    _executable(binary, f'if [[ "$1" == --version ]]; then echo "bubblewrap {version}"; else echo "{help_text}"; fi')
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (cache / "bwrap.sha256").write_text(digest + "\n")
    if mode == "corrupt":
        binary.write_text(binary.read_text() + "# changed\n")
    elif mode == "bad-manifest":
        (cache / "bwrap.sha256").write_text("../another-file\n")
    elif mode == "missing-manifest":
        (cache / "bwrap.sha256").unlink()
    elif mode == "linked-binary":
        binary.rename(cache / "real-binary")
        binary.symlink_to(cache / "real-binary")
    elif mode == "linked-directory":
        link = tmp_path / "cache-link"
        link.symlink_to(cache, target_is_directory=True)
        cache = link
    elif mode in {"miss", "hit-missing-binary"}:
        binary.unlink()
    tools = tmp_path / "tools"
    tools.mkdir()
    log = tmp_path / "commands.log"
    _executable(
        tools / "sudo",
        'printf "%s\\n" "$*" >> "$COMMAND_LOG"\n'
        'case "$1" in\n'
        '  install) "$@" ;;\n'
        "  tee) cat >/dev/null ;;\n"
        '  apparmor_parser) if [[ "$MODE" == policy-failure ]]; then exit 7; fi ;;\n'
        "  *) exit 37 ;;\n"
        "esac",
    )
    _executable(tools / "apparmor_parser", "exit 0")
    script = tmp_path / "installer.sh"
    installed = tmp_path / "installed-bwrap"
    # Substitute only the privileged destination; all verification runs unchanged.
    script.write_text(
        (ROOT / "ci/containment/install-bubblewrap.sh").read_text().replace("/usr/bin/bwrap", str(installed))
    )
    result = subprocess.run(
        [shutil.which("bash"), str(script)],
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
            "BWRAP_BUILD_CACHE_DIR": str(cache),
            "BWRAP_BUILD_CACHE_HIT": "false" if mode == "miss" else "true",
            "COMMAND_LOG": str(log),
            "MODE": mode,
        },
    )
    return result, log.read_text() if log.exists() else ""


def test_cached_binary_skips_build_but_reloads_host_policy(tmp_path: Path) -> None:
    result, commands = _install(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "bubblewrap 0.11.0" in result.stdout
    assert "install -m 0755" in commands
    assert "tee /etc/apparmor.d/hol-guard-bwrap" in commands
    assert "apparmor_parser -r /etc/apparmor.d/hol-guard-bwrap" in commands
    assert "apt-get" not in commands


@pytest.mark.parametrize(
    "mode",
    [
        "corrupt",
        "bad-manifest",
        "missing-manifest",
        "wrong-version",
        "linked-binary",
        "linked-directory",
        "hit-missing-binary",
    ],
)
def test_invalid_cached_binary_fails_before_installation(tmp_path: Path, mode: str) -> None:
    result, commands = _install(tmp_path, mode)
    assert result.returncode != 0
    assert commands == ""


def test_missing_overlay_support_still_fails(tmp_path: Path) -> None:
    result, _ = _install(tmp_path, "no-overlay")
    assert result.returncode != 0


def test_policy_failure_cannot_be_hidden_by_a_cache_hit(tmp_path: Path) -> None:
    result, _ = _install(tmp_path, "policy-failure")
    assert result.returncode == 7


def test_cache_miss_keeps_the_source_build_path(tmp_path: Path) -> None:
    result, commands = _install(tmp_path, "miss")
    assert result.returncode == 37
    assert commands == "apt-get update\n"


def test_cache_is_exact_and_only_trusted_main_can_publish() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/setup-bubblewrap/action.yml").read_text())
    steps = action["runs"]["steps"]
    restore = next(step for step in steps if step.get("id") == "cache")
    assert "restore-keys" not in restore["with"]
    for field in (
        "runner.os",
        "runner.arch",
        "steps.platform.outputs.image",
        "install-bubblewrap.sh",
        "setup-bubblewrap/action.yml",
    ):
        assert field in restore["with"]["key"]
    install = next(step for step in steps if step.get("run") == "bash ci/containment/install-bubblewrap.sh")
    assert "if" not in install
    assert install["env"]["BWRAP_BUILD_CACHE_HIT"] == "${{ steps.cache.outputs.cache-hit }}"
    save = steps[-1]
    assert "github.event_name == 'push' && github.ref == 'refs/heads/main'" in save["if"]
    assert save["with"]["key"] == "${{ steps.cache.outputs.cache-primary-key }}"
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    for job in ("native-workspace", "native-gates"):
        assert any(step.get("uses") == "./.github/actions/setup-bubblewrap" for step in workflow["jobs"][job]["steps"])
    sonar = yaml.safe_load((ROOT / ".github/actions/prepare-rust-coverage/action.yml").read_text())
    assert any(step.get("uses") == "./.github/actions/setup-bubblewrap" for step in sonar["runs"]["steps"])
