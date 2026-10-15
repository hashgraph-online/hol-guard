"""Wheel profile selection tests: dev/release stores, dev env isolation and script gating."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet import qualify, qualify_setup
from tests.test_guard_gauntlet_qualify import SHA


def _dev_wheel_script(marker: bool = True) -> bytes:
    commands = (qualify.REPO / qualify_setup.WHEEL_BUILD_SCRIPT).read_bytes()
    if marker:
        return commands
    return commands.replace(qualify_setup.DEV_WHEEL_MARKER.encode(), b"HOL_GUARD_SIZE_CHECK")


def _wheel_build_fakes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tag: str, *, script: bytes
) -> tuple[list[list[str]], list[dict[str, str]]]:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(qualify_setup.platform, "machine", lambda: "arm64")
    # The rebuild path must not depend on this host actually carrying cargo/jq.
    monkeypatch.setattr(qualify_setup.shutil, "which", lambda tool: "/bin/" + tool)
    monkeypatch.setattr(
        qualify_setup, "git_show", lambda _r, _s, path: script if path == qualify_setup.WHEEL_BUILD_SCRIPT else b""
    )
    calls: list[list[str]] = []
    envs: list[dict[str, str]] = []

    def fake_logged(argv: list[str], *, cwd: Path, log: Path, env: dict[str, str] | None = None, **_kw: Any) -> None:
        calls.append(argv)
        envs.append(dict(env or {}))
        if argv[:3] == ["git", "worktree", "add"]:
            worktree = Path(argv[4])
            (worktree / "scripts" / "ci").mkdir(parents=True)
            (worktree / qualify_setup.WHEEL_BUILD_SCRIPT).write_bytes(script)
        elif argv[:3] == ["nice", "-n", "10"]:
            dist = cwd / "native-dist"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / f"hol_guard-1.0.0-{tag}.whl").write_bytes(b"new wheel bytes")

    monkeypatch.setattr(qualify_setup, "run_logged", fake_logged)
    return calls, envs


def test_wheel_cache_requires_a_matching_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tag = "macosx_11_0_arm64"
    calls, _envs = _wheel_build_fakes(tmp_path, monkeypatch, tag, script=_dev_wheel_script(marker=False))
    store = tmp_path / "cache" / "wheels" / f"{SHA}-{tag}"
    for level in (store.parent.parent, store.parent, store):
        level.mkdir(mode=0o700)
    wheel_bytes = b"fake wheel bytes"
    (store / f"hol_guard-1.0.0-{tag}.whl").write_bytes(wheel_bytes)

    # A stale digest record rebuilds; the cache stores and digests the new wheel.
    (store / "wheel.sha256").write_text("0" * 64 + "\n")
    result = qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    digest = hashlib.sha256(b"new wheel bytes").hexdigest()
    assert result == {
        "path": str(store / f"hol_guard-1.0.0-{tag}.whl"),
        "sha256": digest,
        "cached": False,
        "profile": "release",
    }
    assert any(argv[:3] == ["nice", "-n", "10"] and argv[-1].endswith("build-native-wheel-macos.sh") for argv in calls)
    assert (store / "wheel.sha256").read_text().strip() == digest

    calls.clear()
    result = qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    assert result["cached"] is True and result["profile"] == "release" and not calls


def test_dev_wheel_build_uses_the_dev_profile_and_its_own_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tag = "macosx_11_0_arm64"
    calls, envs = _wheel_build_fakes(tmp_path, monkeypatch, tag, script=_dev_wheel_script())
    metadata = {
        "packages": [
            {"name": "hol-guard-runtime", "id": "path+file:///repo/rust#hol-guard-runtime@3.0.0"},
            {"name": "guard-rules", "id": "path+file:///repo/rust#guard-rules@0.1.0"},
            {"name": "serde", "id": "registry+https://index/serde@1.0.0"},
        ],
        "workspace_members": [
            "path+file:///repo/rust#hol-guard-runtime@3.0.0",
            "path+file:///repo/rust#guard-rules@0.1.0",
        ],
    }

    def fake_metadata(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(metadata), stderr="")

    write_dev_config = qualify_setup._write_dev_cargo_config
    monkeypatch.setattr(
        qualify_setup,
        "_write_dev_cargo_config",
        lambda worktree, **kw: write_dev_config(worktree, runner=fake_metadata),
    )
    result = qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    store = tmp_path / "cache" / "wheels" / f"{SHA}-{tag}-dev"
    assert result["profile"] == "dev" and result["cached"] is False
    assert result["path"] == str(store / f"hol_guard-1.0.0-{tag}.whl")
    build_index = next(i for i, argv in enumerate(calls) if argv[:3] == ["nice", "-n", "10"])
    build_env = envs[build_index]
    assert build_env["HOL_GUARD_DEV_WHEEL"] == "1"
    assert build_env["CARGO_PROFILE_RELEASE_LTO"] == "false"
    assert build_env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] == "16"
    worktree = tmp_path / "cache" / "build-worktree"
    assert (worktree / ".cargo" / "config.toml").read_text() == (
        '[profile.release.package."guard-rules"]\nopt-level = 0\n\n'
        '[profile.release.package."hol-guard-runtime"]\nopt-level = 0\n\n'
    )


def test_release_wheel_build_excludes_the_dev_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tag = "macosx_11_0_arm64"
    calls, envs = _wheel_build_fakes(tmp_path, monkeypatch, tag, script=_dev_wheel_script())
    for name in qualify_setup.DEV_WHEEL_ENV:
        monkeypatch.setenv(name, "leaked")
    result = qualify_setup.ensure_wheel(
        tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run", release_profile=True
    )
    assert result["profile"] == "release"
    assert Path(result["path"]).parent.name == f"{SHA}-{tag}"
    build_index = next(i for i, argv in enumerate(calls) if argv[:3] == ["nice", "-n", "10"])
    assert not any(name in envs[build_index] for name in qualify_setup.DEV_WHEEL_ENV)
    assert not (tmp_path / "cache" / "build-worktree" / ".cargo" / "config.toml").exists()


def test_candidates_without_the_dev_marker_fall_back_to_the_release_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tag = "macosx_11_0_arm64"
    _wheel_build_fakes(tmp_path, monkeypatch, tag, script=_dev_wheel_script(marker=False))
    result = qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    assert result["profile"] == "release"
    assert Path(result["path"]).parent.name == f"{SHA}-{tag}"


def test_dev_wheel_cache_hit_skips_the_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tag = "macosx_11_0_arm64"
    calls, _envs = _wheel_build_fakes(tmp_path, monkeypatch, tag, script=_dev_wheel_script())
    store = tmp_path / "cache" / "wheels" / f"{SHA}-{tag}-dev"
    for level in (store.parent.parent, store.parent, store):
        level.mkdir(mode=0o700)
    wheel = store / f"hol_guard-1.0.0-{tag}.whl"
    wheel.write_bytes(b"cached dev wheel")
    (store / "wheel.sha256").write_text(hashlib.sha256(b"cached dev wheel").hexdigest() + "\n")
    result = qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    assert result["cached"] is True and result["profile"] == "dev"
    assert result["path"] == str(wheel)
    assert not calls


def test_wheel_script_applies_size_budgets_only_without_the_dev_marker() -> None:
    commands = (qualify.REPO / qualify_setup.WHEEL_BUILD_SCRIPT).read_text(encoding="utf-8")
    assert 'if [[ "${HOL_GUARD_DEV_WHEEL:-}" == "1" ]]; then' in commands
    assert "python scripts/ci/check_wheel_size.py --dist-dir native-dist" in commands
