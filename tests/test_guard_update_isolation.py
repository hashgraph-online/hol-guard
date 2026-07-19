"""Integration contracts for the Guard update subprocess boundary."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands, update_subprocess
from codex_plugin_scanner.guard.cli.update_subprocess import InstalledDistribution, TrustedUpdateContext
from codex_plugin_scanner.guard.mdm.contracts import (
    ManagedNetworkPolicy,
    ManagedPolicy,
    ManagedPolicyState,
    ManagedUpdatePolicy,
)


def _managed_policy_state(
    *,
    index_url: str | None,
    allow_public_registries: bool = True,
) -> ManagedPolicyState:
    policy = ManagedPolicy(
        schema_version="1",
        settings={},
        locked_settings=frozenset(),
        network=ManagedNetworkPolicy(
            proxy_mode="none",
            allow_public_registries=allow_public_registries,
        ),
        update=ManagedUpdatePolicy(owner="user", index_url=index_url),
    )
    return ManagedPolicyState(status="active", source="test", policy=policy)


def _write_python_executable(path: Path, body: str) -> None:
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _configure_update_orchestrator(
    monkeypatch: pytest.MonkeyPatch,
    *,
    managed_index_url: str,
) -> None:
    monkeypatch.setattr(
        update_commands,
        "_current_version",
        lambda: (_ for _ in ()).throw(AssertionError("version lookup escaped trusted context")),
    )
    monkeypatch.setattr(
        update_commands,
        "_current_version_from_subprocess",
        lambda _context: "9.9.9",
    )
    monkeypatch.setattr(
        TrustedUpdateContext,
        "query_distribution",
        lambda context: InstalledDistribution(
            name="hol-guard",
            version="9.9.9",
            root=context.install_prefix,
        ),
    )
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: (_ for _ in ()).throw(AssertionError("direct_url lookup escaped trusted context")),
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "uv")
    monkeypatch.setattr(
        update_commands,
        "load_managed_policy",
        lambda: _managed_policy_state(index_url=managed_index_url),
    )


def _poison_workspace(
    workspace: Path,
    *,
    site_marker: Path,
    collision_marker: Path,
) -> None:
    workspace.mkdir(parents=True)
    (workspace / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(site_marker)!r}).write_text('loaded', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (workspace / "pip.conf").write_text(
        "[global]\nindex-url = https://attacker.invalid/simple\n",
        encoding="utf-8",
    )
    (workspace / "uv.toml").write_text(
        'default-index = "https://attacker.invalid/simple"\n',
        encoding="utf-8",
    )
    _write_python_executable(
        workspace / "uv",
        "from pathlib import Path\n"
        f"Path({str(collision_marker)!r}).write_text('executed', encoding='utf-8')\n"
        "raise SystemExit(97)\n",
    )


def _apply_hostile_environment(
    monkeypatch: pytest.MonkeyPatch,
    *,
    workspace: Path,
    trusted_bin: Path,
) -> None:
    poisoned_values = {
        "PATH": os.pathsep.join((str(workspace), str(trusted_bin))),
        "HOME": str(workspace / "poison-home"),
        "PYTHONPATH": str(workspace),
        "PYTHONHOME": str(workspace / "fake-python-home"),
        "PIP_CONFIG_FILE": str(workspace / "pip.conf"),
        "PIP_INDEX_URL": "https://attacker.invalid/pip/simple",
        "PIP_EXTRA_INDEX_URL": "https://attacker.invalid/pip-extra/simple",
        "UV_CONFIG_FILE": str(workspace / "uv.toml"),
        "UV_INDEX_URL": "https://attacker.invalid/uv/simple",
        "UV_DEFAULT_INDEX": "https://attacker.invalid/uv-default/simple",
        "UV_EXTRA_INDEX_URL": "https://attacker.invalid/uv-extra/simple",
        "UV_TOOL_DIR": str(workspace / "uv-tools"),
        "UV_TOOL_BIN_DIR": str(workspace / "uv-bin"),
        "PIPX_HOME": str(workspace / "pipx-home"),
        "PIPX_BIN_DIR": str(workspace / "pipx-bin"),
        "VIRTUAL_ENV": str(workspace / "venv"),
        "CONDA_PREFIX": str(workspace / "conda"),
        "HTTP_PROXY": "http://attacker.invalid:8080",
        "HTTPS_PROXY": "http://attacker.invalid:8443",
        "REQUESTS_CA_BUNDLE": str(workspace / "attacker-ca.pem"),
        "SSL_CERT_FILE": str(workspace / "attacker-ca.pem"),
    }
    for key, value in poisoned_values.items():
        monkeypatch.setenv(key, value)


@pytest.mark.skipif(
    os.name == "nt",
    reason="executes an extensionless POSIX shebang uv fixture for the end-to-end isolation contract",
)
def test_run_guard_update_isolates_hostile_workspaces_and_redacts_managed_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_secret = "tenant-index-secret-4f61"
    managed_index_url = f"https://packages.example.test/{source_secret}/simple"
    record_path = tmp_path / "trusted-uv-records.jsonl"
    fake_prefix = tmp_path / "manager-root" / ".local" / "share" / "uv" / "tools" / "hol-guard"
    trusted_bin = tmp_path / "manager-root" / ".local" / "bin"
    trusted_bin.mkdir(parents=True)
    guard_home = tmp_path / "guard-home"
    trusted_uv = trusted_bin / "uv"
    _write_python_executable(
        trusted_uv,
        "import json\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        "record = {\n"
        "    'argv': sys.argv[1:],\n"
        "    'cwd': str(Path.cwd()),\n"
        "    'environment': dict(os.environ),\n"
        "}\n"
        f"with Path({str(record_path)!r}).open('a', encoding='utf-8') as stream:\n"
        "    stream.write(json.dumps(record, sort_keys=True) + '\\n')\n"
        "source_index = sys.argv[sys.argv.index('--default-index') + 1]\n"
        "print('already at latest version; source=' + source_index)\n",
    )
    monkeypatch.setattr(update_subprocess.sys, "prefix", str(fake_prefix))
    _configure_update_orchestrator(
        monkeypatch,
        managed_index_url=managed_index_url,
    )

    workspaces = (tmp_path / "hostile-a", tmp_path / "hostile-b")
    site_markers: list[Path] = []
    collision_markers: list[Path] = []
    payloads: list[dict[str, object]] = []
    for number, workspace in enumerate(workspaces):
        site_marker = tmp_path / f"sitecustomize-{number}.loaded"
        collision_marker = tmp_path / f"workspace-uv-{number}.executed"
        site_markers.append(site_marker)
        collision_markers.append(collision_marker)
        _poison_workspace(
            workspace,
            site_marker=site_marker,
            collision_marker=collision_marker,
        )
        _apply_hostile_environment(
            monkeypatch,
            workspace=workspace,
            trusted_bin=trusted_bin,
        )
        monkeypatch.chdir(workspace)

        payload, exit_code = update_commands.run_guard_update(
            dry_run=False,
            workspace=str(workspace),
            guard_home=guard_home,
        )

        assert exit_code == 0
        assert payload["status"] == "current"
        assert payload["changed"] is False
        payloads.append(payload)

    records = [json.loads(line) for line in record_path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 2
    assert records[0] == records[1]
    assert payloads[0] == payloads[1]
    assert not any(path.exists() for path in (*site_markers, *collision_markers))

    expected_neutral_cwd = (guard_home / "update-runtime").resolve()
    expected_argv = [
        "--no-config",
        "--no-progress",
        "--no-python-downloads",
        "tool",
        "upgrade",
        "--python",
        sys.executable,
        "--no-sources",
        "--default-index",
        managed_index_url,
        "hol-guard",
    ]
    for record in records:
        assert record["argv"] == expected_argv
        assert Path(record["cwd"]) == expected_neutral_cwd
        environment = record["environment"]
        assert Path(environment["HOME"]) == expected_neutral_cwd / "home"
        assert Path(environment["TMPDIR"]) == expected_neutral_cwd / "tmp"
        assert environment["PYTHONNOUSERSITE"] == "1"
        assert environment["PYTHONSAFEPATH"] == "1"
        assert environment["PIP_CONFIG_FILE"] == os.devnull
        assert environment["UV_NO_CONFIG"] == "1"
        assert environment["UV_PYTHON_DOWNLOADS"] == "never"
        assert environment["UV_TOOL_DIR"] == str(fake_prefix.parent)
        assert environment["UV_TOOL_BIN_DIR"] == str(tmp_path / "manager-root" / ".local" / "bin")
        for forbidden_key in (
            "PYTHONPATH",
            "PYTHONHOME",
            "PIP_INDEX_URL",
            "PIP_EXTRA_INDEX_URL",
            "UV_CONFIG_FILE",
            "UV_INDEX_URL",
            "UV_DEFAULT_INDEX",
            "UV_EXTRA_INDEX_URL",
            "PIPX_HOME",
            "PIPX_BIN_DIR",
            "VIRTUAL_ENV",
            "CONDA_PREFIX",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
        ):
            assert forbidden_key not in environment
        effective_path = {Path(entry).resolve() for entry in environment["PATH"].split(os.pathsep)}
        assert trusted_bin.resolve() in effective_path
        assert all(workspace.resolve() not in effective_path for workspace in workspaces)

    trusted_update = payloads[0]["trusted_update"]
    assert isinstance(trusted_update, dict)
    assert trusted_update["source"] == "managed_index"
    assert trusted_update["source_fingerprint"] == hashlib.sha256(managed_index_url.encode()).hexdigest()
    assert Path(str(trusted_update["cwd"])) == expected_neutral_cwd
    public_payload = json.dumps(payloads, sort_keys=True)
    assert source_secret not in public_payload
    assert managed_index_url not in public_payload
    assert "[redacted-update-source]" in str(payloads[0]["stdout"])


def test_disallowed_public_registry_without_managed_source_blocks_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "9.9.9")
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(
        update_commands,
        "load_managed_policy",
        lambda: _managed_policy_state(
            index_url=None,
            allow_public_registries=False,
        ),
    )
    context_builds = 0
    process_starts = 0

    def unexpected_context_build(**_kwargs: object) -> None:
        nonlocal context_builds
        context_builds += 1
        raise AssertionError("trusted update context must not be built")

    def unexpected_process_start(*_args: object, **_kwargs: object) -> None:
        nonlocal process_starts
        process_starts += 1
        raise AssertionError("subprocess must not start")

    monkeypatch.setattr(update_commands, "build_trusted_update_context", unexpected_context_build)
    monkeypatch.setattr(update_commands.subprocess, "run", unexpected_process_start)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 1
    assert payload["status"] == "blocked"
    assert payload["changed"] is False
    assert payload["reason_code"] == "update_source_unconfigured"
    assert "trusted_update" not in payload
    assert "command" not in payload
    assert context_builds == 0
    assert process_starts == 0


def test_status_uses_trusted_distribution_record_not_parent_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_root = tmp_path / "trusted-site-packages"
    trusted_root.mkdir()
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(
        update_commands,
        "_current_version",
        lambda: (_ for _ in ()).throw(AssertionError("parent version lookup must not run")),
    )
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: (_ for _ in ()).throw(AssertionError("parent direct_url lookup must not run")),
    )
    monkeypatch.setattr(
        update_commands,
        "_status_installed_distribution",
        lambda **_kwargs: InstalledDistribution(
            name="hol-guard",
            version="8.7.6",
            root=trusted_root,
        ),
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "current",
            "current_version": current_version,
            "latest_version": current_version,
            "update_available": False,
        },
    )

    payload = update_commands.build_guard_update_status_payload()

    assert payload["current_version"] == "8.7.6"
    version_check = payload["version_check"]
    assert isinstance(version_check, dict)
    assert version_check["current_version"] == "8.7.6"
    assert payload["auto_updatable"] is True
