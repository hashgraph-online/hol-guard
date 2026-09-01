"""Local protection recovery must restore hooks and evidence in one pass."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import _live_hook_verification
from codex_plugin_scanner.guard.adapters.grok import grok_runtime_hooks_verified
from codex_plugin_scanner.guard.cli.install_commands import (
    _grok_hook_command_is_guard,
    _grok_managed_config_is_active,
    apply_managed_install,
    grok_hooks_protection_ready,
)
from codex_plugin_scanner.guard.daemon.server import (
    _PROTECTION_REPAIR_PROBE_COMMAND,
    GuardDaemonServer,
    _repair_command_activity_persistence_health,
)
from codex_plugin_scanner.guard.managed_install_proof import (
    bind_managed_install_proof,
    verify_managed_install_proof,
)
from codex_plugin_scanner.guard.runtime_artifact_reconciliation import (
    repair_failing_managed_harness_hooks,
)
from codex_plugin_scanner.guard.store import GuardStore

_NOW = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _clear_grok_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROK_HOME", raising=False)


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )


def _stale_pretool_payload() -> dict[str, object]:
    return {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "true", "timeout": 30}]},
                {
                    "matcher": "run_terminal_command",
                    "hooks": [{"type": "command", "command": "true", "timeout": 30}],
                },
            ]
        }
    }


def test_protection_repair_probe_avoids_force_push() -> None:
    assert "git push" not in _PROTECTION_REPAIR_PROBE_COMMAND
    assert "git status --porcelain=v1" in _PROTECTION_REPAIR_PROBE_COMMAND


def _write_intercepting_grok_hooks(hooks_dir: Path) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    command = "hol-guard hook grok"
    (hooks_dir / "hol-guard-pretooluse.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"type": "command", "command": command, "timeout": 30}]},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    observe = {"hooks": [{"type": "command", "command": command, "timeout": 15}]}
    (hooks_dir / "hol-guard-prompt.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "UserPromptSubmit": [observe],
                    "SubagentStart": [observe],
                    "SessionStart": [observe],
                }
            }
        ),
        encoding="utf-8",
    )


def test_live_grok_hooks_pass_when_managed_config_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_intercepting_grok_hooks(ctx.home_dir / ".grok" / "hooks")
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("grok", True, None, {"harness": "grok", "active": True}, "2026-08-17T12:00:00+00:00")

    assert grok_hooks_protection_ready(ctx) is False
    assert grok_runtime_hooks_verified(ctx) is True
    assert _live_hook_verification(store.list_managed_installs(), store) == {"grok": True}


def test_live_grok_hooks_reject_empty_observe_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    hooks_dir = ctx.home_dir / ".grok" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "hol-guard-pretooluse.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "hol-guard hook grok",
                                    "timeout": 30,
                                }
                            ]
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (hooks_dir / "hol-guard-prompt.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "UserPromptSubmit": [],
                    "SubagentStart": [],
                    "SessionStart": [],
                }
            }
        ),
        encoding="utf-8",
    )
    (ctx.home_dir / ".grok" / "managed_config.toml").write_text(
        '# BEGIN HOL GUARD MANAGED GROK\ndeny = ["Read(**/.grok/auth/**)"]\n# END HOL GUARD MANAGED GROK\n',
        encoding="utf-8",
    )
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("grok", True, None, {"harness": "grok", "active": True}, _NOW.isoformat())
    assert grok_hooks_protection_ready(ctx) is False


def test_live_grok_hooks_reject_managed_rule_outside_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    hooks_dir = ctx.home_dir / ".grok" / "hooks"
    hooks_dir.mkdir(parents=True)
    command_hook = {
        "hooks": [{"type": "command", "command": "hol-guard hook grok", "timeout": 15}]
    }
    (hooks_dir / "hol-guard-pretooluse.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "hol-guard hook grok",
                                    "timeout": 30,
                                }
                            ]
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (hooks_dir / "hol-guard-prompt.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "UserPromptSubmit": [command_hook],
                    "SubagentStart": [command_hook],
                    "SessionStart": [command_hook],
                }
            }
        ),
        encoding="utf-8",
    )
    (ctx.home_dir / ".grok" / "managed_config.toml").write_text(
        'deny = ["Read(**/.grok/auth/**)"]\n'
        "# BEGIN HOL GUARD MANAGED GROK\n"
        "# Read(**/.grok/auth/**)\n"
        "# END HOL GUARD MANAGED GROK\n",
        encoding="utf-8",
    )
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("grok", True, None, {"harness": "grok", "active": True}, _NOW.isoformat())
    assert grok_hooks_protection_ready(ctx) is False


def test_grok_hook_command_rejects_placeholder_invocations() -> None:
    assert _grok_hook_command_is_guard("hol-guard hook grok") is True
    assert _grok_hook_command_is_guard("echo hol-guard hook") is False
    assert _grok_hook_command_is_guard("true") is False


def test_grok_managed_config_rejects_inline_commented_rule() -> None:
    assert (
        _grok_managed_config_is_active(
            '# BEGIN HOL GUARD MANAGED GROK\ndeny = ["Read(**/.grok/auth/**)"]\n# END HOL GUARD MANAGED GROK\n'
        )
        is True
    )
    assert (
        _grok_managed_config_is_active(
            "# BEGIN HOL GUARD MANAGED GROK\ndeny = [] # Read(**/.grok/auth/**)\n# END HOL GUARD MANAGED GROK\n"
        )
        is False
    )


def test_live_grok_hooks_reject_placeholder_command_and_marker_only_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    hooks_dir = ctx.home_dir / ".grok" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "hol-guard-pretooluse.json").write_text(
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}]}}),
        encoding="utf-8",
    )
    (hooks_dir / "hol-guard-prompt.json").write_text(
        json.dumps({"hooks": {"UserPromptSubmit": []}}),
        encoding="utf-8",
    )
    (ctx.home_dir / ".grok" / "managed_config.toml").write_text(
        "# BEGIN HOL GUARD MANAGED GROK\n# END HOL GUARD MANAGED GROK\n",
        encoding="utf-8",
    )
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("grok", True, None, {"harness": "grok", "active": True}, "2026-08-17T12:00:00+00:00")

    assert grok_hooks_protection_ready(ctx) is False
    assert _live_hook_verification(store.list_managed_installs(), store) == {"grok": False}


def test_live_grok_hooks_fail_stale_matchers_even_when_sha_proof_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    hooks_dir = ctx.home_dir / ".grok" / "hooks"
    hooks_dir.mkdir(parents=True)
    pretool = hooks_dir / "hol-guard-pretooluse.json"
    pretool.write_text(json.dumps(_stale_pretool_payload()), encoding="utf-8")
    (hooks_dir / "hol-guard-prompt.json").write_text(
        json.dumps({"hooks": {"UserPromptSubmit": []}}),
        encoding="utf-8",
    )
    managed = ctx.home_dir / ".grok" / "managed_config.toml"
    managed.write_text("# BEGIN HOL GUARD MANAGED GROK\n# END HOL GUARD MANAGED GROK\n", encoding="utf-8")
    manifest = bind_managed_install_proof(
        {
            "config_path": str(managed),
            "pretool_hook_path": str(pretool),
        },
        ctx,
    )
    assert verify_managed_install_proof(manifest, ctx) is True
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("grok", True, None, manifest, "2026-08-17T12:00:00+00:00")

    assert grok_hooks_protection_ready(ctx) is False
    assert _live_hook_verification(store.list_managed_installs(), store) == {"grok": False}


def test_grok_install_proof_covers_hooks_and_managed_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    payload = apply_managed_install(
        "install",
        "grok",
        False,
        ctx,
        store,
        None,
        "2026-08-17T12:00:00+00:00",
    )
    managed_install = payload["managed_install"]
    assert isinstance(managed_install, dict)
    manifest = managed_install["manifest"]
    assert isinstance(manifest, dict)
    assert grok_hooks_protection_ready(ctx) is True
    assert verify_managed_install_proof(manifest, ctx) is True
    assert _live_hook_verification(store.list_managed_installs(), store) == {"grok": True}
    artifacts = manifest["protection_artifact_proof"]["artifacts"]
    assert isinstance(artifacts, list)
    artifact_paths = {item["path"] for item in artifacts if isinstance(item, dict)}
    assert any(path.endswith("managed_config.toml") for path in artifact_paths)
    assert any(path.endswith("hol-guard-pretooluse.json") for path in artifact_paths)
    assert any(path.endswith("hol-guard-prompt.json") for path in artifact_paths)


def test_one_pass_repair_restores_stale_grok_hooks_and_command_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    apply_managed_install("install", "grok", False, ctx, store, None, "2026-08-17T12:00:00+00:00")
    pretool = ctx.home_dir / ".grok" / "hooks" / "hol-guard-pretooluse.json"
    pretool.write_text(json.dumps(_stale_pretool_payload()), encoding="utf-8")
    (ctx.home_dir / ".grok" / "managed_config.toml").unlink()
    store.record_command_activity_persistence_failure(error_code="post_record_failed", occurred_at=_NOW)
    store.record_command_activity_persistence_failure(error_code="shadow_evaluation_failed", occurred_at=_NOW)
    store.record_command_activity_persistence_failure(error_code="maintenance_failed", occurred_at=_NOW)
    assert grok_hooks_protection_ready(ctx) is False
    assert store.get_command_activity_persistence_health().active_error_count == 3

    _, failed_hooks = repair_failing_managed_harness_hooks(store)
    _repair_command_activity_persistence_health(store)
    store.maintain_command_activity(now=_NOW, detail_retain_days=30)

    assert failed_hooks == ()
    assert grok_hooks_protection_ready(ctx) is True
    assert _live_hook_verification(store.list_managed_installs(), store) == {"grok": True}
    assert store.get_command_activity_persistence_health().active_error_count == 0
    assert (ctx.home_dir / ".grok" / "managed_config.toml").is_file()
    assert "matcher" not in json.loads(pretool.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]


def test_daemon_ownership_change_repairs_stale_managed_grok_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    apply_managed_install("install", "grok", False, ctx, store, None, "2026-08-17T12:00:00+00:00")
    pretool = ctx.home_dir / ".grok" / "hooks" / "hol-guard-pretooluse.json"
    pretool.write_text(json.dumps(_stale_pretool_payload()), encoding="utf-8")
    (ctx.home_dir / ".grok" / "managed_config.toml").unlink()
    assert grok_hooks_protection_ready(ctx) is False

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        assert grok_hooks_protection_ready(ctx) is True
        assert _live_hook_verification(store.list_managed_installs(), store) == {"grok": True}
    finally:
        daemon.stop()
