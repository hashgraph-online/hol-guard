from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntime,
    use_extension_control_snapshot,
)
from tests.native_command_test_support import inspect_command_native_test as inspect_command


def _inspect_gorgona(command: str, tmp_path: Path) -> dict[str, object]:
    catalog_digest = getattr(BUILT_IN_COMMAND_EXTENSION_REGISTRY, "catalog_digest", "a" * 64)
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.gorgona"),
                state=ControlState.ENABLED,
            ),
        ),
    )
    view = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, catalog_digest, (layer,))
    snapshot = ExtensionControlRuntime(view).current()

    with use_extension_control_snapshot(snapshot):
        return inspect_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_snapshot=snapshot,
        )


def test_gorgona_command_source_boundary(tmp_path: Path) -> None:
    # 1. Plain listen, help, and version flags remain automatic (no_match)
    for cmd in (
        "gorgona listen new 4YzEYpwB9hc=",
        "gorgona listen last 1 4YzEYpwB9hc=",
        "gorgona --help",
        "gorgona --version",
    ):
        res = _inspect_gorgona(cmd, tmp_path)
        assert res["status"] == "no_match"
        assert not any(r["rule_id"].startswith("command.gorgona.") for r in res["rules"])

    # 2. listen with -e / --exec requires review
    exec_short = _inspect_gorgona("gorgona -e listen new 4YzEYpwB9hc=", tmp_path)
    assert exec_short["status"] == "review"
    assert "command.gorgona" in {ext["extension_id"] for ext in exec_short["extensions"]}
    assert exec_short["classification"]["action_class"] == "remote command execution"
    assert any(rule["rule_id"] == "command.gorgona.exec-listen" for rule in exec_short["rules"])

    exec_long = _inspect_gorgona("gorgona --exec listen new 4YzEYpwB9hc=", tmp_path)
    assert exec_long["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.exec-listen" for rule in exec_long["rules"])

    # 3. Key generation, sending, and revocation require review
    genkeys_res = _inspect_gorgona("gorgona genkeys", tmp_path)
    assert genkeys_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.genkeys" for rule in genkeys_res["rules"])

    send_res = _inspect_gorgona(
        'gorgona send "2026-09-22 16:42:30" "2026-10-22 16:42:30" "hello world" "RWTPQzuhzBw=.pub"',
        tmp_path,
    )
    assert send_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.send" for rule in send_res["rules"])

    revoke_res = _inspect_gorgona("gorgona revoke 220745621684224 4YzEYpwB9hc=", tmp_path)
    assert revoke_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.revoke" for rule in revoke_res["rules"])

    # 4. Upstream global options and bundled flags
    bundled_res = _inspect_gorgona("gorgona -ve listen new 4YzEYpwB9hc=", tmp_path)
    assert bundled_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.exec-listen" for rule in bundled_res["rules"])

    config_exec_res = _inspect_gorgona(
        "gorgona -c /etc/gorgona/gorgona-node2.conf -e listen new 4YzEYpwB9hc=",
        tmp_path,
    )
    assert config_exec_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.exec-listen" for rule in config_exec_res["rules"])

    verbose_send = _inspect_gorgona(
        'gorgona -v send "2026-10-01 12:00:00" "2026-11-01 12:00:00" "hello" "RWTPQzuhzBw=.pub"',
        tmp_path,
    )
    assert verbose_send["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.send" for rule in verbose_send["rules"])

    config_revoke = _inspect_gorgona(
        "gorgona -c /etc/gorgona/x.conf revoke 170119927746560 RWTPQzuhzBw=",
        tmp_path,
    )
    assert config_revoke["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.revoke" for rule in config_revoke["rules"])

    # 5. Safe leading options with plain listen
    assert _inspect_gorgona("gorgona -v listen new 4YzEYpwB9hc=", tmp_path)["status"] == "no_match"
    assert _inspect_gorgona("gorgona -c /etc/gorgona/x.conf listen new 4YzEYpwB9hc=", tmp_path)["status"] == "no_match"
