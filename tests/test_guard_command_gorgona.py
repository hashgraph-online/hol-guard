from pathlib import Path
from tests.native_command_test_support import inspect_command_native_test as inspect_command


def test_gorgona_command_source_boundary(tmp_path: Path) -> None:
    # 1. Plain listen, help, and version flags remain automatic (no_match)
    for cmd in (
        "gorgona listen new 4YzEYpwB9hc=",
        "gorgona listen last 1 4YzEYpwB9hc=",
        "gorgona --help",
        "gorgona --version",
    ):
        res = inspect_command(cmd, cwd=tmp_path, home_dir=tmp_path)
        assert res["status"] == "no_match"
        assert not any(r["rule_id"].startswith("command.gorgona.") for r in res["rules"])

    # 2. listen with -e / --exec requires review
    exec_short = inspect_command("gorgona -e listen new 4YzEYpwB9hc=", cwd=tmp_path, home_dir=tmp_path)
    assert exec_short["status"] == "review"
    assert "command.gorgona" in {ext["extension_id"] for ext in exec_short["extensions"]}
    assert exec_short["classification"]["action_class"] == "remote command execution"
    assert any(rule["rule_id"] == "command.gorgona.exec-listen" for rule in exec_short["rules"])

    exec_long = inspect_command("gorgona --exec listen new 4YzEYpwB9hc=", cwd=tmp_path, home_dir=tmp_path)
    assert exec_long["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.exec-listen" for rule in exec_long["rules"])

    # 3. Key generation, sending, and revocation require review
    genkeys_res = inspect_command("gorgona genkeys", cwd=tmp_path, home_dir=tmp_path)
    assert genkeys_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.genkeys" for rule in genkeys_res["rules"])

    send_res = inspect_command(
        'gorgona send "2026-09-22 16:42:30" "2026-10-22 16:42:30" "hello world" "RWTPQzuhzBw=.pub"',
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert send_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.send" for rule in send_res["rules"])

    revoke_res = inspect_command("gorgona revoke 220745621684224 4YzEYpwB9hc=", cwd=tmp_path, home_dir=tmp_path)
    assert revoke_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.revoke" for rule in revoke_res["rules"])

    # 4. Upstream global options and bundled flags
    bundled_res = inspect_command("gorgona -ve listen new 4YzEYpwB9hc=", cwd=tmp_path, home_dir=tmp_path)
    assert bundled_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.exec-listen" for rule in bundled_res["rules"])

    config_exec_res = inspect_command("gorgona -c /etc/gorgona/gorgona-node2.conf -e listen new 4YzEYpwB9hc=", cwd=tmp_path, home_dir=tmp_path)
    assert config_exec_res["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.exec-listen" for rule in config_exec_res["rules"])

    verbose_send = inspect_command('gorgona -v send "2026-10-01 12:00:00" "2026-11-01 12:00:00" "hello" "RWTPQzuhzBw=.pub"', cwd=tmp_path, home_dir=tmp_path)
    assert verbose_send["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.send" for rule in verbose_send["rules"])

    config_revoke = inspect_command("gorgona -c /etc/gorgona/x.conf revoke 170119927746560 RWTPQzuhzBw=", cwd=tmp_path, home_dir=tmp_path)
    assert config_revoke["status"] == "review"
    assert any(rule["rule_id"] == "command.gorgona.revoke" for rule in config_revoke["rules"])

    # 5. Safe leading options with plain listen
    assert inspect_command("gorgona -v listen new 4YzEYpwB9hc=", cwd=tmp_path, home_dir=tmp_path)["status"] == "no_match"
    assert inspect_command("gorgona -c /etc/gorgona/x.conf listen new 4YzEYpwB9hc=", cwd=tmp_path, home_dir=tmp_path)["status"] == "no_match"
