from __future__ import annotations

from codex_plugin_scanner.guard.runtime.benign_dx_guard import (
    BenignCommandClass,
    BenignReason,
    _check_adversarial,
    _check_gh_pr_view_fields,
    _check_git_log_flags,
    _classify_benign_raw,
    _is_git_safe_flag,
    classify_benign_command,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.benign_requests import (
    is_explicitly_benign_tool_action_request,
)

# ---------------------------------------------------------------------------
# Benign allowlist — each command MUST be prompt-free
# ---------------------------------------------------------------------------

_BENIGN_COMMANDS: list[tuple[str, str]] = [
    # ls (exact match only)
    ("ls", BenignReason.BENIGN_READ_ONLY.value),
    # pwd (exact match only)
    ("pwd", BenignReason.BENIGN_READ_ONLY.value),
    # cat README*
    ("cat README.md", BenignReason.BENIGN_READ_ONLY.value),
    ("cat README", BenignReason.BENIGN_READ_ONLY.value),
    ("cat README.rst", BenignReason.BENIGN_READ_ONLY.value),
    # git status (exact match only)
    ("git status", BenignReason.BENIGN_READ_ONLY.value),
    # git log with safe flags only
    ("git log", BenignReason.BENIGN_READ_ONLY.value),
    ("git log -5", BenignReason.BENIGN_READ_ONLY.value),
    ("git log --oneline", BenignReason.BENIGN_READ_ONLY.value),
    ("git log --stat", BenignReason.BENIGN_READ_ONLY.value),
    ("git log -n 10", BenignReason.BENIGN_READ_ONLY.value),
    ("git log -10", BenignReason.BENIGN_READ_ONLY.value),
    # git diff with safe flags
    ("git diff", BenignReason.BENIGN_READ_ONLY.value),
    ("git diff --stat", BenignReason.BENIGN_READ_ONLY.value),
    ("git diff --oneline", BenignReason.BENIGN_READ_ONLY.value),
    # git show with safe flags
    ("git show", BenignReason.BENIGN_READ_ONLY.value),
    ("git show --oneline", BenignReason.BENIGN_READ_ONLY.value),
    ("git show -n 5", BenignReason.BENIGN_READ_ONLY.value),
    # gh pr view
    ("gh pr view 42", BenignReason.BENIGN_READ_ONLY.value),
    ("gh pr view 42 --json title", BenignReason.BENIGN_READ_ONLY.value),
    ("gh pr view 1", BenignReason.BENIGN_READ_ONLY.value),
    # gh pr diff
    ("gh pr diff 42", BenignReason.BENIGN_READ_ONLY.value),
]


def test_all_benign_allowlisted_commands_are_prompt_free() -> None:
    for cmd, reason in _BENIGN_COMMANDS:
        is_prompt_free, rc = classify_benign_command(cmd)
        assert is_prompt_free is True, (
            f"Expected '{cmd}' to be prompt-free, got is_prompt_free={is_prompt_free}, reason={rc}"
        )
        assert rc == reason, f"Expected reason '{reason}' for '{cmd}', got '{rc}'"


def test_release_allowlist_is_used_by_production_benign_request_path(tmp_path) -> None:
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": "gh pr view 42 --json title"},
        cwd=tmp_path,
        home_dir=tmp_path,
    )


# ---------------------------------------------------------------------------
# Adversarial commands — each MUST be rejected
# ---------------------------------------------------------------------------

_ADVERSARIAL_COMMANDS: list[tuple[str, str]] = [
    # Piped
    ("git status | grep foo", BenignReason.NOT_BENIGN_PIPED.value),
    ("git log | wc -l", BenignReason.NOT_BENIGN_PIPED.value),
    # Semicolon compound
    ("git status ; cat secret.txt", BenignReason.NOT_BENIGN_COMPOUND.value),
    ("git status; cat README", BenignReason.NOT_BENIGN_COMPOUND.value),
    # && compound
    ("git status && rm -rf /", BenignReason.NOT_BENIGN_COMPOUND.value),
    # Command substitution $()
    ("git status $(whoami)", BenignReason.NOT_BENIGN_SUBSHELL.value),
    # Backtick
    ("git status `id`", BenignReason.NOT_BENIGN_BACKTICK.value),
    # Redirect
    ("git status > /tmp/out", BenignReason.NOT_BENIGN_REDIRECT.value),
    ("cat README.md > /tmp/readme", BenignReason.NOT_BENIGN_REDIRECT.value),
    ("git log > log.txt", BenignReason.NOT_BENIGN_REDIRECT.value),
    # Input redirect
    ("cat < /dev/null", BenignReason.NOT_BENIGN_REDIRECT.value),
    # sudo
    ("sudo git status", BenignReason.NOT_BENIGN_SUDO.value),
    # curl
    ("curl http://example.com", BenignReason.NOT_BENIGN_CURL.value),
    ("curl -X POST http://x.com", BenignReason.NOT_BENIGN_CURL.value),
    # wget
    ("wget http://example.com", BenignReason.NOT_BENIGN_WGET.value),
    # rm
    ("rm -rf /tmp", BenignReason.NOT_BENIGN_RM.value),
    ("rm file.txt", BenignReason.NOT_BENIGN_RM.value),
    # sh
    ("sh -c 'ls'", BenignReason.NOT_BENIGN_SH.value),
    # eval
    ("eval 'echo hi'", BenignReason.NOT_BENIGN_EVAL.value),
    # -c injection
    ("git status -c user.name='pwned'", BenignReason.NOT_BENIGN_COMPOUND.value),
    # Secret substrings
    ("git status --token", BenignReason.NOT_BENIGN_SECRET.value),
    ("cat .env", BenignReason.NOT_BENIGN_SECRET.value),
    ("ls .aws/credentials", BenignReason.NOT_BENIGN_SECRET.value),
    ("cat secret.txt", BenignReason.NOT_BENIGN_SECRET.value),
    ("git status --password", BenignReason.NOT_BENIGN_SECRET.value),
    ("git log --credential", BenignReason.NOT_BENIGN_SECRET.value),
    # --output
    ("git diff --output=patch", BenignReason.NOT_BENIGN_OUTPUT.value),
    ("git show --output=foo", BenignReason.NOT_BENIGN_OUTPUT.value),
    # --ext-diff
    ("git diff --ext-diff", BenignReason.NOT_BENIGN_OUTPUT.value),
    ("git show --ext-diff", BenignReason.NOT_BENIGN_OUTPUT.value),
    # cat on non-README
    ("cat package.json", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    ("cat src/main.py", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    # Unknown command
    ("python script.py", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    ("npm run build", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    # ls with extra args (not allowed — exact match only)
    ("ls -la /tmp", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    # pwd with extra args (not allowed — exact match only)
    ("pwd -P", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    # git status with extra args (not allowed — exact match only)
    ("git status -s", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    ("git status --porcelain", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    # Invalid git log flag
    ("git log --patch", BenignReason.NOT_BENIGN_INVALID_GIT.value),
    ("git log --porcelain", BenignReason.NOT_BENIGN_INVALID_GIT.value),
    ("git log --unknown-flag", BenignReason.NOT_BENIGN_INVALID_GIT.value),
    ("git log --all", BenignReason.NOT_BENIGN_INVALID_GIT.value),
    # Invalid git diff flag
    ("git diff --patch", BenignReason.NOT_BENIGN_INVALID_GIT.value),
    # Empty command
    ("", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
    ("   ", BenignReason.NOT_BENIGN_NOT_ALLOWED.value),
]


def test_all_adversarial_commands_are_rejected() -> None:
    for cmd, reason in _ADVERSARIAL_COMMANDS:
        is_prompt_free, rc = classify_benign_command(cmd)
        assert is_prompt_free is False, f"Expected '{cmd}' to be rejected, got is_prompt_free={is_prompt_free}"
        assert rc == reason, f"Expected reason '{reason}' for '{cmd}', got '{rc}'"


# ---------------------------------------------------------------------------
# Approval-count assertions (20 benign → 0 approvals, 20 adversarial → 0 slips)
# ---------------------------------------------------------------------------

_BENIGN_20: list[str] = [
    "ls",
    "pwd",
    "cat README.md",
    "cat README.rst",
    "git status",
    "git log",
    "git log -5",
    "git log --oneline",
    "git log --stat",
    "git log -n 10",
    "git diff",
    "git diff --stat",
    "git show",
    "git show --oneline",
    "git show -n 5",
    "gh pr view 42",
    "gh pr view 42 --json title",
    "gh pr diff 42",
    "git log -10",
    "git diff --oneline",
]


_ADVERSARIAL_20: list[str] = [
    "git status | grep foo",
    "git status ; echo pwned",
    "git status && rm -rf /",
    "git status $(whoami)",
    "git status `id`",
    "git status > /tmp/out",
    "cat README.md > /tmp/readme",
    "sudo git status",
    "curl http://example.com",
    "wget http://example.com",
    "rm -rf /tmp",
    "sh -c 'ls'",
    "eval 'echo hi'",
    "git status --token",
    "cat .env",
    "git status --password",
    "git diff --output=patch",
    "git log --patch",
    "python script.py",
    "gh pr diff 42 --patch",
]


def test_20_benign_zero_approvals() -> None:
    approvals = sum(1 for cmd in _BENIGN_20 if classify_benign_command(cmd)[0] is False)
    assert approvals == 0, f"{approvals} benign commands wrongly flagged as not prompt-free"
    assert len(_BENIGN_20) == 20


def test_20_adversarial_zero_slips() -> None:
    slips = sum(1 for cmd in _ADVERSARIAL_20 if classify_benign_command(cmd)[0] is True)
    assert slips == 0, f"{slips} adversarial commands wrongly classified as benign"
    assert len(_ADVERSARIAL_20) == 20


# ---------------------------------------------------------------------------
# Frozen dataclass tests
# ---------------------------------------------------------------------------


def test_benign_command_class_is_frozen() -> None:
    result = BenignCommandClass(
        is_prompt_free=True,
        reason_code=BenignReason.BENIGN_READ_ONLY.value,
        raw_command="git status",
    )
    try:
        result.is_prompt_free = False  # type: ignore[assignment]
        raise AssertionError("Should not be able to mutate frozen dataclass")
    except Exception:
        pass  # expected


def test_benign_command_class_post_init_rejects_bad_reason_code() -> None:
    try:
        BenignCommandClass(
            is_prompt_free=True,
            reason_code="INVALID REASON",
            raw_command="git status",
        )
        raise AssertionError("Should raise ValueError for invalid reason_code")
    except ValueError:
        pass


def test_benign_command_class_post_init_rejects_bad_bool() -> None:
    try:
        BenignCommandClass(
            is_prompt_free="yes",  # type: ignore[arg-type]
            reason_code=BenignReason.BENIGN_READ_ONLY.value,
            raw_command="git status",
        )
        raise AssertionError("Should raise ValueError for non-bool is_prompt_free")
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# _classify_benign_raw returns BenignReason enums
# ---------------------------------------------------------------------------


def test_classify_benign_raw_returns_enum() -> None:
    result = _classify_benign_raw("git status")
    assert result[0] is True
    assert isinstance(result[1], BenignReason)
    assert result[1] == BenignReason.BENIGN_READ_ONLY


def test_classify_benign_raw_rejects_unknown() -> None:
    result = _classify_benign_raw("python script.py")
    assert result[0] is False
    assert result[1] == BenignReason.NOT_BENIGN_NOT_ALLOWED


# ---------------------------------------------------------------------------
# Helper function unit tests
# ---------------------------------------------------------------------------


def test_is_git_safe_flag_accepts_spec_flags() -> None:
    for flag in ("-5", "-10", "--oneline", "--stat", "-n"):
        assert _is_git_safe_flag(flag) is True


def test_is_git_safe_flag_rejects_non_spec() -> None:
    assert _is_git_safe_flag("--patch") is False
    assert _is_git_safe_flag("--porcelain") is False
    assert _is_git_safe_flag("--ext-diff") is False
    assert _is_git_safe_flag("--all") is False


def test_check_adversarial_detects_all_indicators() -> None:
    for pattern, expected_reason in [
        (r"git | grep", BenignReason.NOT_BENIGN_PIPED),
        (r"git ; cat", BenignReason.NOT_BENIGN_COMPOUND),
        (r"git && rm", BenignReason.NOT_BENIGN_COMPOUND),
        (r"git $(id)", BenignReason.NOT_BENIGN_SUBSHELL),
        (r"git `id`", BenignReason.NOT_BENIGN_BACKTICK),
        (r"git > /tmp", BenignReason.NOT_BENIGN_REDIRECT),
        (r"git < /tmp", BenignReason.NOT_BENIGN_REDIRECT),
        (r"sudo git", BenignReason.NOT_BENIGN_SUDO),
        (r"curl url", BenignReason.NOT_BENIGN_CURL),
        (r"wget url", BenignReason.NOT_BENIGN_WGET),
        (r"rm file", BenignReason.NOT_BENIGN_RM),
        (r"sh -c x", BenignReason.NOT_BENIGN_SH),
        (r"eval x", BenignReason.NOT_BENIGN_EVAL),
        (r" .env", BenignReason.NOT_BENIGN_SECRET),
        (r" .aws", BenignReason.NOT_BENIGN_SECRET),
        (r" secret ", BenignReason.NOT_BENIGN_SECRET),
        (r" password ", BenignReason.NOT_BENIGN_SECRET),
        (r" token ", BenignReason.NOT_BENIGN_SECRET),
        (r" credential ", BenignReason.NOT_BENIGN_SECRET),
        (r"--output=x", BenignReason.NOT_BENIGN_OUTPUT),
        (r"--ext-diff", BenignReason.NOT_BENIGN_OUTPUT),
    ]:
        reason = _check_adversarial(pattern)
        assert reason == expected_reason, f"Expected {expected_reason.value} for '{pattern}', got {reason}"


def test_check_adversarial_returns_none_for_clean() -> None:
    assert _check_adversarial("git status") is None
    assert _check_adversarial("ls") is None
    assert _check_adversarial("pwd") is None


def test_check_git_log_flags_rejects_invalid() -> None:
    safe, reason = _check_git_log_flags(["--patch"])
    assert safe is False
    assert reason == BenignReason.NOT_BENIGN_INVALID_GIT

    safe, reason = _check_git_log_flags(["--unknown"])
    assert safe is False
    assert reason == BenignReason.NOT_BENIGN_INVALID_GIT

    safe, reason = _check_git_log_flags(["--all"])
    assert safe is False
    assert reason == BenignReason.NOT_BENIGN_INVALID_GIT


def test_check_git_log_flags_accepts_safe() -> None:
    for flag in ("-5", "-10", "--oneline", "--stat"):
        safe, reason = _check_git_log_flags([flag])
        assert safe is True
        assert reason == BenignReason.BENIGN_READ_ONLY


def test_check_git_log_flags_accepts_n_with_int() -> None:
    for n in ("5", "10", "100"):
        safe, reason = _check_git_log_flags(["-n", n])
        assert safe is True
        assert reason == BenignReason.BENIGN_READ_ONLY


def test_check_git_log_flags_rejects_n_without_int() -> None:
    safe, reason = _check_git_log_flags(["-n"])
    assert safe is False
    assert reason == BenignReason.NOT_BENIGN_INVALID_GIT


def test_check_gh_pr_view_accepts_valid() -> None:
    safe, reason = _check_gh_pr_view_fields(["42", "--json", "title,body"])
    assert safe is True
    assert reason == BenignReason.BENIGN_READ_ONLY


def test_check_gh_pr_view_rejects_non_int() -> None:
    safe, reason = _check_gh_pr_view_fields(["abc"])
    assert safe is False
    assert reason == BenignReason.NOT_BENIGN_NOT_ALLOWED


def test_check_gh_pr_view_rejects_missing_json_arg() -> None:
    safe, reason = _check_gh_pr_view_fields(["42", "--json"])
    assert safe is False
    assert reason == BenignReason.NOT_BENIGN_NOT_ALLOWED


# ---------------------------------------------------------------------------
# BenignReason enum values are stable lowercase
# ---------------------------------------------------------------------------


def test_benign_reason_values_are_lowercase() -> None:
    for reason in BenignReason:
        assert reason.value == reason.value.lower(), f"Reason value '{reason.value}' is not lowercase"


# ---------------------------------------------------------------------------
# classify_benign_command returns str reason_code
# ---------------------------------------------------------------------------


def test_classify_returns_str_tuple() -> None:
    result = classify_benign_command("git status")
    assert isinstance(result, tuple)
    assert isinstance(result[0], bool)
    assert isinstance(result[1], str)
    assert result == (True, BenignReason.BENIGN_READ_ONLY.value)


def test_cat_readme_traversal_not_benign() -> None:
    for payload in ("README/../../etc/passwd", "README/../../.env", "README.md/../../x", "README/.."):
        assert classify_benign_command(f"cat {payload}")[0] is False
