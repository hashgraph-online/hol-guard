"""Immutable classifier for benign DX commands that stay prompt-free."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

# ---------------------------------------------------------------------------
# Regex building blocks
# ---------------------------------------------------------------------------

_REASON_CODE: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")

# Git safe flags — trimmed to the spec: -5,-10,--oneline,--stat,-n <int>.
_GIT_SAFE_FLAGS: Final = frozenset(("-5", "-10", "--oneline", "--stat", "-n"))

# Adversarial indicators — each entry is (compiled_re, reason_code_string).
_ADVERSARIAL: Final = (
    (re.compile(r"\|"), "NOT_BENIGN_PIPED"),
    (re.compile(r";"), "NOT_BENIGN_COMPOUND"),
    (re.compile(r"&&"), "NOT_BENIGN_COMPOUND"),
    (re.compile(r"\$\("), "NOT_BENIGN_SUBSHELL"),
    (re.compile(r"`"), "NOT_BENIGN_BACKTICK"),
    (re.compile(r">"), "NOT_BENIGN_REDIRECT"),
    (re.compile(r"<"), "NOT_BENIGN_REDIRECT"),
    (re.compile(r"\bsudo\b"), "NOT_BENIGN_SUDO"),
    (re.compile(r"\bcurl\b"), "NOT_BENIGN_CURL"),
    (re.compile(r"\bwget\b"), "NOT_BENIGN_WGET"),
    (re.compile(r"\brm\s"), "NOT_BENIGN_RM"),
    (re.compile(r"\bsh\b"), "NOT_BENIGN_SH"),
    (re.compile(r"\beval\b"), "NOT_BENIGN_EVAL"),
    (re.compile(r"\s-c\s"), "NOT_BENIGN_COMPOUND"),
    (re.compile(r"\.env\b"), "NOT_BENIGN_SECRET"),
    (re.compile(r"\.aws\b"), "NOT_BENIGN_SECRET"),
    (re.compile(r"\bsecret\b"), "NOT_BENIGN_SECRET"),
    (re.compile(r"\bpassword\b"), "NOT_BENIGN_SECRET"),
    (re.compile(r"\btoken\b"), "NOT_BENIGN_SECRET"),
    (re.compile(r"\bcredential\b"), "NOT_BENIGN_SECRET"),
    (re.compile(r"--output\b"), "NOT_BENIGN_OUTPUT"),
    (re.compile(r"--ext-diff"), "NOT_BENIGN_OUTPUT"),
)

# ---------------------------------------------------------------------------
# Reason codes
# ---------------------------------------------------------------------------


class BenignReason(str, Enum):
    """Stable reason codes for benign-command classification results."""

    BENIGN_READ_ONLY = "benign.read_only"
    NOT_BENIGN_PIPED = "not_benign.piped"
    NOT_BENIGN_REDIRECT = "not_benign.redirect"
    NOT_BENIGN_SUBSHELL = "not_benign.subshell"
    NOT_BENIGN_BACKTICK = "not_benign.backtick"
    NOT_BENIGN_CURL = "not_benign.curl"
    NOT_BENIGN_WGET = "not_benign.wget"
    NOT_BENIGN_SUDO = "not_benign.sudo"
    NOT_BENIGN_RM = "not_benign.rm"
    NOT_BENIGN_SH = "not_benign.sh"
    NOT_BENIGN_EVAL = "not_benign.eval"
    NOT_BENIGN_SECRET = "not_benign.secret"
    NOT_BENIGN_OUTPUT = "not_benign.output"
    NOT_BENIGN_COMPOUND = "not_benign.compound"
    NOT_BENIGN_NOT_ALLOWED = "not_benign.not_allowed"
    NOT_BENIGN_NON_READ = "not_benign.non_read"
    NOT_BENIGN_INVALID_GIT = "not_benign.invalid_git"


# Map the _ADVERSARIAL string keys to the enum.
_ADVERSARIAL_MAP: Final = {r.name: r for r in BenignReason if r.value.startswith("not_benign.")}

# ---------------------------------------------------------------------------
# Frozen result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BenignCommandClass:
    """Result of a benign-command classification.

    Attributes:
        is_prompt_free: True when the command is an exact allowlisted
            read-only form with no adversarial indicators.
        reason_code: Stable lowercase identifier for the classification.
        raw_command: Echoed back for audit trail (never executed).
    """

    is_prompt_free: bool
    reason_code: str
    raw_command: str

    def __post_init__(self) -> None:
        is_prompt_free = cast(object, self.is_prompt_free)
        if not isinstance(is_prompt_free, bool):
            raise ValueError("is_prompt_free must be a boolean")
        reason_code = self.reason_code
        if _REASON_CODE.fullmatch(reason_code) is None:
            raise ValueError("reason_code must be a stable lowercase identifier")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _check_adversarial(cmd: str) -> BenignReason | None:
    """Return the adversarial reason if *cmd* matches, else None."""
    for pattern, key in _ADVERSARIAL:
        if pattern.search(cmd):
            return _ADVERSARIAL_MAP[key]
    return None


def _is_git_safe_flag(token: str) -> bool:
    """Return True when *token* is a recognised safe git flag.

    Only the spec-approved flags: -5, -10, --oneline, --stat, -n.
    No regex fallbacks — exact membership only.
    """
    return token in _GIT_SAFE_FLAGS


def _check_git_log_flags(args: list[str]) -> tuple[bool, BenignReason]:
    """Validate that git log/diff/show arguments contain only safe flags.

    Safe flags per spec: -5, -10, --oneline, --stat, -n <int>.
    Returns (safe, reason_if_unsafe).
    """
    i = 0
    while i < len(args):
        token = args[i]
        if token == "-n":
            # -n takes an integer argument; consume and validate it.
            if i + 1 >= len(args):
                return False, BenignReason.NOT_BENIGN_INVALID_GIT
            next_token = args[i + 1]
            if not next_token.lstrip("-").isdigit():
                return False, BenignReason.NOT_BENIGN_INVALID_GIT
            i += 2
            continue
        if _is_git_safe_flag(token):
            i += 1
            continue
        # Unrecognised flag — unsafe.
        return False, BenignReason.NOT_BENIGN_INVALID_GIT
    return True, BenignReason.BENIGN_READ_ONLY


def _check_gh_pr_view_fields(args: list[str]) -> tuple[bool, BenignReason]:
    """Validate ``gh pr view <int> --json <fields>``.

    Returns (safe, reason_if_unsafe).
    """
    if not args:
        return False, BenignReason.NOT_BENIGN_NOT_ALLOWED
    pr_num = args[0]
    if not pr_num.isdigit():
        return False, BenignReason.NOT_BENIGN_NOT_ALLOWED

    rest = args[1:]
    if "--json" in rest:
        idx = rest.index("--json")
        if idx + 1 >= len(rest):
            return False, BenignReason.NOT_BENIGN_NOT_ALLOWED
        after = rest[idx + 1 :]
        for f in after:
            if f.startswith("--"):
                return False, BenignReason.NOT_BENIGN_NOT_ALLOWED
    for arg in rest:
        if arg.startswith("--") and arg != "--json":
            return False, BenignReason.NOT_BENIGN_NOT_ALLOWED
    return True, BenignReason.BENIGN_READ_ONLY


# ---------------------------------------------------------------------------
# Public classifier
# ---------------------------------------------------------------------------


def _classify_benign_raw(command: str) -> tuple[bool, BenignReason]:
    """Internal classifier that returns (is_prompt_free, reason).

    Pure string analysis — no execution, no I/O.
    """
    cmd = command.strip()

    if not cmd:
        return False, BenignReason.NOT_BENIGN_NOT_ALLOWED

    # Check adversarial indicators first (fast fail).
    adv = _check_adversarial(cmd)
    if adv is not None:
        return False, adv

    parts = cmd.split()
    executable = parts[0]

    # --- ls (exact match only) ---
    if executable == "ls" and len(parts) == 1:
        return True, BenignReason.BENIGN_READ_ONLY

    # --- pwd (exact match only) ---
    if executable == "pwd" and len(parts) == 1:
        return True, BenignReason.BENIGN_READ_ONLY

    # --- cat README* ---
    if executable == "cat":
        operand = parts[1] if len(parts) == 2 else ""
        if (
            len(parts) == 2
            and operand.startswith("README")
            and "/" not in operand
            and "\\" not in operand
            and ".." not in operand
        ):
            return True, BenignReason.BENIGN_READ_ONLY
        return False, BenignReason.NOT_BENIGN_NOT_ALLOWED

    # --- git status (exact match only) ---
    if executable == "git" and len(parts) == 2 and parts[1] == "status":
        return True, BenignReason.BENIGN_READ_ONLY

    # --- git log ---
    if executable == "git" and len(parts) >= 2 and parts[1] == "log":
        return _check_git_log_flags(parts[2:])

    # --- git diff ---
    if executable == "git" and len(parts) >= 2 and parts[1] == "diff":
        return _check_git_log_flags(parts[2:])

    # --- git show ---
    if executable == "git" and len(parts) >= 2 and parts[1] == "show":
        return _check_git_log_flags(parts[2:])

    # --- gh pr view ---
    if executable == "gh" and len(parts) >= 3 and parts[1] == "pr" and parts[2] == "view":
        return _check_gh_pr_view_fields(parts[3:])

    # --- gh pr diff ---
    if executable == "gh" and len(parts) >= 3 and parts[1] == "pr" and parts[2] == "diff":
        if len(parts) != 4:
            return False, BenignReason.NOT_BENIGN_NOT_ALLOWED
        pr_num = parts[3]
        if not pr_num.isdigit():
            return False, BenignReason.NOT_BENIGN_NOT_ALLOWED
        return True, BenignReason.BENIGN_READ_ONLY

    # Not in the allowlist.
    return False, BenignReason.NOT_BENIGN_NOT_ALLOWED


def classify_benign_command(command_text: str) -> tuple[bool, str]:
    """Classify whether a command is prompt-free benign.

    A command is prompt-free-benign ONLY if:

    1. It contains NO adversarial indicators (piping, redirects, shell
       injection, credential substrings, etc.).
    2. It is an exact match to an allowlisted read-only form:

       - ``git status`` (exact)
       - ``git log`` with only safe flags (-5, -10, --oneline, --stat, -n)
       - ``git diff`` with only safe flags (no --output/--ext-diff)
       - ``git show`` with only safe flags (no --output/--ext-diff)
       - ``ls`` (exact)
       - ``pwd`` (exact)
       - ``cat README*``
       - ``gh pr view <int> --json <fields>``
       - ``gh pr diff <int>``

    Args:
        command_text: The raw command string to classify.

    Returns:
        A ``(is_prompt_free, reason_code)`` tuple.
    """
    is_prompt_free, reason = _classify_benign_raw(command_text)
    return is_prompt_free, reason.value


# Alias for the dataclass return type used in type annotations.
BenignResult = BenignCommandClass
