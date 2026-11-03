"""Tests for the z.ai ZCode hook payload and response helpers."""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters._modules.zcode.zcode_hooks import zcode_hook_process_exit
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload

from .zcode_remediation_reference import (
    _AUTHORITY_BLOCK_REMEDIATION,
    _authority_block_remediation,
    _quote_home,
    zcode_authority_block_reason,
)

_AUTHORITY_REASON = "HOL Guard requires the native command extension policy before this action can execute."


def _expected_home(guard_home: Path) -> str:
    """``guard_home`` as the hook writes it on the platform the test runs on."""

    quoted = _quote_home(str(guard_home), os.name == "nt")
    assert quoted is not None, guard_home
    return quoted


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "zcode" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


class TestZCodeHookPayload:
    def test_normalize_zcode_hook_payload_builds_shell_envelope(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "zcode",
            "",
            _fixture("pretooluse_bash.json"),
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"
        assert envelope.action_type == "shell_command"
        assert envelope.event_name == "PreToolUse"

    def test_normalize_harness_payload_accepts_zcode(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "zcode",
            "PreToolUse",
            _fixture("pretooluse_mcp.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"

    def test_normalize_harness_payload_accepts_zai_alias(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "zai",
            "UserPromptSubmit",
            _fixture("user_prompt_submit.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"


class TestZCodeHookResponses:
    def test_authority_block_reason_appends_remediation(self) -> None:
        reason = "HOL Guard requires the native command extension policy before this action can execute."
        enriched = zcode_authority_block_reason(reason)
        assert enriched.startswith(reason)
        assert "hol-guard command controls recover-authority" in enriched
        assert "acknowledge-degraded" not in enriched

    def test_authority_block_reason_is_idempotent(self) -> None:
        once = zcode_authority_block_reason(
            "HOL Guard requires the native command extension policy before this action can execute."
        )
        assert zcode_authority_block_reason(once) == once

    def test_authority_block_reason_leaves_other_reasons_alone(self) -> None:
        assert zcode_authority_block_reason("Blocked by policy.") == "Blocked by policy."

    def test_authority_block_reason_names_a_home_the_bare_command_misses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Pasting the bare command into a shell pointing at the default home
        # would recover a different install while this one stays blocked.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/casey")))
        named = Path("/opt/guards/ci")
        enriched = zcode_authority_block_reason(_AUTHORITY_REASON, named)
        # Built from the same path the hook renders, so the expectation uses
        # the platform's own separators rather than a POSIX spelling Windows
        # would never produce.
        assert f"hol-guard command --guard-home {_expected_home(named)} controls recover-authority" in enriched

    def test_authority_block_reason_quotes_a_named_home_for_the_shell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/casey")))
        spaced = Path("/opt/shared guards/.hol-guard")
        enriched = zcode_authority_block_reason(_AUTHORITY_REASON, spaced)
        assert f"--guard-home {_expected_home(spaced)} controls recover-authority" in enriched
        assert _expected_home(spaced) != str(spaced), "a home with a space has to carry quotes"

    def test_authority_block_reason_keeps_the_short_command_for_the_default_home(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The short command is the one almost everyone needs, and a path that
        # adds nothing only invites editing.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/casey")))
        enriched = zcode_authority_block_reason(_AUTHORITY_REASON, Path("/Users/casey/.hol-guard"))
        assert "hol-guard command controls recover-authority" in enriched
        assert "--guard-home" not in enriched

    def test_authority_block_reason_keeps_the_short_command_without_a_home(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Either side unknown leaves nothing to compare, so there is nothing
        # worth adding to the command.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/casey")))
        assert "--guard-home" not in zcode_authority_block_reason(_AUTHORITY_REASON)

        def _no_home(cls: type[Path]) -> Path:
            raise RuntimeError("home directory cannot be resolved")

        monkeypatch.setattr(Path, "home", classmethod(_no_home))
        assert "--guard-home" not in zcode_authority_block_reason(_AUTHORITY_REASON, Path("/opt/guards/ci"))

    def test_authority_block_reason_spells_a_windows_home_for_a_windows_shell(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `cmd.exe` and PowerShell hand a single-quoted path on as part of the
        # path, so POSIX quoting would hand a Windows person a command that
        # repairs nothing. The platform is a parameter rather than a reading of
        # `os.name`, so this runs on any host.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/casey")))
        plain = _authority_block_remediation(Path("C:\\guards\\ci"), True)
        assert "--guard-home C:\\guards\\ci controls recover-authority" in plain

        spaced = _authority_block_remediation(Path("C:\\Program Files\\guard\\.hol-guard"), True)
        assert '--guard-home "C:\\Program Files\\guard\\.hol-guard" controls' in spaced
        assert "'" not in spaced

    def test_a_windows_home_the_shells_would_rewrite_keeps_the_short_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # PowerShell expands `$name` inside double quotes and reads a backtick
        # as an escape; `cmd.exe` expands `%VAR%`, and `!name!` too once delayed
        # expansion is on. Single quotes would hold them in PowerShell but
        # become part of the path in `cmd.exe`, so no rendering reaches the
        # store. All four characters are legal in a Windows file name. Naming
        # such a home would send the person to repair whatever the shell
        # rewrote it into while this install stays blocked.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/casey")))
        for home in (
            "C:\\guards\\$ci",
            "C:\\guards\\%CI%",
            "C:\\guards\\`ci",
            "C:\\guards\\!ci",
            "C:\\Program Files\\guard$\\.hol-guard",
        ):
            assert _quote_home(home, True) is None, home
            assert _authority_block_remediation(Path(home), True) == _AUTHORITY_BLOCK_REMEDIATION, home

    def test_a_posix_home_holding_those_characters_is_still_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Single quotes make all three literal to a POSIX shell.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/casey")))
        named = _authority_block_remediation(Path("/opt/g$x/ci"), False)
        assert "--guard-home '/opt/g$x/ci' controls" in named

    def test_the_two_shells_get_their_own_spelling(self) -> None:
        # Same path, two renderings: the whole reason the platform is carried
        # rather than read from the host.
        spaced = "/opt/shared guards/.hol-guard"
        assert _quote_home(spaced, False) == "'/opt/shared guards/.hol-guard'"
        assert _quote_home(spaced, True) == '"/opt/shared guards/.hol-guard"'

    def test_process_exit_review_pretool_exits_zero_so_ask_json_is_parsed(self) -> None:
        # ZCode only parses stdout JSON for successful hook processes; exit 2
        # would discard the ask envelope and deny the call outright.
        assert zcode_hook_process_exit(policy_action="review", event_name="PreToolUse") == 0
        assert zcode_hook_process_exit(policy_action="require-reapproval", event_name="PreToolUse") == 0

    def test_process_exit_hard_denials_keep_blocking_exit(self) -> None:
        assert zcode_hook_process_exit(policy_action="block", event_name="PreToolUse") == 2
        assert zcode_hook_process_exit(policy_action="sandbox-required", event_name="PreToolUse") == 2

    def test_process_exit_prompt_blocks_keep_blocking_exit(self) -> None:
        assert zcode_hook_process_exit(policy_action="review", event_name="UserPromptSubmit") == 2
        assert zcode_hook_process_exit(policy_action="block", event_name="UserPromptSubmit") == 2

    def test_process_exit_allows_exit_zero(self) -> None:
        assert zcode_hook_process_exit(policy_action="allow", event_name="PreToolUse") == 0

    def test_process_exit_treats_an_action_outside_the_lattice_as_review(self) -> None:
        # ``policy_action`` arrives as a bare string decoded from the resident's
        # response. A newer, truncated or corrupted value must take the review
        # tier rather than the allow exit the blocking-set test used to give it.
        for action in ("quarantine-required", "", "BLOCK", "deny", "0", None, 7):
            assert zcode_hook_process_exit(policy_action=action, event_name="PreToolUse") == 0, action
            assert zcode_hook_process_exit(policy_action=action, event_name="UserPromptSubmit") == 2, action
            assert zcode_hook_process_exit(policy_action=action, event_name="PostToolUse") == 2, action

    def test_process_exit_maps_the_legacy_ask_alias_onto_review(self) -> None:
        # ``ask`` predates the lattice; it resolves to review rather than to a
        # permissive rank.
        for event in ("PreToolUse", "UserPromptSubmit", "PostToolUse"):
            assert zcode_hook_process_exit(policy_action="ask", event_name=event) == zcode_hook_process_exit(
                policy_action="review", event_name=event
            ), event


_REPO_ROOT = Path(__file__).resolve().parents[1]
_TEMPLATE_PATH = (
    _REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "adapters" / "bounded_cli_hook_script_template.py"
)
_BRIDGE_PATH = _REPO_ROOT / "rust" / "crates" / "guard-runtime" / "src" / "bounded_hook_bridge_remediation.rs"
# Punctuation only: the alphanumerics are plain in every copy, so the probe is
# the part of the alphabet a copy could disagree about.
_PUNCTUATION = "_-.:\\/ ~$'\"@%^&(){}[]|;,<>?*!+=#`"


def _standalone_hook_script_names() -> dict[str, object]:
    """The quoting rule the generated standalone hook script carries.

    The script is a string literal inside the template, and running it would
    start a hook, so the two definitions this test compares are lifted out of
    its syntax tree and nothing else is executed.
    """

    literal: str | None = None
    for node in ast.walk(ast.parse(_TEMPLATE_PATH.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "def _quote_home" in node.value:
            literal = node.value
            break
    assert literal is not None, "the hook script template no longer defines _quote_home"
    wanted = {"_quote_home", "_AUTHORITY_REMEDIATION"}
    body = [
        node
        for node in ast.parse(literal).body
        if (isinstance(node, ast.FunctionDef) and node.name in wanted)
        or (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id in wanted for target in node.targets)
        )
    ]
    namespace: dict[str, object] = {"shlex": shlex}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(_TEMPLATE_PATH), "exec"), namespace)
    assert wanted <= namespace.keys()
    return namespace


def _bridge_source() -> str:
    return _BRIDGE_PATH.read_text(encoding="utf-8")


class TestAuthorityRemediationParity:
    """The remediation sentence is written in three places, so pin them together.

    The native bridge answers the native path, ``zcode_hooks`` answers the
    Python daemon path, and the generated standalone script can import neither,
    so the duplication is structural. What a test can do is fail the moment one
    copy drifts from the others.
    """

    def test_the_standalone_script_quotes_a_home_exactly_like_the_package(self) -> None:
        script_quote = _standalone_hook_script_names()["_quote_home"]
        homes = (
            "/opt/guards/ci",
            "/opt/shared guards/.hol-guard",
            "C:\\guards\\ci",
            "C:\\Program Files\\guard\\.hol-guard",
            "C:\\Users\\RUNNER~1\\Temp\\g",
            "/opt/g$x/ci",
            "C:\\guards\\$ci",
            "C:\\guards\\%CI%",
            "C:\\guards\\`ci",
            "C:\\guards\\!ci",
            "",
        )
        for home in homes:
            for windows in (False, True):
                assert script_quote(home, windows) == _quote_home(home, windows), (home, windows)

    def test_the_native_bridge_shares_the_plain_character_set(self) -> None:
        arm = re.search(r"matches!\(\s*character,([^)]*)\)", _bridge_source())
        assert arm is not None, "the native bridge no longer spells its plain character set"
        bridge = {"\\" if literal == "\\\\" else literal for literal in re.findall(r"'(\\\\|[^'])'", arm.group(1))}
        package = {character for character in _PUNCTUATION if _quote_home("a" + character, True) == "a" + character}
        assert bridge == package

    def test_all_three_copies_offer_the_same_sentence(self) -> None:
        constant = re.search(r'const AUTHORITY_BLOCK_REMEDIATION: &str = "([^"]*)";', _bridge_source())
        assert constant is not None, "the native bridge no longer spells the remediation sentence"
        script = _standalone_hook_script_names()["_AUTHORITY_REMEDIATION"]
        assert constant.group(1) == _AUTHORITY_BLOCK_REMEDIATION == script

    def test_all_three_copies_splice_the_home_into_the_same_phrase(self) -> None:
        # Each copy reaches its named form with `.replace`, so a phrase that
        # drifts leaves one copy offering the bare command for a home the bare
        # command cannot find.
        phrase = "command controls recover-authority"
        assert phrase in _AUTHORITY_BLOCK_REMEDIATION
        assert _bridge_source().count(f'"{phrase}"') == 1
        assert phrase in str(_standalone_hook_script_names()["_AUTHORITY_REMEDIATION"])
