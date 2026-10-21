"""Guard edits `~/.codex/config.toml`; it does not get to rewrite it.

A Windows tester reported that installing Guard reflowed their whole Codex
config. Codex users write that file by hand, so the comments and the ordering
they put there have to survive every Guard write.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.codex_config import dump_toml, read_toml_payload

from .test_codex_publication_preparation import _context

_HAND_WRITTEN = """\
# Which model Codex talks to. Keep this at the top.
model = "fixture"
model_reasoning_effort = 'medium'   # single quotes on purpose

# Everything below is mine.
[mcp_servers.fixture]
command = "node"
args = ["fixture.js"]        # trailing comment
env = { FIXTURE = "1" }

[tui]
# A comment with no key after it.
"""


def test_an_edit_keeps_the_comments_and_the_spelling_around_it() -> None:
    payload = {"model": "fixture", "model_reasoning_effort": "medium", "approval_policy": "never"}
    rendered = dump_toml(payload, original=_HAND_WRITTEN)

    assert "# Which model Codex talks to. Keep this at the top." in rendered
    assert "model_reasoning_effort = 'medium'   # single quotes on purpose" in rendered
    assert 'approval_policy = "never"' in rendered


def test_the_rendered_file_still_means_exactly_the_payload() -> None:
    payload: dict[str, object] = {
        "model": "replacement",
        "mcp_servers": {"fixture": {"command": "node", "args": ["fixture.js", "--guard"]}},
    }
    rendered = dump_toml(payload, original=_HAND_WRITTEN)

    import tomllib

    assert tomllib.loads(rendered) == payload
    assert "# Everything below is mine." in rendered


def test_a_file_guard_cannot_parse_falls_back_to_the_plain_renderer() -> None:
    payload = {"model": "fixture"}

    assert dump_toml(payload, original="model = = =\n") == dump_toml(payload)
    assert dump_toml(payload, original=b"\xff\xfe not utf-8") == dump_toml(payload)


def test_install_and_uninstall_leave_a_hand_written_config_recognizable(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path, monkeypatch)
    harness = adapter.CodexHarnessAdapter()
    config_path = harness._target_config_path(context)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_HAND_WRITTEN, encoding="utf-8")

    harness.install(context)
    installed = config_path.read_text(encoding="utf-8")
    assert "# Which model Codex talks to. Keep this at the top." in installed
    assert "# Everything below is mine." in installed
    assert "model_reasoning_effort = 'medium'   # single quotes on purpose" in installed
    assert read_toml_payload(config_path)["hooks"]

    harness.uninstall(context)
    removed = config_path.read_text(encoding="utf-8")
    assert "# Which model Codex talks to. Keep this at the top." in removed
    assert "# Everything below is mine." in removed
    assert read_toml_payload(config_path).get("mcp_servers", {}).get("fixture", {}).get("command") == "node"


_WITH_USER_HOOKS = """\
model = "fixture"

[features]
hooks = 1   # the user wrote an integer here

[[hooks.PreToolUse]]
# My own hook. Hands off.
matcher = "Bash"

  [[hooks.PreToolUse.hooks]]
  type = "command"
  command = "echo mine"   # keep this spelling
"""


def test_an_integer_standing_in_for_a_boolean_is_corrected() -> None:
    """`1 == True` in Python, so a plain comparison would leave the integer.

    Codex reads `[features] hooks` as a boolean and Guard's own state check
    asks whether it is `True`, so a config left holding `1` makes an installed
    Guard report its hooks as disabled.
    """

    rendered = dump_toml({"model": "fixture", "features": {"hooks": True}}, original=_WITH_USER_HOOKS)

    import tomllib

    assert tomllib.loads(rendered)["features"]["hooks"] is True


_GUARD_GROUP_BEFORE_THE_USER = """\
[[hooks.PreToolUse]]
# Guard group.
matcher = "Bash"

  [[hooks.PreToolUse.hooks]]
  type = "command"
  command = "guard-hook"

[[hooks.PreToolUse]]
# My own hook. Hands off.
matcher = "Bash"

  [[hooks.PreToolUse.hooks]]
  type = "command"
  command = "echo mine"   # keep this spelling
"""


def test_reordering_hook_groups_does_not_move_the_users_comments() -> None:
    """Install drops Guard's group and appends it, so positions swap.

    Matching by index writes the user's group into Guard's old table. The
    user's comment then sits on Guard's command and is deleted with that
    table on uninstall, while the readback still sees the right values.
    """

    payload = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]},
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard-hook"}]},
            ]
        }
    }
    rendered = dump_toml(payload, original=_GUARD_GROUP_BEFORE_THE_USER)
    user_comment = rendered.index("# My own hook. Hands off.")
    user_command = rendered.index('command = "echo mine"   # keep this spelling')
    guard_comment = rendered.index("# Guard group.")
    guard_command = rendered.index('command = "guard-hook"')
    assert user_comment < user_command < guard_comment < guard_command


def test_a_user_owned_hook_group_keeps_its_comments_through_install_and_uninstall(tmp_path: Path, monkeypatch) -> None:
    """Guard adds and removes its own group; the array holds the user's too.

    Assigning the event's whole array back would rewrite every group in it, so
    the comments and spelling inside a group Guard never touched would be lost
    to an edit that has nothing to do with it.
    """

    context = _context(tmp_path, monkeypatch)
    harness = adapter.CodexHarnessAdapter()
    config_path = harness._target_config_path(context)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_WITH_USER_HOOKS, encoding="utf-8")

    harness.install(context)
    installed = config_path.read_text(encoding="utf-8")
    assert "# My own hook. Hands off." in installed
    assert 'command = "echo mine"   # keep this spelling' in installed
    assert read_toml_payload(config_path)["features"]["hooks"] is True

    harness.uninstall(context)
    removed = config_path.read_text(encoding="utf-8")
    assert "# My own hook. Hands off." in removed
    assert 'command = "echo mine"   # keep this spelling' in removed
    groups = read_toml_payload(config_path)["hooks"]["PreToolUse"]
    assert [group["matcher"] for group in groups] == ["Bash"]
