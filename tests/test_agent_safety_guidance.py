from __future__ import annotations

from pathlib import Path
from typing import final

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.agent_safety_guidance import (
    install_agent_safety_guidance,
    uninstall_agent_safety_guidance,
)
from codex_plugin_scanner.guard.cli import install_commands
from codex_plugin_scanner.guard.store import GuardStore


def test_install_agent_safety_guidance_preserves_user_content_and_is_idempotent(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    _ = agents_path.write_text("# My instructions\n\n- Preserve this rule.\n", encoding="utf-8")
    agents_path.chmod(0o600)

    first = install_agent_safety_guidance(home_dir)
    first_agents = agents_path.read_text(encoding="utf-8")
    safety = (home_dir / ".hol-support" / "SAFETY.md").read_text(encoding="utf-8")
    second = install_agent_safety_guidance(home_dir)

    assert first["status"] == "installed"
    assert first["changed"] is True
    assert "# My instructions" in first_agents
    assert "- Preserve this rule." in first_agents
    assert first_agents.count("BEGIN HOL GUARD SAFETY GUIDANCE") == 1
    assert "`~/.hol-support/SAFETY.md`" in first_agents
    assert agents_path.stat().st_mode & 0o777 == 0o600
    assert "Use one semantic action per tool call." in safety
    assert "Do not reshape commands to conceal those effects." in safety
    assert second == {
        "status": "installed",
        "changed": False,
        "agents_path": "~/.codex/AGENTS.md",
        "safety_path": "~/.hol-support/SAFETY.md",
    }


def test_install_agent_safety_guidance_replaces_only_managed_block(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    _ = agents_path.write_text(
        """\
User rule.

<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->
stale pointer
<!-- END HOL GUARD SAFETY GUIDANCE -->

Final user rule.
""",
        encoding="utf-8",
    )

    result = install_agent_safety_guidance(home_dir)
    updated = agents_path.read_text(encoding="utf-8")

    assert result["status"] == "installed"
    assert "User rule." in updated
    assert "Final user rule." in updated
    assert "stale pointer" not in updated
    assert updated.count("BEGIN HOL GUARD SAFETY GUIDANCE") == 1


def test_install_agent_safety_guidance_refuses_unmanaged_safety_document(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    safety_path = home_dir / ".hol-support" / "SAFETY.md"
    safety_path.parent.mkdir(parents=True)
    _ = safety_path.write_text("# Team safety\n\nKeep this rule.\n", encoding="utf-8")
    safety_path.chmod(0o600)

    with pytest.raises(RuntimeError, match=r"unmanaged SAFETY\.md"):
        _ = install_agent_safety_guidance(home_dir)

    assert safety_path.read_text(encoding="utf-8") == "# Team safety\n\nKeep this rule.\n"
    assert safety_path.stat().st_mode & 0o777 == 0o600


def test_install_agent_safety_guidance_refuses_symlinked_agents_file(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    protected_target = tmp_path / "protected.md"
    agents_path.parent.mkdir(parents=True)
    _ = protected_target.write_text("do not change\n", encoding="utf-8")
    agents_path.symlink_to(protected_target)

    with pytest.raises(RuntimeError, match=r"non-regular support file: AGENTS\.md"):
        _ = install_agent_safety_guidance(home_dir)
    assert protected_target.read_text(encoding="utf-8") == "do not change\n"
    assert not (home_dir / ".hol-support" / "SAFETY.md").exists()


def test_install_agent_safety_guidance_refuses_incomplete_managed_block(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    original = "<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->\nuser-edited text\n"
    _ = agents_path.write_text(original, encoding="utf-8")

    with pytest.raises(RuntimeError, match="incomplete managed safety guidance"):
        _ = install_agent_safety_guidance(home_dir)

    assert agents_path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize(
    "content",
    [
        "<!-- END HOL GUARD SAFETY GUIDANCE -->\nuser\n<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->\n",
        "  <!-- BEGIN HOL GUARD SAFETY GUIDANCE -->\nuser\n  <!-- END HOL GUARD SAFETY GUIDANCE -->\n",
    ],
)
def test_install_agent_safety_guidance_refuses_malformed_managed_markers(
    tmp_path: Path,
    content: str,
) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    _ = agents_path.write_text(content, encoding="utf-8")

    with pytest.raises(RuntimeError, match="incomplete managed safety guidance"):
        _ = install_agent_safety_guidance(home_dir)

    assert agents_path.read_text(encoding="utf-8") == content


def test_install_agent_safety_guidance_refuses_symlinked_support_directory(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    protected_dir = tmp_path / "protected"
    protected_dir.mkdir()
    home_dir.mkdir()
    (home_dir / ".hol-support").symlink_to(protected_dir, target_is_directory=True)

    with pytest.raises(RuntimeError, match="non-directory support path"):
        _ = install_agent_safety_guidance(home_dir)

    assert not (protected_dir / "SAFETY.md").exists()


def test_uninstall_agent_safety_guidance_preserves_user_agents_content(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    _ = agents_path.write_text("# User agents\n", encoding="utf-8")
    _ = install_agent_safety_guidance(home_dir)

    result = uninstall_agent_safety_guidance(home_dir)

    assert result["status"] == "removed"
    assert result["changed"] is True
    assert agents_path.read_text(encoding="utf-8") == "# User agents\n"
    assert not (home_dir / ".hol-support" / "SAFETY.md").exists()


def test_uninstall_preserves_user_bytes_around_managed_block(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    original = "Before  \n\nAfter\t\n\n"
    _ = agents_path.write_text(original, encoding="utf-8")
    _ = install_agent_safety_guidance(home_dir)

    result = uninstall_agent_safety_guidance(home_dir)

    assert result["status"] == "removed"
    assert agents_path.read_text(encoding="utf-8") == original


def test_install_and_uninstall_preserve_crlf_user_bytes(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    agents_path = home_dir / ".codex" / "AGENTS.md"
    agents_path.parent.mkdir(parents=True)
    original = b"alpha\r\nbeta\r\n"
    _ = agents_path.write_bytes(original)

    _ = install_agent_safety_guidance(home_dir)
    result = uninstall_agent_safety_guidance(home_dir)

    assert result["status"] == "removed"
    assert agents_path.read_bytes() == original


_PREVIOUS_SAFETY_BODY = (Path(__file__).parent / "fixtures" / "agent-safety-guidance-previous.md").read_text(
    encoding="utf-8"
)


_SECRET_CARVEOUT_SAFETY_BODY = (
    Path(__file__).parent / "fixtures" / "agent-safety-guidance-secret-carveout.md"
).read_text(encoding="utf-8")


_BEFORE_SCRIPT_FREE_INSTALLS_BODY = (
    Path(__file__).parent / "fixtures" / "agent-safety-guidance-before-script-free-installs.md"
).read_text(encoding="utf-8")


_BEFORE_CONNECTOR_SETUP_BODY = (
    Path(__file__).parent / "fixtures" / "agent-safety-guidance-before-connector-setup.md"
).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "legacy",
    [
        pytest.param(_PREVIOUS_SAFETY_BODY, id="unprefixed"),
        pytest.param(f"<!-- HOL GUARD MANAGED SAFETY DOCUMENT v2 -->\n{_PREVIOUS_SAFETY_BODY}", id="v2"),
        pytest.param(
            f"<!-- HOL GUARD MANAGED SAFETY DOCUMENT v2 -->\n{_SECRET_CARVEOUT_SAFETY_BODY}",
            id="secret-carveout",
        ),
        pytest.param(
            f"<!-- HOL GUARD MANAGED SAFETY DOCUMENT v2 -->\n{_BEFORE_SCRIPT_FREE_INSTALLS_BODY}",
            id="before-script-free-installs",
        ),
        pytest.param(
            f"<!-- HOL GUARD MANAGED SAFETY DOCUMENT v2 -->\n{_BEFORE_CONNECTOR_SETUP_BODY}",
            id="before-connector-setup",
        ),
    ],
)
def test_install_migrates_known_previous_safety_document(tmp_path: Path, legacy: str) -> None:
    home_dir = tmp_path / "home"
    safety_path = home_dir / ".hol-support" / "SAFETY.md"
    _ = install_agent_safety_guidance(home_dir)
    current = safety_path.read_text(encoding="utf-8")
    _ = safety_path.write_text(legacy, newline="", encoding="utf-8")

    result = install_agent_safety_guidance(home_dir)

    assert result["status"] == "installed"
    assert result["changed"] is True
    assert safety_path.read_text(encoding="utf-8") == current
    assert "Never approve, deny, or resolve your own Guard approval requests." in current


def test_safety_document_leaves_secret_reads_to_guard(tmp_path: Path) -> None:
    """A Windows tester watched Codex read a `.env` and cite this document for it.

    The old wording excepted access "the user explicitly authorizes", which the
    agent is in no position to establish: it decided it had been authorized and
    read the file. Nothing here may give an agent that call to make.
    """

    home_dir = tmp_path / "home"
    _ = install_agent_safety_guidance(home_dir)
    safety = (home_dir / ".hol-support" / "SAFETY.md").read_text(encoding="utf-8")

    assert "Never read secret files, credential stores, or environment files on your own judgment." in safety
    assert "unless the user explicitly authorizes" not in safety
    # The bullet must not end on an imperative to go ahead: an agent weighing
    # two sentences against each other takes the concrete one.
    assert "Run the read" not in safety


def test_safety_document_forbids_self_approval(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    _ = install_agent_safety_guidance(home_dir)
    safety = (home_dir / ".hol-support" / "SAFETY.md").read_text(encoding="utf-8")

    assert "## Leave approvals to the user" in safety
    assert "Never open, fetch, or follow a Guard approval link." in safety
    assert "`hol-guard` approval commands" in safety
    assert "show its approval link to the user verbatim" in safety


def test_uninstall_agent_safety_guidance_removes_guard_only_files(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    _ = install_agent_safety_guidance(home_dir)

    result = uninstall_agent_safety_guidance(home_dir)

    assert result["status"] == "removed"
    assert not (home_dir / ".codex" / "AGENTS.md").exists()
    assert not (home_dir / ".hol-support" / "SAFETY.md").exists()


def test_successful_harness_install_attaches_agent_safety_guidance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @final
    class FakeAdapter:
        harness = "codex"

        @staticmethod
        def install(_context: HarnessContext) -> dict[str, object]:
            return {"config_path": "~/.codex/config.toml"}

        @staticmethod
        def uninstall(_context: HarnessContext) -> dict[str, object]:
            return {"removed": True}

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )

    def fake_get_adapter(_harness: str) -> FakeAdapter:
        return FakeAdapter()

    monkeypatch.setattr(install_commands, "get_adapter", fake_get_adapter)

    payload = install_commands.apply_managed_install(
        "install",
        "opencode",
        False,
        context,
        GuardStore(context.guard_home),
        str(workspace_dir),
        "2026-07-28T00:00:00Z",
    )

    assert payload["agent_safety_guidance"] == {
        "status": "installed",
        "changed": True,
        "agents_path": "~/.codex/AGENTS.md",
        "safety_path": "~/.hol-support/SAFETY.md",
    }
    assert (home_dir / ".codex" / "AGENTS.md").is_file()
    assert (home_dir / ".hol-support" / "SAFETY.md").is_file()

    removed = install_commands.apply_managed_install(
        "uninstall",
        "opencode",
        False,
        context,
        GuardStore(context.guard_home),
        str(workspace_dir),
        "2026-07-28T00:01:00Z",
    )

    guidance = removed["agent_safety_guidance"]
    assert isinstance(guidance, dict)
    assert guidance["status"] == "removed"
    assert not (home_dir / ".codex" / "AGENTS.md").exists()
    assert not (home_dir / ".hol-support" / "SAFETY.md").exists()


def test_cli_install_fails_visibly_when_guidance_cannot_be_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    @final
    class FakeAdapter:
        harness = "opencode"

        @staticmethod
        def install(_context: HarnessContext) -> dict[str, object]:
            return {"config_path": "~/.config/opencode/config.json"}

    home_dir = tmp_path / "home"
    safety_path = home_dir / ".hol-support" / "SAFETY.md"
    safety_path.parent.mkdir(parents=True)
    _ = safety_path.write_text("unmanaged\n", encoding="utf-8")

    def fake_get_adapter(_harness: str) -> FakeAdapter:
        return FakeAdapter()

    monkeypatch.setattr(install_commands, "get_adapter", fake_get_adapter)

    return_code = main(
        [
            "guard",
            "install",
            "opencode",
            "--home",
            str(home_dir),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--json",
        ]
    )

    assert return_code != 0
    assert "unmanaged SAFETY.md" in capsys.readouterr().err


def test_uninstall_retains_guidance_while_another_harness_is_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @final
    class FakeAdapter:
        harness = "codex"

        @staticmethod
        def uninstall(_context: HarnessContext) -> dict[str, object]:
            return {"removed": True}

    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    store = GuardStore(guard_home)
    store.set_managed_install("codex", True, None, {}, "2026-07-28T00:00:00Z")
    store.set_managed_install("pi", True, None, {}, "2026-07-28T00:00:00Z")
    _ = install_agent_safety_guidance(home_dir)

    def fake_get_adapter(_harness: str) -> FakeAdapter:
        return FakeAdapter()

    monkeypatch.setattr(install_commands, "get_adapter", fake_get_adapter)

    payload = install_commands.apply_managed_install(
        "uninstall",
        "codex",
        False,
        context,
        store,
        None,
        "2026-07-28T00:01:00Z",
    )

    assert "agent_safety_guidance" not in payload
    assert (home_dir / ".codex" / "AGENTS.md").is_file()
    assert (home_dir / ".hol-support" / "SAFETY.md").is_file()


def test_install_fails_closed_without_the_native_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    def no_runtime(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(runtime_request, "runtime_answer", no_runtime)

    with pytest.raises(RuntimeError, match=r"agents_changed=false, safety_changed=false\): native runtime unavailable"):
        _ = install_agent_safety_guidance(tmp_path / "home")

    assert not (tmp_path / "home").exists()
