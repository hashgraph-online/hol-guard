from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.local_cli_hook import observe_unlisted_cli
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.runtime.custom_extension_suggestion import (
    common_utility_reject_message,
    is_common_shell_utility,
    is_suggestable_custom_tool,
    observation_path_class,
    suggestion_score,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import (
    UnlistedCliIdentity,
    identify_unlisted_cli,
    recognize_operator_cli,
)
from codex_plugin_scanner.guard.store import GuardStore

_SCREENSHOT_JUNK = ("script", "rg", "whoami", "vitest.mjs")


def test_screenshot_names_are_not_suggestable() -> None:
    assert not is_suggestable_custom_tool(name="script", kind="executable")
    assert not is_suggestable_custom_tool(name="rg", kind="executable")
    assert not is_suggestable_custom_tool(name="whoami", kind="executable")
    assert not is_suggestable_custom_tool(name="vitest.mjs", kind="script")


def test_project_tools_stay_suggestable() -> None:
    assert is_suggestable_custom_tool(name="cwv.py", kind="script")
    assert is_suggestable_custom_tool(name="internal-deploy", kind="executable")


def test_mcp_surface_stays_suggestable_even_for_short_names() -> None:
    assert is_suggestable_custom_tool(name="github", kind="executable", surface="mcp")


def test_package_store_scripts_are_not_suggestable() -> None:
    assert not is_suggestable_custom_tool(
        name="ship.mjs",
        kind="script",
        source_path="/workspace/app/node_modules/vitest/vitest.mjs",
    )


def test_windows_system_bins_are_not_promoted() -> None:
    assert observation_path_class(r"C:\Windows\System32\where.exe") == "system-bin"
    assert (
        suggestion_score(
            name="where",
            kind="executable",
            source_path=r"C:\Windows\System32\where.exe",
            observed_count=4,
        )
        == 0
    )
    assert observation_path_class("/opt/demo/windows/system32/ship-it") == "user-tool"


def test_search_and_identity_reject_copy() -> None:
    assert "search tool" in common_utility_reject_message("rg")
    assert "identity" in common_utility_reject_message("whoami")
    assert "terminal recorder" in common_utility_reject_message("script")
    assert "shell command" in common_utility_reject_message("ls")


def test_repeat_use_outranks_generic_one_shot() -> None:
    project = suggestion_score(name="cwv.py", kind="script", observed_count=4)
    generic = suggestion_score(name="foo", kind="executable", observed_count=1)
    assert project > generic


def test_screenshot_junk_is_not_observed_or_suggested(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    tool = tmp_path / "internal-deploy"
    tool.write_text("#!/bin/sh\necho deploy\n", encoding="utf-8")
    tool.chmod(0o755)
    vitest = tmp_path / "vitest.mjs"
    vitest.write_text("export {}\n", encoding="utf-8")
    for command in ("rg pattern", "whoami", "script"):
        observe_unlisted_cli(store=store, command=command, cwd=tmp_path, home_dir=tmp_path)
        assert identify_unlisted_cli(command, cwd=tmp_path, home_dir=tmp_path) is None
        assert is_common_shell_utility(command.split()[0])
    observe_unlisted_cli(store=store, command=f"node {vitest}", cwd=tmp_path, home_dir=tmp_path)
    observe_unlisted_cli(store=store, command=str(tool), cwd=tmp_path, home_dir=tmp_path)
    items = store.list_local_cli_items()
    names = {str(item["name"]) for item in items}
    assert "internal-deploy" in names
    assert not ({"script", "rg", "whoami"} & names)
    suggestable = {str(item["name"]) for item in items if item["suggestable"] is True}
    assert suggestable == {"internal-deploy"}
    assert "vitest.mjs" not in suggestable
    deploy = next(item for item in items if item["name"] == "internal-deploy")
    assert deploy["source_path"] == "user-tool"
    assert isinstance(deploy["suggestion_score"], int)
    assert int(deploy["suggestion_score"]) >= 15


def test_legacy_stored_junk_rows_are_not_suggestable(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script = tmp_path / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity = identify_unlisted_cli(f"python3 {script}", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    store.record_local_cli_observation(identity, seen_at=utc_now())
    for name in _SCREENSHOT_JUNK:
        fake = UnlistedCliIdentity(
            cli_id=f"local-cli.{name.replace('.', '-')}-aaaaaaaa",
            name=name,
            kind="script" if name.endswith(".mjs") else "executable",
            identity_hash="a" * 64,
            example_label=name,
        )
        store.record_local_cli_observation(fake, seen_at=utc_now())
    items = {str(item["name"]): item for item in store.list_local_cli_items()}
    assert items["cwv.py"]["suggestable"] is True
    for name in _SCREENSHOT_JUNK:
        assert items[name]["suggestable"] is False


def test_sourced_helper_in_compound_command_is_observed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    helper = tmp_path / "server-access.sh"
    helper.write_text("#!/bin/sh\necho access\n", encoding="utf-8")
    helper.chmod(0o755)
    observe_unlisted_cli(
        store=store,
        command=f"source {helper} && ssh -o BatchMode=yes host 'echo ok'",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    items = store.list_local_cli_items()
    names = {str(item["name"]) for item in items}
    assert names == {"server-access.sh"}
    item = items[0]
    assert item["suggestable"] is True
    assert item["state"] == "unset"


def test_recognize_explains_screenshot_utilities(tmp_path: Path) -> None:
    _, code, message = recognize_operator_cli("rg pattern", cwd=tmp_path, home_dir=tmp_path)
    assert code == "common_shell_utility"
    assert "search tool" in message
    _, whoami_code, whoami_message = recognize_operator_cli("whoami", cwd=tmp_path, home_dir=tmp_path)
    assert whoami_code == "common_shell_utility"
    assert "identity" in whoami_message
