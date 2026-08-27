from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.local_cli_hook import apply_local_cli_grant, observe_unlisted_cli
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.runtime.local_cli_commands import resolve_command_id_for_text
from codex_plugin_scanner.guard.runtime.package_json_script_memory import (
    refresh_package_script_catalogs,
)
from codex_plugin_scanner.guard.runtime.package_json_scripts import (
    command_id_for_script,
    commands_from_package_scripts,
    recognize_package_json_scripts,
)
from codex_plugin_scanner.guard.store import GuardStore


def _write_package(
    directory: Path,
    *,
    scripts: dict[str, str],
    name: str = "demo-app",
    lock: str | None = "pnpm-lock.yaml",
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "package.json").write_text(
        _package_json(name=name, scripts=scripts),
        encoding="utf-8",
    )
    if lock:
        (directory / lock).write_text("{}\n", encoding="utf-8")
    return directory


def _package_json(*, name: str, scripts: dict[str, str]) -> str:
    import json

    return json.dumps({"name": name, "scripts": scripts}, indent=2) + "\n"


def test_nested_colon_scripts_are_discovered(tmp_path: Path) -> None:
    project = _write_package(
        tmp_path / "app",
        scripts={
            "guard": "tsx scripts/guard.ts",
            "guard:reddit-targeting:audit": "tsx scripts/audit.ts",
            "guard:reddit-targeting:plan": "tsx scripts/plan.ts",
            "build": "vite build",
            "preinstall": "echo hidden",
            "preguard": "echo hidden-pre",
        },
    )
    discovery = recognize_package_json_scripts("npm run", cwd=project, home_dir=tmp_path)
    assert discovery is not None
    assert discovery.runner == "pnpm"
    names = {command.name for command in discovery.commands}
    assert "guard" in names
    assert "guard:reddit-targeting:audit" in names
    assert "guard:reddit-targeting:plan" in names
    assert "build" in names
    assert "preinstall" not in names
    assert "preguard" not in names
    nested = next(command for command in discovery.commands if command.name == "guard:reddit-targeting:audit")
    assert nested.command_id == "guard.reddit-targeting.audit"
    assert nested.parent_id == "guard.reddit-targeting"
    assert nested.usage == "pnpm run guard:reddit-targeting:audit"


def test_directory_and_prefix_pastes_use_that_package_json(tmp_path: Path) -> None:
    nested = _write_package(
        tmp_path / "packages" / "ads",
        scripts={"guard:reddit-targeting:audit": "tsx audit.ts"},
        name="ads",
    )
    _write_package(tmp_path, scripts={"root": "echo root"}, name="root-app")
    from_dir = recognize_package_json_scripts(str(nested), cwd=tmp_path, home_dir=tmp_path)
    from_prefix = recognize_package_json_scripts(
        f"npm --prefix {nested} run guard:reddit-targeting:audit",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert from_dir is not None
    assert from_prefix is not None
    assert from_dir.identity.cli_id == from_prefix.identity.cli_id
    assert from_dir.identity.name == "ads"
    assert any(command.name == "guard:reddit-targeting:audit" for command in from_dir.commands)
    assert from_prefix.focused_script == "guard:reddit-targeting:audit"


def test_focused_nested_script_sorts_first() -> None:
    commands = commands_from_package_scripts(
        {
            "build": "vite build",
            "guard:reddit-targeting:audit": "tsx audit.ts",
            "guard": "tsx guard.ts",
        },
        runner="npm",
        focused_script="guard:reddit-targeting:audit",
    )
    script_names = [command.name for command in commands if command.command_id not in {"root", "other"}]
    assert script_names[0] == "guard:reddit-targeting:audit"


def test_command_id_splits_colon_namespaces() -> None:
    assert command_id_for_script("guard:reddit-targeting:audit") == "guard.reddit-targeting.audit"


def test_reserved_script_names_do_not_alias_synthetic_commands() -> None:
    commands = commands_from_package_scripts(
        {"root": "echo root", "other": "echo other"},
        runner="npm",
        focused_script=None,
    )
    named = {command.name: command.command_id for command in commands}
    assert named["root"] != "root"
    assert named["other"] != "other"


def test_dotted_script_live_tokens_match_catalog(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.package_json_scripts import package_script_command_tokens

    project = _write_package(tmp_path / "app", scripts={"db.migrate": "prisma migrate deploy"})
    discovery = recognize_package_json_scripts("npm run db.migrate", cwd=project, home_dir=tmp_path)
    assert discovery is not None
    command_id = command_id_for_script("db.migrate")
    assert command_id != "other"
    assert any(command.command_id == command_id for command in discovery.commands)
    tokens = package_script_command_tokens("npm run db.migrate", cwd=project, home_dir=tmp_path)
    assert tokens is not None
    assert ".".join(tokens) == command_id


def test_recognize_explains_missing_package_json(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError

    empty = tmp_path / "empty"
    empty.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    service = LocalCliApiService(store=GuardStore(home))
    try:
        service.recognize({"command": "npm run", "cwd": str(empty)})
    except LocalCliApiError as exc:
        assert exc.code == "missing_package_json"
        assert "package.json" in str(exc)
    else:
        raise AssertionError("expected missing_package_json")


def test_recognize_api_lists_scripts_instead_of_built_in_npm(tmp_path: Path) -> None:
    project = _write_package(
        tmp_path / "app",
        scripts={"guard:reddit-targeting:audit": "tsx audit.ts", "guard": "tsx guard.ts"},
    )
    home = tmp_path / "home"
    home.mkdir()
    service = LocalCliApiService(store=GuardStore(home))
    payload = service.recognize({"command": "npm run guard", "cwd": str(project)})
    item = payload["item"]
    assert isinstance(item, dict)
    assert item["surface"] == "package-scripts"
    names = {str(command["name"]) for command in item["commands"] if isinstance(command, dict)}
    assert "guard" in names
    assert "guard:reddit-targeting:audit" in names
    assert "pnpm run" in str(payload["summary"])


def test_allowed_nested_script_grant_matches_live_command(tmp_path: Path) -> None:
    project = _write_package(
        tmp_path / "app",
        scripts={"guard:reddit-targeting:audit": "tsx audit.ts", "guard": "tsx guard.ts"},
    )
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    service = LocalCliApiService(store=store)
    recognized = service.recognize({"command": "pnpm run", "cwd": str(project)})
    item = recognized["item"]
    assert isinstance(item, dict)
    identity = store.list_local_cli_items()[0]
    from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

    listed = UnlistedCliIdentity(
        cli_id=str(identity["cli_id"]),
        name=str(identity["name"]),
        kind="script",
        identity_hash=str(identity["identity_hash"]),
        example_label=str(identity["example_label"]),
        interpreter_name="pnpm",
    )
    store.upsert_local_cli_grant(
        identity=listed,
        state="allowed",
        expected_revision=int(recognized["revision"]),
        updated_at=utc_now(),
        command_states={
            "guard.reddit-targeting.audit": "allow",
            "guard": "inherit",
        },
    )
    live = "pnpm run guard:reddit-targeting:audit"
    assert (
        resolve_command_id_for_text(
            live,
            cwd=project,
            home_dir=home,
            identity=listed,
            commands=store.read_local_cli_command_catalog(listed.cli_id),
        )
        == "guard.reddit-targeting.audit"
    )
    observe_unlisted_cli(store=store, command=live, cwd=project, home_dir=home)
    assert (
        apply_local_cli_grant(
            store=store,
            command=live,
            cwd=project,
            home_dir=home,
            current_action="review",
        )
        == "allow"
    )
    assert (
        apply_local_cli_grant(
            store=store,
            command="pnpm run guard",
            cwd=project,
            home_dir=home,
            current_action="review",
        )
        == "allow"
    )
    assert (
        apply_local_cli_grant(
            store=store,
            command="pnpm run not-a-script",
            cwd=project,
            home_dir=home,
            current_action="review",
        )
        == "review"
    )


def test_hook_remembers_real_package_json_path(tmp_path: Path) -> None:
    project = _write_package(tmp_path / "app", scripts={"guard:audit": "tsx audit.ts"})
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    observe_unlisted_cli(
        store=store,
        command="pnpm run guard:audit",
        cwd=project,
        home_dir=home,
    )
    stored = store.list_local_cli_items()[0]
    assert stored["surface"] == "package-scripts"
    assert stored["source_path"] == str((project / "package.json").resolve())


def test_list_items_does_not_scan_cwd_as_a_package_project(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = _write_package(tmp_path / "cwd-app", scripts={"guard:audit": "tsx audit.ts"})
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    payload = LocalCliApiService(store=GuardStore(home)).list_items()
    items = payload["items"]
    assert isinstance(items, list)
    assert all(not isinstance(item, dict) or item.get("surface") != "package-scripts" for item in items)


def test_list_items_redacts_remembered_package_paths(tmp_path: Path) -> None:
    project = _write_package(tmp_path / "ads-app", scripts={"guard:reddit-targeting:audit": "tsx audit.ts"})
    home = tmp_path / "home"
    home.mkdir()
    service = LocalCliApiService(store=GuardStore(home))
    _ = service.recognize({"command": "pnpm run", "cwd": str(project)})
    payload = service.list_items()
    items = payload["items"]
    assert isinstance(items, list)
    package_items = [item for item in items if isinstance(item, dict) and item.get("surface") == "package-scripts"]
    listed = next(item for item in package_items if item.get("source_label") == "ads-app")
    assert listed["source_path"] == "user-tool"
    assert listed["source_label"] == "ads-app"
    serialized = str(payload)
    assert str(project) not in serialized
    assert "package.json" not in str(listed["source_path"])
    names = {str(command["name"]) for command in listed["commands"] if isinstance(command, dict)}
    assert "guard:reddit-targeting:audit" in names


def test_recognize_uses_remembered_project_without_prefix(tmp_path: Path) -> None:
    project = _write_package(
        tmp_path / "app",
        scripts={"guard:reddit-targeting:audit": "tsx audit.ts", "build": "vite build"},
    )
    empty = tmp_path / "empty"
    empty.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    service = LocalCliApiService(store=GuardStore(home))
    first = service.recognize({"command": "pnpm run", "cwd": str(project)})
    second = service.recognize({"command": "npm run guard:reddit-targeting:audit", "cwd": str(empty)})
    first_item = first["item"]
    second_item = second["item"]
    assert isinstance(first_item, dict)
    assert isinstance(second_item, dict)
    assert first_item["cli_id"] == second_item["cli_id"]
    assert second_item["source_path"] == "user-tool"
    names = {str(command["name"]) for command in second_item["commands"] if isinstance(command, dict)}
    assert "guard:reddit-targeting:audit" in names


def test_refresh_includes_workspace_packages(tmp_path: Path) -> None:
    root = tmp_path / "mono"
    nested = root / "packages" / "ads"
    nested.mkdir(parents=True)
    (root / "package.json").write_text(
        '{"name":"mono","private":true,"workspaces":["packages/*"],"scripts":{"lint":"echo lint"}}\n',
        encoding="utf-8",
    )
    _write_package(nested, scripts={"guard:reddit-targeting:audit": "tsx audit.ts"}, name="ads")
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    service = LocalCliApiService(store=store)
    _ = service.recognize({"command": "pnpm run", "cwd": str(root)})
    refresh_package_script_catalogs(store, home_dir=home)
    payload = service.list_items()
    items = payload["items"]
    assert isinstance(items, list)
    labels = {
        str(item.get("source_label") or item.get("name"))
        for item in items
        if isinstance(item, dict) and item.get("surface") == "package-scripts"
    }
    assert "mono" in labels
    assert "ads" in labels


def test_remembered_script_requires_a_unique_project(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError

    first = _write_package(tmp_path / "one", scripts={"build": "echo one"}, name="one")
    second = _write_package(tmp_path / "two", scripts={"build": "echo two"}, name="two")
    empty = tmp_path / "empty"
    empty.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    service = LocalCliApiService(store=GuardStore(home))
    _ = service.recognize({"command": "pnpm run", "cwd": str(first)})
    _ = service.recognize({"command": "pnpm run", "cwd": str(second)})
    try:
        service.recognize({"command": "npm run build", "cwd": str(empty)})
    except LocalCliApiError as exc:
        assert exc.code == "missing_package_json"
    else:
        raise AssertionError("expected missing_package_json for an ambiguous script")


def test_refresh_updates_identity_hash_when_scripts_change(tmp_path: Path) -> None:
    project = _write_package(tmp_path / "app", scripts={"build": "echo first"})
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    service = LocalCliApiService(store=store)
    first = service.recognize({"command": "pnpm run", "cwd": str(project)})
    item = first["item"]
    assert isinstance(item, dict)
    original_hash = str(item["identity_hash"])
    (project / "package.json").write_text(
        _package_json(name="app", scripts={"build": "echo first", "guard:audit": "echo audit"}),
        encoding="utf-8",
    )
    refresh_package_script_catalogs(store, home_dir=home)
    payload = service.list_items()
    listed = next(
        entry
        for entry in payload["items"]
        if isinstance(entry, dict) and entry.get("surface") == "package-scripts" and entry.get("source_label") == "app"
    )
    assert str(listed["identity_hash"]) != original_hash
    names = {str(command["name"]) for command in listed["commands"] if isinstance(command, dict)}
    assert "guard:audit" in names


def test_missing_package_json_is_hidden_from_public_list(tmp_path: Path) -> None:
    project = _write_package(tmp_path / "gone", scripts={"build": "echo gone"})
    home = tmp_path / "home"
    home.mkdir()
    service = LocalCliApiService(store=GuardStore(home))
    _ = service.recognize({"command": "pnpm run", "cwd": str(project)})
    (project / "package.json").unlink()
    payload = service.list_items()
    labels = {
        str(item.get("source_label"))
        for item in payload["items"]
        if isinstance(item, dict) and item.get("surface") == "package-scripts"
    }
    assert "gone" not in labels
