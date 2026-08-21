from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.local_cli_hook import apply_local_cli_grant, observe_unlisted_cli
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.runtime.local_cli_commands import resolve_command_id_for_text
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
        == "review"
    )
