"""Reconciliation rewrites hook artifacts that launch another install's Python or an older runtime."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import runtime_artifact_reconciliation as reconciliation
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_hooks import _posix_wrapper, _powershell_wrapper
from codex_plugin_scanner.guard.foreign_hook_interpreter import current_guard_python, names_foreign_interpreter
from codex_plugin_scanner.guard.runtime_transition import TransitionFile

_FOREIGN = "/home/u/.local/pipx/venvs/hol-guard/bin/python"
_SPACED_FOREIGN = "/opt/Application Support/pipx/venvs/hol-guard/bin/python"


class _Store:
    def __init__(self, guard_home: Path, install: dict[str, object]) -> None:
        self.guard_home = guard_home
        self.install = install

    def list_managed_installs(self) -> list[dict[str, object]]:
        return [self.install]

    def get_managed_install(self, _harness: str) -> dict[str, object] | None:
        return self.install


def _current() -> str:
    current = current_guard_python()
    assert current is not None
    return current


def _worker(guard_home: Path) -> Path:
    return guard_home / "managed" / "cline" / "hook-workers" / "PreToolUse.py"


def _write_launcher(launcher: Path, guard_home: Path, python: str) -> None:
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(_posix_wrapper(worker=_worker(guard_home), python=python), encoding="utf-8")


def _cline_store(tmp_path: Path, python: str) -> tuple[_Store, Path]:
    guard_home = tmp_path / "guard"
    launcher = tmp_path / "home" / "Documents" / "Cline" / "Hooks" / "PreToolUse"
    _write_launcher(launcher, guard_home, python)
    manifest = {
        "transport": {
            "managed_hooks_root": str(launcher.parent),
            "managed_hook_paths": {"PreToolUse": str(launcher)},
        }
    }
    return _Store(guard_home, {"harness": "cline", "active": True, "manifest": manifest}), launcher


def _patch_reconciliation(monkeypatch: pytest.MonkeyPatch, launcher: Path, guard_home: Path) -> list[str]:
    applied: list[str] = []

    def apply(_command: str, harness: str, *_args: object) -> None:
        applied.append(harness)
        _write_launcher(launcher, guard_home, _current())

    # The install-time proof only hashes the shim, so it still reads as intact.
    monkeypatch.setattr(reconciliation, "_live_hook_verification", lambda *_args: {"cline": True})
    monkeypatch.setattr(reconciliation, "_current_durable_runtime_digest", lambda: None)
    monkeypatch.setattr(reconciliation, "apply_managed_install", apply)
    return applied


@pytest.mark.parametrize("foreign", [_FOREIGN, _SPACED_FOREIGN])
def test_repair_rewrites_a_launcher_naming_another_installs_interpreter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    foreign: str,
) -> None:
    store, launcher = _cline_store(tmp_path, foreign)
    applied = _patch_reconciliation(monkeypatch, launcher, store.guard_home)

    repaired, failed = reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home")

    assert (repaired, failed) == (("cline",), ())
    assert applied == ["cline"]
    assert foreign not in launcher.read_text(encoding="utf-8")
    assert _current() in launcher.read_text(encoding="utf-8")


def test_repair_leaves_a_launcher_naming_the_current_interpreter_alone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, launcher = _cline_store(tmp_path, _current())
    before = launcher.read_text(encoding="utf-8")
    applied = _patch_reconciliation(monkeypatch, launcher, store.guard_home)

    repaired, failed = reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home")

    assert (repaired, failed) == ((), ())
    assert applied == []
    assert launcher.read_text(encoding="utf-8") == before


def test_a_frozen_guard_owns_no_python_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, launcher = _cline_store(tmp_path, _current())
    _patch_reconciliation(monkeypatch, launcher, store.guard_home)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    applied: list[str] = []

    def apply(_command: str, harness: str, *_args: object) -> None:
        # A frozen Guard has no interpreter to bake in; Cline moves to its plugin transport.
        applied.append(harness)
        launcher.unlink()

    monkeypatch.setattr(reconciliation, "apply_managed_install", apply)

    repaired, failed = reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home")

    assert (repaired, failed) == (("cline",), ())
    assert applied == ["cline"]


def test_repair_fails_when_reinstall_leaves_the_foreign_launcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, launcher = _cline_store(tmp_path, _FOREIGN)
    _patch_reconciliation(monkeypatch, launcher, store.guard_home)
    monkeypatch.setattr(reconciliation, "apply_managed_install", lambda *_args: None)

    assert reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home") == ((), ("cline",))


def test_a_launcher_beyond_the_path_bound_is_still_read(tmp_path: Path) -> None:
    store, launcher = _cline_store(tmp_path, _FOREIGN)
    elsewhere = []
    for index in range(reconciliation._MANIFEST_SCAN_MAX_PATHS + 4):
        extra = tmp_path / f"artifact-{index}"
        extra.write_text("x", encoding="utf-8")
        elsewhere.append(str(extra))
    manifest = {**store.install["manifest"], "later": elsewhere}  # type: ignore[dict-item]

    assert reconciliation._manifest_file_paths(manifest)[0] == launcher


def _scan(tmp_path: Path, text: str, *, current: str | None = None) -> bool:
    artifact = tmp_path / "artifact"
    artifact.write_text(text, encoding="utf-8")
    return names_foreign_interpreter(artifact, current=current or _current(), guard_home=tmp_path / "guard")


def _bootstrap(package_root: str) -> str:
    return (
        f"import sys;sys.path.insert(0,{package_root!r});"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv;"
        "raise SystemExit(main_from_argv(sys.argv[1:]))"
    )


@pytest.mark.parametrize("interpreter", [_FOREIGN, _SPACED_FOREIGN])
def test_a_json_argv_hook_naming_another_interpreter_is_foreign(tmp_path: Path, interpreter: str) -> None:
    argv = [interpreter, "-I", "-c", _bootstrap("/site"), '{"harness":"zcode"}']
    config = json.dumps({"hooks": {"PreToolUse": [{"command": argv}]}})

    assert _scan(tmp_path, config)
    assert not _scan(tmp_path, config.replace(json.dumps(interpreter)[1:-1], _current()))


def test_a_shell_command_inside_json_names_its_interpreter(tmp_path: Path) -> None:
    command = f"{_FOREIGN} -I -c '{_bootstrap('/site')}' '{{\"harness\": \"zcode\"}}'"
    config = json.dumps({"hooks": {"PreToolUse": [{"command": command}]}})

    assert _scan(tmp_path, config)
    assert not _scan(tmp_path, config.replace(_FOREIGN, _current()))


def test_a_native_bridge_prefix_does_not_hide_the_interpreter(tmp_path: Path) -> None:
    argv = ["/g/native-runtime/" + "a" * 64 + "/hol-guard-runtime", "bounded-hook-bridge", _FOREIGN, "-I", "-c"]
    config = json.dumps({"command": [*argv, _bootstrap("/site")]})

    assert _scan(tmp_path, config)


def test_the_source_cli_form_names_its_interpreter(tmp_path: Path) -> None:
    config = json.dumps({"command": [_FOREIGN, "-I", "-s", "-m", "codex_plugin_scanner.cli", "guard", "hook"]})

    assert _scan(tmp_path, config)


def test_a_user_hook_before_guards_entry_is_not_read_with_it(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    user = {"type": "command", "command": "/usr/bin/python3 -I -c 'print(1)'"}
    managed = [
        f"{_current()} -I -c '{_bootstrap('/site')}'",
        f"{guard}/native-runtime/{'a' * 64}/hol-guard-runtime bounded-hook-bridge",
    ]
    for command in managed:
        handler = {"type": "command", "command": command}
        config = json.dumps({"hooks": {"events": {"PreToolUse": [{"hooks": [user, handler]}]}}}, indent=2)

        assert not _scan(tmp_path, config)


def test_a_posix_launcher_for_an_interpreter_path_with_an_apostrophe_is_read(tmp_path: Path) -> None:
    interpreter = "/opt/O'Brien/venv/bin/python"
    worker = tmp_path / "guard" / "managed" / "cline" / "hook-workers" / "PreToolUse.py"
    launcher = _posix_wrapper(worker=worker, python=interpreter)

    assert _scan(tmp_path, launcher)
    assert not _scan(tmp_path, launcher, current=interpreter)


def test_a_windows_launcher_names_its_interpreter(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    worker = guard_home / "managed" / "cline" / "hook-workers" / "PreToolUse.py"
    launcher = _powershell_wrapper(
        worker=worker, python=r"C:\Users\u\pipx\venvs\hol-guard\Scripts\python.exe", blocking=True
    )

    assert _scan(tmp_path, launcher)
    assert not _scan(tmp_path, launcher, current=r"C:\Users\u\pipx\venvs\hol-guard\Scripts\python.exe")


def test_a_windows_json_escaped_path_is_compared_unescaped(tmp_path: Path) -> None:
    interpreter = r"C:\Users\u\pipx\venvs\hol-guard\Scripts\python.exe"
    config = json.dumps({"command": [interpreter, "-I", "-s", "-m", "codex_plugin_scanner.cli"]})

    assert _scan(tmp_path, config)
    assert not _scan(tmp_path, config, current=interpreter)


@pytest.mark.parametrize(
    "text",
    [
        # A stdlib-only client does not depend on which Guard install owns the interpreter.
        json.dumps({"command": ["/usr/bin/python3", "-I", "{guard}/managed/bounded-hooks/grok.py"]}),
        # A user's own hook is not Guard's client.
        json.dumps({"command": ["/usr/bin/python3", "-I", "-c", "print('ok')"]}),
        json.dumps({"command": ["/usr/bin/python3", "-I", "-s", "/home/u/my_hook.py"]}),
        "grep -I -c needle haystack\n",
        # No interpreter path precedes the flag.
        json.dumps({"args": ["-I", "-s", "-m", "codex_plugin_scanner.cli"]}),
        "",
    ],
)
def test_other_invocations_are_not_foreign(tmp_path: Path, text: str) -> None:
    assert not _scan(tmp_path, text.replace("{guard}", str(tmp_path / "guard")))


def test_a_binary_or_missing_file_is_not_foreign(tmp_path: Path) -> None:
    binary = tmp_path / "python"
    binary.write_bytes(b"\x7fELF\0\0" + f"{_FOREIGN} -I -s -m codex_plugin_scanner.cli".encode())

    assert not names_foreign_interpreter(binary, current=_current(), guard_home=tmp_path / "guard")
    assert not names_foreign_interpreter(tmp_path / "absent", current=_current(), guard_home=tmp_path / "guard")


def test_a_long_unbroken_file_is_scanned_in_linear_time(tmp_path: Path) -> None:
    assert not _scan(tmp_path, "x" * (1024 * 1024) + " -I -s " + "y" * 4096)


_OLD_DIGEST = "8" * 64
_NEW_DIGEST = "2" * 64


def _pinned(digest: str) -> str:
    return json.dumps({"hooks": [{"command": f"/g/native-runtime/{digest}/hol-guard-runtime bounded-hook-bridge"}]})


def _plan_adapter(monkeypatch: pytest.MonkeyPatch, *changes: TransitionFile) -> None:
    adapter = SimpleNamespace(prepare_install=lambda _context: SimpleNamespace(files=changes))
    monkeypatch.setattr(reconciliation, "get_adapter", lambda _harness: adapter)


def _zcode_store(tmp_path: Path) -> tuple[_Store, Path]:
    """A ZCode install whose manifest names Desktop's config.json but not the CLI's setting.json."""

    guard_home = tmp_path / "guard"
    config = tmp_path / "home" / ".zcode" / "cli" / "config.json"
    setting = config.with_name("setting.json")
    config.parent.mkdir(parents=True)
    config.write_text(_pinned(_NEW_DIGEST), encoding="utf-8")
    setting.write_text(_pinned(_OLD_DIGEST), encoding="utf-8")
    manifest = {"config_path": str(config)}
    return _Store(guard_home, {"harness": "zcode", "active": True, "manifest": manifest}), setting


def test_repair_repins_a_file_only_the_install_plan_names(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, setting = _zcode_store(tmp_path)
    _plan_adapter(monkeypatch, TransitionFile(setting, setting.read_bytes(), _pinned(_NEW_DIGEST).encode()))
    applied: list[str] = []

    def apply(_command: str, harness: str, *_args: object) -> None:
        applied.append(harness)
        setting.write_text(_pinned(_NEW_DIGEST), encoding="utf-8")

    monkeypatch.setattr(reconciliation, "_live_hook_verification", lambda *_args: {"zcode": True})
    monkeypatch.setattr(reconciliation, "_current_durable_runtime_digest", lambda: _NEW_DIGEST)
    monkeypatch.setattr(reconciliation, "apply_managed_install", apply)

    repaired, failed = reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home")

    assert (repaired, failed) == (("zcode",), ())
    assert applied == ["zcode"]
    assert _OLD_DIGEST not in setting.read_text(encoding="utf-8")


def test_a_planned_file_the_install_would_leave_unchanged_is_not_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, setting = _zcode_store(tmp_path)
    # A preserved backup of the user's earlier config: the install keeps it byte for byte.
    _plan_adapter(monkeypatch, TransitionFile(setting, setting.read_bytes(), setting.read_bytes()))
    monkeypatch.setattr(reconciliation, "_live_hook_verification", lambda *_args: {"zcode": True})
    monkeypatch.setattr(reconciliation, "_current_durable_runtime_digest", lambda: _NEW_DIGEST)
    monkeypatch.setattr(reconciliation, "apply_managed_install", lambda *_args: pytest.fail("repaired"))

    assert reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home") == ((), ())


def test_repair_fails_when_reinstall_leaves_the_planned_file_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, setting = _zcode_store(tmp_path)
    _plan_adapter(monkeypatch, TransitionFile(setting, setting.read_bytes(), _pinned(_NEW_DIGEST).encode()))
    monkeypatch.setattr(reconciliation, "_live_hook_verification", lambda *_args: {"zcode": True})
    monkeypatch.setattr(reconciliation, "_current_durable_runtime_digest", lambda: _NEW_DIGEST)
    monkeypatch.setattr(reconciliation, "apply_managed_install", lambda *_args: None)

    assert reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home") == ((), ("zcode",))


def test_an_adapter_that_writes_without_a_plan_is_read_through_its_manifest(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")

    assert reconciliation._planned_artifact_paths("cline", context) == ()
    assert reconciliation._planned_artifact_paths("no-such-harness", context) == ()


def test_a_real_zcode_cli_setting_file_is_read_though_its_manifest_omits_it(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter

    home = tmp_path / "home"
    cli_root = home / ".zcode" / "cli"
    cli_root.mkdir(parents=True)
    for name in ("config.json", "setting.json"):
        (cli_root / name).write_text("{}", encoding="utf-8")
    context = HarnessContext(
        home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard", home_override_explicit=True
    )
    for change in ZCodeHarnessAdapter().prepare_install(context).files:
        change.path.parent.mkdir(parents=True, exist_ok=True)
        change.path.write_bytes(change.after or b"")
    install = {"harness": "zcode", "manifest": {"config_path": str(cli_root / "config.json")}}

    assert not reconciliation._launches_stale_client("zcode", install, context, None)

    setting = cli_root / "setting.json"
    setting.write_text(setting.read_text(encoding="utf-8").replace(_current(), _FOREIGN), encoding="utf-8")

    assert _FOREIGN in setting.read_text(encoding="utf-8")
    assert reconciliation._launches_stale_client("zcode", install, context, None)
