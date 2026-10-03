from __future__ import annotations

import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from contextvars import copy_context
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import codex_native_hook_state
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path
from codex_plugin_scanner.guard.codex_hook_runtime_trust import validate_codex_hook_launch
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction, require_codex_install_owner


def test_copied_context_cannot_borrow_another_threads_publication_owner(tmp_path):
    guard = tmp_path / "guard"
    with codex_install_transaction(guard, guard / "managed", actor="parent") as owner:
        borrowed = copy_context()
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(borrowed.run, require_codex_install_owner, guard)
            with pytest.raises(CodexHookIntegrityError) as failure:
                result.result(timeout=5)
        assert failure.value.reason == "codex_hook_transaction_owner_missing"
        assert require_codex_install_owner(guard) is owner


FORK_OWNER = r"""
import os, subprocess, sys, time
from pathlib import Path
from codex_plugin_scanner.guard.codex_install_transaction import (
    codex_install_transaction, require_codex_install_owner,
)
root = Path(sys.argv[1])
mode = sys.argv[2]
ready_read, ready_write = os.pipe()
release_read, release_write = os.pipe()
child = None
try:
    with codex_install_transaction(root, root / "config", actor="parent"):
        child = os.fork()
        if child == 0:
            os.close(ready_read)
            os.close(release_write)
            try:
                require_codex_install_owner(root)
            except Exception:
                pass
            else:
                os._exit(21)
            if mode == "child-reacquires":
                try:
                    with codex_install_transaction(root, root / "config", actor="child",
                                                   deadline=time.monotonic() + 0.1):
                        os._exit(22)
                except TimeoutError:
                    pass
                except RuntimeError as error:
                    assert "codex_lifecycle_busy" in str(error)
            os.write(ready_write, b"ready")
            os.read(release_read, 1)
            os._exit(0)
        os.close(ready_write)
        os.close(release_read)
        assert os.read(ready_read, 5) == b"ready"
    # Child is still alive. Its inherited descriptor must not keep the
    # parent's released lock alive, including after an attempted reacquisition.
    probe = '''
import sys, time
from pathlib import Path
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
home = Path(sys.argv[1])
with codex_install_transaction(home, home / "config", actor="competitor",
                               deadline=time.monotonic() + 0.3):
    print("acquired")
'''
    result = subprocess.run([sys.executable, "-c", probe, str(root)], capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout.strip() == b"acquired"
finally:
    if child:
        os.write(release_write, b"x")
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
"""


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork ownership")
@pytest.mark.parametrize("mode", ["idle-child", "child-reacquires"])
def test_fork_does_not_retain_parent_lock_or_authority(tmp_path: Path, mode: str):
    result = subprocess.run(
        [sys.executable, "-c", FORK_OWNER, str(tmp_path / "home"), mode], capture_output=True, timeout=15
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")


FORK_UNWIND = r"""
import os, subprocess, sys, time
from pathlib import Path
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
root = Path(sys.argv[1])
ready_read, ready_write = os.pipe()
release_read, release_write = os.pipe()
class ChildUnwind(Exception):
    pass
child = None
try:
    with codex_install_transaction(root, root / "config", actor="parent"):
        child = os.fork()
        if child == 0:
            raise ChildUnwind()
        assert os.read(ready_read, 5) == b"ready"
        probe = '''
import sys, time
from pathlib import Path
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
home = Path(sys.argv[1])
try:
    with codex_install_transaction(home, home / "config", actor="competitor",
                                   deadline=time.monotonic() + 0.2):
        print("entered")
except TimeoutError:
    print("excluded")
except RuntimeError as error:
    assert "codex_lifecycle_busy" in str(error)
    print("excluded")
'''
        result = subprocess.run([sys.executable, "-c", probe, str(root)], capture_output=True, timeout=5)
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout.strip() == b"excluded", result.stdout
except ChildUnwind:
    os.write(ready_write, b"ready")
    os.read(release_read, 1)
    os._exit(0)
finally:
    if child:
        os.write(release_write, b"x")
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
"""


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork ownership")
def test_fork_child_unwind_cannot_unlock_live_parent(tmp_path: Path):
    result = subprocess.run(
        [sys.executable, "-c", FORK_UNWIND, str(tmp_path / "home")], capture_output=True, timeout=15
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")


FORK_THREAD_OWNER = r"""
import os, sys, threading, time
from pathlib import Path
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
root = Path(sys.argv[1])
owned, release = threading.Event(), threading.Event()
ready_read, ready_write = os.pipe()
release_read, release_write = os.pipe()
def owner():
    with codex_install_transaction(root, root / "config", actor="parent-thread"):
        owned.set()
        assert release.wait(10)
thread = threading.Thread(target=owner)
thread.start()
assert owned.wait(5)
child = os.fork()
if child == 0:
    try:
        with codex_install_transaction(root, root / "config", actor="child",
                                       deadline=time.monotonic() + 0.1):
            os._exit(22)
    except TimeoutError:
        pass
    except RuntimeError as error:
        assert "codex_lifecycle_busy" in str(error)
    os.write(ready_write, b"ready")
    os.read(release_read, 1)
    with codex_install_transaction(root, root / "config", actor="child-new-owner",
                                   deadline=time.monotonic() + 0.3):
        pass
    os._exit(0)
try:
    assert os.read(ready_read, 5) == b"ready"
finally:
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    os.write(release_write, b"x")
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
"""


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork ownership")
def test_fork_replaces_locks_owned_by_other_parent_threads(tmp_path: Path):
    result = subprocess.run(
        [sys.executable, "-c", FORK_THREAD_OWNER, str(tmp_path / "home")], capture_output=True, timeout=15
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_missing_manifest_is_rejected_before_key_access(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import codex_hook_integrity as integrity

    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    manifest = hook_manifest_path(guard_home, home / ".codex" / "config.toml")

    def forbidden_key_read(*_args, **_kwargs):
        pytest.fail("a missing manifest must not read or rotate authority")

    monkeypatch.setattr(integrity, "load_hook_secret", forbidden_key_read)
    with pytest.raises(CodexHookIntegrityError) as failure:
        validate_codex_hook_launch(
            manifest_path=manifest,
            state_path=guard_home / "daemon-state.json",
            fallback_command=[],
            start_command=[],
            config_json="{}",
        )
    assert failure.value.reason == "codex_hook_manifest_missing"
    assert not guard_home.exists()
    print(f"H1 pass reason={failure.value.reason} key_accessed=false")


INSTALLER = r"""
import sys, time
from pathlib import Path
from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
root = Path(sys.argv[1])
actor = sys.argv[2]
context = HarnessContext(home_dir=root / "home", workspace_dir=None, guard_home=root / "home/.hol-guard")
if actor == "A":
    def fail_publish(*args, **kwargs):
        (root / "snapshot-taken").touch()
        end = time.monotonic() + 10
        while not (root / "release-A").exists():
            if time.monotonic() >= end:
                raise TimeoutError("fixture synchronization expired")
            time.sleep(0.01)
        raise OSError("injected publication failure")
    codex.build_authenticated_hook_manifest = fail_publish
try:
    codex.CodexHarnessAdapter().install(context)
except RuntimeError as error:
    if actor != "B" or "codex_lifecycle_busy" not in str(error):
        raise
    (root / "B-refused-busy").touch()
except OSError:
    if actor != "A":
        raise
else:
    (root / (actor + "-committed")).touch()
"""


def test_failed_installer_cannot_remove_separate_process_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise actual install snapshots, publication, readback and rollback."""
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex/config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    environment = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    first = subprocess.Popen(
        [sys.executable, "-c", INSTALLER, str(tmp_path), "A"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    second = None
    try:
        end = time.monotonic() + 10
        while not (tmp_path / "snapshot-taken").exists():
            if first.poll() is not None or time.monotonic() >= end:
                stdout, stderr = first.communicate(timeout=2)
                pytest.fail(f"first installer failed before snapshot: {stdout!r} {stderr!r}")
            time.sleep(0.01)
        second = subprocess.Popen(
            [sys.executable, "-c", INSTALLER, str(tmp_path), "B"],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Adapter admission now refuses busy configurations before discovery.
        # The competing call must neither publish nor snapshot A's generation.
        with suppress(subprocess.TimeoutExpired):
            second.wait(timeout=1)
        (tmp_path / "release-A").touch()
        first_out, first_err = first.communicate(timeout=10)
        second_out, second_err = second.communicate(timeout=10)
        assert first.returncode == 0, (first_out, first_err)
        assert second.returncode == 0, (second_out, second_err)
        assert (tmp_path / "B-refused-busy").exists()
        assert not (tmp_path / "B-committed").exists()
        # A new operation after the failed owner has retired can win safely.
        winner = subprocess.run(
            [sys.executable, "-c", INSTALLER, str(tmp_path), "B"],
            env=environment,
            capture_output=True,
            timeout=10,
        )
        assert winner.returncode == 0, winner.stderr
        assert (tmp_path / "B-committed").exists()
        state = codex_native_hook_state(
            HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".hol-guard")
        )
        assert state["protection_active"], (state["integrity_reason"], state.get("integrity_message"))
        assert state["integrity_reason"] == "codex_hook_manifest_valid"
        print("H3 pass excluded_contender=busy winner=codex_hook_manifest_valid")
    finally:
        (tmp_path / "release-A").touch()
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def test_transaction_rejects_symlink_and_bounds_separate_process_wait(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction

    home = tmp_path / "guard-home"
    config = tmp_path / "home/.codex/config.toml"
    code = """
import sys, time
from pathlib import Path
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
try:
    with codex_install_transaction(
        Path(sys.argv[1]), Path(sys.argv[2]), actor="contender", deadline=time.monotonic()+0.1
    ):
        raise AssertionError("contender entered a held transaction")
except TimeoutError:
    pass
"""
    with codex_install_transaction(home, config, actor="owner") as first:
        with codex_install_transaction(home, config, actor="nested") as nested:
            assert nested.operation_id == first.operation_id
        result = subprocess.run([sys.executable, "-c", code, str(home), str(config)], capture_output=True, timeout=5)
        assert result.returncode == 0, result.stderr
    lock = home / "managed/codex/installation.lock"
    original = lock.stat()
    with codex_install_transaction(home, config, actor="next") as second:
        assert second.operation_id != first.operation_id
    assert lock.stat().st_ino == original.st_ino, "ownership lock must never be unlinked"
    if os.name != "nt":
        unsafe_home = tmp_path / "unsafe"
        directory = unsafe_home / "managed/codex"
        directory.mkdir(parents=True)
        victim = tmp_path / "victim"
        victim.write_bytes(b"preserve")
        (directory / "installation.lock").symlink_to(victim)
        with pytest.raises(OSError), codex_install_transaction(unsafe_home, config, actor="unsafe"):
            pytest.fail("symlink was accepted")
        assert victim.read_bytes() == b"preserve"


def test_mutation_journal_contains_identities_and_no_private_contents(tmp_path: Path) -> None:
    import json

    from codex_plugin_scanner.guard.codex_hook_integrity import atomic_write_text, restore_private_file
    from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction

    home = tmp_path / "guard-home"
    config = tmp_path / "home/.codex/config.toml"
    with codex_install_transaction(home, config, actor="fixture"):
        atomic_write_text(config, "private fixture text")
        restore_private_file(config, None)
    journal = (home / "managed/codex/authority-mutations.jsonl").read_text()
    assert "private fixture text" not in journal
    assert str(config) not in journal
    events = [json.loads(line) for line in journal.splitlines()]
    assert [event["operation"] for event in events] == ["begin", "publish", "restore_absent", "committed"]
    assert len({event["operation_id"] for event in events}) == 1
    assert events[1]["after_digest"] == events[2]["before_digest"]
    assert events[1]["before_present"] is False
    assert events[2]["after_present"] is False


def test_cached_launch_retains_exact_previous_artifact_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from codex_plugin_scanner.guard import codex_hook_runtime_trust as runtime_trust
    from codex_plugin_scanner.guard.adapters import codex

    context = HarnessContext(
        home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home", home_override_explicit=True
    )
    source_root = Path(codex.__file__).resolve().parents[3]
    files = [path for _role, path in codex._hook_packaged_file_paths()]
    # Two immutable package layouts with identical reviewed code, so this
    # models a path/format migration without authenticating altered code.
    for generation in ("old", "new"):
        for source in (*files, Path(codex.__file__)):
            destination = tmp_path / generation / source.relative_to(source_root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o644)
    adapter_path = Path(codex.__file__).relative_to(source_root)
    monkeypatch.setattr(codex, "__file__", str(tmp_path / "old" / adapter_path))
    codex.CodexHarnessAdapter().install(context)
    old_argv = codex._hook_command_parts(context)
    config = json.loads(old_argv[3])
    monkeypatch.setattr(codex, "__file__", str(tmp_path / "new" / adapter_path))
    codex.CodexHarnessAdapter().install(context)
    monkeypatch.setattr(
        runtime_trust, "__file__", str(tmp_path / "old" / "codex_plugin_scanner/guard/codex_hook_runtime_trust.py")
    )
    trusted = validate_codex_hook_launch(
        manifest_path=config["manifest_path"],
        state_path=config["state_path"],
        fallback_command=config["fallback_command"],
        start_command=config["start_command"],
        config_json=old_argv[3],
    )
    assert trusted.cwd.exists()
    # A retained hash cannot permit modified artifact bytes.
    old_bridge = Path(old_argv[2])
    old_bridge.write_bytes(old_bridge.read_bytes() + b"\n# altered retained generation\n")
    with pytest.raises((CodexHookIntegrityError, ValueError)):
        validate_codex_hook_launch(
            manifest_path=config["manifest_path"],
            state_path=config["state_path"],
            fallback_command=config["fallback_command"],
            start_command=config["start_command"],
            config_json=old_argv[3],
        )
    print("H2 pass retained_previous=allow altered_bytes=denied")


def test_real_cached_bridge_denies_missing_manifest_without_replacing_authority(tmp_path: Path) -> None:
    import json

    from codex_plugin_scanner.guard.adapters import codex
    from codex_plugin_scanner.guard.codex_hook_integrity import hook_secret_path

    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
        home_override_explicit=True,
    )
    codex.CodexHarnessAdapter().install(context)
    argv = codex._hook_command_parts(context)
    config = context.home_dir / ".codex/config.toml"
    before_config = config.read_bytes()
    secret = hook_secret_path(context.guard_home)
    before_secret = secret.stat()
    manifest = hook_manifest_path(context.guard_home, config)
    manifest.unlink()

    # Exercise the actual cached -I bridge in a new process, with no daemon
    # state to hide the missing fallback authority. No in-process validator
    # patch or fabricated integrity error participates in this observation.
    result = subprocess.run(
        argv,
        input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "true"}}),
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "HOME": str(context.home_dir), "USERPROFILE": str(context.home_dir)},
    )
    assert result.returncode == 0, result.stderr
    response = json.loads(result.stdout)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    diagnostic = json.loads(result.stderr)
    assert diagnostic["schema"] == "hol-guard.codex-bridge-failure.v1"
    assert any(cause["reason_code"] == "codex_hook_manifest_missing" for cause in diagnostic["causes"])
    assert config.read_bytes() == before_config
    assert not manifest.exists()
    after_secret = secret.stat()
    assert (after_secret.st_dev, after_secret.st_ino, after_secret.st_mtime_ns, after_secret.st_size) == (
        before_secret.st_dev,
        before_secret.st_ino,
        before_secret.st_mtime_ns,
        before_secret.st_size,
    )
    assert not (context.guard_home / "daemon-state.json").exists()
    assert codex_native_hook_state(context)["protection_active"] is False
    print("H1 pass bridge_decision=deny reason=codex_hook_manifest_missing key_rotated=false protection_active=false")


def test_retained_launch_cap_revokes_oldest_without_accepting_changed_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from codex_plugin_scanner.guard import codex_hook_runtime_trust as runtime_trust
    from codex_plugin_scanner.guard.adapters import codex
    from codex_plugin_scanner.guard.codex_hook_integrity import load_authenticated_hook_manifest

    context = HarnessContext(
        home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home", home_override_explicit=True
    )
    source_root = Path(codex.__file__).resolve().parents[3]
    adapter_path = Path(codex.__file__).relative_to(source_root)
    files = [path for _role, path in codex._hook_packaged_file_paths()]
    commands = []
    for number in range(10):
        root = tmp_path / f"generation-{number}"
        for source in (*files, source_root / adapter_path):
            destination = root / source.relative_to(source_root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o644)
        monkeypatch.setattr(codex, "__file__", str(root / adapter_path))
        codex.CodexHarnessAdapter().install(context)
        commands.append(codex._hook_command_parts(context))
    manifest = load_authenticated_hook_manifest(context.guard_home, context.home_dir / ".codex/config.toml")
    assert len(manifest["retained_bridge_generations"]) == 8
    assert len(manifest["compatible_bridge_argv_sha256"]) == 8

    def validate(number: int, config_json: str | None = None):
        argv = commands[number]
        config = json.loads(argv[3])
        monkeypatch.setattr(
            runtime_trust,
            "__file__",
            str(tmp_path / f"generation-{number}" / "codex_plugin_scanner/guard/codex_hook_runtime_trust.py"),
        )
        return validate_codex_hook_launch(
            manifest_path=config["manifest_path"],
            state_path=config["state_path"],
            fallback_command=config["fallback_command"],
            start_command=config["start_command"],
            config_json=argv[3] if config_json is None else config_json,
        )

    assert validate(1).cwd.exists()
    assert validate(8).cwd.exists()
    with pytest.raises((ValueError, CodexHookIntegrityError)):
        validate(0)
    forged = json.loads(commands[8][3])
    forged["query"] = "changed-unregistered-binding"
    with pytest.raises((ValueError, CodexHookIntegrityError)):
        validate(8, json.dumps(forged, separators=(",", ":")))
    print("H2 pass retained=8 oldest_revoked=true changed_argv=denied")


def test_uninstall_preserves_key_needed_by_other_authenticated_target(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters import codex
    from codex_plugin_scanner.guard.codex_hook_integrity import hook_secret_path
    from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction

    guard_home = tmp_path / "guard-home"
    first = HarnessContext(
        home_dir=tmp_path / "first", workspace_dir=None, guard_home=guard_home, home_override_explicit=True
    )
    second = HarnessContext(
        home_dir=tmp_path / "second", workspace_dir=None, guard_home=guard_home, home_override_explicit=True
    )
    adapter = codex.CodexHarnessAdapter()
    adapter.install(first)
    # Qualify cleanup against two authenticated targets without weakening the
    # public install gate for an absent manifest beside an existing key.
    config = second.home_dir / ".codex/config.toml"
    payload = {"features": {"hooks": True}}
    adapter._install_config_hooks(payload, second)
    with codex_install_transaction(guard_home, config, actor="fixture-second-target"):
        state = adapter._write_authenticated_hook_config(
            second, config_path=config, payload=payload, previous_manifest=None
        )
    assert state["protection_active"]
    key = hook_secret_path(guard_home)
    identity = key.stat()
    adapter.uninstall(first)
    assert key.stat().st_ino == identity.st_ino
    assert codex_native_hook_state(second)["protection_active"]
    adapter.uninstall(second)
    assert not key.exists()
    print("H5 pass other_target_key_retained=true last_uninstall_removes_key=true")
