"""Fresh-process controls for the public daemon import boundary."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "src"


def run_fresh(code: str) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); " + code, str(SOURCE)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "module",
    [
        "codex_plugin_scanner.guard.daemon",
        "codex_plugin_scanner.guard.daemon.discovery",
        "codex_plugin_scanner.guard.adapters.claude_daemon_state",
        "codex_plugin_scanner.guard.adapters.claude_daemon_hook_bridge",
    ],
)
def test_lightweight_import_does_not_attempt_manager_or_mdm(module: str) -> None:
    run_fresh(
        f"""
import importlib
class RefuseHeavyImports:
    def find_spec(self, fullname, path=None, target=None):
        if (fullname == 'codex_plugin_scanner.guard.daemon.manager'
                or fullname.startswith('codex_plugin_scanner.guard.mdm')):
            raise AssertionError('unneeded manager or MDM import: ' + fullname)
sys.meta_path.insert(0, RefuseHeavyImports())
importlib.import_module({module!r})
assert 'codex_plugin_scanner.guard.daemon.manager' not in sys.modules
assert 'codex_plugin_scanner.guard.mdm' not in sys.modules
"""
    )


def test_all_public_exports_keep_real_identities_and_discoverability() -> None:
    run_fresh(
        """
import importlib, pickle
package = importlib.import_module('codex_plugin_scanner.guard.daemon')
names = (
    'ensure_guard_daemon', 'guard_daemon_url_for_home', 'load_guard_daemon_auth_token',
    'load_guard_daemon_url', 'recover_guard_daemon_after_hook_failure',
    'repair_approval_center_locator', 'schedule_guard_daemon_recovery',
)
assert len(package.__all__) == 11 and set(names) <= set(package.__all__) <= set(dir(package))
assert all(name not in vars(package) for name in names)
from codex_plugin_scanner.guard.daemon import ensure_guard_daemon
manager = importlib.import_module('codex_plugin_scanner.guard.daemon.manager')
assert ensure_guard_daemon is manager.ensure_guard_daemon
for name in names:
    value = getattr(package, name)
    assert value is getattr(manager, name) is vars(package)[name]
    assert pickle.loads(pickle.dumps(value)) is value
namespace = {}
exec('from codex_plugin_scanner.guard.daemon import *', namespace)
assert set(namespace) - {'__builtins__'} == set(package.__all__)
for name in package.__all__:
    assert namespace[name] is getattr(package, name)
try:
    package.unknown_export
except AttributeError as error:
    assert error.args == ('unknown_export',)
else:
    raise AssertionError('unknown name accepted')
"""
    )


def test_reload_rebinds_current_manager_function_and_clears_only_eager_exports() -> None:
    run_fresh(
        """
import importlib, pickle
package = importlib.import_module('codex_plugin_scanner.guard.daemon')
original = package.ensure_guard_daemon
manager = importlib.import_module('codex_plugin_scanner.guard.daemon.manager')
lifecycle = importlib.import_module('codex_plugin_scanner.guard.daemon.manager_lifecycle')
importlib.reload(lifecycle)
importlib.reload(manager)
assert manager.ensure_guard_daemon is not original
assert package.ensure_guard_daemon is original
sentinel = object()
package.custom_attribute = sentinel
importlib.reload(package)
assert package.custom_attribute is sentinel
assert 'ensure_guard_daemon' not in vars(package)
assert package.ensure_guard_daemon is manager.ensure_guard_daemon
assert pickle.loads(pickle.dumps(package.ensure_guard_daemon)) is manager.ensure_guard_daemon
"""
    )


def test_explicit_package_monkeypatch_survives_lookup_until_reload() -> None:
    run_fresh(
        """
import importlib
package = importlib.import_module('codex_plugin_scanner.guard.daemon')
sentinel = lambda: None
package.ensure_guard_daemon = sentinel
from codex_plugin_scanner.guard.daemon import ensure_guard_daemon
assert ensure_guard_daemon is sentinel
assert 'codex_plugin_scanner.guard.daemon.manager' not in sys.modules
importlib.reload(package)
manager = importlib.import_module('codex_plugin_scanner.guard.daemon.manager')
assert package.ensure_guard_daemon is manager.ensure_guard_daemon
package.ensure_guard_daemon = sentinel
assert package.ensure_guard_daemon is sentinel
importlib.reload(package)
assert package.ensure_guard_daemon is manager.ensure_guard_daemon
"""
    )


def test_manager_state_exists_before_implementation_import_and_is_shared() -> None:
    run_fresh(
        """
import importlib
seen = []
class CheckManagerOwnership:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('codex_plugin_scanner.guard.daemon.manager_'):
            manager = sys.modules['codex_plugin_scanner.guard.daemon.manager']
            assert isinstance(manager._RECOVERY_LOCKS, dict)
            assert isinstance(manager._STATE_WRITE_LOCKS, dict)
            names = ('_RECOVERY_LOCKS_GUARD', '_STATE_WRITE_LOCKS_GUARD',
                     '_EPHEMERAL_REAP_SCHEDULE_LOCK', '_DUPLICATE_RETIRE_SCHEDULE_LOCK')
            for name in names:
                lock = getattr(manager, name)
                assert lock.acquire(blocking=False)
                lock.release()
            seen.append(fullname)
sys.meta_path.insert(0, CheckManagerOwnership())
package = importlib.import_module('codex_plugin_scanner.guard.daemon')
function = package.ensure_guard_daemon
manager = sys.modules['codex_plugin_scanner.guard.daemon.manager']
assert len(set(seen)) == 13
for name in seen:
    assert sys.modules[name]._manager is manager
assert function is manager.ensure_guard_daemon
"""
    )


def test_concurrent_first_access_uses_one_manager_function() -> None:
    run_fresh(
        """
import importlib, threading
package = importlib.import_module('codex_plugin_scanner.guard.daemon')
barrier = threading.Barrier(8)
values, errors = [], []
def read():
    try:
        barrier.wait(timeout=5)
        values.append(package.ensure_guard_daemon)
    except BaseException as error:
        errors.append(error)
threads = [threading.Thread(target=read) for _ in range(8)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join(timeout=10)
assert not errors and len(values) == 8 and all(not thread.is_alive() for thread in threads)
assert all(value is values[0] for value in values)
assert values[0] is sys.modules['codex_plugin_scanner.guard.daemon.manager'].ensure_guard_daemon
"""
    )


def test_manager_import_failure_is_delayed_unchanged_and_retryable() -> None:
    run_fresh(
        """
import importlib
error = ImportError('controlled manager dependency failure')
class RefuseManager:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'codex_plugin_scanner.guard.daemon.manager':
            raise error
refusal = RefuseManager()
sys.meta_path.insert(0, refusal)
package = importlib.import_module('codex_plugin_scanner.guard.daemon')
try:
    package.ensure_guard_daemon
except ImportError as caught:
    assert caught is error
else:
    raise AssertionError('manager failure hidden')
assert 'ensure_guard_daemon' not in vars(package)
assert 'codex_plugin_scanner.guard.daemon.manager' not in sys.modules
sys.meta_path.remove(refusal)
manager = importlib.import_module('codex_plugin_scanner.guard.daemon.manager')
assert package.ensure_guard_daemon is manager.ensure_guard_daemon
"""
    )
