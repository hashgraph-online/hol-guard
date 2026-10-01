from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Callable, Iterator
from hashlib import sha256
from pathlib import Path

import pytest

from tests.guard_test_invariants import TEST_INVARIANTS, invariant_markers_for_nodeid

pytest_plugins = ["tests.bundle_first_cloud"]

SRC_PATH = Path(__file__).resolve().parents[1] / "src"
SUPPORT_PATH = Path(__file__).resolve().parent / "support"

use_installed_package = os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") == "1"
if not use_installed_package and str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))
if str(SUPPORT_PATH) not in sys.path:
    sys.path.insert(0, str(SUPPORT_PATH))

existing_pythonpath = os.environ.get("PYTHONPATH", "")
pythonpath_entries = [entry for entry in existing_pythonpath.split(os.pathsep) if entry]
source_paths = (SUPPORT_PATH,) if use_installed_package else (SUPPORT_PATH, SRC_PATH)
pythonpath_prefix = [str(path) for path in source_paths if str(path) not in pythonpath_entries]
if pythonpath_prefix:
    os.environ["PYTHONPATH"] = os.pathsep.join([*pythonpath_prefix, *pythonpath_entries])

# Unit tests must never open real browser tabs. The flag is assigned at import
# time so it is also inherited by helpers spawned from session-scoped fixtures,
# and so an inherited value cannot silently re-enable launches.
os.environ["HOL_GUARD_TEST_DISABLE_BROWSER_OPEN"] = "1"
os.environ.pop("HOL_GUARD_TEST_ALLOW_BROWSER_OPEN", None)


@pytest.fixture(autouse=True)
def _default_unit_tests_to_python_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep legacy unit fixtures off the production native default.

    Production default remains ``auto``. Native-authority tests monkeypatch
    ``native_mode`` or delete this variable themselves. There is no Python
    semantic evaluator; ``off`` exercises the fail-safe surface.
    """

    monkeypatch.setenv("HOL_GUARD_TEST_MODE", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
    if "HOL_GUARD_NATIVE" not in os.environ:
        monkeypatch.setenv("HOL_GUARD_NATIVE", "off")


class _GuardCommandsProxy:
    """Patch target that rebinds a symbol in every loaded guard module.

    The hook pipeline is split across ``commands_*``/``commands_support_*``
    modules that share bindings through the ``commands_support`` union, so a
    name patched on ``cli.commands`` alone would never reach the moved call
    sites. ``monkeypatch.setattr(guard_commands_module, name, value)`` fans
    the rebind out to every loaded ``codex_plugin_scanner`` module that holds
    the same object, and restores through the same fan-out on teardown.
    """

    @staticmethod
    def _original(name: str) -> object:
        sentinel = object()
        commands = sys.modules.get("codex_plugin_scanner.guard.cli.commands")
        if commands is not None:
            value = getattr(commands, name, sentinel)
            if value is not sentinel:
                return value
        for module in list(sys.modules.values()):
            if not getattr(module, "__name__", "").startswith("codex_plugin_scanner"):
                continue
            value = getattr(module, name, sentinel)
            if value is not sentinel:
                return value
        raise AttributeError(name)

    def __getattr__(self, name: str) -> object:
        return self._original(name)

    def __setattr__(self, name: str, value: object) -> None:
        original = self._original(name)
        for module in list(sys.modules.values()):
            if not getattr(module, "__name__", "").startswith("codex_plugin_scanner"):
                continue
            if getattr(module, name, None) is original:
                setattr(module, name, value)


guard_commands_module = _GuardCommandsProxy()


@pytest.fixture
def native_hook_force(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Drive hook entrypoints through the compiled native runtime.

    Hook integration tests that assert real decisions (deny/review/allow)
    need the Rust authority: ``force`` makes ``HOL_GUARD_NATIVE_BINARY``
    authoritative, and the standalone CLI publishes its own policy snapshot.
    There is no Python fallback, so the runtime is required, not skipped.
    """

    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if binary:
        runtime = Path(binary).expanduser()
    else:
        root = Path(__file__).resolve().parents[1]
        runtime = root / "rust" / "target" / "release" / "hol-guard-runtime"
        if not runtime.is_file():
            runtime = root / "rust" / "target" / "debug" / "hol-guard-runtime"
    if not runtime.is_file():
        pytest.fail("HOL_GUARD_NATIVE_BINARY must name the compiled Rust runtime; native retirement proof cannot skip")
    runtime = runtime.resolve(strict=True)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))
    return runtime


@pytest.fixture(scope="session")
def _native_context_home(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Session-shared guard home so the resident is spawned once per run."""

    from codex_plugin_scanner.guard.native_policy_snapshot import (
        provision_native_policy_verifier_key,
    )
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    guard_home = tmp_path_factory.mktemp("native-context-guard-home")
    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    # The managed resident refuses to serve until the policy verifier key the
    # publisher would normally provision exists; seed a test key once.
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    # Pre-warm the capabilities cache and the persistent resident client pool
    # at session scope.  Tests that patch subprocess.Popen globally would
    # otherwise intercept the first probe/pool spawn mid-test and break the
    # digest path (the pool spawns once and is then reused).
    binary = _context_digest_runtime_binary()
    if binary is not None:
        from codex_plugin_scanner.guard import native_context

        previous_native = os.environ.get("HOL_GUARD_NATIVE")
        previous_binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
        os.environ["HOL_GUARD_NATIVE"] = "force"
        os.environ["HOL_GUARD_NATIVE_BINARY"] = str(binary)
        try:
            native_context.native_context_digest(
                "launch_argv_digest",
                {"argv": ["guard-context-warmup"]},
                guard_home=guard_home,
            )
        finally:
            if previous_native is None:
                os.environ.pop("HOL_GUARD_NATIVE", None)
            else:
                os.environ["HOL_GUARD_NATIVE"] = previous_native
            if previous_binary is None:
                os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
            else:
                os.environ["HOL_GUARD_NATIVE_BINARY"] = previous_binary
    yield guard_home
    close_native_residents(guard_home)


def _context_digest_runtime_binary() -> Path | None:
    """Locate the compiled runtime for ambient digest calls."""

    override = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if override:
        return Path(override).expanduser()
    root = Path(__file__).resolve().parents[1]
    # Release only: the debug resident exceeds the 600ms startup budget.
    candidate = root / "rust" / "target" / "release" / "hol-guard-runtime"
    return candidate if candidate.is_file() else None


@pytest.fixture(autouse=True)
def _ambient_context_digest_home(
    _native_context_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Route ambient context-digest calls to the provisioned session resident.

    ``context_digest`` calls resolve their guard home either from the bound
    flow context or the default user home; both are pointed at the keyed
    session home.  Unit tests default to ``HOL_GUARD_NATIVE=off`` so the
    adapter's status probe is additionally re-evaluated under ``force`` —
    scoped to the ``native_context`` module only, leaving every other
    off-mode surface (hook eval, fail-safe denials) untouched.  With no
    resolvable runtime the probe is left alone and digests stay unavailable,
    preserving the no-binary behavior.
    """

    from codex_plugin_scanner.guard import native_context, native_runtime
    from codex_plugin_scanner.guard.runtime import approval_context

    real_status = native_runtime.native_runtime_status

    def _digest_status() -> object:
        status = real_status()
        if status.mode != "off":
            return status
        binary = _context_digest_runtime_binary()
        if binary is None:
            return status
        previous_mode = os.environ.get("HOL_GUARD_NATIVE")
        previous_binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
        os.environ["HOL_GUARD_NATIVE"] = "force"
        os.environ["HOL_GUARD_NATIVE_BINARY"] = str(binary)
        try:
            return real_status()
        finally:
            if previous_mode is None:
                os.environ.pop("HOL_GUARD_NATIVE", None)
            else:
                os.environ["HOL_GUARD_NATIVE"] = previous_mode
            if previous_binary is None:
                os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
            else:
                os.environ["HOL_GUARD_NATIVE_BINARY"] = previous_binary

    monkeypatch.setattr(native_context, "native_runtime_status", _digest_status)
    monkeypatch.setattr(native_context, "context_digest_guard_home", lambda: _native_context_home)
    monkeypatch.setattr(
        approval_context,
        "_context_digest_guard_home",
        lambda _home: _native_context_home,
    )


@pytest.fixture
def native_context_digest(
    native_hook_force: Path,
    _native_context_home: Path,
) -> Path:
    """Force the compiled runtime and return the isolated session resident home.

    Retained for tests that must prove the op works under ``force`` mode
    specifically; the ambient home redirection is autouse.
    """

    return _native_context_home


@pytest.fixture
def native_command_artifact_reviews(monkeypatch: pytest.MonkeyPatch) -> None:
    """Supply actual native command evidence to legacy hook orchestration tests."""
    from codex_plugin_scanner.guard.cli import commands_support_runtime_artifacts
    from tests.native_command_test_support import real_native_command_evaluation

    def review(command: str, *, guard_home: Path, cwd: Path | None = None, home_dir: Path | None = None):
        del guard_home
        try:
            return real_native_command_evaluation(command, cwd=cwd, home_dir=home_dir)
        except Exception as exc:
            pytest.fail(f"Native command artifact fixture failed: {type(exc).__name__}: {exc}")

    monkeypatch.setattr(commands_support_runtime_artifacts, "review_command_native", review)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--validate-test-invariants",
        action="store_true",
        default=False,
        help="fail collection when a protected invariant no longer resolves to a concrete test",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    fault_injection_enabled = os.environ.get("GUARD_FAULT_INJECTION") == "1"
    for item in items:
        for marker in invariant_markers_for_nodeid(item.nodeid):
            item.add_marker(marker)
        if not fault_injection_enabled and item.get_closest_marker("fault_injection") is not None:
            item.add_marker(pytest.mark.skip(reason="requires GUARD_FAULT_INJECTION=1"))

    if not config.getoption("--validate-test-invariants"):
        return
    collected = {item.nodeid for item in items}
    missing = [
        invariant
        for invariant in TEST_INVARIANTS
        if not any(nodeid == invariant.selector or nodeid.startswith(f"{invariant.selector}[") for nodeid in collected)
    ]
    if missing:
        details = ", ".join(f"{invariant.invariant_id} ({invariant.selector})" for invariant in missing)
        raise pytest.UsageError(f"Protected test invariants are missing from collection: {details}")


def _test_guard_homes_with_daemon_state(root: Path) -> set[Path]:
    guard_homes: set[Path] = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False) and entry.name == "daemon-state.json":
                            guard_homes.add(Path(entry.path).parent)
                    except OSError:
                        continue
        except OSError:
            continue
    return guard_homes


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(item: pytest.Item, nextitem: pytest.Item | None) -> Iterator[None]:
    """Retire Guard daemons launched from the completed test's temporary tree."""
    del nextitem
    test_tmp_path = item.funcargs.get("tmp_path")
    yield
    if not isinstance(test_tmp_path, Path):
        return

    from codex_plugin_scanner.guard.daemon.manager import retire_all_guard_daemons_for_home

    for guard_home in sorted(_test_guard_homes_with_daemon_state(test_tmp_path)):
        retire_all_guard_daemons_for_home(guard_home)


@pytest.fixture(autouse=True)
def _reset_guard_sync_resolver_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo any _resolve_guard_sync_auth_context override leaked by _seed_guard_cloud."""
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    monkeypatch.setattr(
        guard_runner_module,
        "_resolve_guard_sync_auth_context",
        guard_runner_module._resolve_guard_sync_auth_context,
    )
    guard_runner_module._test_sync_auth_context_override = None


@pytest.fixture(autouse=True)
def _isolate_lifecycle_authority_home(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Keep lifecycle authorization independent from the developer's real Guard state."""
    from codex_plugin_scanner.guard.cli import commands_lifecycle_gate

    node_digest = sha256(request.node.nodeid.encode()).hexdigest()[:24]
    user_home = tmp_path_factory.getbasetemp() / "lifecycle-authority" / node_digest
    monkeypatch.setattr(commands_lifecycle_gate, "trusted_user_home", lambda: user_home)


@pytest.fixture(autouse=True)
def _isolate_trust_attestation_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear trust attestation env vars so tests don't inherit the developer's shell config."""
    for key in (
        "GUARD_AIBOM_TRUST_ATTESTATION_V2",
        "GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY",
        "GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID",
        "GUARD_AIBOM_TRUST_ATTESTATION_HEADLESS_SHORT_LIVED",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _isolate_daemon_background_refresh_workers(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Start daemon refresh workers only in tests that exercise them."""
    from codex_plugin_scanner.guard.daemon import server as daemon_server

    worker_markers = {
        "daemon_aibom_refresh": "_start_aibom_inventory_refresh",
        "daemon_bundle_refresh": "_start_supply_chain_bundle_refresh",
        "daemon_headless_refresh": "_start_headless_cloud_sync",
    }
    for marker, method_name in worker_markers.items():
        if request.node.get_closest_marker(marker) is None:
            monkeypatch.setattr(daemon_server.GuardDaemonServer, method_name, lambda _self: None)
    if request.node.get_closest_marker("daemon_headless_queue") is None:
        monkeypatch.setattr(
            daemon_server,
            "_queue_headless_cloud_sync",
            lambda *, store: {
                "status": "not_configured",
                "message": "Cloud sync is isolated for this test.",
            },
        )
    if request.node.get_closest_marker("daemon_service_workers") is None:
        monkeypatch.setattr(daemon_server, "start_command_queue_worker", lambda _store, existing: existing)
        monkeypatch.setattr(daemon_server, "start_cloud_sync_sync_worker", lambda _store, existing: existing)


class _FakeSystemKeyringModule:
    def __init__(self) -> None:
        self._secrets: dict[tuple[str, str], str] = {}
        self._lock: threading.RLock = threading.RLock()

    @staticmethod
    def _store_path() -> Path | None:
        value = os.environ.get("HOL_GUARD_TEST_KEYRING_FILE", "").strip()
        return Path(value) if value else None

    def _load(self) -> dict[tuple[str, str], str]:
        store_path = self._store_path()
        if store_path is None or not store_path.is_file():
            return dict(self._secrets)
        payload = json.loads(store_path.read_text(encoding="utf-8"))
        return {
            (str(service_name), str(secret_id)): str(secret_value)
            for service_name, secrets in payload.items()
            if isinstance(service_name, str) and isinstance(secrets, dict)
            for secret_id, secret_value in secrets.items()
            if isinstance(secret_id, str) and isinstance(secret_value, str)
        }

    def _persist(self, secrets: dict[tuple[str, str], str]) -> None:
        self._secrets = dict(secrets)
        store_path = self._store_path()
        if store_path is None:
            return
        payload: dict[str, dict[str, str]] = {}
        for (service_name, secret_id), secret_value in secrets.items():
            payload.setdefault(service_name, {})[secret_id] = secret_value
        store_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = store_path.with_name(f".{store_path.name}.{os.getpid()}.{id(self)}.tmp")
        try:
            _ = temporary_path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            _ = temporary_path.replace(store_path)
        finally:
            temporary_path.unlink(missing_ok=True)

    @staticmethod
    def get_keyring():
        class _Backend:
            priority = 1

        return _Backend()

    def set_password(self, service_name: str, secret_id: str, value: str) -> None:
        with self._lock:
            secrets = self._load()
            secrets[(service_name, secret_id)] = value
            self._persist(secrets)

    def get_password(self, service_name: str, secret_id: str) -> str | None:
        with self._lock:
            return self._load().get((service_name, secret_id))

    def delete_password(self, service_name: str, secret_id: str) -> None:
        with self._lock:
            secrets = self._load()
            secrets.pop((service_name, secret_id), None)
            self._persist(secrets)


@pytest.fixture
def install_fake_system_keyring(monkeypatch: pytest.MonkeyPatch) -> Callable[[], _FakeSystemKeyringModule]:
    from codex_plugin_scanner.guard.store import SystemKeyringSecretStore

    def _install() -> _FakeSystemKeyringModule:
        module = _FakeSystemKeyringModule()
        monkeypatch.setattr(SystemKeyringSecretStore, "_load_keyring_module", staticmethod(lambda: module))
        monkeypatch.setattr(
            SystemKeyringSecretStore,
            "_macos_default_keychain_is_usable",
            classmethod(lambda cls: True),
        )
        return module

    return _install


@pytest.fixture
def allow_transient_shell_profile_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import shims as guard_shims_module

    monkeypatch.setattr(guard_shims_module, "_is_transient_path", lambda _path: False)


_FAKE_SYSTEM_KEYRING_DISABLED_FILES = {
    "test_guard_store_migrations.py",
}


@pytest.fixture(autouse=True)
def _policy_integrity_keyring_for_selected_tests(
    request: pytest.FixtureRequest,
    install_fake_system_keyring,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if request.node.path.name in _FAKE_SYSTEM_KEYRING_DISABLED_FILES:
        return
    monkeypatch.setenv("HOL_GUARD_TEST_KEYRING_FILE", str(tmp_path / "fake-system-keyring.json"))
    install_fake_system_keyring()


@pytest.fixture
def seed_connected_oauth_without_entitlement() -> Callable[[object], None]:
    from codex_plugin_scanner.guard.store import GuardStore

    def _seed(store: GuardStore) -> None:
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-token-1",
            dpop_private_key_pem="private-key",
            dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"},
            dpop_public_jwk_thumbprint="thumbprint-1",
            grant_id="grant-1",
            machine_id="machine-1",
            workspace_id="workspace-1",
            now="2026-06-05T01:39:51+00:00",
        )
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-05T01:39:51+00:00",
            request_id="connect-1",
        )

    return _seed
