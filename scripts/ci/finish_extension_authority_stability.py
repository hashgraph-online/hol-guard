from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path.cwd()
STORE_BASE = ROOT / "src/codex_plugin_scanner/guard/store_base.py"
AUTH_TEST = ROOT / "tests/test_guard_extension_control_authority.py"
NEW_HELPER = ROOT / "src/codex_plugin_scanner/guard/encrypted_secret_store_key.py"
NEW_AUTH_TEST = ROOT / "tests/test_guard_extension_control_authority_keyring_stability.py"

HELPER_CONTENT = '''\
"""Race-safe initialization for Guard's encrypted secret-store key."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import IO, Protocol

from cryptography.fernet import Fernet

_LOCK_TIMEOUT_SECONDS = 30.0
_LOCK_POLL_SECONDS = 0.01
_THREAD_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.Lock] = {}


class _EncryptedSecretStore(Protocol):
    key_path: Path

    def _atomic_write_bytes(self, path: Path, payload: bytes, mode: int) -> None: ...

    def _load_fernet_key(self) -> bytes: ...


def initialize_encrypted_secret_store_key(store: _EncryptedSecretStore) -> bytes:
    """Create one durable key across threads/processes, or load it fail-closed."""

    lock_key = os.path.realpath(os.fspath(store.key_path))
    with _THREAD_LOCKS_GUARD:
        thread_lock = _THREAD_LOCKS.setdefault(lock_key, threading.Lock())
    with thread_lock:
        lock_path = store.key_path.parent / ".key-init.lock"
        with lock_path.open("a+b") as lock_handle:
            os.chmod(lock_path, 0o600)
            _acquire_with_timeout(lock_handle)
            try:
                if not store.key_path.exists():
                    store._atomic_write_bytes(store.key_path, Fernet.generate_key(), 0o600)
                key = store._load_fernet_key()
                os.chmod(store.key_path, 0o600)
                return key
            finally:
                _release_advisory_lock(lock_handle)


def _acquire_with_timeout(handle: IO[bytes]) -> None:
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    while True:
        try:
            _acquire_advisory_lock(handle)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out initializing encrypted Guard secrets") from None
            time.sleep(_LOCK_POLL_SECONDS)


def _acquire_advisory_lock(handle: IO[bytes]) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            handle.seek(0)
            if not handle.read(1):
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise BlockingIOError from error
        return

    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise BlockingIOError from error


def _release_advisory_lock(handle: IO[bytes]) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
'''


def _rewrite_store_base() -> None:
    text = STORE_BASE.read_text(encoding="utf-8")
    text = text.replace(
        "from .artifact_identity import artifact_family_key\n\n# ruff: noqa: F401,I001\n\nimport base64",
        "from .artifact_identity import artifact_family_key\n"
        "from .encrypted_secret_store_key import initialize_encrypted_secret_store_key\n\n"
        "# ruff: noqa: F401,I001\nimport base64",
    )
    text = text.replace("import sys\nimport threading\nimport time", "import sys\nimport time")
    text = text.replace(
        '_POLICY_INTEGRITY_MIGRATION_ELIGIBLE_STATUSES = frozenset({"missing_integrity", "unknown_key"})\n'
        "_ENCRYPTED_SECRET_INIT_LOCKS_GUARD = threading.Lock()\n"
        "_ENCRYPTED_SECRET_INIT_LOCKS: dict[str, threading.Lock] = {}",
        '_POLICY_INTEGRITY_MIGRATION_ELIGIBLE_STATUSES = frozenset({"missing_integrity", "unknown_key"})',
    )
    old_block = '''        lock_key = os.path.realpath(os.fspath(self.key_path))
        with _ENCRYPTED_SECRET_INIT_LOCKS_GUARD:
            thread_lock = _ENCRYPTED_SECRET_INIT_LOCKS.setdefault(lock_key, threading.Lock())
        with thread_lock:
            if self._fernet is not None:
                return
            lock_path = self.base_dir / ".key-init.lock"
            with lock_path.open("a+b") as lock_handle:
                os.chmod(lock_path, 0o600)
                deadline = time.monotonic() + 30.0
                while True:
                    try:
                        _acquire_advisory_file_lock(lock_handle)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("timed out initializing encrypted Guard secrets") from None
                        time.sleep(0.01)
                try:
                    if not self.key_path.exists():
                        self._atomic_write_bytes(self.key_path, Fernet.generate_key(), 0o600)
                    key = self._load_fernet_key()
                    os.chmod(self.key_path, 0o600)
                    self._fernet = Fernet(key)
                finally:
                    _release_advisory_file_lock(lock_handle)
'''
    new_block = '''        self._fernet = Fernet(
            initialize_encrypted_secret_store_key(self),
        )
'''
    if old_block not in text:
        raise RuntimeError("expected current encrypted-key initialization block was not found")
    text = text.replace(old_block, new_block)
    text = text.replace(
        '''        if not existing:
            raise RuntimeError("encrypted Guard secret key is empty")
''',
        '''        if not existing:
            raise RuntimeError(
                "encrypted Guard secret key is empty",
            )
''',
    )
    text = text.replace(
        '''        raise RuntimeError("encrypted Guard secret key is invalid")
''',
        '''        raise RuntimeError(
            "encrypted Guard secret key is invalid",
        )
''',
    )
    if "threading" in text or "_ENCRYPTED_SECRET_INIT_LOCKS" in text:
        raise RuntimeError("stale inline encrypted-key lock implementation remains")
    STORE_BASE.write_text(text, encoding="utf-8")


def _move_authority_tests() -> None:
    auth_text = AUTH_TEST.read_text(encoding="utf-8")
    tree = ast.parse(auth_text)
    lines = auth_text.splitlines(keepends=True)
    remove_names = {
        "test_unavailable_system_keyring_uses_owner_only_vault",
        "test_linux_legacy_keyring_authority_migrates_then_survives_keyring_loss",
    }
    remove_ranges: list[tuple[int, int]] = []
    found_names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in remove_names:
            found_names.add(node.name)
            start = node.lineno - 1
            end = node.end_lineno or node.lineno
            while end < len(lines) and not lines[end].strip():
                end += 1
            remove_ranges.append((start, end))
    if found_names != remove_names:
        raise RuntimeError(f"authority tests to move were not found: {sorted(remove_names - found_names)}")
    for start, end in sorted(remove_ranges, reverse=True):
        del lines[start:end]
    AUTH_TEST.write_text("".join(lines), encoding="utf-8")

    node_by_name: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node_by_name[node.name] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    node_by_name[target.id] = node

    selected = {"MemorySecretStore", "_store", "_enroll", "_PASSWORD"}
    changed = True
    while changed:
        changed = False
        for name in list(selected):
            node = node_by_name.get(name)
            if node is None:
                continue
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Name)
                    and isinstance(child.ctx, ast.Load)
                    and child.id in node_by_name
                    and child.id not in selected
                    and not child.id.startswith("test_")
                ):
                    selected.add(child.id)
                    changed = True

    import_nodes = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    selected_nodes: list[ast.AST] = []
    seen_ids: set[int] = set()
    for node in tree.body:
        include = False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            include = node.name in selected
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            include = any(isinstance(target, ast.Name) and target.id in selected for target in targets)
        if include and id(node) not in seen_ids:
            seen_ids.add(id(node))
            selected_nodes.append(node)

    parts = ["from __future__ import annotations\n\n"]
    for node in import_nodes:
        segment = ast.get_source_segment(auth_text, node)
        if segment and segment != "from __future__ import annotations":
            parts.append(segment + "\n")
    parts.append("\n")
    for node in selected_nodes:
        segment = ast.get_source_segment(auth_text, node)
        if segment:
            parts.append(segment.rstrip() + "\n\n")
    parts.append('''\
def test_unavailable_system_keyring_uses_owner_only_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, _secret_id: (_ for _ in ()).throw(RuntimeError("keyring unavailable")),
    )
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "set_secret",
        lambda _self, _secret_id, _value: (_ for _ in ()).throw(RuntimeError("keyring unavailable")),
    )
    store = GuardStore(tmp_path, prime_policy_integrity=False)
    update_settings(
        tmp_path,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
    )

    assert isinstance(store._secret_store(), MigratingFallbackSecretStore)
    assert _enroll(store).health is AuthorityHealth.PROTECTED

    restarted = GuardStore(tmp_path, prime_policy_integrity=False)
    view = restarted.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert view.health is AuthorityHealth.PROTECTED
    secrets_dir = tmp_path / "secrets"
    if os.name != "nt":
        assert secrets_dir.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in secrets_dir.iterdir() if path.is_file())


def test_linux_legacy_keyring_authority_migrates_then_survives_keyring_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    legacy_secrets = MemorySecretStore()
    legacy_store = _store(tmp_path, legacy_secrets)
    assert legacy_store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    ).health is AuthorityHealth.PROTECTED
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, secret_id: legacy_secrets.get_secret(secret_id),
    )
    monkeypatch.setattr(SystemKeyringSecretStore, "set_secret", lambda _self, _secret_id, _value: None)

    migrated = GuardStore(tmp_path, prime_policy_integrity=False)
    assert migrated.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    ).health is AuthorityHealth.PROTECTED

    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "get_secret",
        lambda _self, _secret_id: (_ for _ in ()).throw(RuntimeError("session keyring disappeared")),
    )
    restarted = GuardStore(tmp_path, prime_policy_integrity=False)
    assert restarted.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    ).health is AuthorityHealth.PROTECTED
''')
    NEW_AUTH_TEST.write_text("".join(parts), encoding="utf-8")


def main() -> None:
    NEW_HELPER.write_text(HELPER_CONTENT, encoding="utf-8")
    _rewrite_store_base()
    _move_authority_tests()


if __name__ == "__main__":
    main()
