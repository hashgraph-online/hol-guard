"""Provision only the private key required by an isolated corpus resident."""

from __future__ import annotations

import os
from pathlib import Path


def seed_private_verifier_key(home: Path) -> None:
    if os.name == "nt":
        # POSIX modes do not establish the protected owner+SYSTEM Windows DACL.
        # Reuse the production provisioner without importing a real store.
        from codex_plugin_scanner.guard.native_policy_snapshot_windows_key import (
            provision_native_policy_verifier_key,
        )

        provision_native_policy_verifier_key(home, os.urandom(32))
        return

    from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
        NATIVE_POLICY_VERIFIER_KEY_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
    )

    state_dir = home / NATIVE_RUNTIME_STATE_DIRECTORY
    state_dir.mkdir(mode=0o700)
    key_path = state_dir / NATIVE_POLICY_VERIFIER_KEY_NAME
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(os.urandom(32))
