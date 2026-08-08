from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.project_identity import resolve_portable_project_identity
from tests.test_guard_project_identity import _init_repository


def test_ipv6_remote_endpoints_do_not_collide(tmp_path: Path) -> None:
    explicit_port = tmp_path / "explicit-port"
    address_suffix = tmp_path / "address-suffix"
    _init_repository(explicit_port, "ssh://git@[::1]:9418/owner/repo.git")
    _init_repository(address_suffix, "ssh://git@[::1:9418]/owner/repo.git")

    explicit_identity = resolve_portable_project_identity(explicit_port)
    address_identity = resolve_portable_project_identity(address_suffix)

    assert explicit_identity is not None
    assert address_identity is not None
    assert explicit_identity != address_identity
