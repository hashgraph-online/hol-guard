"""SCRG264-270: shim status, PATH verification, tamper detection, repair, daemon coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.shims import (
    build_shim_content_hash,
    get_path_order_status,
    get_real_binary_info,
    install_package_shims,
    package_shim_status,
    repair_package_shims,
    uninstall_package_shims,
)


def _make_context(tmp_path: Path):
    """Build a minimal HarnessContext-like object for testing."""
    from unittest.mock import MagicMock

    ctx = MagicMock()
    ctx.guard_home = tmp_path / "guard_home"
    ctx.guard_home.mkdir(parents=True, exist_ok=True)
    ctx.workspace_dir = None
    ctx.home_dir = None
    return ctx


class TestScrg264PackageShimStatusAccurate:
    """SCRG264: shim status reports installed, active, PATH, real binary."""

    def test_status_empty_when_no_shims_installed(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        result = package_shim_status(ctx)
        assert result["installed_managers"] == []
        assert result["active_managers"] == []
        assert result["missing_managers"] == []

    def test_status_active_when_shim_file_exists(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        result = package_shim_status(ctx)
        assert "npm" in result["installed_managers"]
        assert "npm" in result["active_managers"]
        assert "npm" not in result["missing_managers"]

    def test_status_missing_when_shim_file_deleted(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = ctx.guard_home / "package-shims" / "bin"
        (shim_dir / "npm").unlink()
        result = package_shim_status(ctx)
        assert "npm" in result["missing_managers"]
        assert "npm" not in result["active_managers"]


class TestScrg265PathOrderVerification:
    """SCRG265: verify shim precedes real manager in PATH."""

    def test_shim_first_in_path_returns_active(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = str(ctx.guard_home / "package-shims" / "bin")
        real_dir = str(tmp_path / "usr" / "bin")
        fake_path = f"{shim_dir}:{real_dir}:/usr/local/bin"
        result = get_path_order_status(ctx, manager="npm", path_env=fake_path)
        assert result["shim_precedes_real"] is True
        assert result["shim_dir"] == shim_dir

    def test_real_before_shim_returns_broken(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = str(ctx.guard_home / "package-shims" / "bin")
        real_dir = str(tmp_path / "usr" / "bin")
        (Path(real_dir)).mkdir(parents=True, exist_ok=True)
        (Path(real_dir) / "npm").write_text("#!/bin/sh\nnpm $@", encoding="utf-8")
        (Path(real_dir) / "npm").chmod(0o755)
        fake_path = f"{real_dir}:{shim_dir}"
        result = get_path_order_status(ctx, manager="npm", path_env=fake_path)
        assert result["shim_precedes_real"] is False
        assert result["path_broken"] is True

    def test_no_real_binary_found_returns_unknown(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = str(ctx.guard_home / "package-shims" / "bin")
        result = get_path_order_status(ctx, manager="npm", path_env=shim_dir)
        assert result["real_binary_found"] is False

    def test_stale_package_shim_dirs_are_ignored_on_path(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = str(ctx.guard_home / "package-shims" / "bin")
        stale_home = tmp_path / "pytest-guard-home"
        stale_shim_dir = stale_home / "package-shims" / "bin"
        stale_shim_dir.mkdir(parents=True)
        stale_shim = stale_shim_dir / "npm"
        stale_shim.write_text("#!/bin/sh\nstale shim", encoding="utf-8")
        stale_shim.chmod(0o755)
        real_dir = str(tmp_path / "usr" / "bin")
        Path(real_dir).mkdir(parents=True, exist_ok=True)
        real_binary = Path(real_dir) / "npm"
        real_binary.write_text("#!/bin/sh\nnpm $@", encoding="utf-8")
        real_binary.chmod(0o755)
        fake_path = f"{shim_dir}:{stale_shim_dir}:{real_dir}"
        result = get_path_order_status(ctx, manager="npm", path_env=fake_path)
        assert result["shim_precedes_real"] is True
        assert result["path_broken"] is False
        assert result["real_binary_path"] == str(real_binary)

    def test_only_stale_package_shim_before_canonical_is_path_broken(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = str(ctx.guard_home / "package-shims" / "bin")
        stale_home = tmp_path / "pytest-guard-home"
        stale_shim_dir = stale_home / "package-shims" / "bin"
        stale_shim_dir.mkdir(parents=True)
        stale_shim = stale_shim_dir / "npm"
        stale_shim.write_text("#!/bin/sh\nstale shim", encoding="utf-8")
        stale_shim.chmod(0o755)
        fake_path = f"{stale_shim_dir}:{shim_dir}"
        result = get_path_order_status(ctx, manager="npm", path_env=fake_path)
        assert result["shim_precedes_real"] is False
        assert result["path_broken"] is True
        assert result["foreign_shim_bypass"] is True
        assert result["foreign_shim_path"] == str(stale_shim)

    def test_foreign_package_shim_before_trusted_marks_path_broken(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = str(ctx.guard_home / "package-shims" / "bin")
        evil_shim_dir = tmp_path / "evil" / "package-shims" / "bin"
        evil_shim_dir.mkdir(parents=True)
        evil_shim = evil_shim_dir / "npm"
        evil_shim.write_text("#!/bin/sh\nevil npm", encoding="utf-8")
        evil_shim.chmod(0o755)
        real_dir = str(tmp_path / "usr" / "bin")
        Path(real_dir).mkdir(parents=True, exist_ok=True)
        real_binary = Path(real_dir) / "npm"
        real_binary.write_text("#!/bin/sh\nnpm $@", encoding="utf-8")
        real_binary.chmod(0o755)
        fake_path = f"{evil_shim_dir}:{shim_dir}:{real_dir}"
        result = get_path_order_status(ctx, manager="npm", path_env=fake_path)
        assert result["shim_precedes_real"] is False
        assert result["path_broken"] is True
        assert result["foreign_shim_bypass"] is True
        assert result["foreign_shim_path"] == str(evil_shim)


class TestScrg268RealBinaryInfo:
    """SCRG268: real binary info recorded safely (hash, mtime), no private path in Cloud."""

    def test_get_real_binary_info_returns_hash_and_mtime(self, tmp_path: Path) -> None:
        real_bin = tmp_path / "npm"
        real_bin.write_bytes(b"#!/bin/sh\necho npm")
        real_bin.chmod(0o755)
        info = get_real_binary_info(str(real_bin))
        assert info["found"] is True
        assert len(info["content_hash"]) == 64
        assert info["mtime"] > 0

    def test_get_real_binary_info_not_found(self, tmp_path: Path) -> None:
        info = get_real_binary_info(str(tmp_path / "nonexistent"))
        assert info["found"] is False
        assert info["content_hash"] is None

    def test_real_binary_info_redacts_private_path_prefix(self, tmp_path: Path) -> None:
        real_bin = tmp_path / "npm"
        real_bin.write_bytes(b"#!/bin/sh")
        info = get_real_binary_info(str(real_bin), redact_path_prefix=str(tmp_path))
        assert str(tmp_path) not in info.get("path_display", "")


class TestScrg269ShimTamperDetection:
    """SCRG269: shim content hash/version stored; status reports modified/missing/stale."""

    def test_build_shim_content_hash_is_deterministic(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = ctx.guard_home / "package-shims" / "bin"
        content = (shim_dir / "npm").read_bytes()
        h1 = build_shim_content_hash(content)
        h2 = build_shim_content_hash(content)
        assert h1 == h2
        assert len(h1) == 64

    def test_status_reports_tampered_when_shim_modified(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = ctx.guard_home / "package-shims" / "bin"
        (shim_dir / "npm").write_text("#!/bin/sh\nmalicious", encoding="utf-8")
        result = package_shim_status(ctx)
        npm_info = next((m for m in result.get("manager_details", []) if m["manager"] == "npm"), None)
        assert npm_info is not None
        assert npm_info["integrity"] in ("tampered", "unknown")

    def test_status_reports_ok_when_shim_unchanged(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        result = package_shim_status(ctx)
        npm_info = next((m for m in result.get("manager_details", []) if m["manager"] == "npm"), None)
        assert npm_info is not None
        assert npm_info["integrity"] == "ok"


class TestScrg266ShimAutoRepair:
    """SCRG266: repair detects missing/stale shims and reinstalls them."""

    def test_repair_reinstalls_missing_shim(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm", "pip"))
        shim_dir = ctx.guard_home / "package-shims" / "bin"
        (shim_dir / "npm").unlink()
        result = repair_package_shims(ctx)
        assert "npm" in result["repaired"]
        assert (shim_dir / "npm").exists()

    def test_repair_reinstalls_tampered_shim(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = ctx.guard_home / "package-shims" / "bin"
        original = (shim_dir / "npm").read_text(encoding="utf-8")
        (shim_dir / "npm").write_text("#!/bin/sh\nmalicious", encoding="utf-8")
        result = repair_package_shims(ctx)
        assert "npm" in result["repaired"]
        restored = (shim_dir / "npm").read_text(encoding="utf-8")
        assert restored == original

    def test_repair_reports_nothing_when_all_ok(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        result = repair_package_shims(ctx)
        assert result["repaired"] == []
        assert result["nothing_to_repair"] is True

    def test_repair_only_selected_managers(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm", "pip"))
        shim_dir = ctx.guard_home / "package-shims" / "bin"
        (shim_dir / "npm").unlink()
        (shim_dir / "pip").unlink()
        result = repair_package_shims(ctx, managers=("npm",))
        assert result["repaired"] == ["npm"]
        assert (shim_dir / "npm").exists()
        assert not (shim_dir / "pip").exists()

    def test_repair_reports_path_repair_when_shim_exists_but_path_inactive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        real_dir = tmp_path / "usr" / "bin"
        real_dir.mkdir(parents=True)
        real_binary = real_dir / "npm"
        real_binary.write_text("#!/bin/sh\nexit 0", encoding="utf-8")
        real_binary.chmod(0o755)
        shim_dir = ctx.guard_home / "package-shims" / "bin"
        monkeypatch.setenv("PATH", f"{real_dir}:{shim_dir}")
        result = repair_package_shims(ctx, managers=("npm",))
        assert result["repaired"] == []
        assert result["path_repair_required"] == ["npm"]
        assert result["shell_hints"]["bash"].startswith("export PATH=")

    def test_status_includes_shell_hints_for_path_repair(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        result = package_shim_status(ctx)
        assert result["shell_hints"]["zsh"].startswith("export PATH=")
        assert "fish_add_path" in result["shell_hints"]["fish"]


class TestScrg267FixtureAllManagers:
    """SCRG267: fixture tests for each supported manager."""

    @pytest.mark.parametrize(
        "manager",
        [
            "npm",
            "pnpm",
            "yarn",
            "pip",
            "poetry",
            "uv",
            "pipenv",
            "bun",
        ],
    )
    def test_install_and_status_for_manager(self, manager: str, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=(manager,))
        result = package_shim_status(ctx)
        assert manager in result["installed_managers"]
        assert manager in result["active_managers"]

    def test_uninstall_preserves_remaining_manager_integrity(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm", "pip"))
        result = uninstall_package_shims(ctx, managers=("npm",))
        assert result["remaining_managers"] == ["pip"]
        status = package_shim_status(ctx)
        pip_detail = next((m for m in status.get("manager_details", []) if m["manager"] == "pip"), None)
        assert pip_detail is not None
        assert pip_detail["integrity"] == "ok"

    def test_uninstall_tolerates_null_manifest_hashes(self, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm", "pip"))
        manifest_path = ctx.guard_home / "package-shims" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["content_hashes"] = None
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = uninstall_package_shims(ctx, managers=("npm",))

        assert result["remaining_managers"] == ["pip"]

    @pytest.mark.parametrize("manager", ["npm", "pip"])
    def test_status_manager_details_include_integrity(self, manager: str, tmp_path: Path) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=(manager,))
        result = package_shim_status(ctx)
        detail = next((m for m in result.get("manager_details", []) if m["manager"] == manager), None)
        assert detail is not None
        assert "integrity" in detail
        assert "shim_path" in detail

    def test_status_manager_details_include_real_binary_and_path_order(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm",))
        shim_dir = ctx.guard_home / "package-shims" / "bin"
        real_dir = tmp_path / "usr" / "bin"
        real_dir.mkdir(parents=True)
        real_binary = real_dir / "npm"
        real_binary.write_text("#!/bin/sh\nexit 0", encoding="utf-8")
        real_binary.chmod(0o755)
        monkeypatch.setenv("PATH", f"{shim_dir}:{real_dir}")

        result = package_shim_status(ctx)
        detail = next((m for m in result.get("manager_details", []) if m["manager"] == "npm"), None)

        assert detail is not None
        assert detail["real_binary_found"] is True
        assert detail["real_binary_path"] == str(real_binary)
        assert detail["path_index"] == 0
        assert detail["real_binary_path_index"] == 1


class TestScrg270DaemonShimCoverage:
    """SCRG270: daemon snapshot includes shim coverage."""

    def test_daemon_snapshot_route_includes_shim_coverage(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon.server import _build_snapshot_payload

        ctx = _make_context(tmp_path)
        install_package_shims(ctx, managers=("npm", "pip"))
        snapshot = _build_snapshot_payload(ctx)
        assert "package_manager_coverage" in snapshot
        coverage = snapshot["package_manager_coverage"]
        assert "shims_installed" in coverage
        assert "npm" in coverage["shims_installed"]
        assert "pip" in coverage["shims_installed"]
