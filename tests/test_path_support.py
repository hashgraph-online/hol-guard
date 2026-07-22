"""Security regressions for shared path containment helpers."""

from pathlib import Path

from codex_plugin_scanner.path_support import resolve_path_within_allowed_roots


def test_resolve_path_within_allowed_roots_accepts_contained_directory(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    workspace = allowed_root / "workspace"
    workspace.mkdir(parents=True)

    assert resolve_path_within_allowed_roots(str(workspace), (allowed_root,), require_exists=True) == workspace


def test_resolve_path_within_allowed_roots_rejects_traversal(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    traversal = f"{allowed_root}/../{outside.name}"

    assert resolve_path_within_allowed_roots(traversal, (allowed_root,), require_exists=True) is None


def test_resolve_path_within_allowed_roots_rejects_symlink_escape(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = allowed_root / "workspace"
    link.symlink_to(outside, target_is_directory=True)

    assert resolve_path_within_allowed_roots(str(link), (allowed_root,), require_exists=True) is None


def test_resolve_path_within_allowed_roots_accepts_symlinked_allowed_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real-root"
    workspace = real_root / "workspace"
    workspace.mkdir(parents=True)
    allowed_root = tmp_path / "allowed-root"
    allowed_root.symlink_to(real_root, target_is_directory=True)

    selected = allowed_root / workspace.name

    assert resolve_path_within_allowed_roots(str(selected), (allowed_root,), require_exists=True) == workspace
