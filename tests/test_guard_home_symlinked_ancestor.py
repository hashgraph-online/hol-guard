"""Guard state IO must survive a symlinked ancestor of the Guard home.

Fedora Silverblue ships ``/home`` as a symlink to ``var/home``; a relocated
home directory and a Windows profile behind a directory symlink have the same
shape. Every cache path Guard builds under the Guard home then carried a
symlinked component, and ``checked_path`` refused the lot, so the daemon could
neither take its cache lease nor stage, read or prune a publication.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import cache_io, current_refresh
from codex_plugin_scanner.guard.catalog_delivery.activation_store import directory_for_store
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path, read_bytes
from tests.symlink_support import SYMLINK_REASON, directory_symlinks_available

pytestmark = pytest.mark.skipif(not directory_symlinks_available(), reason=SYMLINK_REASON)


def _silverblue(tmp_path: Path) -> tuple[SimpleNamespace, Path]:
    """Return a store whose Guard home sits under a symlinked ``/home`` stand-in.

    ``tmp_path/var/home/tester`` is real; ``tmp_path/home`` is the symlink the
    distribution installs, so ``tmp_path/home/tester/.hol-guard`` reaches the
    same directory through a symlinked ancestor.
    """

    real = tmp_path / "var" / "home" / "tester"
    real.mkdir(parents=True)
    (tmp_path / "home").symlink_to(tmp_path / "var" / "home", target_is_directory=True)
    guard_home = tmp_path / "home" / "tester" / ".hol-guard"
    guard_home.mkdir(mode=0o700)
    return SimpleNamespace(guard_home=guard_home), real / ".hol-guard"


def test_the_guard_home_prefix_resolves_while_the_home_itself_stays_checked(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.catalog_delivery.state_paths import resolved_guard_home

    store, real = _silverblue(tmp_path)

    assert resolved_guard_home(store.guard_home) == real
    assert directory_for_store(store) == real / "native-runtime" / "command-packs"
    assert current_refresh._cache(store, "current-publication") == real / "command-packs" / "current-publication"

    # The unresolved path is exactly what the parent commit handed downstream.
    with pytest.raises(BuilderError, match="Symlink paths"):
        checked_path(store.guard_home / "native-runtime" / "command-packs")


def test_a_cache_lease_opens_under_a_symlinked_ancestor(tmp_path: Path) -> None:
    store, real = _silverblue(tmp_path)
    directory = directory_for_store(store)

    with cache_io.Lease(directory) as lease:
        assert lease.fd is not None
    assert (real / "native-runtime" / "command-packs" / ".cache-lease").is_file()


def test_immutable_transfers_write_and_reread_under_a_symlinked_ancestor(tmp_path: Path) -> None:
    store, real = _silverblue(tmp_path)
    directory = directory_for_store(store)
    digest = "a" * 64
    archive = directory / "archives" / (digest + ".zip")

    cache_io.write_once(archive, b"payload")
    cache_io.write_once(archive, b"payload")  # Re-publishing identical bytes is a no-op.

    assert (real / "native-runtime" / "command-packs" / "archives" / (digest + ".zip")).read_bytes() == b"payload"
    assert read_bytes(archive, limit=16) == b"payload"
    assert checked_path(directory / "objects") == real / "native-runtime" / "command-packs" / "objects"


def test_publication_staging_reading_and_pruning_survive_a_symlinked_ancestor(tmp_path: Path) -> None:
    store, real = _silverblue(tmp_path)
    directory = current_refresh._cache(store, "current-publication")
    authority = SimpleNamespace(data=b'{"publication":true}', digest="b" * 64)

    with current_refresh._stage(directory, authority, b"provenance") as pending:
        current_refresh._publish(pending)

    staged = real / "command-packs" / "current-publication"
    assert (staged / (authority.digest + ".root")).read_bytes() == authority.data
    # _load reads both halves back through the same prefix.
    assert read_bytes(directory / (authority.digest + ".root"), limit=65536) == authority.data
    assert read_bytes(directory / (authority.digest + ".provenance"), limit=65536) == b"provenance"

    names = current_refresh._filenames(directory)
    assert sorted(names) == [authority.digest + ".provenance", authority.digest + ".root"]

    current_refresh._remove(directory, names)
    assert current_refresh._filenames(directory) == []


def test_a_symlink_planted_inside_the_guard_home_is_still_refused(tmp_path: Path) -> None:
    store, real = _silverblue(tmp_path)
    directory = directory_for_store(store)
    directory.mkdir(mode=0o700, parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    (real / "native-runtime" / "command-packs" / "objects").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(BuilderError, match="Symlink paths"):
        checked_path(directory / "objects")

    (elsewhere / "planted.zip").write_bytes(b"planted")
    with pytest.raises(BuilderError, match="Symlink paths"):
        cache_io.write_once(directory / "objects" / "planted.zip", b"planted")

    (real / "native-runtime" / "command-packs" / "archives").mkdir(mode=0o700)
    (real / "native-runtime" / "command-packs" / "archives" / ("c" * 64 + ".zip")).symlink_to(elsewhere / "planted.zip")
    with pytest.raises(BuilderError, match="Symlink paths"):
        read_bytes(directory / "archives" / ("c" * 64 + ".zip"), limit=16)


def test_a_symlinked_guard_home_itself_is_still_refused(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.catalog_delivery.state_paths import resolved_guard_home

    _, real = _silverblue(tmp_path)
    linked = tmp_path / "home" / "tester" / ".hol-guard-link"
    linked.symlink_to(real, target_is_directory=True)

    assert resolved_guard_home(linked) == tmp_path / "var" / "home" / "tester" / ".hol-guard-link"
    with pytest.raises(BuilderError, match="Symlink paths"):
        checked_path(directory_for_store(SimpleNamespace(guard_home=linked)))
