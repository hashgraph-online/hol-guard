"""Generated pytest data must not hide source or dirty a committed artifact."""
import os
from pathlib import Path

import pytest
from _pytest.cacheprovider import CACHEDIR_TAG_CONTENT, README_CONTENT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.developer_oracles import source_tree_digest
from ci.gauntlet.benchmark.synthetic_developer_services import SyntheticGitService, _git


def cache(root):
    directory = root / '.pytest_cache'
    (directory / 'v/cache').mkdir(parents=True)
    for name, raw in {
        '.gitignore': b'# Created by pytest automatically.\n*\n',
        'CACHEDIR.TAG': CACHEDIR_TAG_CONTENT,
        'README.md': README_CONTENT.encode(),
        'v/cache/nodeids': b'["test_sample.py::test_example"]',
    }.items():
        (directory / name).write_bytes(raw)
    return directory


def seeded(tmp_path):
    service = SyntheticGitService(tmp_path / 'world', signing_key=Ed25519PrivateKey.generate())
    before = service.seed('python-cli-with-tests')
    return service, before, Path(before['checkout_path'])


def test_standard_pytest_metadata_does_not_dirty_committed_source(tmp_path):
    service, before, checkout = seeded(tmp_path)
    cache(checkout)
    # Only this author-created fixture uses Git status. Runtime observation must
    # continue reading inert bytes without trusting candidate configuration.
    assert _git(checkout, 'status', '--porcelain', '--untracked-files=all') == b''
    assert source_tree_digest(checkout) == before['tree_digest']
    assert service.freeze('run-repository')['clean'] is True


def test_generated_cache_is_not_staged_as_candidate_source(tmp_path):
    service, _, checkout = seeded(tmp_path)
    cache(checkout)
    staged = service.export_committed_snapshot('run-repository', branch='main', stage_name='cache-control')
    assert not (staged / '.pytest_cache').exists()
    assert source_tree_digest(checkout) == source_tree_digest(staged)


@pytest.mark.parametrize('relative,raw', [
    ('plugin.py', b'raise RuntimeError("must remain ordinary untracked source")'),
    ('v/cache/nodeids', b'[NaN]'),
    ('v/cache/nodeids', b'{"not":"nodeids"}'),
    ('v/cache/lastfailed', b'{"test.py":true,"test.py":false}'),
    ('v/cache/lastfailed', b'{"test.py":"not a boolean"}'),
    ('v/cache/unknown-plugin-state', b'[]'),
    ('.gitignore', b'*\n'),
    ('CACHEDIR.TAG', b'Signature: counterfeit'),
    ('README.md', b'counterfeit cache metadata'),
    ('v/cache/nodeids', b' ' * 65537),
])
def test_cache_lookalikes_cannot_hide_untracked_source(tmp_path, relative, raw):
    service, before, checkout = seeded(tmp_path)
    directory = cache(checkout)
    path = directory / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    assert source_tree_digest(checkout) != before['tree_digest']
    assert service.freeze('run-repository')['clean'] is False


def test_executable_cache_metadata_is_not_ignored(tmp_path):
    service, _, checkout = seeded(tmp_path)
    directory = cache(checkout)
    (directory / 'README.md').chmod(0o755)
    assert service.freeze('run-repository')['clean'] is False


def test_cache_leaf_link_does_not_read_or_change_outside_data(tmp_path):
    service, _, checkout = seeded(tmp_path)
    directory = cache(checkout)
    outside = tmp_path / 'outside.txt'
    outside.write_text('outside canary')
    leaf = directory / 'v/cache/nodeids'
    leaf.unlink()
    leaf.symlink_to(outside)
    assert service.freeze('run-repository')['clean'] is False
    assert outside.read_text() == 'outside canary'


def test_cache_directory_link_is_not_ignored(tmp_path):
    service, _, checkout = seeded(tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (checkout / '.pytest_cache').symlink_to(outside, target_is_directory=True)
    assert service.freeze('run-repository')['clean'] is False


def test_cache_fifo_refuses_without_waiting_for_a_writer(tmp_path):
    service, _, checkout = seeded(tmp_path)
    directory = cache(checkout)
    leaf = directory / 'v/cache/nodeids'
    leaf.unlink()
    os.mkfifo(leaf)
    with pytest.raises(ValueError, match='special file'):
        service.freeze('run-repository')


def test_tracked_cache_bytes_still_bind_the_exact_commit(tmp_path):
    service, _, checkout = seeded(tmp_path)
    directory = cache(checkout)
    _git(checkout, 'add', '--force', '.pytest_cache')
    _git(checkout, 'commit', '-m', 'Author fixture with explicitly committed cache data')
    assert service.freeze('run-repository')['clean'] is True
    (directory / 'v/cache/nodeids').write_text('["changed but still valid cache data"]')
    assert service.freeze('run-repository')['clean'] is False


def test_project_ignore_patterns_cannot_hide_untracked_code(tmp_path):
    service, _, checkout = seeded(tmp_path)
    (checkout / '.gitignore').write_text('node_modules/\nignored.py\n')
    _git(checkout, 'add', '.gitignore')
    _git(checkout, 'commit', '-m', 'Author fixture with ignored code path')
    (checkout / 'ignored.py').write_text('print("must remain visible to the raw observer")')
    assert _git(checkout, 'status', '--porcelain', '--untracked-files=all') == b''
    assert service.freeze('run-repository')['clean'] is False


def test_full_dependency_inventory_still_includes_cache_data(tmp_path):
    root = tmp_path / 'dependencies'
    root.mkdir()
    before = source_tree_digest(root, excluded=frozenset())
    directory = cache(root)
    assert source_tree_digest(root, excluded=frozenset()) != before
    original = source_tree_digest(root, excluded=frozenset())
    (directory / 'v/cache/nodeids').write_text('[]')
    assert source_tree_digest(root, excluded=frozenset()) != original


def test_standard_boolean_lastfailed_metadata_is_data(tmp_path):
    service, _, checkout = seeded(tmp_path)
    directory = cache(checkout)
    (directory / 'v/cache/lastfailed').write_text('{"test_sample.py::test_example":true}')
    assert service.freeze('run-repository')['clean'] is True
