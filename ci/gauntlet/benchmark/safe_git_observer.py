"""Observe Git through private inert metadata, never candidate configuration.

Only raw object/ref commands are permitted. No status, diff, checkout, hash-object,
filters, hooks, helpers, includes, remotes, worktree discovery or lazy fetch run.
Unsupported metadata fails closed rather than asserting observation succeeded.
"""
from __future__ import annotations

import configparser
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

MAX_ENTRIES = 10000
MAX_TOTAL = 128 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024
SHA = re.compile(r'[a-f0-9]{40}')
REF = re.compile(r'refs/(?:heads|tags|remotes)/[A-Za-z0-9][A-Za-z0-9_./-]{0,100}')


def _ref(value):
    return bool(REF.fullmatch(value) and '..' not in value and '//' not in value)


def _text_ref(value):
    text = value.decode('ascii').strip()
    if SHA.fullmatch(text) or (text.startswith('ref: ') and _ref(text[5:])):
        return value
    raise ValueError('unsupported Git reference metadata')


def _regular(path, *, limit=MAX_TOTAL):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        raise ValueError('Git metadata must be bounded regular inert files')
    # Reject final-component replacement before open; agent must already be stopped.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if ((opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or opened.st_size > limit):
            raise ValueError('Git metadata changed during capture')
        content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError('Git metadata changed beyond byte budget')
        return content


def _config(path):
    if not path.exists():
        return
    parser = configparser.ConfigParser(interpolation=None, strict=True, allow_no_value=True)
    try:
        parser.read_string(_regular(path, limit=65536).decode('utf-8'))
    except (UnicodeError, configparser.Error) as exc:
        raise ValueError('unsupported candidate Git configuration syntax') from exc
    forbidden = {'include', 'includeif', 'filter', 'alias', 'credential', 'diff', 'merge', 'gpg', 'pager'}
    for section in parser.sections():
        kind = section.split()[0].lower()
        if kind in forbidden:
            raise ValueError('candidate executable/include Git configuration is unsupported')
        if kind == 'core' and set(parser[section]) & {'worktree', 'fsmonitor', 'hookspath',
                                                     'attributesfile', 'sshcommand', 'editor', 'pager'}:
            raise ValueError('candidate Git execution/path overrides are unsupported')
    # Even accepted local settings are never copied or loaded by observer Git.


def _command(args):
    fixed = {
        ('fsck', '--full', '--strict', '--no-reflogs'),
        ('for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads/'),
        ('symbolic-ref', '--short', 'HEAD'),
    }
    if args in fixed:
        return
    if args[:1] == ('rev-parse',) and args[1:] in {('HEAD',), ('refs/heads/main',)}:
        return
    if len(args) == 3 and args[:2] == ('rev-parse', '--verify') and (args[2] == 'HEAD' or _ref(args[2])):
        return
    if len(args) == 4 and args[:3] == ('ls-tree', '-rz', '--full-tree') and SHA.fullmatch(args[3]):
        return
    if len(args) == 3 and args[0] == 'cat-file' and args[1] in {'-s', 'blob'} and SHA.fullmatch(args[2]):
        return
    if len(args) == 5 and args[:4] == ('rev-list', '--parents', '-n', '1') and SHA.fullmatch(args[4]):
        return
    raise ValueError('Git observer permits only declared raw object/ref commands')


def raw_tracked_files_match(checkout: Path, blobs: dict) -> bool:
    """Compare literal bytes/modes/link text, never attributes or index filters."""
    for name, (mode, expected) in blobs.items():
        if mode not in {'100644', '100755', '120000'}:
            raise ValueError('unsupported committed source mode')
        path = checkout / name
        if any(parent.is_symlink() for parent in path.parents if parent.is_relative_to(checkout)):
            raise ValueError('tracked candidate source has an indirect parent path')
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return False
        if mode == '120000':
            if not stat.S_ISLNK(metadata.st_mode) or os.readlink(path).encode() != expected:
                return False
        elif (not stat.S_ISREG(metadata.st_mode) or bool(metadata.st_mode & 0o111) != (mode == '100755')
              or _regular(path, limit=MAX_OUTPUT) != expected):
            return False
    return True


def owned_directory(path: Path, custody_root: Path) -> bool:
    """Validate every literal ancestor before following a dependency directory."""
    if not path.is_relative_to(custody_root):
        raise ValueError('observed directory escaped controller-owned root')
    if any(parent.is_symlink() for parent in [path, *path.parents] if parent.is_relative_to(custody_root)):
        raise ValueError('observed directory has an indirect custody path')
    return path.is_dir()


class SafeGitObserver:
    """One bounded metadata snapshot; no candidate index or configuration consumed."""

    def __init__(self, repository: Path, *, custody_root: Path, namespace_roots=None):
        self.repository, self.custody_root = Path(repository), Path(custody_root)
        # Supplied only by the trusted launch controller, never by Git metadata.
        self.namespace_roots = dict(namespace_roots or {})
        if len(self.namespace_roots) > 8:
            raise ValueError('bounded explicit Git namespace roots required')
        for virtual, physical in self.namespace_roots.items():
            virtual_path, physical = Path(virtual), Path(physical)
            if (not virtual_path.is_absolute() or str(virtual_path) != virtual
                    or '..' in virtual_path.parts or virtual_path == Path('/')
                    or not physical.is_absolute() or physical == Path('/')
                    or physical.resolve() != physical or not physical.is_dir()
                    or any(p.is_symlink() for p in (physical, *physical.parents))):
                raise ValueError('canonical explicit Git namespace roots required')
            self.namespace_roots[virtual] = physical
        self._temporary = None

    def _pointer(self, raw):
        path = Path(raw)
        if (not path.is_absolute() or str(path) != raw or '..' in path.parts
                or '\\' in raw or any(ord(c) < 32 for c in raw)):
            raise ValueError('linked worktree has a noncanonical pointer')
        for virtual, physical in sorted(self.namespace_roots.items(), key=lambda item: -len(item[0])):
            if path.is_relative_to(virtual):
                path = physical / path.relative_to(virtual)
                break
        else:
            if not path.is_relative_to(self.custody_root):
                raise ValueError('linked worktree escapes controller-owned root')
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('linked worktree has an indirect custody path')
        return path

    def __enter__(self):
        metadata = self.repository / '.git' if (self.repository / '.git').is_dir() else self.repository
        if (metadata.is_symlink() or not metadata.is_dir()
                or not metadata.resolve().is_relative_to(self.custody_root.resolve())):
            raise ValueError('Git metadata escaped controller-owned root')
        entries, total = 0, 0
        pending = [metadata]
        while pending:
            for path in pending.pop().iterdir():
                entries += 1
                mode = path.lstat().st_mode
                if entries > MAX_ENTRIES or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise ValueError('Git metadata symlinks/special files/oversized inventory unsupported')
                if stat.S_ISDIR(mode):
                    pending.append(path)
                else:
                    total += path.stat().st_size
                    if total > MAX_TOTAL:
                        raise ValueError('Git metadata exceeds byte budget')
                    if path.name in {'alternates', 'http-alternates'} and _regular(path).strip():
                        raise ValueError('Git object alternates are unsupported')
                    if path.parent == metadata and path.name in {'commondir', 'gitdir', 'shallow'}:
                        raise ValueError('Git metadata indirection/shallow graph unsupported')
        _config(metadata / 'config')
        self.metadata = metadata
        self._temporary = tempfile.TemporaryDirectory(prefix='gauntlet-git-observation-')
        self.private = Path(self._temporary.name)
        try:
            self._capture()
        except BaseException:
            self._temporary.cleanup()
            raise
        return self

    def _capture(self):
        (self.private / 'objects' / 'pack').mkdir(parents=True)
        (self.private / 'refs').mkdir()
        (self.private / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = true\n'
                                            'hooksPath = /dev/null\nfsmonitor = false\n'
                                            'attributesFile = /dev/null\n[protocol]\nallow = never\n[gc]\nauto = 0\n')
        (self.private / 'HEAD').write_bytes(_text_ref(_regular(self.metadata / 'HEAD', limit=4096)))
        refs = self.metadata / 'refs'
        if refs.exists():
            for path in refs.rglob('*'):
                if not path.is_file():
                    continue
                name = path.relative_to(self.metadata).as_posix()
                if not _ref(name):
                    raise ValueError('unsupported Git reference namespace')
                target = self.private / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(_text_ref(_regular(path, limit=4096)))
        packed = self.metadata / 'packed-refs'
        if packed.exists():
            content = _regular(packed, limit=65536)
            for line in content.decode('ascii').splitlines():
                if line.startswith('#') or not line:
                    continue
                if line.startswith('^') and SHA.fullmatch(line[1:]):
                    continue
                parts = line.split(' ')
                if len(parts) != 2 or not SHA.fullmatch(parts[0]) or not _ref(parts[1]):
                    raise ValueError('unsupported packed Git references')
            (self.private / 'packed-refs').write_bytes(content)
        objects = self.metadata / 'objects'
        for path in objects.rglob('*'):
            if not path.is_file():
                continue
            name = path.relative_to(objects).as_posix()
            if not (re.fullmatch(r'[a-f0-9]{2}/[a-f0-9]{38}', name)
                    or re.fullmatch(r'pack/pack-[a-f0-9]{40}\.(?:pack|idx)', name)):
                continue
            target = self.private / 'objects' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_regular(path))

    def run(self, *args):
        _command(args)
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(self.private), 'LC_ALL': 'C',
                       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null',
                       'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
                       'GIT_NO_LAZY_FETCH': '1', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_ATTR_NOSYSTEM': '1'}
        result = subprocess.run(['/usr/bin/git', '--git-dir=' + str(self.private), *args],
                                cwd=self.private, env=environment, capture_output=True, timeout=30, check=False)
        if len(result.stdout) + len(result.stderr) > MAX_OUTPUT:
            raise ValueError('raw Git observation exceeds output budget')
        if result.returncode:
            raise ValueError('safe raw Git operation failed: ' + result.stderr.decode(errors='replace')[:2048])
        return result.stdout

    def worktrees(self):
        """Read only literal owned linked-worktree pointers, never Git discovery."""
        paths = []
        directory = self.metadata / 'worktrees'
        if not directory.exists():
            return paths
        for entry in directory.iterdir():
            if not entry.is_dir():
                raise ValueError('unsupported linked worktree metadata')
            target = self._pointer(_regular(entry / 'gitdir', limit=4096).decode().strip())
            common = (entry / _regular(entry / 'commondir', limit=4096).decode().strip()).resolve()
            if (target.name != '.git' or not target.is_file()
                    or common != self.metadata.resolve()):
                raise ValueError('linked worktree escapes controller-owned root')
            backlink = _regular(target, limit=4096).decode().strip()
            try:
                correct = backlink.startswith('gitdir: ') and self._pointer(backlink[8:]) == entry
            except ValueError as error:
                raise ValueError('linked worktree lacks its exact metadata backlink') from error
            if not correct:
                raise ValueError('linked worktree lacks its exact metadata backlink')
            paths.append(str(target.parent))
        return sorted(paths)

    def __exit__(self, *exc):
        self._temporary.cleanup()
