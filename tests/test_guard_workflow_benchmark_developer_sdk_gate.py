"""Kernel binding reducer tests; fake identities below are not live SDK evidence."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import developer_sdk_gate as gate


def test_gate_prepare_sets_exact_mode_under_private_umask_without_global_change(tmp_path):
    # The subprocess exercises real chmod masking; mocked chown records the
    # requested Root ownership only, with no claim of a real Root SDK peer.
    script = '''
import os, stat, sys
from pathlib import Path
from types import SimpleNamespace
from ci.gauntlet.benchmark import developer_sdk_gate as gate
os.umask(0o077)
calls = []
gate.os.chown = lambda path, uid, gid: calls.append((str(path), uid, gid))
directory = Path(sys.argv[1]) / 'gate'
subject = gate.DeveloperSdkGate(directory, bun=Path('/unused'), product=SimpleNamespace())
subject.prepare()
assert stat.S_IMODE(directory.stat().st_mode) == 0o710
assert calls == [(str(directory), 0, 10001)]
private = Path(sys.argv[1]) / 'private-fixture'
private.write_text('private')
assert stat.S_IMODE(private.stat().st_mode) == 0o600
'''
    subprocess.run([sys.executable, '-c', script, str(tmp_path)], check=True, timeout=15,
                   cwd=Path(__file__).parents[1])


@pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() != 0,
                    reason='actual UID10001 socket reachability requires Linux Root fixture')
def test_linux_root_gate_group_traverse_reaches_kernel_peer_check_under_private_umask():
    """Trusted UID10001 Python peer reaches gate and is rejected as non-Bun."""
    with tempfile.TemporaryDirectory(prefix='bm-gate-', dir='/tmp') as name:
        parent = Path(name)
        os.chown(parent, 0, 10001)
        parent.chmod(0o710)
        product = SimpleNamespace(bind_sdk=lambda *args, **kwargs: pytest.fail('non-SDK peer was admitted'))
        subject = gate.DeveloperSdkGate(parent / 'gate', bun=Path('/usr/bin/false'), product=product)
        previous = os.umask(0o077)
        try:
            subject.prepare()
            subject.start({})
        finally:
            os.umask(previous)
        try:
            child = subprocess.run(['/usr/bin/python3', '-c',
                'import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1]); '
                's.sendall(b"developer-sdk-ready.v1\\n"); assert s.recv(128)==b""; s.close()',
                str(subject.directory / 'ready.sock')], user=10001, group=10001, extra_groups=(),
                capture_output=True, timeout=5, check=False, env={'PATH': '/usr/bin:/bin'})
            assert child.returncode == 0, child.stderr.decode()
            assert 'frozen Bun executable' in subject.error
            assert not subject.bound.is_set() and subject.observation is None
            info = subject.directory.stat()
            assert info.st_uid == 0 and info.st_gid == 10001 and info.st_mode & 0o777 == 0o710
        finally:
            subject.close()
        assert subject.evidence()['cleanup_complete']


@pytest.fixture
def kernel(monkeypatch):
    identity = {'effective_uid': 10001, 'effective_gid': 10001, 'effective_capabilities': '0000000000000000',
                'no_new_privileges': 1, 'boot_id': 'unit-boot', 'mount_namespace': 'mnt:agent',
                'pid_namespace': 'pid:agent', 'network_namespace': 'net:agent', 'start_time': 'unit-start'}
    monkeypatch.setattr(gate, 'process_identity', lambda pid: dict(identity))
    monkeypatch.setattr(Path, 'stat', lambda path, **kwargs: SimpleNamespace(st_dev=1, st_ino=7))
    monkeypatch.setattr(Path, 'read_bytes', lambda path: (
        b'/runtime/bun\0/runtime/public/developer_omp_episode.ts\0/runtime/public/episode.json\0'))
    return identity


def test_exact_frozen_bun_command_and_agent_kernel_boundary(kernel):
    actual = gate.observe_sdk(42, bun=Path('/frozen/bun'), agent_identity=kernel)
    assert actual == kernel and actual['start_time'] == 'unit-start'


@pytest.mark.parametrize('field,value', [('effective_uid', 0), ('effective_gid', 0),
    ('effective_capabilities', '0000000000000001'), ('no_new_privileges', 0)])
def test_privileged_sdk_identity_rejected(kernel, field, value):
    kernel[field] = value
    with pytest.raises(ValueError, match='agent boundary'):
        gate.observe_sdk(42, bun=Path('/frozen/bun'), agent_identity=kernel)


def test_matching_filename_cannot_replace_bun_inode(kernel, monkeypatch):
    monkeypatch.setattr(Path, 'stat', lambda path, **kwargs: SimpleNamespace(
        st_dev=1, st_ino=9 if str(path).startswith('/proc/') else 7))
    with pytest.raises(ValueError, match='frozen Bun'):
        gate.observe_sdk(42, bun=Path('/frozen/bun'), agent_identity=kernel)


def test_same_binary_wrong_script_rejected(kernel, monkeypatch):
    monkeypatch.setattr(Path, 'read_bytes', lambda path: b'/runtime/bun\0/candidate/fake.ts\0')
    with pytest.raises(ValueError, match='controller-launched'):
        gate.observe_sdk(42, bun=Path('/frozen/bun'), agent_identity=kernel)


def test_new_diagnostic_script_cannot_enter_declared_sdk_gate():
    with pytest.raises(ValueError, match='explicit supported SDK entrypoint'):
        gate.DeveloperSdkGate(Path('/unused'), bun=Path('/frozen/bun'), product=SimpleNamespace(),
            script='/runtime/public/private-cell-agent-surface-sdk-control-001.ts')


def test_namespace_must_match_observed_agent(kernel):
    expected = {**kernel, 'network_namespace': 'net:controller'}
    with pytest.raises(ValueError, match='agent boundary'):
        gate.observe_sdk(42, bun=Path('/frozen/bun'), agent_identity=expected)


def test_binding_precedes_release_and_rechecks_start_time(kernel, monkeypatch):
    import struct
    monkeypatch.setattr(gate.socket, 'SO_PEERCRED', 17, raising=False)
    events = []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def settimeout(self, seconds): pass
        def getsockopt(self, *args): return struct.pack('3i', 42, 10001, 10001)
        def recv(self, size): return b'developer-sdk-ready.v1\n'
        def sendall(self, data): events.append(('release', data))
    class Server:
        def accept(self): return Connection(), None
    product = SimpleNamespace(bind_sdk=lambda pid, **kwargs: events.append(('bind', pid)))
    actual = gate.DeveloperSdkGate(Path('/unit/gate'), bun=Path('/frozen/bun'), product=product)
    actual.server, actual.agent_identity = Server(), kernel
    actual._serve()
    assert events == [('bind', 42), ('release', b'developer-sdk-bound.v1\n')]
    assert actual.bound.is_set() and actual.observation['kernel_peer_authenticated']
    events.clear()
    actual = gate.DeveloperSdkGate(Path('/unit/gate2'), bun=Path('/frozen/bun'), product=product)
    actual.server, actual.agent_identity = Server(), kernel
    calls = iter([kernel, {**kernel, 'start_time': 'reused'}])
    monkeypatch.setattr(gate, 'process_identity', lambda pid: next(calls))
    actual._serve()
    assert events == [('bind', 42)] and not actual.bound.is_set()
    assert 'identity changed' in actual.error
