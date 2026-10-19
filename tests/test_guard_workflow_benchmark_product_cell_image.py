"""Image-backed cells retain fixed layout and externally anchored inputs."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import product_cell_image as image
from ci.gauntlet.benchmark import product_cell_layout as layout
from ci.gauntlet.benchmark.product_cell_system import read_system

IMAGE = 'sha256:' + 'a' * 64


def declaration(stage, filesystem, **updates):
    info = filesystem.stat()
    value = {'schema': 'product-cell-image-system.v1', 'root': str(filesystem),
             'device': info.st_dev, 'inode': info.st_ino, 'image_id': IMAGE,
             'workspace': '/runtime/home/project'}
    value.update(updates)
    raw = json.dumps(value).encode()
    (stage / 'system.json').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_system_anchor_and_actual_inode_are_required(tmp_path):
    root = tmp_path / 'image'
    (root / 'usr').mkdir(parents=True)
    digest = declaration(tmp_path, root)
    checked = []
    def trust(path, **kwargs):
        checked.append(path)
    assert read_system(tmp_path, digest, trusted=trust) == (root, '/runtime/home/project')
    assert root / 'usr' in checked and root.parent in checked
    with pytest.raises(ValueError, match='external'):
        read_system(tmp_path, None, trusted=trust)
    with pytest.raises(ValueError, match='digest'):
        read_system(tmp_path, 'b' * 64, trusted=trust)
    digest = declaration(tmp_path, root, inode=root.stat().st_ino + 1)
    with pytest.raises(ValueError, match='inode changed'):
        read_system(tmp_path, digest, trusted=trust)


@pytest.mark.parametrize('updates', [
    {'workspace': '/etc'}, {'workspace': []}, {'device': True},
    {'image_id': 'latest'}, {'root': '/'}, {'root': '/opt/../usr'},
    {'extra': 'untrusted selector'},
])
def test_system_declaration_rejects_unsafe_selectors(tmp_path, updates):
    digest = declaration(tmp_path, tmp_path, **updates)
    with pytest.raises(ValueError):
        read_system(tmp_path, digest, trusted=lambda *args, **kwargs: None)


@pytest.mark.parametrize('value', [
    {'schema': 'product-cell-layout.v1', 'workspace': '/etc', 'path': '/usr/bin:/bin'},
    {'schema': 'product-cell-layout.v1', 'workspace': '/task', 'path': '/task:/usr/bin'},
    {'schema': 'product-cell-layout.v1', 'workspace': [], 'path': '/usr/bin:/bin'},
])
def test_layout_does_not_accept_product_selected_paths(monkeypatch, tmp_path, value):
    path = tmp_path / 'layout.json'
    path.write_text(json.dumps(value))
    # Root ownership check is exercised by the actual VM control. Fail-closed
    # parsing is tested here without requiring local privileged filesystem writes.
    view = SimpleNamespace(exists=lambda: True, is_symlink=lambda: False,
                           is_file=lambda: True, open=path.open,
                           lstat=lambda: SimpleNamespace(st_uid=0, st_mode=0o100444))
    monkeypatch.setattr(layout, 'Path', lambda _: view)
    with pytest.raises(ValueError):
        layout.load_layout()


def fake_podman(monkeypatch, tmp_path, *, preexisting=False, bad_mount=False):
    calls = []
    state = {'mounted': preexisting}
    def run(*argv):
        calls.append(argv)
        if argv[:2] == ('image', 'inspect'):
            return json.dumps([{'Id': IMAGE[7:], 'Os': 'linux', 'Architecture': 'arm64'}]).encode()
        if argv == ('image', 'mount', '--format', 'json'):
            return json.dumps([{'id': IMAGE[7:], 'mountpoint': '/wrong' if bad_mount else str(tmp_path)}]
                              if state['mounted'] else []).encode()
        if argv == ('image', 'mount', IMAGE):
            state['mounted'] = True
            return str(tmp_path).encode() + b'\n'
        if argv == ('image', 'unmount', IMAGE):
            state['mounted'] = False
            return b''
        pytest.fail(str(argv))
    monkeypatch.setattr(image, '_podman', run)
    monkeypatch.setattr(image.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(image, '_trusted', lambda *args, **kwargs: None)
    return calls, state


def test_image_lease_binds_identity_and_owns_only_its_mount(monkeypatch, tmp_path):
    calls, state = fake_podman(monkeypatch, tmp_path)
    lease = image.ImageLease(IMAGE).acquire()
    digest = lease.declare(tmp_path)
    assert hashlib.sha256((tmp_path / 'system.json').read_bytes()).hexdigest() == digest
    with pytest.raises(FileExistsError):
        lease.declare(tmp_path)
    with pytest.raises(ValueError, match='reacquired'):
        lease.acquire()
    lease.close()
    lease.close()
    assert not state['mounted'] and calls.count(('image', 'unmount', IMAGE)) == 1


def test_preexisting_image_mount_is_never_unmounted(monkeypatch, tmp_path):
    calls, _ = fake_podman(monkeypatch, tmp_path, preexisting=True)
    lease = image.ImageLease(IMAGE)
    with pytest.raises(ValueError, match='already mounted'):
        lease.acquire()
    lease.close()
    assert ('image', 'unmount', IMAGE) not in calls


def test_mount_validation_failure_still_has_cleanup_owner(monkeypatch, tmp_path):
    _, state = fake_podman(monkeypatch, tmp_path, bad_mount=True)
    lease = image.ImageLease(IMAGE)
    with pytest.raises(ValueError, match='provenance'):
        lease.acquire()
    lease.close()
    assert not state['mounted']


def test_helper_failure_after_mount_still_has_cleanup_owner(monkeypatch, tmp_path):
    _, state = fake_podman(monkeypatch, tmp_path)
    original = image._podman
    def fail_after_mount(*arguments):
        result = original(*arguments)
        if arguments == ('image', 'mount', IMAGE):
            raise OSError('helper failed after mount effect')
        return result
    monkeypatch.setattr(image, '_podman', fail_after_mount)
    lease = image.ImageLease(IMAGE)
    with pytest.raises(OSError, match='after mount'):
        lease.acquire()
    assert lease.owned and state['mounted']
    lease.close()
    assert not lease.owned and not state['mounted']


def test_idmap_unknown_profile_and_changed_helper_never_execute(monkeypatch, tmp_path):
    from ci.gauntlet.benchmark import product_cell_idmap as idmap

    with pytest.raises(ValueError, match='versioned'):
        idmap.verify('unreviewed', trusted=lambda *args: pytest.fail('unknown profile touched disk'))
    helper = tmp_path / 'mount'
    helper.write_bytes(b'changed helper')
    monkeypatch.setattr(idmap, 'Path', lambda _: helper)
    with pytest.raises(ValueError, match='digest mismatch'):
        idmap.verify('ubuntu2404-controller-v1', trusted=lambda *args: None)


def test_exec_gate_uses_only_verified_layout(monkeypatch):
    from ci.gauntlet.benchmark import product_exec_gate as gate

    effects = []
    monkeypatch.setattr(gate, 'load_layout', lambda: {'workspace': '/runtime/home/project',
                                                   'path': '/usr/local/bin:/usr/bin:/bin'})
    monkeypatch.setattr(gate, 'sys', SimpleNamespace(argv=['gate', '/usr/bin/node', '--version']))
    monkeypatch.setattr(gate.ctypes, 'CDLL', lambda *a, **kw: SimpleNamespace(prctl=lambda *a: 0))
    monkeypatch.setattr(gate, 'os', SimpleNamespace(
        getuid=lambda: 10004, getgid=lambda: 10004, write=lambda *a: None, read=lambda *a: b'\x01',
        chdir=lambda path: effects.append(path), execve=lambda path, argv, env: effects.append(env)))
    gate.main()
    assert effects[0] == '/runtime/home/project'
    assert effects[1] == {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/product/home',
                          'LANG': 'C.UTF-8', 'MALLOC_ARENA_MAX': '2'}


def test_cpu_profile_only_narrows_actual_available_cpus(monkeypatch):
    from ci.gauntlet.benchmark import product_cell_supervisor as supervisor

    monkeypatch.setattr(supervisor.os, 'sched_getaffinity', lambda _: {3, 5}, raising=False)
    assert supervisor.cpu_configuration('single-core-v1') == (
        3, ['--property=AllowedCPUs=3', '--property=CPUAffinity=3'])
    assert supervisor.cpu_configuration('quota-v1') == (None, [])
    with pytest.raises(ValueError, match='versioned'):
        supervisor.cpu_configuration('all-host-cpus')


def test_actor_with_wider_cpu_mask_is_refused_before_release():
    from ci.gauntlet.benchmark.product_cell_supervisor import verify_actor

    status = {'Uid': '10004 '*4, 'Gid': '10004 '*4, 'Groups': '', 'NoNewPrivs': '1',
              'Seccomp': '2', 'Seccomp_filters': '2', 'Cpus_allowed_list': '0-7'}
    status.update({name: '0' for name in ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb')})
    identity = {'status': status, 'lsm_label': 'owned-profile (enforce)'}
    with pytest.raises(ValueError, match='CPU affinity'):
        verify_actor(identity, profile='owned-profile', allowed_cpu=3)
    status['Cpus_allowed_list'] = '3'
    verify_actor(identity, profile='owned-profile', allowed_cpu=3)
