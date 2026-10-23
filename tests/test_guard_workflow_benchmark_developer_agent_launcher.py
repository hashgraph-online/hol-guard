"""Explicit launcher scheduling units; no candidate or native product execution."""
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import developer_agent_launcher as launcher
from ci.gauntlet.benchmark import developer_product_runtime as product_module


def test_public_helpers_and_rewritten_episode_readable_under_private_umask(tmp_path):
    """Only a trusted staging helper runs in this subprocess, never candidate code."""
    script = '''
import os, stat, sys
from pathlib import Path
from ci.gauntlet.benchmark.developer_agent_launcher import stage_public_episode
os.umask(0o077)
root = Path(sys.argv[1])
private = root / 'private-oracle-fixture'
private.write_text('private fixture remains private')
public = root / 'public'
public.mkdir()
public.chmod(0o755)
stage_public_episode(public, {'prompt': 'public mission'}, copy_helpers=True)
stage_public_episode(public, {'prompt': 'public mission', 'guardExtension': '/runtime/public/builtin_guard_bridge.ts'})
assert {p.name: stat.S_IMODE(p.stat().st_mode) for p in public.iterdir()} == {
 'developer_omp_episode.ts': 0o644, 'developer_model_relay.py': 0o644,
 'developer_provider_relay.py': 0o644, 'service_relay.py': 0o644, 'episode.json': 0o644}
assert stat.S_IMODE(private.stat().st_mode) == 0o600
after = root / 'after-private-fixture'
after.write_text('caller private umask preserved')
assert stat.S_IMODE(after.stat().st_mode) == 0o600
'''
    subprocess.run([sys.executable, '-c', script, str(tmp_path)], check=True, timeout=15,
                   cwd=Path(__file__).parents[1])


def test_failed_product_constructor_closes_existing_provider_without_agent_mounts(monkeypatch, tmp_path):
    closed = []
    class BrokenRuntime:
        def __init__(self, **kwargs):
            assert kwargs['upstream'] == 'private-uid10004'
            raise ValueError('frozen product prefix mismatch')
    monkeypatch.setattr(product_module, 'DeveloperProductRuntime', BrokenRuntime)
    inputs = SimpleNamespace(supervisor='private-uid10004', close=lambda: closed.append('upstream'))
    provider = SimpleNamespace(close=lambda: closed.append('provider'))
    with pytest.raises(ValueError, match='prefix mismatch'):
        launcher.prepare_product(root=tmp_path, public=tmp_path / 'public', inputs=inputs,
            python=tmp_path / 'python', source_sha='a'*40, prefix_digest='b'*64, bwrap_sha256='c'*64,
            executor_image_id='sha256:'+'d'*64, checkout=tmp_path/'checkout', remote=tmp_path/'bare',
            home=tmp_path/'home', git_root=tmp_path/'git', prompt='public task', deadline=30,
            tool_limit=20, bun=tmp_path/'bun', provider=provider)
    assert closed == ['provider', 'upstream']


@pytest.mark.parametrize('failed', ['unbound', 'gate-error'])
@pytest.mark.parametrize('exit_code', [0, 1, -15])
def test_sdk_exit_cannot_replace_kernel_binding_and_retains_reaped_status(monkeypatch, tmp_path, failed, exit_code):
    class Process:
        returncode = None
        reaped = False
        def wait(self, **kwargs):
            self.returncode, self.reaped = exit_code, True
            return exit_code
    process = Process()
    monkeypatch.setattr(launcher.subprocess, 'Popen', lambda *args, **kwargs: process)
    gate = SimpleNamespace(bound=SimpleNamespace(is_set=lambda: failed != 'unbound'),
                           error='bad peer' if failed == 'gate-error' else None)
    with pytest.raises(launcher.SdkLaunchError, match='not controller bound') as caught:
        launcher.launch_sdk(name='unit-agent', events_path=tmp_path/'events', errors_path=tmp_path/'errors',
                            deadline=30, gate=gate)
    assert caught.value.process is process and process.reaped and process.returncode == exit_code
    assert isinstance(caught.value.original_exception, ValueError)
    assert caught.value.__cause__ is caught.value.original_exception


def test_subprocess_timeout_reaps_host_exec_handle_and_preserves_container_cleanup_requirement(monkeypatch, tmp_path):
    class Process:
        returncode = None
        killed, reaped = False, False
        def wait(self, timeout):
            if not self.killed:
                raise launcher.subprocess.TimeoutExpired('unit-exec', timeout)
            assert timeout <= 5
            self.returncode, self.reaped = -15, True
            return self.returncode
        def kill(self): self.killed = True
    process = Process()
    monkeypatch.setattr(launcher.subprocess, 'Popen', lambda *args, **kwargs: process)
    with pytest.raises(launcher.SdkLaunchError) as caught:
        launcher.launch_sdk(name='unit-agent', events_path=tmp_path/'events',
                            errors_path=tmp_path/'errors', deadline=30)
    assert caught.value.process is process and process.killed and process.reaped
    assert process.returncode == -15
    assert isinstance(caught.value.original_exception, launcher.subprocess.TimeoutExpired)
    assert caught.value.__cause__ is caught.value.original_exception
