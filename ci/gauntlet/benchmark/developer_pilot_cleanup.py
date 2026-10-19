"""Bounded cleanup continues after individual controller lifecycle failures."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .contracts import canonical_json


def cleanup_runtime(*, podman, name, root, guard_identity, guard_python, bridge, provider_bridge,
                    relay, provider, inputs, reuse_observer, profile_loaded, profile_path, product=None, sdk_gate=None):
    errors = []

    def attempt(label, action):
        try:
            action()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            errors.append(f'{label}: {type(error).__name__}: {error}')

    def daemon_stop():
        result = podman('exec', name, str(guard_python.parent / 'hol-guard'), 'daemon', 'stop',
            '--guard-home', '/runtime/guard', '--home', '/runtime/home', '--json', timeout=15, check=False)
        (root / 'guard-daemon-stop.json').write_text(canonical_json({'exit_code': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}))
        if result.returncode:
            raise ValueError('actual Guard daemon stop failed')

    def process_stop(process):
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def profile_stop():
        subprocess.run(['/usr/sbin/apparmor_parser', '--remove', str(profile_path)],
                       capture_output=True, timeout=10, check=True)
        if any(line.split(' ', 1)[0] == name for line in
               Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines()):
            raise ValueError('owned agent AppArmor profile survived cleanup')

    if reuse_observer is not None:
        attempt('live-inode-observer', reuse_observer.stop)
    if guard_identity is not None:
        attempt('actual-product-daemon', daemon_stop)
    attempt('agent-container', lambda: podman('rm', '--force', '--time=0', name, check=False))
    if sdk_gate is not None:
        attempt('sdk-binding-gate', sdk_gate.close)
    if product is not None:
        attempt('native-developer-product', product.close)
    if bridge is not None:
        attempt('model-namespace-bridge', lambda: process_stop(bridge))
    attempt('controller-model-relay', relay.close)
    attempt('synthetic-git-package-provider', provider.close)
    attempt('developer-resource-supervisor', inputs.close)
    if provider_bridge is not None:
        attempt('provider-namespace-bridge', lambda: process_stop(provider_bridge))
    if profile_loaded:
        attempt('owned-apparmor-profile', profile_stop)
    return errors
