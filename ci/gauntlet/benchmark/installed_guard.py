"""Require a genuine installed wheel with matching packaged native provenance."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .adapters import ManagedGuardAdapter, NativeBuildIdentity

_PROBE = '''
import dataclasses, importlib.metadata, json, pathlib, sys
import codex_plugin_scanner
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
status = native_runtime_status()
module = pathlib.Path(codex_plugin_scanner.__file__).resolve()
prefix = pathlib.Path(sys.prefix).resolve()
print(json.dumps({"available": status.available, "compatible": status.compatible,
 "reason": status.reason, "installed": module.is_relative_to(prefix),
 "module": str(module), "prefix": str(prefix),
 "package_version": importlib.metadata.version("hol-guard"),
 "manifest": dataclasses.asdict(status.manifest) if status.manifest else None,
 "capabilities": dataclasses.asdict(status.capabilities) if status.capabilities else None,
 "runtime_sha256": status.identity.sha256 if status.identity else None}))
'''


def inspect_installed_guard(python: Path, *, expected_sha: str, home: Path) -> dict:
    if not python.is_absolute() or not home.is_absolute():
        raise ValueError('installed Guard paths must be absolute')
    if len(expected_sha) != 40 or any(c not in '0123456789abcdef' for c in expected_sha):
        raise ValueError('installed Guard requires an exact source commit')
    probe = subprocess.run([str(python), '-I', '-c', _PROBE], cwd=home,
                           env={'PATH': '/usr/bin:/bin', 'HOME': str(home),
                                'LANG': 'C.UTF-8'}, capture_output=True,
                           timeout=15, check=False)
    if probe.returncode != 0 or len(probe.stdout) > 64 * 1024:
        raise ValueError('installed Guard identity probe failed')
    try:
        identity = json.loads(probe.stdout)
        manifest, capabilities = identity['manifest'], identity['capabilities']
        native = NativeBuildIdentity(expected_sha, capabilities['build_sha'],
                                    identity['available'] and identity['compatible'])
        native.require_matching()
        if (identity['installed'] is not True or not isinstance(manifest, dict)
                or manifest['source_sha'] != expected_sha
                or manifest['runtime_sha256'] != identity['runtime_sha256']
                or manifest['package_version'] != identity['package_version']
                or capabilities['runtime_version'] != identity['package_version']):
            raise ValueError('installed wheel provenance does not match')
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError('installed Guard lacks matching native wheel provenance') from exc
    return identity


def guard_endpoints(upstreams, *, python: Path, home: Path, guard_home: Path,
                    workspace: Path, config_path: Path, identity: dict):
    native = NativeBuildIdentity(identity['manifest']['source_sha'],
                                identity['capabilities']['build_sha'], True)
    return [ManagedGuardAdapter().endpoint(upstream, python=python, harness='omp',
            guard_home=guard_home, home=home, workspace=workspace,
            config_path=config_path, native=native) for upstream in upstreams]
