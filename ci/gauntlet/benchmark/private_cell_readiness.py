"""Observe the installed OMP setup barrier before semantic hook admission."""
from __future__ import annotations

import time

from .contracts import strict_json_loads

EXPECTED = {'ready': True, 'native_required': True, 'native_route': 'native_resident',
            'workspace_acknowledged': True, 'worker_ready': True}

# Runs only as the isolated product UID. Its normal client loads the disposable
# daemon credential internally; neither the credential nor headers reach Root.
# HTTPConnection uses direct fixed loopback, without proxies or redirects.
PROBE = r'''
import http.client,json,sys
from pathlib import Path
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
token=load_guard_daemon_auth_token(Path('/product/guard'))
if type(token) is not str or not token:
    raise SystemExit(69)
connection=http.client.HTTPConnection('127.0.0.1',18765,timeout=float(sys.argv[2])-1)
try:
    connection.request('POST','/v1/hooks/omp/readiness',
        body=json.dumps({'workspace':sys.argv[1]}).encode(),
        headers={'Content-Type':'application/json','X-Guard-Token':token})
    response=connection.getresponse()
    body=response.read(4097)
    if len(body)>4096:raise SystemExit(69)
    sys.stdout.buffer.write(body)
    raise SystemExit(0 if response.status==200 else 69)
finally:
    connection.close()
'''


def require_native_workspace(plane, *, deadline):
    """One setup request, bounded by the existing startup deadline; no retry."""
    if plane.workspace_path != '/runtime/home/project':
        raise ValueError('exact private-cell workspace required for readiness')
    timeout = min(35, int(deadline-time.monotonic()))
    if timeout < 2:
        raise TimeoutError('native workspace setup exhausted the startup deadline')
    result = plane.cell.capture([str(plane.python), '-I', '-B', '-c', PROBE,
                                 plane.workspace_path, str(timeout)], timeout=timeout)
    if len(result.stdout) > 4096:
        raise ValueError('native workspace readiness response exceeds bound')
    response = strict_json_loads(result.stdout)
    plane._emit(plane.observations, {'kind':'native-workspace-readiness',
                'returncode':result.returncode, 'response':response})
    if (result.returncode != 0 or type(response) is not dict or set(response) != set(EXPECTED)
            or any(type(response[name]) is not type(value) or response[name] != value
                   for name,value in EXPECTED.items())):
        raise ValueError('installed native workspace readiness not confirmed')
