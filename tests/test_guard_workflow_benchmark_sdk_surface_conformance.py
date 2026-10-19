"""Actual Bun input refusals; these are not installed Native/model controls."""
import json
import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize('change,reason',[
    ({'mcpAgentSurfaces':'unknown'},'explicit v5 profile'),
    ({'mcpAgentSurfaces':None},'explicit v5 profile'),
    ({'schema':'private-cell-sdk-conformance.v4'},'explicit v5 profile'),
    ({'workspace':'/candidate'},'fixed conformance config'),
    ({'command':'/usr/bin/node arbitrary.cjs'},'fixed conformance config'),
    ({'resourceEndpoints':{'docs':{}}},'exact declared docs/mail transports'),
])
def test_surface_control_rejects_bad_inputs_before_sdk_peer_binding(tmp_path,change,reason):
    bun=os.environ.get('HOL_WORKFLOW_BUN')
    if not bun:
        pytest.skip('explicit pinned Linux Bun required for actual entrypoint control')
    config={'schema':'private-cell-sdk-conformance.v5',
        'mcpAgentSurfaces':'mcp-agent-surfaces.v1','workspace':'/runtime/home/project',
        'command':'/usr/bin/node --test tests/node-control.test.cjs',
        'resourceEndpoints':{'docs':{},'mail':{}},**change}
    path=tmp_path/'episode.json';path.write_text(json.dumps(config))
    helper=Path(__file__).parents[1]/'ci/gauntlet/benchmark/private_cell_sdk_conformance.ts'
    run=subprocess.run([bun,str(helper),str(path)],capture_output=True,text=True,timeout=10,
        cwd=tmp_path,env={'PATH':'/usr/bin:/bin','HOME':str(tmp_path)})
    assert run.returncode==1 and reason in run.stderr
    assert 'ready.sock' not in run.stderr and not run.stdout
