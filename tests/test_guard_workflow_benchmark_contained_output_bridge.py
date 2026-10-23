"""Actual Bun bridge callbacks against inert controller replies; no native credit."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest


def test_reviewed_controller_output_is_exactly_delivered_or_withheld():
    bun=os.environ.get('HOL_WORKFLOW_BUN')
    if not bun:
        pytest.skip('explicit pinned Bun required for TypeScript bridge contract')
    binary=Path(bun)
    assert binary.is_absolute()
    assert hashlib.sha256(binary.read_bytes()).hexdigest()==(
        '37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086')
    script=Path(__file__).parent/'fixtures/workflow_benchmark/contained_output_bridge.ts'
    result=subprocess.run([bun,str(script)],capture_output=True,text=True,timeout=30,
                          cwd=Path(__file__).parents[1])
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)=={'cases':8,'networkConnections':0,'modelRequests':0,'nativeExecuted':False}
