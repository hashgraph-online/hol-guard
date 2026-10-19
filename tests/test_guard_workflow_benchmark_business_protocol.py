"""Behavioral controls for bounded same-episode malformed-tool recovery."""
import json
import os
import subprocess
from pathlib import Path

import pytest


def test_business_protocol_recovery_is_bounded_and_budget_aware(tmp_path):
    bun = os.environ.get('HOL_WORKFLOW_BUN')
    if not bun:
        pytest.skip('explicit pinned HOL_WORKFLOW_BUN needed for TypeScript controls')
    assert Path(bun).is_absolute()
    source = Path(__file__).parents[1]/'ci/gauntlet/benchmark/business_protocol_conformance.ts'
    result = subprocess.run([bun, str(source)], capture_output=True, text=True, timeout=30,
        cwd=tmp_path, env={'PATH':'/usr/bin:/bin', 'HOME':str(tmp_path)})
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report['passed'] is True and report['controls'] == 9
    assert report['actualModelEpisode'] is report['qualificationEligible'] is False
