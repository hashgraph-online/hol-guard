"""Actual locked OMP registry regression; no model or candidate execution."""
import json
import os
import subprocess
from pathlib import Path

import pytest


def test_locked_sdk_retained_device_partition_is_pinned_to_exact_declared_top_level(tmp_path):
    sdk_root = os.environ.get('HOL_WORKFLOW_OMP_SDK_ROOT')
    bun = os.environ.get('HOL_WORKFLOW_BUN')
    if not sdk_root or not bun:
        pytest.skip('actual locked SDK conformance needs explicit HOL_WORKFLOW_OMP_SDK_ROOT and HOL_WORKFLOW_BUN')
    if not Path(sdk_root).is_absolute() or not Path(bun).is_absolute():
        pytest.fail('SDK/Bun conformance paths must be explicit absolute public artifacts')
    source = Path(__file__).parents[1] / 'ci/gauntlet/benchmark/developer_tool_inventory_conformance.ts'
    result = subprocess.run([bun, str(source), sdk_root], capture_output=True, text=True, timeout=45,
        env={'PATH': '/usr/bin:/bin', 'HOME': str(tmp_path), 'TMPDIR': str(tmp_path)}, cwd=tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    row = json.loads(result.stdout)
    assert row['version'] == '18.4.12' and row['providerCalls'] == row['toolCalls'] == 0
    assert row['actualModelEpisode'] is False and row['qualificationEligible'] is False
    before, after = row['before'], row['after']
    assert set(before['mounted']) == set(before['enabled']) - set(before['active'])
    assert before['mounted'] and all(name.startswith('mcp__') for name in before['mounted'])
    assert set(after['active']) == set(before['enabled']) == set(after['enabled'])
    assert after['mounted'] == [] and len(after['active']) == len(set(after['active']))
    assert row['missingRejected'] and row['duplicateRejected']
    diagnostic = row['missingDiagnostic']
    assert diagnostic['missing'] == ['mcp__missing_unregistered'] and diagnostic['unexpected'] == []
    assert set(diagnostic['expected']) == set(after['active']) | {'mcp__missing_unregistered'}
    assert set(diagnostic['actual']) == set(diagnostic['enabled']) == set(after['active'])
    assert diagnostic['mounted'] == []
