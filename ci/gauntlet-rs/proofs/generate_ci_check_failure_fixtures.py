"""Freeze only the pinned Python ci-check pre-execution failure branch."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from ci.gauntlet.benchmark.ci_pipeline import failed  # noqa: E402


def main() -> None:
    source = ROOT / 'ci/gauntlet/benchmark'
    files = ('ci_pipeline.py', 'beta_profile.py', 'deterministic.py')
    pins = {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
            for name in files}
    cases = []
    for profile in ('deterministic', 'beta-e2e', 'feature-ai', 'feature-ai-protocol'):
        for reason, code in (('pipeline-not-started', 2),
                             ('pipeline-execution-invalid', 130)):
            cases.append({'profile': profile, 'reason': reason, 'code': code,
                          'expected': failed(profile, reason, code)})
    path = (ROOT / 'ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/'
            'python_ci_check_failures_v1.json')
    path.write_text(json.dumps({'source_sha256': pins, 'cases': cases},
                               sort_keys=True, indent=2) + '\n')
    print(f'froze {len(cases)} Python ci-check failure cases at {path}')


if __name__ == '__main__':
    main()
