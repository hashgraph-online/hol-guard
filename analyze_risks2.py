#!/usr/bin/env python3
"""Analyze Hermes skills for edge cases and risk signals."""

import sys
sys.path.insert(0, 'src')
from pathlib import Path
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.risk import artifact_risk_signals

context = HarnessContext(
    home_dir=Path.home(),
    workspace_dir=None,
    guard_home=Path.home() / '.guard',
)
adapter = HermesHarnessAdapter()
detection = adapter.detect(context)

# Count by signal type
network = []
env_secrets = []
sensitive_files = []
no_signals = []

for a in detection.artifacts:
    signals = artifact_risk_signals(a)
    if 'network' in ' '.join(signals).lower():
        network.append(a.name)
    if 'secrets' in ' '.join(signals).lower():
        env_secrets.append(a.name)
    if 'sensitive' in ' '.join(signals).lower():
        sensitive_files.append(a.name)
    if not signals:
        no_signals.append(a.name)

print(f'Total artifacts: {len(detection.artifacts)}')
print(f'Network signals: {len(network)}')
print(f'Env secret signals: {len(env_secrets)}')
print(f'Sensitive file signals: {len(sensitive_files)}')
print(f'No signals: {len(no_signals)}')
print()

# Show some examples
print('Network examples:')
for n in network[:5]:
    print(f'  - {n}')
print()

print('Sensitive file examples:')
for n in sensitive_files[:5]:
    print(f'  - {n}')