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

# Count risk signals
high_risk = []
medium_risk = []
low_risk = []
no_risk = []

for a in detection.artifacts:
    signals = artifact_risk_signals(a)
    # signals is a tuple of strings
    signal_str = ' '.join(signals).lower()
    
    if 'severe' in signal_str or 'high' in signal_str:
        high_risk.append((a.name, signal_str[:60]))
    elif 'medium' in signal_str:
        medium_risk.append((a.name, signal_str[:60]))
    elif signals:
        low_risk.append((a.name, signal_str[:60]))
    else:
        no_risk.append(a.name)

print(f'Total artifacts: {len(detection.artifacts)}')
print(f'High risk: {len(high_risk)}')
print(f'Medium risk: {len(medium_risk)}')
print(f'Low risk: {len(low_risk)}')
print(f'No risk signals: {len(no_risk)}')
print()
if high_risk[:5]:
    print('High risk examples:')
    for name, sig in high_risk[:5]:
        print(f'  - {name}')
        print(f'    {sig}...')
    print()

# Unique signal types
all_signals = set()
for a in detection.artifacts:
    signals = artifact_risk_signals(a)
    all_signals.update(signals)
    
print('All unique risk signals:')
for s in sorted(all_signals):
    print(f'  - {s}')