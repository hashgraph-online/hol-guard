#!/usr/bin/env python3
"""Analyze Hermes skills for edge cases."""

import sys
sys.path.insert(0, 'src')
from pathlib import Path

# Analyze Hermes skills in user's home
home = Path.home()
skills_dir = home / '.hermes' / 'skills'

stats = {
    'total': 0,
    'no_frontmatter': 0,
    'no_code_blocks': 0,
    'small': 0,
    'has_curl': 0,
    'has_env': 0,
    'has_ssh': 0,
    'has_api_key': 0,
    'has_json': 0,
}

edge_cases = []

for cat_dir in skills_dir.iterdir():
    if not cat_dir.is_dir():
        continue
    for skill_dir in cat_dir.iterdir():
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / 'SKILL.md'
        if not skill_md.is_file():
            continue
            
        stats['total'] += 1
        content = skill_md.read_text()
        
        # No frontmatter
        if not content.startswith('---'):
            stats['no_frontmatter'] += 1
            edge_cases.append(f"No frontmatter: {skill_dir.name}")
            
        # No code blocks
        if '```' not in content:
            stats['no_code_blocks'] += 1
            
        # Small (< 100 bytes)
        if len(content) < 100:
            stats['small'] += 1
            edge_cases.append(f"Small ({len(content)}b): {skill_dir.name}")
            
        # Has curl (network call)
        if 'curl' in content.lower():
            stats['has_curl'] += 1
            
        # Has env access
        if '$HOME' in content or '$PATH' in content:
            stats['has_env'] += 1
            
        # Has .ssh
        if '.ssh' in content:
            stats['has_ssh'] += 1
            
        # Has API key mention
        if 'api_key' in content.lower() or 'api-key' in content.lower():
            stats['has_api_key'] += 1
            
        # Has JSON
        if 'json' in content.lower():
            stats['has_json'] += 1

print('Skill Statistics:')
for k, v in stats.items():
    pct = (v / stats['total'] * 100) if stats['total'] else 0
    print(f'  {k}: {v} ({pct:.1f}%)')

print(f'\nEdge cases found: {len(edge_cases)}')
for ec in edge_cases[:10]:
    print(f'  - {ec}')