#!/usr/bin/env python3
"""Test edge cases in Hermes adapter."""

import sys
sys.path.insert(0, 'src')
import json
import tempfile
from pathlib import Path
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext

adapter = HermesHarnessAdapter()

# Test cases
test_cases = []

# 1. Empty skills directory
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    hermes_home = home / ".hermes"
    skills_dir = hermes_home / "skills"
    skills_dir.mkdir(parents=True)
    # Add a category dir even if empty - adapter iterates category_dir
    (skills_dir / "test").mkdir()
    (hermes_home / "config.toml").write_text("[hermes]")
    ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".guard")
    result = adapter.detect(ctx)
    test_cases.append(("Empty skills dir", len(result.artifacts)))

# 2. Skill with no frontmatter
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    hermes_home = home / ".hermes"
    skills_dir = hermes_home / "skills" / "test" / "no-fm"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("# Just a title\nNo frontmatter here.")
    (hermes_home / "config.toml").write_text("[hermes]")
    ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".guard")
    result = adapter.detect(ctx)
    test_cases.append(("No frontmatter", len(result.artifacts)))

# 3. Skill with empty content
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    hermes_home = home / ".hermes"
    skills_dir = hermes_home / "skills" / "test" / "empty"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("")
    (hermes_home / "config.toml").write_text("[hermes]")
    ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".guard")
    result = adapter.detect(ctx)
    test_cases.append(("Empty content", len(result.artifacts)))

# 4. Malformed MCP JSON  
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    hermes_home = home / ".hermes"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.toml").write_text("[hermes]")
    (hermes_home / "mcp_servers.json").write_text("{ not valid json")
    ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".guard")
    result = adapter.detect(ctx)
    test_cases.append(("Malformed MCP", len(result.artifacts)))

# 5. MCP with URL instead of command
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    hermes_home = home / ".hermes"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.toml").write_text("[hermes]")
    (hermes_home / "mcp_servers.json").write_text(json.dumps({
        "url-server": {"url": "https://example.com/mcp"}
    }))
    ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".guard")
    result = adapter.detect(ctx)
    test_cases.append(("URL-based MCP", len(result.artifacts)))

# 6. MCP with non-list args
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    hermes_home = home / ".hermes"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.toml").write_text("[hermes]")
    (hermes_home / "mcp_servers.json").write_text(json.dumps({
        "bad-args": {"command": "echo", "args": "not-a-list"}
    }))
    ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".guard")
    result = adapter.detect(ctx)
    test_cases.append(("Non-list args", len(result.artifacts)))

# 7. Valid MCP server
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    hermes_home = home / ".hermes"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.toml").write_text("[hermes]")
    (hermes_home / "mcp_servers.json").write_text(json.dumps({
        "test-server": {"command": "npx", "args": ["-y", "some-package"]}
    }))
    ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".guard")
    result = adapter.detect(ctx)
    test_cases.append(("Valid MCP", len(result.artifacts)))

# Run all tests
print("Testing edge cases:")
failures = 0
for name, count in test_cases:
    status = "✓" if count >= 0 else "✗"
    print(f"  {status} {name}: {count} artifacts")
    if count == 0 and name != "Empty skills dir":
        failures += 1

if failures:
    print(f"\n{failures} edge cases need fixing!")
else:
    print("\nAll edge cases handled correctly!")