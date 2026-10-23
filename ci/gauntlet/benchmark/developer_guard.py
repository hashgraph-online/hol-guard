"""Unmodified installed product extension attachment for local developer pilots.

Only public installed identity and product event APIs are read. No auth store,
private product key, operator configuration, or raw database is exported.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from .installed_guard import inspect_installed_guard

_GENERATE = """
from pathlib import Path
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
print(managed_extension_source(guard_home=Path('/runtime/guard'), home_dir=Path('/runtime/home'),
 settings_path=Path('/runtime/agent/settings.json'), harness='omp', display_name='Oh My Pi'),end='')
"""
_EVENTS = """
import json,sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
store=GuardStore(Path(sys.argv[1]),prime_policy_integrity=False,allow_system_keyring=False)
print(json.dumps(store.list_events(limit=1000)))
"""


def prepare_installed_guard(*, python: Path, expected_source_sha: str, home: Path,
                            guard_home: Path, public: Path, agent_dir: Path) -> dict:
    identity = inspect_installed_guard(python, expected_sha=expected_source_sha, home=home)
    if not python.is_absolute() or python.name != "python" or python.parent.name != "bin":
        raise ValueError("installed Guard needs its lexical virtualenv Python path")
    guard_home.mkdir(mode=0o700)
    (guard_home / "config.toml").write_text('mode="enforce"\nsync=false\ntelemetry=false\n'
                                           'desktop_notifications=false\napproval_wait_timeout_seconds=1\n')
    (guard_home / "config.toml").chmod(0o600)
    os.chown(guard_home, 10001, 10001)
    os.chown(guard_home / "config.toml", 10001, 10001)
    settings = agent_dir / "settings.json"
    settings.write_text("{}\n")
    settings.chmod(0o600)
    os.chown(settings, 10001, 10001)
    generated = subprocess.run([str(python), "-I", "-c", _GENERATE], cwd=home,
                               env={"PATH": str(python.parent) + ":/usr/bin:/bin", "HOME": "/runtime/home"},
                               capture_output=True, timeout=20, check=False)
    if generated.returncode != 0:
        raise ValueError("installed product generation failed: " + generated.stderr.decode(errors="replace")[:4096])
    if len(generated.stdout) > 1024 * 1024 or not generated.stdout:
        raise ValueError("installed product returned invalid generated extension")
    extension = public / "hol-guard.ts"
    extension.write_bytes(generated.stdout)
    extension.chmod(0o644)
    return {"installed": identity, "extension_sha256": hashlib.sha256(generated.stdout).hexdigest(),
            "python": str(python), "prefix": str(python.parent.parent),
            "guard_home": str(guard_home), "source_sha": expected_source_sha,
            "attachment": "unmodified-product-managed-extension-harness-omp",
            "inbound_prevention": "unsupported-in-this-installed-baseline"}


def collect_product_events(*, identity: dict, home: Path) -> list[dict]:
    collected = subprocess.run([identity["python"], "-I", "-c", _EVENTS, identity["guard_home"]],
                               cwd=home, env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
                               capture_output=True, timeout=20, check=False)
    if collected.returncode != 0:
        raise ValueError("public product event API failed: " + collected.stderr.decode(errors="replace")[:4096])
    if len(collected.stdout) > 8 * 1024 * 1024:
        raise ValueError("public product events exceed pilot evidence budget")
    events = json.loads(collected.stdout)
    if not isinstance(events, list):
        raise ValueError("product event API did not return events")
    return events
