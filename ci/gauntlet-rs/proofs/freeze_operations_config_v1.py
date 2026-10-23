"""Freeze Python operator-config merge and refusal cases without live state."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

from ci.gauntlet.control_plane import config


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/config.py"
SOURCE_SHA256 = "8b0777a6d89bcdc29d80981fd8542316a3dcced017b1e132907dd6fbf1e0476b"


def main() -> None:
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned Python operator configuration source changed")
    valid = [
        ("defaults", {}),
        ("other_stable_tags", {"release_tags": ["v3.50.0"], "poll_seconds": 30}),
        ("pr_artifacts", {"discovery_mode": "pull-requests", "release_build_backend": "github-actions"}),
        ("paired_dependency_and_adapter", {
            "staging_dependency_prefix": "/opt/hol-prefix", "staging_dependency_prefix_digest": "a" * 64,
            "prepare_argv": ["/usr/bin/python3", "--check"],
            "public_dashboard_url": "https://example.org/gauntlet",
        }),
    ]
    invalid = [
        ("unknown_key", {"unreviewed": True}),
        ("discovery_mode", {"discovery_mode": "all"}),
        ("release_backend", {"release_build_backend": "untrusted"}),
        ("tags_empty", {"release_tags": []}),
        ("tags_duplicate", {"release_tags": ["v3.48.0", "v3.48.0"]}),
        ("tags_prerelease", {"release_tags": ["v3.50.0-alpha"]}),
        ("tags_wrong_type", {"release_tags": "v3.48.0"}),
        ("tags_nonstring", {"release_tags": [42]}),
        ("schema", {"schema": "hol-gauntlet-operations.v2"}),
        ("base_branch", {"base_branch": "develop"}),
        ("repository", {"repository": "hgo/guard/other"}),
        ("vm", {"vm": "-unsafe"}),
        ("relative_git", {"git": "usr/bin/git"}),
        ("parent_git", {"git": "/usr/../bin/git"}),
        ("space_git", {"git": "/usr/my git"}),
        ("prefix_only", {"staging_dependency_prefix": "/opt/prefix"}),
        ("digest_only", {"staging_dependency_prefix_digest": "a" * 64}),
        ("prefix_relative", {"staging_dependency_prefix": "opt/prefix", "staging_dependency_prefix_digest": "a" * 64}),
        ("prefix_digest", {"staging_dependency_prefix": "/opt/prefix", "staging_dependency_prefix_digest": "A" * 64}),
        ("poll_zero", {"poll_seconds": 0}),
        ("vm_cpus_bool", {"vm_cpus": True}),
        ("build_memory_negative", {"build_memory_gib": -1}),
        ("disk_float", {"vm_disk_gib": 48.5}),
        ("memory_reserve", {"vm_memory_gib": 16, "build_memory_gib": 15}),
        ("poll_short", {"poll_seconds": 29}),
        ("telemetry_short", {"telemetry_seconds": 4}),
        ("argv_string", {"prepare_argv": "/usr/bin/python3"}),
        ("argv_empty_item", {"prepare_argv": ["/usr/bin/python3", ""]}),
        ("argv_relative", {"prepare_argv": ["python3"]}),
        ("artifact_workflow", {"artifact_workflow": "other.yml"}),
        ("template_digest", {"template_config_digest": "A" * 64}),
        ("http_url", {"public_dashboard_url": "http://example.org"}),
        ("numeric_url", {"public_dashboard_url": 42}),
    ]
    cases = []
    with tempfile.TemporaryDirectory(prefix="hol-operations-fixture-") as directory:
        path = Path(directory) / "config.json"
        for name, overrides in [*valid, *invalid]:
            path.write_text(json.dumps(overrides))
            try:
                result = config.load(path)
            except ValueError as error:
                cases.append({"name": name, "overrides": overrides, "accepted": False, "reason": str(error)})
            else:
                cases.append({"name": name, "overrides": overrides, "accepted": True, "value": result})
    print(json.dumps({
        "schema": "gauntlet-operations-config-fixtures.v1",
        "source_sha256": SOURCE_SHA256,
        "defaults": config.DEFAULTS,
        "cases": cases,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
