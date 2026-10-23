"""Freeze Python's exact tag lookup argv and parser with no network call."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from ci.gauntlet.control_plane import config, local_vm


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/local_vm.py"
SOURCE_SHA256 = "b7f4274c4656dba13ec7b3dcc71ad96a71b0cc4dd8fccca2218041fc3db3aa20"
A = "a" * 40
B = "b" * 40
REF = "refs/tags/v3.48.0"


def main() -> None:
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned Python local VM source changed")
    cases = [
        ("direct", "v3.48.0", f"{A}\t{REF}\n", {}),
        ("annotated", "v3.48.0", f"{A}\t{REF}\n{B}\t{REF}^{{}}\n", {}),
        ("peeled_first", "v3.48.0", f"{B}\t{REF}^{{}}\n{A}\t{REF}\n", {}),
        ("crlf", "v3.48.0", f"{A}\t{REF}\r\n", {}),
        ("quoted_helper", "v3.48.0", f"{A}\t{REF}\n", {"gh": "/opt/homebrew/odd'gh"}),
        ("unlisted_tag", "v3.50.0", f"{A}\trefs/tags/v3.50.0\n", {}),
        ("missing", "v3.48.0", "", {}),
        ("peeled_without_direct", "v3.48.0", f"{B}\t{REF}^{{}}\n", {}),
        ("duplicate_direct", "v3.48.0", f"{A}\t{REF}\n{B}\t{REF}\n", {}),
        ("unexpected_ref", "v3.48.0", f"{A}\trefs/tags/v3.49.0\n", {}),
        ("upper_sha", "v3.48.0", f"{'A' * 40}\t{REF}\n", {}),
        ("short_sha", "v3.48.0", f"{'a' * 39}\t{REF}\n", {}),
        ("extra_column", "v3.48.0", f"{A}\t{REF}\textra\n", {}),
        ("missing_tab", "v3.48.0", f"{A} {REF}\n", {}),
    ]
    rows = []
    for name, tag, stdout, overrides in cases:
        operations = dict(config.DEFAULTS) | overrides
        captured = []

        def fake_check_output(argv, **kwargs):
            captured.append({"argv": argv, "text": kwargs["text"], "timeout": kwargs["timeout"],
                             "git_terminal_prompt": kwargs["env"]["GIT_TERMINAL_PROMPT"]})
            return stdout

        with patch.object(local_vm.subprocess, "check_output", side_effect=fake_check_output):
            try:
                result = local_vm.resolve_release(operations, tag)
            except ValueError as error:
                reason = str(error)
                if reason == "explicit stable tag allowlist required":
                    refusal = "tag-not-allowed"
                elif reason == "exact release tag is missing":
                    refusal = "missing-tag"
                else:
                    refusal = "invalid-response"
                rows.append({"name": name, "tag": tag, "overrides": overrides,
                             "stdout": stdout, "accepted": False,
                             "reason": reason, "refusal": refusal, "calls": captured})
            else:
                rows.append({"name": name, "tag": tag, "overrides": overrides,
                             "stdout": stdout, "accepted": True,
                             "result": result, "calls": captured})
    print(json.dumps({
        "schema": "gauntlet-release-source-fixtures.v1",
        "source_sha256": SOURCE_SHA256,
        "cases": rows,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
