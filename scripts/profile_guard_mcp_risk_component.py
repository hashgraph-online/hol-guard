#!/usr/bin/env python3
"""Bounded cProfile witness for the 128 KiB MCP classification hotspot.

Set PYTHONPATH to the desired source checkout and run under the shared timing
lock. This is an isolated algorithm diagnostic, not proxy qualification.
"""

import argparse
import cProfile
import io
import json
import pstats

from codex_plugin_scanner.guard import mcp_tool_calls as calls


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-bytes", type=int, default=131072)
    parser.add_argument("--payload-kind", choices=("ascii", "unicode"), default="ascii")
    parser.add_argument("--iterations", type=int, default=20)
    options = parser.parse_args()
    if not 1 <= options.payload_bytes <= 4 * 1024 * 1024 - 512 or not 1 <= options.iterations <= 100:
        parser.error("payload must fit the near-frame fixture and iterations must be 1..100")
    artifact = calls.build_tool_call_artifact(
        harness="codex",
        server_name="synthetic",
        tool_name="echo_0",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        tool_schema={"type": "object", "properties": {"text": {"type": "string"}}},
        tool_description="Echo text version 0",
    )
    payload = (
        "€" * (options.payload_bytes // 3) + "x" * (options.payload_bytes % 3)
        if options.payload_kind == "unicode"
        else "x" * options.payload_bytes
    )
    arguments = {"text": payload, "sample": 1}
    profile = cProfile.Profile()
    profile.enable()
    for _ in range(options.iterations):
        assert calls.tool_call_risk_categories(artifact, arguments) == ()
    profile.disable()
    output = io.StringIO()
    pstats.Stats(profile, stream=output).strip_dirs().sort_stats("cumulative").print_stats(30)
    print(json.dumps({"fixture": vars(options), "qualification": False, "expected_categories": []}))
    print(output.getvalue())


if __name__ == "__main__":
    main()
