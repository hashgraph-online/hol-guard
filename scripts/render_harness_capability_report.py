#!/usr/bin/env python3
"""Render the versioned harness capability report from contract authority."""

from __future__ import annotations

import argparse

from codex_plugin_scanner.guard.adapters.capability_report import (
    build_capability_report,
    render_capability_report_json,
    render_capability_report_markdown,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--build", dest="build_id", default="unknown")
    parser.add_argument("--commit", default="unknown")
    parser.add_argument("--host", dest="requested_host", default=None)
    parser.add_argument("--host-version-scope", default=None)
    parser.add_argument("--os-arch", default=None)
    parser.add_argument("--local-hosted", choices=("local", "hosted", "unknown"), default=None)
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = build_capability_report(
        build_id=args.build_id,
        commit=args.commit,
        requested_host=args.requested_host,
        host_version_scope=args.host_version_scope,
        os_arch=args.os_arch,
        local_hosted=args.local_hosted,
    )
    if args.format == "json":
        print(render_capability_report_json(report), end="")
    else:
        print(render_capability_report_markdown(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
