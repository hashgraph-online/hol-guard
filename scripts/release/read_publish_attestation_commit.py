#!/usr/bin/env python3
"""Print the main commit attested by a publish-workflow provenance bundle."""

from __future__ import annotations

import base64
import json
import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: read_publish_attestation_commit.py BUNDLE EXPECTED_REF", file=sys.stderr)
        return 2
    bundle_path, expected_ref = args
    document = json.loads(open(bundle_path, encoding="utf-8").readline())
    payload = json.loads(base64.b64decode(document["dsseEnvelope"]["payload"]))
    build = payload["predicate"]["buildDefinition"]
    workflow = build["externalParameters"]["workflow"]
    digest = build["resolvedDependencies"][0]["digest"]["gitCommit"]
    if workflow.get("path") != ".github/workflows/publish.yml":
        raise SystemExit("provenance workflow is not the publish workflow")
    if workflow.get("ref") != expected_ref:
        raise SystemExit("provenance ref is not the release branch")
    if (
        not isinstance(digest, str)
        or len(digest) != 40
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise SystemExit("provenance commit is not a commit sha")
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
