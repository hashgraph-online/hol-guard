"""Apply one explicitly reviewed Sonar disposition only while its source pins match."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

PROJECT = "hashgraph-online_hol-guard"
ISSUE = "AaBvKDhNMjkgZ7apuESm"
PULL_REQUEST = 2778
MANIFEST = Path("docs/guard/security/sonar-audit-origin-review.json")
OUTPUT = Path("sonar-audit-review")
MAX_BYTES = 2 * 1024 * 1024
REVIEWED_SOURCES = frozenset(
    {
        "src/codex_plugin_scanner/guard/local_supply_chain.py",
        "src/codex_plugin_scanner/guard/cloud_audit_request.py",
        "src/codex_plugin_scanner/guard/cli/oauth_client.py",
        "src/codex_plugin_scanner/guard/mdm/network_transport.py",
        "src/codex_plugin_scanner/no_redirect.py",
    }
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sonar(path: str, *, post: bool = False, raw: bool = False, **parameters: object):
    if path not in {
        "/api/issues/search", "/api/sources/raw", "/api/issues/add_comment", "/api/issues/do_transition",
    }:
        raise ValueError("unapproved Sonar endpoint")
    encoded = urlencode(parameters).encode()
    headers = {"Authorization": "Bearer " + os.environ["SONAR_TOKEN"]}
    url = "https://sonarcloud.io" + path
    if post:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        url += "?" + encoded.decode()
    request = Request(url, data=encoded if post else None, headers=headers, method="POST" if post else "GET")
    with build_opener(NoRedirect()).open(request, timeout=30) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("Sonar response exceeded limit")
    return body.decode("utf-8") if raw else json.loads(body)


def fingerprint(source: str) -> str:
    return hashlib.sha256(source.replace("\r\n", "\n").rstrip().encode()).hexdigest()


def read_issue() -> dict:
    payload = sonar(
        "/api/issues/search", componentKeys=PROJECT, issues=ISSUE, pullRequest=PULL_REQUEST, ps=100,
    )
    if payload.get("total") != 1 or len(payload.get("issues", [])) != 1:
        raise ValueError("reviewed issue is missing or ambiguous")
    issue = payload["issues"][0]
    if (
        issue.get("key") != ISSUE or issue.get("project") != PROJECT
        or issue.get("rule") != "pythonsecurity:S5144"
        or issue.get("component") != PROJECT + ":src/codex_plugin_scanner/guard/cloud_audit_request.py"
        or str(issue.get("pullRequest")) != str(PULL_REQUEST)
    ):
        raise ValueError("reviewed issue identity changed")
    return issue


def verify_sources(manifest: dict) -> None:
    if set(manifest["source_sha256"]) != REVIEWED_SOURCES:
        raise ValueError("reviewed source set changed")
    for path, expected in manifest["source_sha256"].items():
        if not path.startswith("src/codex_plugin_scanner/") or ".." in Path(path).parts:
            raise ValueError("invalid reviewed source path")
        local = Path(path).read_text(encoding="utf-8")
        analyzed = sonar("/api/sources/raw", raw=True, key=PROJECT + ":" + path, pullRequest=PULL_REQUEST)
        if fingerprint(local) != expected or fingerprint(analyzed) != expected:
            raise ValueError("reviewed or analyzed source changed: " + path)


def main(*, apply: bool = False) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if (manifest["project"], manifest["issue"], manifest["pull_request"]) != (PROJECT, ISSUE, PULL_REQUEST):
        raise ValueError("review manifest identity changed")
    OUTPUT.mkdir(exist_ok=True)
    issue = read_issue()
    (OUTPUT / "before.json").write_text(json.dumps(issue, indent=2), encoding="utf-8")
    verify_sources(manifest)
    # Re-read after all source checks so a concurrent analysis cannot silently change the finding.
    current = read_issue()
    if (current.get("hash"), current.get("lastChangeAnalysisUuid")) != (
        issue.get("hash"), issue.get("lastChangeAnalysisUuid"),
    ):
        raise ValueError("Sonar finding changed during verification")
    if current.get("resolution") in {"FALSE-POSITIVE", "FIXED"} or current.get("issueStatus") in {"FALSE_POSITIVE", "FIXED"}:
        print("The source-pinned audit finding is already resolved.")
    elif apply:
        comment = "Reviewed at " + manifest["reviewed_commit"] + ". " + manifest["reason"]
        sonar("/api/issues/add_comment", post=True, issue=ISSUE, text=comment)
        sonar("/api/issues/do_transition", post=True, issue=ISSUE, transition="falsepositive")
        current = read_issue()
        if current.get("resolution") != "FALSE-POSITIVE" and current.get("issueStatus") != "FALSE_POSITIVE":
            raise ValueError("Sonar did not confirm the requested disposition")
    (OUTPUT / "after.json").write_text(json.dumps(current, indent=2), encoding="utf-8")
    (OUTPUT / "review.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("Verified one reviewed audit-origin finding; apply=" + str(apply))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    main(apply=parser.parse_args().apply)
