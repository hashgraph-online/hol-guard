"""Apply one explicitly reviewed Sonar disposition only while its source pins match."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

PROJECT = "hashgraph-online_hol-guard"
ISSUE = "AaFVWubqjlIsfgWZxpG_"
BRANCH = "main"
RULE = "pythonsecurity:S8705"
COMPONENT = "src/codex_plugin_scanner/guard/adapters/claude_daemon_hook_bridge.py"
MANIFEST = Path("docs/guard/security/sonar-hook-bridge-argv-review.json")
OUTPUT = Path("sonar-hook-bridge-review")
MAX_BYTES = 2 * 1024 * 1024
REVIEWED_SOURCES = frozenset(
    {
        "src/codex_plugin_scanner/guard/adapters/claude_daemon_hook_bridge.py",
        "src/codex_plugin_scanner/guard/adapters/native_hook_bridge.py",
        "src/codex_plugin_scanner/guard/native_runtime_durable.py",
    }
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sonar(path: str, *, post: bool = False, **parameters: object):
    if path not in {
        "/api/issues/search",
        "/api/project_branches/list",
        "/api/issues/add_comment",
        "/api/issues/do_transition",
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
    return json.loads(body)


def fingerprint(source: str) -> str:
    return hashlib.sha256(source.replace("\r\n", "\n").rstrip().encode()).hexdigest()


def read_issue() -> dict:
    payload = sonar("/api/issues/search", componentKeys=PROJECT, issues=ISSUE, branch=BRANCH, ps=100)
    if payload.get("total") != 1 or len(payload.get("issues", [])) != 1:
        raise ValueError("reviewed issue is missing or ambiguous")
    issue = payload["issues"][0]
    if (
        issue.get("key") != ISSUE
        or issue.get("project") != PROJECT
        or issue.get("rule") != RULE
        or issue.get("component") != PROJECT + ":" + COMPONENT
        # A branch query must never answer with a pull-request finding; only the
        # reviewed long-lived branch analysis is in scope for this disposition.
        or issue.get("pullRequest") is not None
    ):
        raise ValueError("reviewed issue identity changed")
    return issue


def read_analysis() -> dict:
    payload = sonar("/api/project_branches/list", project=PROJECT)
    matches = [item for item in payload["branches"] if item.get("name") == BRANCH]
    if len(matches) != 1:
        raise ValueError("reviewed analysis is missing or ambiguous")
    analysis = matches[0]
    sha = analysis.get("commit", {}).get("sha")
    if (
        analysis.get("isMain") is not True
        or analysis.get("type") != "LONG"
        or not isinstance(sha, str)
        or re.fullmatch(r"[0-9a-f]{40}", sha) is None
        or not analysis.get("analysisDate")
    ):
        raise ValueError("reviewed analysis identity is invalid")
    return {"sha": sha, "date": analysis["analysisDate"]}


def analyzed_source(sha: str, path: str) -> str:
    """Read the immutable SCM revision reported by Sonar, without sending its token."""
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None or path not in REVIEWED_SOURCES:
        raise ValueError("unapproved analyzed source")
    request = Request("https://raw.githubusercontent.com/hashgraph-online/hol-guard/" + sha + "/" + path)
    with build_opener(NoRedirect()).open(request, timeout=30) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("analyzed source exceeded limit")
    return body.decode("utf-8")


def verify_sources(manifest: dict, analysis: dict) -> None:
    if set(manifest["source_sha256"]) != REVIEWED_SOURCES:
        raise ValueError("reviewed source set changed")
    for path, expected in manifest["source_sha256"].items():
        if not path.startswith("src/codex_plugin_scanner/") or ".." in Path(path).parts:
            raise ValueError("invalid reviewed source path")
        local = Path(path).read_text(encoding="utf-8")
        analyzed = analyzed_source(analysis["sha"], path)
        if fingerprint(local) != expected or fingerprint(analyzed) != expected:
            raise ValueError("reviewed or analyzed source changed: " + path)


def main(*, apply: bool = False) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if (manifest["project"], manifest["issue"], manifest["branch"], manifest["rule"], manifest["component"]) != (
        PROJECT,
        ISSUE,
        BRANCH,
        RULE,
        COMPONENT,
    ):
        raise ValueError("review manifest identity changed")
    OUTPUT.mkdir(exist_ok=True)
    analysis = read_analysis()
    issue = read_issue()
    (OUTPUT / "before.json").write_text(json.dumps(issue, indent=2), encoding="utf-8")
    verify_sources(manifest, analysis)
    if read_analysis() != analysis:
        raise ValueError("Sonar analyzed revision changed during verification")
    # Re-read after all source checks so a concurrent analysis cannot silently change the finding.
    current = read_issue()
    if (current.get("hash"), current.get("lastChangeAnalysisUuid")) != (
        issue.get("hash"),
        issue.get("lastChangeAnalysisUuid"),
    ):
        raise ValueError("Sonar finding changed during verification")
    if current.get("resolution") in {"FALSE-POSITIVE", "FIXED"} or current.get("issueStatus") in {
        "FALSE_POSITIVE",
        "FIXED",
    }:
        print("The source-pinned hook-bridge finding is already resolved.")
    elif apply:
        comment = "Reviewed at " + manifest["reviewed_commit"] + ". " + manifest["reason"]
        sonar("/api/issues/add_comment", post=True, issue=ISSUE, text=comment)
        sonar("/api/issues/do_transition", post=True, issue=ISSUE, transition="falsepositive")
        current = read_issue()
        if current.get("resolution") != "FALSE-POSITIVE" and current.get("issueStatus") != "FALSE_POSITIVE":
            raise ValueError("Sonar did not confirm the requested disposition")
    (OUTPUT / "analysis.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    (OUTPUT / "after.json").write_text(json.dumps(current, indent=2), encoding="utf-8")
    (OUTPUT / "review.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("Verified one reviewed hook-bridge argv finding; apply=" + str(apply))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    main(apply=parser.parse_args().apply)
