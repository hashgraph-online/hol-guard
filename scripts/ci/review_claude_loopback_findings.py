"""Apply three individually reviewed local-IPC dispositions after source verification."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

PROJECT = "hashgraph-online_hol-guard"
COMPONENT = PROJECT + ":src/codex_plugin_scanner/guard/adapters/claude_daemon_hook_transport.py"
SOURCE_BLOB = "82b08a68987e9e4c586aee6b5674bf9a0ace945e"
FINDINGS = {
    "AaBurY7LOEl4G0YgTSvh": "python:S5332",
    "AaBurY7LOEl4G0YgTSvi": "python:S5332",
    "AaBurY7LOEl4G0YgTSvj": "pythonsecurity:S5144",
}
COMMENT = (
    "Reviewed against 5baa16260049dffe518e5d0409d218d942ac61b1. This is local daemon IPC, not an external HTTP endpoint. "
    "_authenticated_state verifies the owner-only signed discovery record, restricts the host to exact loopback names, "
    "and validates the port. The client verifies a fresh nonce-bound daemon proof and unchanged generation before "
    "sending hook data on the same connection. HTTPConnection does not follow redirects. No reusable bearer token "
    "is sent by the Claude bridge. Existing Claude bridge and path-authority regression suites pass. "
    "The reported remote-destination/cleartext-network exposure does not exist on this authenticated local-only path."
)
OUT = Path("sonar-loopback-review")


def call(path: str, *, post: bool = False, raw: bool = False, **parameters: object):
    encoded = urlencode(parameters).encode()
    url = "https://sonarcloud.io" + path
    headers = {"Authorization": "Bearer " + os.environ["SONAR_TOKEN"]}
    if post:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        url += "?" + encoded.decode()
    request = Request(url, data=encoded if post else None, headers=headers, method="POST" if post else "GET")
    try:
        with urlopen(request, timeout=30) as response:
            body = response.read(2 * 1024 * 1024 + 1)
    except HTTPError as error:
        print("Sonar API rejected", path, error.code, error.read(4096).decode(errors="replace"))
        raise
    if len(body) > 2 * 1024 * 1024:
        raise ValueError("Sonar response exceeded limit")
    return body if raw else json.loads(body)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    source = call("/api/sources/raw", raw=True, key=COMPONENT, pullRequest=2771)
    actual = hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest()
    if actual != SOURCE_BLOB:
        raise RuntimeError("analyzed source differs from the reviewed source: " + actual)
    findings = call("/api/issues/search", issues=",".join(FINDINGS), componentKeys=PROJECT, pullRequest=2771, ps=100)
    (OUT / "before.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    by_key = {item["key"]: item for item in findings["issues"]}
    if set(by_key) != set(FINDINGS):
        raise RuntimeError("reviewed issue set changed; no dispositions applied")
    for key, rule in FINDINGS.items():
        issue = by_key[key]
        if issue["component"] != COMPONENT or issue["rule"] != rule:
            raise RuntimeError("reviewed issue identity changed")
    results = []
    for key in FINDINGS:
        issue = by_key[key]
        if issue.get("resolution") in {"FALSE-POSITIVE", "FIXED"} or issue.get("issueStatus") in {"FALSE_POSITIVE", "FIXED"}:
            results.append({"key": key, "already_resolved": True})
            continue
        comments = issue.get("comments", [])
        if not any(item.get("markdown") == COMMENT for item in comments):
            call("/api/issues/add_comment", post=True, issue=key, text=COMMENT)
        result = call("/api/issues/do_transition", post=True, issue=key, transition="falsepositive")
        results.append({"key": key, "result": result})
        print("Reviewed local-only IPC finding:", key)
    (OUT / "dispositions.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    gate = call("/api/qualitygates/project_status", projectKey=PROJECT, pullRequest=2771)
    (OUT / "gate.json").write_text(json.dumps(gate, indent=2), encoding="utf-8")
    print(json.dumps(gate))


if __name__ == "__main__":
    main()
