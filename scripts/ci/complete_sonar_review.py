"""Validate reviewed changes and source-pinned dispositions without updating refs."""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

OUT = Path("sonar-final-review")
PROJECT = "hashgraph-online_hol-guard"
MANIFEST = Path("docs/guard/security/sonar-reviewed-contracts.json")
REPORT = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
FILES = [
    "src/codex_plugin_scanner/guard/cloud_audit_request.py",
    "src/codex_plugin_scanner/guard/local_supply_chain.py",
    "tests/test_cloud_workspace_audit_destination.py",
    "tests/test_sonar_reviewed_contracts.py",
]


def run(*args: str) -> None:
    result = subprocess.run(args, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, flush=True)
    with (OUT / "validation.log").open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(args) + "\n" + result.stdout)
    if result.returncode:
        raise SystemExit(result.returncode)


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError("reviewed base changed: " + str(path))
    path.write_text(text.replace(old, new), encoding="utf-8")


def prepare() -> None:
    path = Path("src/codex_plugin_scanner/guard/local_supply_chain.py")
    replace_once(path, "from .config import GuardConfig, resolve_risk_action\n",
                 "from .cloud_audit_request import build_cloud_workspace_audit_request\n"
                 "from .config import GuardConfig, resolve_risk_action\n")
    old = '''    request_headers = runner._guard_sync_headers(auth_context, request_url=request_url, method=method)
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        request_url,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers=request_headers,
        method=method,
    )
'''
    new = '''    request = build_cloud_workspace_audit_request(
        auth_context=auth_context, request_url=request_url, method=method,
        payload=payload, build_headers=runner._guard_sync_headers,
    )
'''
    replace_once(path, old, new)


def validate() -> None:
    run("uv", "run", "--no-sync", "ruff", "format", *FILES)
    run("uv", "run", "--no-sync", "ruff", "check", *FILES)
    before = json.loads(Path(REPORT).read_text())
    run("uv", "run", "--no-sync", "python", "tests/guard_command_decision_diff.py", "--write")
    after = json.loads(Path(REPORT).read_text())
    if {k: v for k, v in before.items() if k != "bindings"} != {k: v for k, v in after.items() if k != "bindings"}:
        raise RuntimeError("decision corpus outcomes changed")
    run("uv", "run", "--no-sync", "pytest", "-q", "--tb=short",
        "tests/test_cloud_workspace_audit_destination.py", "tests/test_sonar_reviewed_contracts.py",
        "tests/test_guard_local_supply_chain_audit_phase16.py", "tests/test_guard_local_supply_chain_phase15.py",
        "tests/test_guard_js_semver_phase11.py", "tests/test_guard_js_semver_policy_phase11.py",
        "tests/test_guard_action_lattice.py", "tests/test_windows_process_termination_results.py",
        "tests/test_guard_command_decision_diff.py", "tests/test_codex_daemon_hook_bridge.py",
        "tests/test_codex_daemon_hook_bridge_resilience.py")
    run("uv", "run", "--no-sync", "basedpyright", "--level", "error")
    run("uv", "run", "--no-sync", "python", "scripts/ci/code_quality_audit.py", "--baseline", "ci/code-quality-baseline.json")
    run("git", "diff", "--check")
    changed = subprocess.check_output(["git", "diff", "--name-only"], text=True).splitlines()
    if not set(changed) <= set(FILES + [REPORT]):
        raise RuntimeError("unexpected source mutation")
    manifest = {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "files": FILES + [REPORT]}
    for name in manifest["files"]:
        path = OUT / "files" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(Path(name).read_bytes())
    (OUT / "validated.json").write_text(json.dumps(manifest), encoding="utf-8")


def read_bytes(request: Request) -> bytes:
    with urlopen(request, timeout=30) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise RuntimeError("API response exceeded limit")
    return data


def sonar(path: str, *, post: bool = False, raw: bool = False, **parameters: object):
    encoded = urlencode(parameters).encode()
    url = "https://sonarcloud.io" + path
    headers = {"Authorization": "Bearer " + os.environ["SONAR_TOKEN"]}
    if post:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        url += "?" + encoded.decode()
    body = read_bytes(Request(url, data=encoded if post else None, headers=headers, method="POST" if post else "GET"))
    return body if raw else json.loads(body)


def source_node(text: str, qualified_name: str) -> ast.AST:
    node = ast.parse(text)
    if qualified_name != "<module>":
        for name in qualified_name.split("."):
            node = next(item for item in node.body if isinstance(item, (ast.ClassDef, ast.FunctionDef)) and item.name == name)
    return node


def review() -> None:
    if not (OUT / "validated.json").is_file():
        raise RuntimeError("regression validation is required before dispositions")
    manifest = json.loads(MANIFEST.read_text())
    findings = manifest["findings"]
    ids = [entry[0] for entry in findings]
    before = sonar("/api/issues/search", issues=",".join(ids), componentKeys=PROJECT, ps=100)
    (OUT / "issues-before.json").write_text(json.dumps(before, indent=2))
    issues = {item["key"]: item for item in before["issues"]}
    if set(issues) != set(ids):
        raise RuntimeError("reviewed issue set differs from Sonar")
    branch = sonar("/api/project_branches/list", project=PROJECT)
    (OUT / "analyzed-branches.json").write_text(json.dumps(branch, indent=2))
    source_root = manifest["source_root"]
    pin = manifest["reviewed_main"]
    files = sorted({source_root + entry[2] for entry in findings})

    def load(path: str):
        analyzed = sonar("/api/sources/raw", raw=True, key=PROJECT + ":" + path).decode("utf-8")
        reviewed = read_bytes(Request("https://raw.githubusercontent.com/hashgraph-online/hol-guard/" + pin + "/" + path)).decode("utf-8")
        for label, text in (("analyzed", analyzed), ("reviewed", reviewed)):
            destination = OUT / label / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
        return path, (reviewed, analyzed)

    with ThreadPoolExecutor(max_workers=5) as pool:
        sources = dict(pool.map(load, files))
    verified = []
    for key, group, relative, qualified in findings:
        path = source_root + relative
        rule = manifest["groups"][group]["rule"]
        issue = issues[key]
        if issue["component"] != PROJECT + ":" + path or issue["rule"] != rule:
            raise RuntimeError("reviewed issue identity changed: " + key)
        original, current = (source_node(text, qualified) for text in sources[path])
        original_ast = ast.dump(original, include_attributes=False)
        if original_ast != ast.dump(current, include_attributes=False):
            raise RuntimeError("reviewed function changed: " + path + "::" + qualified)
        if qualified != "<module>" and not current.lineno <= issue.get("line", current.lineno) <= current.end_lineno:
            raise RuntimeError("issue moved outside its reviewed function: " + key)
        if group == "variadic" and not any(isinstance(node, ast.Constant) and node.value is Ellipsis for node in ast.walk(original.returns)):
            raise RuntimeError("reviewed tuple is not explicitly variadic")
        verified.append({"key": key, "rule": rule, "path": path, "symbol": qualified,
                         "ast_sha256": hashlib.sha256(original_ast.encode()).hexdigest(),
                         "reason": manifest["groups"][group]["reason"]})
    (OUT / "verified-review.json").write_text(json.dumps(verified, indent=2))
    if sonar("/api/project_branches/list", project=PROJECT) != branch:
        raise RuntimeError("Sonar analysis changed during source verification")
    results = []
    for entry in verified:
        key = entry["key"]
        issue = issues[key]
        if issue.get("resolution") in {"FALSE-POSITIVE", "FIXED"} or issue.get("issueStatus") in {"FALSE_POSITIVE", "FIXED"}:
            results.append({"key": key, "already_resolved": True})
        else:
            comment = ("Reviewed " + entry["path"] + "::" + entry["symbol"] + " against " + pin + ". "
                       + entry["reason"] + " The analyzed AST matches the reviewed function. "
                       "Regression evidence and the per-finding review are retained in PR #2778. No rule or quality threshold is disabled.")
            if not any(item.get("markdown") == comment for item in issue.get("comments", [])):
                sonar("/api/issues/add_comment", post=True, issue=key, text=comment)
            result = sonar("/api/issues/do_transition", post=True, issue=key, transition="falsepositive")
            results.append({"key": key, "result": result})
        (OUT / "dispositions.json").write_text(json.dumps(results, indent=2))
        print("Reviewed", key, entry["rule"], entry["symbol"], flush=True)
    after = sonar("/api/issues/search", componentKeys=PROJECT, resolved="false", ps=100)
    (OUT / "remaining-main-issues.json").write_text(json.dumps(after, indent=2))
    print("Remaining main findings", after["total"])


def export() -> None:
    manifest = json.loads((OUT / "validated.json").read_text())
    entries = []
    for name in manifest["files"]:
        data = (OUT / "files" / name).read_bytes()
        digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        request = Request("https://api.github.com/repos/hashgraph-online/hol-guard/git/blobs",
            data=json.dumps({"encoding": "base64", "content": base64.b64encode(data).decode()}).encode(),
            headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"], "Content-Type": "application/json"}, method="POST")
        result = json.loads(read_bytes(request))
        if result["sha"] != digest:
            raise RuntimeError("created blob differs from validated bytes")
        entries.append({"path": name, "mode": "100644", "type": "blob", "sha": digest, "sha256": hashlib.sha256(data).hexdigest()})
    manifest["entries"] = entries
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    {"prepare": prepare, "validate": validate, "review": review, "export": export}[sys.argv[1]]()
