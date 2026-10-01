"""Contract for the privileged Desktop Core stable-feed wake workflow."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "wake-desktop-core-alpha-feed.yml"


def test_desktop_core_feed_wake_is_narrow_and_least_privilege() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    value = yaml.safe_load(text)
    events = value[True]
    workflow_path = ".github/workflows/wake-desktop-core-alpha-feed.yml"
    script_path = "scripts/release/wake_desktop_core_feeds.py"
    test_path = "tests/test_wake_desktop_core_feeds.py"
    assert set(events) == {"workflow_run", "issues", "push", "pull_request"}
    assert events["workflow_run"] == {"workflows": ["Publish to PyPI"], "types": ["completed"]}
    assert events["issues"] == {"types": ["opened"]}
    assert events["push"] == {
        "branches": ["main"],
        "paths": [workflow_path, "scripts/release/wake_desktop_core_feeds.py"],
    }
    assert events["pull_request"] == {
        "paths": [
            workflow_path,
            script_path,
            test_path,
        ]
    }
    assert value["permissions"] == {"contents": "read"}
    assert set(value["jobs"]) == {"wake"}
    wake = value["jobs"]["wake"]
    assert wake["permissions"] == {"actions": "write", "contents": "read"}
    actions_write_jobs = [
        name for name, job in value["jobs"].items() if job.get("permissions", {}).get("actions") == "write"
    ]
    assert actions_write_jobs == ["wake"]
    condition = " ".join(wake["if"].split())
    assert condition == (
        "github.event_name == 'push' || "
        "(github.event_name == 'issues' && "
        "(github.event.issue.author_association == 'OWNER' || "
        "github.event.issue.author_association == 'MEMBER' || "
        "github.event.issue.author_association == 'COLLABORATOR') && "
        "startsWith(github.event.issue.title, '[desktop-core-feed]')) || "
        "(github.event_name == 'workflow_run' && github.event.workflow_run.conclusion == 'success' && "
        "(github.event.workflow_run.event == 'push' || github.event.workflow_run.event == 'workflow_dispatch') && "
        "((github.event.workflow_run.event == 'workflow_dispatch' && "
        "github.event.workflow_run.head_branch == 'main') || "
        "startsWith(github.event.workflow_run.head_branch, 'v3.')))"
    )
    dispatch_steps = [step for step in wake["steps"] if step.get("name") == "Dispatch feed producer"]
    assert len(dispatch_steps) == 1
    dispatch = dispatch_steps[0]
    assert dispatch["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "REPOSITORY": "${{ github.repository }}",
        "PUBLICATION_CHECKSUMS": ".publication/distribution-sha256-native.txt",
    }
    download = next(step for step in wake["steps"] if step.get("name") == "Download completed publication checksums")
    assert download["with"]["run-id"] == "${{ github.event.workflow_run.id }}"
    assert download["with"]["name"] == "distribution-sha256-native"
    checkout = wake["steps"][0]
    assert checkout["with"] == {"ref": "${{ github.sha }}", "persist-credentials": False}
    parsed_values = json.dumps(value)
    assert not re.search(r"\$\{\{\s*secrets\.", parsed_values)
    assert "id-token: write" not in parsed_values
    assert "pypa/gh-action-pypi-publish" not in parsed_values

    assert dispatch["run"] == f"python3 {script_path}"
    python_source = (WORKFLOW.parents[2] / script_path).read_text(encoding="utf-8")
    tree = ast.parse(python_source)
    requests = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Request"
    ]
    requests = [
        node
        for node in requests
        if any(
            item.arg == "method" and isinstance(item.value, ast.Constant) and item.value.value == "POST"
            for item in node.keywords
        )
    ]
    assert len(requests) == 1
    request = requests[0]
    assert len(request.args) == 1 and isinstance(request.args[0], ast.JoinedStr)
    url_parts = request.args[0].values
    assert len(url_parts) == 5
    assert isinstance(url_parts[0], ast.Constant) and url_parts[0].value == "https://api.github.com/repos/"
    assert isinstance(url_parts[1], ast.FormattedValue)
    assert ast.unparse(url_parts[1].value) == "repository"
    assert isinstance(url_parts[2], ast.Constant)
    assert url_parts[2].value == "/actions/workflows/"
    assert ast.unparse(url_parts[3].value) == "workflow"
    assert url_parts[4].value == "/dispatches"
    assert 'repository != "hashgraph-online/hol-guard"' in python_source
    assert 'WORKFLOWS = ("desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml")' in python_source
    keywords = {item.arg: item.value for item in request.keywords if item.arg is not None}
    assert isinstance(keywords["method"], ast.Constant) and keywords["method"].value == "POST"
    data = keywords["data"]
    assert isinstance(data, ast.Call) and isinstance(data.func, ast.Attribute) and data.func.attr == "encode"
    dumps = data.func.value
    assert isinstance(dumps, ast.Call)
    assert isinstance(dumps.func, ast.Attribute)
    assert ast.unparse(dumps.func) == "json.dumps"
    assert ast.unparse(dumps.args[0]) == "payload"

    redirect_classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "NoRedirect"
        and any(ast.unparse(base) == "urllib.request.HTTPRedirectHandler" for base in node.bases)
    ]
    assert len(redirect_classes) == 1
    redirect_method = next(
        node
        for node in redirect_classes[0].body
        if isinstance(node, ast.FunctionDef) and node.name == "redirect_request"
    )
    assert any(isinstance(node, ast.Raise) and "HTTPError" in ast.unparse(node) for node in ast.walk(redirect_method))
    assert "urllib.request.build_opener(NoRedirect())" in python_source
    assert "urllib.request.urlopen" not in python_source
