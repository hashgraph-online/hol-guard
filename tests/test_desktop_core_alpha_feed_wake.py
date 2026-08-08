"""Contract for the privileged Desktop Core alpha-feed wake workflow."""

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
    assert set(events) == {"workflow_run", "release", "issues", "push", "pull_request"}
    assert events["workflow_run"] == {"workflows": ["Publish to PyPI"], "types": ["completed"]}
    assert events["release"] == {"types": ["published"]}
    assert events["issues"] == {"types": ["opened"]}
    assert events["push"] == {"branches": ["main"], "paths": [workflow_path]}
    assert events["pull_request"] == {"paths": [workflow_path]}
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
        "(github.event_name == 'release' && startsWith(github.event.release.tag_name, 'alpha/v3.')) || "
        "(github.event_name == 'workflow_run' && github.event.workflow_run.conclusion == 'success' && "
        "github.event.workflow_run.event == 'push' && "
        "startsWith(github.event.workflow_run.head_branch, 'release/3.'))"
    )
    dispatch_steps = [step for step in wake["steps"] if step.get("name") == "Dispatch feed producer"]
    assert len(dispatch_steps) == 1
    dispatch = dispatch_steps[0]
    assert dispatch["env"] == {"GH_TOKEN": "${{ github.token }}", "REPOSITORY": "${{ github.repository }}"}
    parsed_values = json.dumps(value)
    assert not re.search(r"\$\{\{\s*secrets\.", parsed_values)
    assert "id-token: write" not in parsed_values
    assert "pypa/gh-action-pypi-publish" not in parsed_values

    run = dispatch["run"]
    python_source = run.split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(python_source)
    requests = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Request"
    ]
    assert len(requests) == 1
    request = requests[0]
    assert len(request.args) == 1 and isinstance(request.args[0], ast.JoinedStr)
    url_parts = request.args[0].values
    assert len(url_parts) == 3
    assert isinstance(url_parts[0], ast.Constant) and url_parts[0].value == "https://api.github.com/repos/"
    assert isinstance(url_parts[1], ast.FormattedValue)
    assert ast.unparse(url_parts[1].value) == "os.environ['REPOSITORY']"
    assert isinstance(url_parts[2], ast.Constant)
    assert url_parts[2].value == "/actions/workflows/desktop-core-alpha-feed.yml/dispatches"
    keywords = {item.arg: item.value for item in request.keywords if item.arg is not None}
    assert isinstance(keywords["method"], ast.Constant) and keywords["method"].value == "POST"
    data = keywords["data"]
    assert isinstance(data, ast.Call) and isinstance(data.func, ast.Attribute) and data.func.attr == "encode"
    dumps = data.func.value
    assert isinstance(dumps, ast.Call)
    assert isinstance(dumps.func, ast.Attribute)
    assert ast.unparse(dumps.func) == "json.dumps"
    payload = dumps.args[0]
    assert isinstance(payload, ast.Dict)
    payload_items = [
        (ast.literal_eval(key), ast.literal_eval(item)) for key, item in zip(payload.keys, payload.values, strict=True)
    ]
    assert payload_items == [("ref", "main")]

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
