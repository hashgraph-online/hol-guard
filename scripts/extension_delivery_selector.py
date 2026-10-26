"""Advance an advisory release pointer with Git's fast-forward compare-and-swap."""

from __future__ import annotations

import base64
import json
import re

from extension_delivery_github import pace_write
from extension_delivery_objects import encoded
from publish_extension_snapshot import REPOSITORY, github

from codex_plugin_scanner.guard.catalog_delivery.selection import BRANCH, FILE, SHA, validate


def current():
    try:
        ref = json.loads(github("api", f"repos/{REPOSITORY}/git/ref/heads/{BRANCH}"))
    except RuntimeError as error:
        if "HTTP 404" in str(error):
            return None, None
        raise
    obj = ref.get("object", {})
    if obj.get("type") != "commit" or not isinstance(obj.get("sha"), str) or SHA.fullmatch(obj["sha"]) is None:
        raise ValueError("delivery pointer is not a commit")
    data = json.loads(github("api", f"repos/{REPOSITORY}/contents/{FILE}?ref={obj['sha']}"))
    if (
        data.get("encoding") != "base64"
        or type(data.get("size")) is not int
        or not 0 < data["size"] <= 4096
        or not isinstance(data.get("content"), str)
        or len(data["content"]) > 8192
    ):
        raise ValueError("delivery pointer content exceeds bounds")
    raw = base64.b64decode(re.sub(r"\s", "", data["content"]), validate=True)
    if len(raw) != data["size"]:
        raise ValueError("delivery pointer content length differs")
    return obj["sha"], validate(json.loads(raw))


def can_advance(previous, candidate):
    if previous is None:
        return True
    if previous["source_sha"] != candidate["source_sha"]:
        comparison = json.loads(
            github("api", f"repos/{REPOSITORY}/compare/{previous['source_sha']}...{candidate['source_sha']}")
        )
        if comparison.get("status") == "behind":
            return False
        if comparison.get("status") != "ahead":
            raise ValueError("delivery selector source ancestry is invalid")
    old = tuple(map(int, previous["publication_id"].split(".")))
    new = tuple(map(int, candidate["publication_id"].split(".")))
    if new == old:
        if previous != candidate:
            raise ValueError("delivery publication identity was reused with different content")
        return False
    return new > old


def pointer_commit(parent, candidate):
    # Only fixed public metadata is committed on this delivery branch. Policy
    # authority still requires the independently authenticated release root.
    pace_write()
    tree = json.loads(
        github(
            "api",
            f"repos/{REPOSITORY}/git/trees",
            "--method",
            "POST",
            "--input",
            "-",
            input_data=encoded(
                {
                    "tree": [{"path": FILE, "mode": "100644", "type": "blob", "content": encoded(candidate).decode()}],
                }
            ),
        )
    )
    tree_sha = tree.get("sha")
    if not isinstance(tree_sha, str) or SHA.fullmatch(tree_sha) is None:
        raise ValueError("delivery pointer tree identity invalid")
    payload = {
        "message": "chore: select verified extension data",
        "tree": tree_sha,
        "parents": [parent] if parent else [],
        "author": {"name": "github-actions[bot]", "email": "41898282+github-actions[bot]@users.noreply.github.com"},
        "committer": {"name": "github-actions[bot]", "email": "41898282+github-actions[bot]@users.noreply.github.com"},
    }
    pace_write()
    value = json.loads(
        github(
            "api", f"repos/{REPOSITORY}/git/commits", "--method", "POST", "--input", "-", input_data=encoded(payload)
        )
    )
    commit = value.get("sha")
    if not isinstance(commit, str) or SHA.fullmatch(commit) is None:
        raise ValueError("delivery pointer commit identity invalid")
    return commit


def select(candidate):
    validate(candidate)
    for _ in range(3):
        parent, previous = current()
        if not can_advance(previous, candidate):
            return previous == candidate
        commit = pointer_commit(parent, candidate)
        try:
            pace_write()
            if parent is None:
                result = json.loads(
                    github(
                        "api",
                        f"repos/{REPOSITORY}/git/refs",
                        "--method",
                        "POST",
                        "-f",
                        "ref=refs/heads/" + BRANCH,
                        "-f",
                        "sha=" + commit,
                    )
                )
            else:
                result = json.loads(
                    github(
                        "api",
                        f"repos/{REPOSITORY}/git/refs/heads/{BRANCH}",
                        "--method",
                        "PATCH",
                        "-f",
                        "sha=" + commit,
                        "-F",
                        "force=false",
                    )
                )
        except RuntimeError as error:
            message = str(error)
            expected = "reference already exists" if parent is None else "not a fast forward"
            if "HTTP 422" not in message or expected not in message.lower():
                raise
            continue
        if result.get("object", {}).get("sha") != commit:
            raise ValueError("delivery pointer update was not confirmed")
        return True
    raise ValueError("delivery pointer changed repeatedly; retry publication")
