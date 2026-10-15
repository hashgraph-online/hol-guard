"""Read complete claim-notice comment evidence in bounded GitHub query batches."""

from __future__ import annotations

import json
import sys
from typing import Any


def batched_pull_comments(client: Any, numbers: list[int]) -> dict[int, list[dict[str, Any]]]:
    if not callable(getattr(client, "_request", None)):
        return {}
    owner, repo = client.repo.split("/")
    comments: dict[int, list[dict[str, Any]]] = {}
    fields = """number comments(last:100) {
      pageInfo { hasPreviousPage }
      nodes { databaseId body author { __typename login ... on Bot { databaseId } ... on User { databaseId } } }
    }"""
    for offset in range(0, len(numbers), 20):
        batch = numbers[offset:offset + 20]
        pulls = " ".join(f"p{i}: pullRequest(number:{number}) {{ {fields} }}" for i, number in enumerate(batch))
        query = f"query {{ repository(owner:{json.dumps(owner)},name:{json.dumps(repo)}) {{ {pulls} }} }}"
        try:
            result = client._request("https://api.github.com/graphql", method="POST", payload={"query": query})
            if not isinstance(result, dict) or result.get("errors"):
                raise ValueError("Claim comment query is unavailable")
            repository = result.get("data", {}).get("repository")
            if not isinstance(repository, dict):
                raise ValueError("Claim comment repository is unavailable")
            for i, number in enumerate(batch):
                pull = repository.get(f"p{i}")
                if not isinstance(pull, dict) or pull.get("number") != number:
                    continue
                connection = pull.get("comments", {})
                rows = connection.get("nodes")
                # An older notice may be outside this page. The caller uses
                # the bounded paginated REST reader for incomplete evidence.
                if connection.get("pageInfo", {}).get("hasPreviousPage") is not False:
                    continue
                if not isinstance(rows, list) or len(rows) > 100:
                    continue
                comments[number] = [{
                    "id": row.get("databaseId"), "body": row.get("body"),
                    "user": {"id": (row.get("author") or {}).get("databaseId"),
                             "type": (row.get("author") or {}).get("__typename")},
                } for row in rows if isinstance(row, dict)]
        except Exception as error:
            print(f"Claim comment batch unavailable; rechecking PRs independently: {error}", file=sys.stderr)
    return comments
