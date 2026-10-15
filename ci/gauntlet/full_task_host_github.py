"""The trusted host's GitHub access for full tasks: seed, verify and retire run-owned repositories.

This code runs only on the host, outside every container. The token it holds is read from the
operator's own `gh` login into process memory and handed to children only through their
environment. It is never printed, logged, written to evidence or placed on a command line.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.github.com"
RETIRED_PREFIX = "guard-ft-retired-"


class GitHubError(RuntimeError):
    """A GitHub call failed; the message carries the operation and status, never a credential."""


def acquire_token(owner: str) -> str:
    """The operator's token for ``owner``, straight from `gh`; the parent's own token variables are ignored."""
    environment = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
    result = subprocess.run(
        ["gh", "auth", "token", "--hostname", "github.com", "--user", owner],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    token = result.stdout.strip()
    if result.returncode != 0 or not token:
        raise GitHubError("gh could not provide a token for the configured owner")
    return token


class HostGitHub:
    """A small REST client for exactly the operations the orchestrator needs."""

    def __init__(self, owner: str, token: str) -> None:
        self.owner = owner
        self._token = token

    def child_environment(self, name: str) -> dict[str, str]:
        """Environment for one child process that must carry the token (for example the gateway container)."""
        return {**os.environ, name: self._token}

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(API + path, data=data, method=method)
        request.add_header("Authorization", "Bearer " + self._token)
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("User-Agent", "hol-guard-gauntlet-host")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = response.read()
                return response.status, json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                return exc.code, json.loads(body) if body else None
            except ValueError:
                return exc.code, None

    def login(self) -> str:
        status, data = self.request("GET", "/user")
        if status != 200 or not isinstance(data, dict):
            raise GitHubError(f"GET /user failed with status {status}")
        return str(data.get("login"))

    def create_private_repo(self, name: str, description: str) -> str:
        """A private seed repository; returns its node id and refuses anything that is not private."""
        status, data = self.request("POST", "/user/repos", {"name": name, "private": True, "description": description})
        if status != 201 or not isinstance(data, dict) or data.get("private") is not True:
            raise GitHubError(f"private repository creation failed with status {status}")
        return str(data["node_id"])

    def repo(self, name: str) -> dict[str, Any] | None:
        status, data = self.request("GET", f"/repos/{self.owner}/{name}")
        return data if status == 200 and isinstance(data, dict) else None

    def pulls(self, name: str) -> list[dict[str, Any]]:
        status, data = self.request("GET", f"/repos/{self.owner}/{name}/pulls?state=all&per_page=100")
        if status != 200 or not isinstance(data, list):
            raise GitHubError(f"listing pull requests failed with status {status}")
        return [row for row in data if isinstance(row, dict)]

    def mirror(self, name: str, destination: Path) -> Path:
        """A bare mirror clone of a run-owned repository; authentication travels in the child's environment only."""
        pair = base64.b64encode(f"x-access-token:{self._token}".encode()).decode()
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(destination.parent),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": "Authorization: Basic " + pair,
        }
        result = subprocess.run(
            ["git", "clone", "--mirror", "--quiet", f"https://github.com/{self.owner}/{name}.git", str(destination)],
            capture_output=True,
            timeout=300,
            env=environment,
        )
        if result.returncode != 0:
            raise GitHubError(f"mirror clone of {name} failed")
        return destination

    def retire(self, name: str, run_id: str) -> dict[str, Any]:
        """Free the name for the next run: rename to a retired name and archive.

        Tokens here carry no ``delete_repo`` scope and the operator is never asked for one.
        """
        stem = name.removeprefix(f"guard-ft-{run_id}-")
        retired = f"{RETIRED_PREFIX}{run_id}-{stem}"[:100]
        result: dict[str, Any] = {"repository": name, "retired_as": retired, "renamed": False, "archived": False}
        status, data = self.request("PATCH", f"/repos/{self.owner}/{name}", {"name": retired})
        result["renamed"] = status == 200
        result["private"] = bool(data.get("private")) if status == 200 and isinstance(data, dict) else None
        target = retired if result["renamed"] else name
        status, _ = self.request("PATCH", f"/repos/{self.owner}/{target}", {"archived": True})
        result["archived"] = status == 200
        result["ok"] = result["renamed"] and result["archived"]
        return result

    def created_since(self, since_iso: str, known: set[str]) -> list[str]:
        """Repositories created after ``since_iso`` that the gateway never recorded (a policy-gap backstop)."""
        status, data = self.request("GET", "/user/repos?sort=created&direction=desc&per_page=30&affiliation=owner")
        if status != 200 or not isinstance(data, list):
            raise GitHubError(f"listing recent repositories failed with status {status}")
        return [
            row["name"]
            for row in data
            if isinstance(row, dict)
            and str(row.get("created_at", "")) >= since_iso
            and str(row.get("name", "")).lower() not in known
        ]
