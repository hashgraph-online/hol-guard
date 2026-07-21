"""Guard-owned context and review-thread provenance for GitHub workflow tasks."""

# pyright: reportAny=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnusedCallResult=false

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final, cast

from ..workflow_capabilities import WorkflowCapabilityRuleBinding, canonical_framed_payload
from .command_model import parse_shell_command
from .github_workflow_authorization import GitHubWorkflowBindingContext, github_repository_sha256
from .github_workflow_operations import (
    GitHubWorkflowOperation,
    GitHubWorkflowOperationKind,
    parse_github_workflow_operation,
)

GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA: Final = "guard.github-workflow-descriptor.v1"
_OUTPUT_LIMIT: Final = 64 * 1024
_WORKSPACE_FILE_LIMIT: Final = 8 * 1024 * 1024
_TIMEOUT_SECONDS: Final = 5.0
_GRAPHQL_QUERY: Final = (
    "query($threadId:ID!){viewer{login}node(id:$threadId){__typename id "
    "... on PullRequestReviewThread{pullRequest{number repository{nameWithOwner}}}}}"
)
_HTTPS_REMOTE = re.compile(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
_SSH_REMOTE = re.compile(r"(?:ssh://git@github\.com/|git@github\.com:)([^/]+)/([^/]+?)(?:\.git)?$")


@dataclass(frozen=True, slots=True)
class GitHubWorkflowDescriptor:
    schema_version: str
    operation: GitHubWorkflowOperation
    binding_context: GitHubWorkflowBindingContext
    viewer_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "operation": asdict(self.operation),
            "binding_context": asdict(self.binding_context),
            "viewer_sha256": self.viewer_sha256,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GitHubWorkflowDescriptor:
        if set(payload) != {"schema_version", "operation", "binding_context", "viewer_sha256"}:
            raise ValueError("invalid GitHub workflow descriptor shape")
        operation_payload = payload["operation"]
        context_payload = payload["binding_context"]
        if not isinstance(operation_payload, Mapping) or not isinstance(context_payload, Mapping):
            raise ValueError("invalid GitHub workflow descriptor payload")
        rules_payload = context_payload.get("rules")
        if not isinstance(rules_payload, (list, tuple)) or len(rules_payload) != 1:
            raise ValueError("invalid GitHub workflow descriptor rules")
        rule_payload = rules_payload[0]
        if not isinstance(rule_payload, Mapping):
            raise ValueError("invalid GitHub workflow descriptor rule")
        rule = WorkflowCapabilityRuleBinding(
            rule_id=_required_string(rule_payload, "rule_id"),
            rule_version=_required_string(rule_payload, "rule_version"),
        )
        descriptor = cls(
            schema_version=_required_string(payload, "schema_version"),
            operation=GitHubWorkflowOperation(
                kind=cast(GitHubWorkflowOperationKind, _required_string(operation_payload, "kind")),
                resource_type=_required_string(operation_payload, "resource_type"),
                resource_id=_required_string(operation_payload, "resource_id"),
                repository=_required_string(operation_payload, "repository"),
                command_identity=_required_string(operation_payload, "command_identity"),
                operation_digest=_required_string(operation_payload, "operation_digest"),
            ),
            binding_context=GitHubWorkflowBindingContext(
                repository_sha256=_required_string(context_payload, "repository_sha256"),
                workspace_sha256=_required_string(context_payload, "workspace_sha256"),
                executable_sha256=_required_string(context_payload, "executable_sha256"),
                cwd_sha256=_required_string(context_payload, "cwd_sha256"),
                environment_sha256=_required_string(context_payload, "environment_sha256"),
                configuration_sha256=_required_string(context_payload, "configuration_sha256"),
                manifest_sha256=_required_string(context_payload, "manifest_sha256"),
                lockfile_sha256=_required_string(context_payload, "lockfile_sha256"),
                sandbox_sha256=_required_string(context_payload, "sandbox_sha256"),
                policy_id=_required_string(context_payload, "policy_id"),
                policy_version=_required_string(context_payload, "policy_version"),
                effect_id=_required_string(context_payload, "effect_id"),
                effect_version=_required_string(context_payload, "effect_version"),
                decision_id=_required_string(context_payload, "decision_id"),
                decision_version=_required_string(context_payload, "decision_version"),
                rules=(rule,),
            ),
            viewer_sha256=_required_string(payload, "viewer_sha256"),
        )
        if descriptor.schema_version != GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA or len(descriptor.viewer_sha256) != 64:
            raise ValueError("invalid GitHub workflow descriptor version")
        if descriptor.binding_context.repository_sha256 != github_repository_sha256(descriptor.operation.repository):
            raise ValueError("invalid GitHub workflow descriptor repository")
        return descriptor


def build_github_workflow_descriptor(
    command_text: str,
    *,
    workspace: Path | None,
    config_path: str,
    configuration: Mapping[str, object],
    sandbox: Mapping[str, object],
    environment: Mapping[str, str] | None = None,
) -> GitHubWorkflowDescriptor | None:
    """Build an exact descriptor using only current Guard-owned process state."""

    if workspace is None:
        return None
    try:
        root = workspace.resolve(strict=True)
        env = dict(os.environ if environment is None else environment)
        gh_path = _resolve_executable("gh", env)
        repository = _workspace_repository(root, env)
        command = parse_shell_command(command_text, cwd=root, home_dir=Path.home())
        operation = parse_github_workflow_operation(
            command,
            repository=repository,
            expected_executable=str(gh_path),
        )
        viewer = ""
        candidate = operation or parse_github_workflow_operation(
            command,
            repository="guard/locator",
            expected_executable=str(gh_path),
        )
        if candidate is not None and candidate.resource_type == "github-review-thread":
            located_repository, viewer = _locate_review_thread(
                gh_path, candidate.resource_id, expected_repository=repository, env=env, cwd=root
            )
            operation = parse_github_workflow_operation(
                command,
                repository=located_repository,
                expected_executable=str(gh_path),
            )
        else:
            if operation is None:
                return None
            viewer = _github_viewer(gh_path, env=env, cwd=root)
        if operation is None or operation.repository != repository or not viewer:
            return None
        viewer_sha256 = _digest("github-viewer", viewer.casefold())
        context = GitHubWorkflowBindingContext(
            repository_sha256=github_repository_sha256(repository),
            workspace_sha256=_digest("github-workspace", str(root)),
            executable_sha256=_file_sha256(gh_path),
            cwd_sha256=_digest("github-cwd", str(root)),
            environment_sha256=_digest(
                "github-environment",
                {
                    "environment": {key: env[key] for key in sorted(env)},
                    "viewer_sha256": viewer_sha256,
                },
            ),
            configuration_sha256=_digest(
                "github-configuration",
                {"config_path": config_path, "effective": configuration},
            ),
            manifest_sha256=_workspace_files_sha256(root, ("pyproject.toml", "package.json")),
            lockfile_sha256=_workspace_files_sha256(root, ("uv.lock", "bun.lock", "bun.lockb")),
            sandbox_sha256=_digest("github-sandbox", sandbox),
            policy_id="guard.command-policy",
            policy_version="policy.v1",
            effect_id="github.maintain-remote",
            effect_version="effect.v1",
            decision_id="github.workflow-authorized",
            decision_version="decision.v1",
            rules=(WorkflowCapabilityRuleBinding("github.maintain-remote", "rule.v1"),),
        )
        return GitHubWorkflowDescriptor(GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA, operation, context, viewer_sha256)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _workspace_repository(workspace: Path, env: Mapping[str, str]) -> str:
    git_path = _resolve_executable("git", env)
    raw = _run_bounded(
        (str(git_path), "-C", str(workspace), "config", "--get", "remote.origin.url"),
        cwd=workspace,
        env=env,
    )
    remote = raw.decode("utf-8", errors="strict").strip()
    match = _HTTPS_REMOTE.fullmatch(remote) or _SSH_REMOTE.fullmatch(remote)
    if match is None:
        raise ValueError("GitHub workspace remote is not github.com")
    return f"{match.group(1)}/{match.group(2)}".casefold()


def _github_viewer(gh_path: Path, *, env: Mapping[str, str], cwd: Path) -> str:
    payload = _load_unique_json(_run_bounded((str(gh_path), "api", "user"), cwd=cwd, env=env))
    if not isinstance(payload, dict) or set(payload) < {"login"}:
        raise ValueError("invalid GitHub viewer response")
    return _required_string(payload, "login")


def _locate_review_thread(
    gh_path: Path, thread_id: str, *, expected_repository: str, env: Mapping[str, str], cwd: Path
) -> tuple[str, str]:
    raw = _run_bounded(
        (str(gh_path), "api", "graphql", "-f", f"query={_GRAPHQL_QUERY}", "-f", f"threadId={thread_id}"),
        cwd=cwd,
        env=env,
    )
    payload = _load_unique_json(raw)
    if not isinstance(payload, dict) or set(payload) != {"data"} or not isinstance(payload["data"], dict):
        raise ValueError("invalid review-thread locator response")
    data = payload["data"]
    if set(data) != {"node", "viewer"} or not isinstance(data["node"], dict) or not isinstance(data["viewer"], dict):
        raise ValueError("invalid review-thread locator data")
    node = data["node"]
    viewer = data["viewer"]
    if set(node) != {"__typename", "id", "pullRequest"} or node.get("__typename") != "PullRequestReviewThread":
        raise ValueError("review-thread locator returned wrong node type")
    if node.get("id") != thread_id or not isinstance(node["pullRequest"], dict):
        raise ValueError("review-thread locator returned wrong node")
    pull_request = node["pullRequest"]
    if set(pull_request) != {"number", "repository"} or not isinstance(pull_request.get("number"), int):
        raise ValueError("review-thread locator returned wrong pull request")
    repository_payload = pull_request["repository"]
    if not isinstance(repository_payload, dict) or set(repository_payload) != {"nameWithOwner"}:
        raise ValueError("review-thread locator returned wrong repository")
    repository = _required_string(repository_payload, "nameWithOwner").casefold()
    if repository != expected_repository:
        raise ValueError("review-thread repository does not match workspace")
    return repository, _required_string(viewer, "login")


def _run_bounded(arguments: tuple[str, ...], *, cwd: Path, env: Mapping[str, str]) -> bytes:
    allowed_environment = ("GH_CONFIG_DIR", "GH_HOST", "GH_TOKEN", "GITHUB_TOKEN", "HOME", "PATH")
    safe_env = {key: env[key] for key in allowed_environment if key in env}
    process = subprocess.Popen(
        arguments,
        cwd=cwd,
        env=safe_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    assert process.stdout is not None
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=1) as executor:
        read = executor.submit(process.stdout.read, _OUTPUT_LIMIT + 1)
        try:
            output = read.result(timeout=_TIMEOUT_SECONDS)
            remaining = max(0.01, _TIMEOUT_SECONDS - (time.monotonic() - started))
            return_code = process.wait(timeout=remaining)
        except (FutureTimeoutError, subprocess.TimeoutExpired):
            process.kill()
            process.wait()
            _ = read.result(timeout=1)
            raise subprocess.TimeoutExpired(arguments, _TIMEOUT_SECONDS) from None
        except BaseException:
            process.kill()
            process.wait()
            raise
    if return_code != 0 or len(output) > _OUTPUT_LIMIT:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise subprocess.SubprocessError("bounded GitHub locator failed")
    return output


def _resolve_executable(name: str, env: Mapping[str, str]) -> Path:
    resolved = shutil.which(name, path=env.get("PATH"))
    if resolved is None:
        raise OSError(f"{name} executable unavailable")
    path = Path(resolved)
    canonical = path.resolve(strict=True)
    if not path.is_absolute() or path != canonical or not path.is_file() or not os.access(path, os.X_OK):
        raise OSError(f"{name} executable invalid")
    return path


def _load_unique_json(raw: bytes) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _workspace_files_sha256(workspace: Path, names: tuple[str, ...]) -> str:
    entries: list[dict[str, str]] = []
    for name in names:
        path = workspace / name
        try:
            initial = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > _WORKSPACE_FILE_LIMIT:
            raise ValueError(f"invalid GitHub workflow binding file: {name}")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
                or opened.st_size > _WORKSPACE_FILE_LIMIT
            ):
                raise ValueError(f"unstable GitHub workflow binding file: {name}")
            content = stream.read(_WORKSPACE_FILE_LIMIT + 1)
            final = os.fstat(stream.fileno())
        named = path.lstat()
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        final_identity = (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns)
        named_identity = (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns, named.st_ctime_ns)
        if (
            len(content) > _WORKSPACE_FILE_LIMIT
            or final_identity != opened_identity
            or named_identity != final_identity
        ):
            raise ValueError(f"unstable GitHub workflow binding file: {name}")
        entries.append({"name": name, "sha256": hashlib.sha256(content).hexdigest()})
    return _digest("github-workspace-files", entries)


def _digest(purpose: str, payload: object) -> str:
    return hashlib.sha256(canonical_framed_payload(purpose, payload)).hexdigest()


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {key}")
    return value


__all__ = ("GITHUB_WORKFLOW_DESCRIPTOR_SCHEMA", "GitHubWorkflowDescriptor", "build_github_workflow_descriptor")
