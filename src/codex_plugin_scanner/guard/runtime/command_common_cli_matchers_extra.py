"""Focused release/3.2 matchers for remaining common-CLI edge cases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import final

from .command_common_cli_support import _node_bundle, _path_bundle
from .command_extension_matchers import executable_names
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import AnyMatcher

_HELP_FLAGS = frozenset({"--help", "-h"})
_SQL_MUTATION = re.compile(r"(?:^|;)\s*(?:alter|delete|drop|truncate|update)\b", re.IGNORECASE)


def _basename(value: str | None) -> str:
    if value is None:
        return ""
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _has_any(arguments: tuple[str, ...], values: frozenset[str]) -> bool:
    return any(argument.lower().split("=", 1)[0] in values for argument in arguments)


def _option_value(arguments: tuple[str, ...], long_name: str, short_name: str) -> tuple[str, ...]:
    values: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        lowered = argument.lower()
        if lowered in {long_name, short_name} and index + 1 < len(arguments):
            values.append(arguments[index + 1])
            index += 2
            continue
        if lowered.startswith(f"{long_name}="):
            values.append(argument.split("=", 1)[1])
        elif lowered.startswith(short_name) and lowered != short_name:
            value = argument[len(short_name) :]
            if value.startswith("="):
                value = value[1:]
            if value:
                values.append(value)
        index += 1
    return tuple(values)


@final
@dataclass(frozen=True, slots=True)
class AnsibleExecutionMatcher:
    """Match actual Ansible execution while excluding documented read-only modes."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        executables = {
            **{name: "ansible" for name in executable_names("ansible")},
            **{name: "ansible-playbook" for name in executable_names("ansible-playbook")},
            **{name: "ansible-pull" for name in executable_names("ansible-pull")},
        }
        for index, segment in enumerate(command.segments):
            kind = executables.get(_basename(segment.executable))
            if kind is None or not segment.arguments:
                continue
            lowered = tuple(argument.lower() for argument in segment.arguments)
            if _has_any(lowered, frozenset({"--help", "-h", "--version"})):
                continue
            if kind == "ansible" and _has_any(lowered, frozenset({"--list-hosts"})):
                continue
            if kind == "ansible-playbook" and _has_any(
                lowered,
                frozenset({"--syntax-check", "--list-hosts", "--list-tasks", "--list-tags"}),
            ):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched Ansible execution after excluding read-only modes.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class SqlOptionMutationMatcher:
    """Match destructive SQL passed only through a documented one-shot SQL option."""

    executable: str
    long_option: str
    short_option: str

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        executables = executable_names(self.executable)
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in executables or _has_any(segment.arguments, _HELP_FLAGS):
                continue
            for value in _option_value(segment.arguments, self.long_option, self.short_option):
                if _SQL_MUTATION.search(value.strip()):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched destructive SQL in a documented one-shot option value.",
                        )
                    )
                    break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class DotnetPositionalProjectPackageMatcher:
    """Match `dotnet add <PROJECT> package <PACKAGE>` without guessing project paths."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        executables = executable_names("dotnet")
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in executables or _has_any(segment.arguments, _HELP_FLAGS):
                continue
            lowered = tuple(argument.lower() for argument in segment.arguments)
            for position in range(max(0, len(lowered) - 3)):
                if lowered[position] != "add" or lowered[position + 2] != "package":
                    continue
                project = lowered[position + 1]
                package = lowered[position + 3]
                if project.startswith("-") or package.startswith("-"):
                    continue
                evidence.append(
                    MatcherEvidence(
                        segment_index=index,
                        executable=segment.executable,
                        detail="Matched positional-project .NET package addition.",
                    )
                )
                break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class MongoEvalMutationMatcher:
    """Match destructive mongosh programs supplied through --eval/-e only."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        executables = executable_names("mongosh")
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in executables or _has_any(segment.arguments, _HELP_FLAGS):
                continue
            for value in _option_value(segment.arguments, "--eval", "-e"):
                compact = "".join(value.lower().split())
                if any(
                    marker in compact
                    for marker in (
                        "dropdatabase(",
                        "dropuser(",
                        ".drop(",
                        ".deleteone(",
                        ".deletemany(",
                        ".remove(",
                    )
                ):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched destructive MongoDB operation in --eval payload.",
                        )
                    )
                    break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class SqliteMutationMatcher:
    """Match destructive SQLite positional SQL and restore/import commands."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        executables = executable_names("sqlite3")
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in executables or _has_any(segment.arguments, _HELP_FLAGS):
                continue
            for argument in segment.arguments:
                stripped = argument.strip()
                lowered = " ".join(stripped.lower().split())
                if _SQL_MUTATION.search(stripped) or lowered.startswith((".restore ", ".import ")):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched destructive SQLite positional statement.",
                        )
                    )
                    break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class OpenShiftDeleteDrainMatcher:
    """Match oc delete/drain while preserving bounded delete dry-runs."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        executables = executable_names("oc")
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in executables or _has_any(segment.arguments, _HELP_FLAGS):
                continue
            lowered = tuple(argument.lower() for argument in segment.arguments)
            operands = tuple(argument for argument in lowered if not argument.startswith("-"))
            delete = bool(operands and operands[0] == "delete")
            drain = len(operands) >= 2 and operands[:2] == ("adm", "drain")
            if not delete and not drain:
                continue
            if delete:
                dry_values = _option_value(segment.arguments, "--dry-run", "--dry-run")
                if dry_values and dry_values[-1].lower() in {"client", "server"}:
                    continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched OpenShift destructive operation with bounded dry-run handling.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class OpenShiftMutationMatcher:
    """Match common oc mutations while preserving documented client/server dry-runs."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        executables = executable_names("oc")
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in executables or _has_any(segment.arguments, _HELP_FLAGS):
                continue
            lowered = tuple(argument.lower() for argument in segment.arguments)
            operands = tuple(argument for argument in lowered if not argument.startswith("-"))
            path = operands[:2]
            mutating = bool(operands and operands[0] in {"apply", "patch", "scale"}) or path == ("rollout", "restart")
            if not mutating:
                continue
            dry_values = _option_value(segment.arguments, "--dry-run", "--dry-run")
            if dry_values and dry_values[-1].lower() in {"client", "server"}:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched OpenShift mutation with bounded dry-run handling.",
                )
            )
        return tuple(evidence)


# Wrapper aliases that differ from package names.
_RAILWAY_ALIAS_DESTRUCTIVE = _node_bundle(
    "railway",
    ("railway",),
    (("delete",), ("volume", "delete")),
    options=frozenset({"--project", "--service", "--environment", "-e"}),
    flags=frozenset({"--help", "-h", "--yes", "-y"}),
)
_RAILWAY_ALIAS_CHANGE = _node_bundle(
    "railway",
    ("railway",),
    (("up",), ("redeploy",), ("restart",), ("down",), ("variables", "set"), ("variables", "delete"), ("shell",)),
    options=frozenset({"--project", "--service", "--environment", "-e"}),
    flags=frozenset({"--help", "-h", "--yes", "-y"}),
)
_CDK_ALIAS_DESTROY = _node_bundle("cdk", ("cdk",), (("destroy",),))
_SLS_ALIAS_REMOVE = _node_bundle("sls", ("sls",), (("remove",),))

_PACKAGE_PUBLICATION_GAPS = AnyMatcher(
    matchers=(
        *_path_bundle(("yarn",), (("publish",),)).matchers,
        *_path_bundle(("pnpm",), (("unpublish",),)).matchers,
    )
)
_ALT_CONTAINER_RESOURCE_REMOVAL = _path_bundle(
    ("podman", "nerdctl"),
    (("rm",), ("container", "rm"), ("image", "rm"), ("volume", "rm"), ("network", "rm")),
)
_ALT_CONTAINER_EXECUTION = _path_bundle(("podman", "nerdctl"), (("run",), ("exec",)))
_FIREBASE_SECRET_CHANGE = _node_bundle(
    "firebase",
    ("firebase", "firebase-tools"),
    (("functions:secrets:set",), ("functions:secrets:destroy",)),
    options=frozenset({"--project", "-P", "--config", "--token", "--account"}),
    flags=frozenset({"--help", "-h", "--non-interactive"}),
)
_FLY_ADDITIONAL_DESTRUCTIVE = _path_bundle(
    ("fly", "flyctl"),
    (("machines", "destroy"), ("volume", "destroy")),
    options=frozenset({"--app", "-a", "--config", "-c", "--org"}),
    flags=frozenset({"--help", "-h", "--verbose"}),
)
_FLY_ADDITIONAL_CHANGE = _path_bundle(
    ("fly", "flyctl"),
    (("releases", "rollback"), ("machine", "restart"), ("machines", "restart")),
    options=frozenset({"--app", "-a", "--config", "-c", "--org"}),
    flags=frozenset({"--help", "-h", "--verbose"}),
)
_GITLAB_CI_VARIABLE = _path_bundle(
    ("glab",),
    (("ci", "variable", "get"), ("ci", "variable", "set"), ("ci", "variable", "delete")),
    options=frozenset({"--repo", "-R", "--hostname"}),
    flags=frozenset({"--help", "-h"}),
)
_ARGO_ADDITIONAL_RECONCILE = _path_bundle(
    ("argocd",),
    (("app", "set"), ("app", "actions", "run")),
    options=frozenset({"--server", "--grpc-web-root-path", "--config", "--auth-token", "--context"}),
    flags=frozenset({"--help", "-h", "--grpc-web", "--insecure", "--plaintext"}),
)
_VAULT_ADDITIONAL_MUTATION = _path_bundle(
    ("vault",),
    (("kv", "undelete"), ("policy", "write")),
    options=frozenset({"-address", "-namespace", "-output-format"}),
    flags=frozenset({"-h", "--help"}),
)

ANSIBLE_EXECUTION_REFINED = AnyMatcher(matchers=(AnsibleExecutionMatcher(),))
OC_DESTRUCTIVE_REFINED = AnyMatcher(matchers=(OpenShiftDeleteDrainMatcher(),))
OPENSHIFT_MUTATION = AnyMatcher(matchers=(OpenShiftMutationMatcher(),))
DOTNET_POSITIONAL_PACKAGE = AnyMatcher(matchers=(DotnetPositionalProjectPackageMatcher(),))
PSQL_MUTATION = AnyMatcher(matchers=(SqlOptionMutationMatcher("psql", "--command", "-c"),))
MYSQL_MUTATION = AnyMatcher(matchers=(SqlOptionMutationMatcher("mysql", "--execute", "-e"),))
MONGOSH_MUTATION = AnyMatcher(matchers=(MongoEvalMutationMatcher(),))
SQLITE_MUTATION = AnyMatcher(matchers=(SqliteMutationMatcher(),))
IAC_RUNNER_GAPS = AnyMatcher(matchers=(*_CDK_ALIAS_DESTROY.matchers, *_SLS_ALIAS_REMOVE.matchers))
