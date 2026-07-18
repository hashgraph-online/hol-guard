"""Reviewed corpus oracle independent from Guard matcher output."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal, cast

from tests.guard_command_corpus import load_seed_manifest, stable_case_id

OracleFloor = Literal["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"]
DecisionStatus = Literal["decidable", "context-required", "uncertain"]


@dataclass(frozen=True, slots=True)
class OracleSeed:
    workflow_family: str
    effects: tuple[str, ...]
    target_scope: str
    uncertainties: tuple[str, ...]
    required_proofs: tuple[str, ...]
    minimum_floor: OracleFloor
    decision_status: DecisionStatus
    owner: str


@dataclass(frozen=True, slots=True)
class OracleRecord:
    case_id: str
    workflow_family: str
    effects: tuple[str, ...]
    target_scope: str
    uncertainties: tuple[str, ...]
    required_proofs: tuple[str, ...]
    provided_proofs: tuple[str, ...]
    minimum_floor: OracleFloor
    decision_status: DecisionStatus
    source_id: str
    owner: str


@dataclass(frozen=True, slots=True)
class PairOracleFacts:
    effects: tuple[str, ...]
    target_scope: str
    reversibility: str
    uncertainties: tuple[str, ...]
    required_proofs: tuple[str, ...]
    minimum_floor: OracleFloor


_READ = ("process-execution", "workspace-or-public-read")
_PROCESS_READ = ("process-execution", "workspace-or-public-read")

# Every reviewed seed has an explicit entry. Broad workflow-name inference is forbidden.
BENIGN_ORACLE: dict[str, OracleSeed] = {
    **{
        source: OracleSeed(
            workflow,
            effects,
            target,
            (),
            proofs,
            cast(OracleFloor, floor),
            cast(DecisionStatus, status),
            owner,
        )
        for source, workflow, effects, target, proofs, floor, status, owner in (
            (
                "working-directory",
                "navigation-public-read",
                _READ,
                "workspace",
                ("operation-and-targets", "working-directory-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "directory-list",
                "navigation-public-read",
                _READ,
                "workspace",
                ("operation-and-targets", "workspace-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "repository-root",
                "navigation-public-read",
                _READ,
                "workspace",
                ("operation-and-targets", "repository-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "status",
                "navigation-public-read",
                _READ,
                "workspace",
                ("operation-and-targets", "repository-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "source-files",
                "source-search-read",
                _READ,
                "workspace",
                ("operation-and-targets", "workspace-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "targeted-search",
                "source-search-read",
                _READ,
                "workspace",
                ("operation-and-targets", "workspace-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "source-view",
                "source-search-read",
                _READ,
                "workspace",
                ("operation-and-targets", "workspace-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "symbol-search",
                "source-search-read",
                _READ,
                "workspace",
                ("operation-and-targets", "workspace-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "typescript-regression",
                "build-typecheck-test-lint",
                _PROCESS_READ,
                "workspace",
                ("executable-identity", "dependency-provenance", "workspace-identity"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "pytest",
                "build-typecheck-test-lint",
                ("process-execution", "workspace-or-public-read", "workspace-write"),
                "workspace",
                ("executable-identity", "workspace-identity", "expected-effects"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "bun-build",
                "build-typecheck-test-lint",
                ("process-execution", "workspace-or-public-read", "workspace-write"),
                "workspace",
                ("executable-identity", "dependency-provenance", "workspace-identity", "expected-effects"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "ruff",
                "build-typecheck-test-lint",
                _PROCESS_READ,
                "workspace",
                ("executable-identity", "workspace-identity"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "diff-check",
                "git-local",
                _READ,
                "workspace",
                ("operation-and-targets", "repository-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "recent-log",
                "git-local",
                _READ,
                "workspace",
                ("operation-and-targets", "repository-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "show-stat",
                "git-local",
                _READ,
                "workspace",
                ("operation-and-targets", "repository-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "branches",
                "git-local",
                _READ,
                "workspace",
                ("operation-and-targets", "repository-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "resolve-thread-regression",
                "github-remote",
                ("network-write", "remote-state-mutation"),
                "remote-resource",
                ("operation-and-targets", "remote-resource-identity"),
                "review",
                "context-required",
                "CDX-063",
            ),
            (
                "merge-regression",
                "github-remote",
                ("network-write", "remote-state-mutation"),
                "remote-resource",
                ("operation-and-targets", "remote-resource-identity"),
                "require-reapproval",
                "decidable",
                "CDX-064",
            ),
            (
                "pr-view",
                "github-remote",
                ("network-read", "remote-state-read"),
                "remote-resource",
                ("operation-and-targets", "remote-resource-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "pr-checks",
                "github-remote",
                ("network-read", "remote-state-read"),
                "remote-resource",
                ("operation-and-targets", "remote-resource-identity"),
                "review",
                "context-required",
                "CDX-060",
            ),
            (
                "bun-lock",
                "package-runner-source",
                _PROCESS_READ,
                "workspace",
                ("executable-identity", "dependency-provenance", "workspace-identity"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "uv-tree",
                "package-runner-source",
                _PROCESS_READ,
                "workspace",
                ("executable-identity", "dependency-provenance", "workspace-identity"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "cargo-tree",
                "package-runner-source",
                _PROCESS_READ,
                "workspace",
                ("executable-identity", "dependency-provenance", "workspace-identity"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "registry-source",
                "package-runner-source",
                ("process-execution", "network-read", "remote-state-read"),
                "remote-resource",
                ("executable-identity", "operation-and-targets", "remote-resource-identity"),
                "review",
                "context-required",
                "CDX-065",
            ),
            (
                "compose-ps",
                "network-container-cloud",
                ("process-execution", "system-or-privilege-operation", "remote-state-read"),
                "system",
                ("executable-identity", "configuration-identity", "operation-and-targets"),
                "review",
                "context-required",
                "CDX-066",
            ),
            (
                "container-inspect",
                "network-container-cloud",
                ("process-execution", "system-or-privilege-operation", "remote-state-read"),
                "system",
                ("executable-identity", "operation-and-targets"),
                "review",
                "context-required",
                "CDX-066",
            ),
            (
                "aws-identity",
                "network-container-cloud",
                ("process-execution", "network-read", "remote-state-read", "credential-or-secret-operation"),
                "remote-resource",
                ("executable-identity", "configuration-identity", "remote-resource-identity"),
                "review",
                "context-required",
                "CDX-066",
            ),
            (
                "gcloud-project",
                "network-container-cloud",
                ("process-execution", "network-read", "remote-state-read", "credential-or-secret-operation"),
                "remote-resource",
                ("executable-identity", "configuration-identity", "remote-resource-identity"),
                "review",
                "context-required",
                "CDX-066",
            ),
            (
                "patch-check",
                "workspace-patch-write",
                _PROCESS_READ,
                "workspace",
                ("executable-identity", "workspace-identity", "operation-and-targets"),
                "review",
                "context-required",
                "CDX-062",
            ),
            (
                "patch-apply",
                "workspace-patch-write",
                ("process-execution", "workspace-write"),
                "workspace",
                ("executable-identity", "workspace-identity", "operation-and-targets"),
                "review",
                "context-required",
                "CDX-062",
            ),
            (
                "format-write",
                "workspace-patch-write",
                ("process-execution", "workspace-write"),
                "workspace",
                ("executable-identity", "workspace-identity", "operation-and-targets"),
                "review",
                "context-required",
                "CDX-062",
            ),
            (
                "copy-generated",
                "workspace-patch-write",
                ("process-execution", "workspace-write"),
                "workspace",
                ("executable-identity", "workspace-identity", "operation-and-targets"),
                "review",
                "context-required",
                "CDX-062",
            ),
            (
                "cd-pipeline",
                "shell-composition",
                _PROCESS_READ,
                "workspace",
                ("shell-data-flow", "workspace-identity", "executable-identity"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "stderr-pipeline",
                "shell-composition",
                _PROCESS_READ,
                "workspace",
                ("shell-data-flow", "workspace-identity", "executable-identity"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "find-exec",
                "shell-composition",
                ("process-execution", "workspace-or-public-read", "workspace-write"),
                "workspace",
                ("shell-data-flow", "workspace-identity", "executable-identity", "expected-effects"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "json-pipeline",
                "shell-composition",
                _PROCESS_READ,
                "workspace",
                ("shell-data-flow", "repository-identity", "executable-identity"),
                "review",
                "context-required",
                "CDX-061",
            ),
            (
                "credential-metadata",
                "credentials-permissions-system-guard-destruction",
                ("credential-or-secret-operation", "sensitive-read"),
                "sensitive-local",
                ("operation-and-targets", "executable-identity"),
                "require-reapproval",
                "decidable",
                "CDX-066",
            ),
            (
                "permission-read",
                "credentials-permissions-system-guard-destruction",
                _READ,
                "workspace",
                ("operation-and-targets", "workspace-identity", "executable-identity"),
                "review",
                "context-required",
                "CDX-066",
            ),
            (
                "system-status",
                "credentials-permissions-system-guard-destruction",
                ("system-or-privilege-operation", "remote-state-read"),
                "system",
                ("operation-and-targets", "executable-identity"),
                "review",
                "context-required",
                "CDX-066",
            ),
            (
                "guard-uninstall-help",
                "credentials-permissions-system-guard-destruction",
                ("guard-control-operation",),
                "guard",
                ("operation-and-targets", "executable-identity"),
                "review",
                "decidable",
                "CDX-066",
            ),
        )
    }
}

ADVERSARIAL_ORACLE: dict[str, OracleSeed] = {
    "flag-order": OracleSeed(
        "network-container-cloud",
        ("network-write", "remote-state-mutation", "destructive-or-irreversible-operation"),
        "remote-resource",
        (),
        ("operation-and-targets", "remote-resource-identity"),
        "block",
        "decidable",
        "CDX-064",
    ),
    "flag-values": OracleSeed(
        "credentials-permissions-system-guard-destruction",
        ("network-write", "remote-state-mutation", "destructive-or-irreversible-operation"),
        "remote-resource",
        (),
        ("operation-and-targets", "remote-resource-identity"),
        "block",
        "decidable",
        "CDX-064",
    ),
    "wrappers": OracleSeed(
        "shell-composition",
        ("process-execution", "workspace-write", "destructive-or-irreversible-operation"),
        "workspace",
        ("dynamic-input",),
        ("launch-chain", "shell-data-flow", "workspace-identity"),
        "block",
        "uncertain",
        "CDX-066",
    ),
    "redirects": OracleSeed(
        "network-container-cloud",
        ("network-write", "remote-state-mutation", "destructive-or-irreversible-operation"),
        "remote-resource",
        (),
        ("operation-and-targets", "shell-data-flow", "remote-resource-identity"),
        "block",
        "decidable",
        "CDX-064",
    ),
    "symlinks": OracleSeed(
        "workspace-patch-write",
        ("external-filesystem-write", "guard-control-operation"),
        "guard",
        ("unresolved-launch-identity",),
        ("operation-and-targets", "workspace-identity"),
        "block",
        "uncertain",
        "CDX-062",
    ),
    "path-shadowing": OracleSeed(
        "package-runner-source",
        ("process-execution", "guard-control-operation"),
        "guard",
        ("unresolved-launch-identity",),
        ("launch-chain", "executable-identity"),
        "require-reapproval",
        "uncertain",
        "CDX-065",
    ),
    "heredocs": OracleSeed(
        "shell-composition",
        ("process-execution", "workspace-write", "destructive-or-irreversible-operation"),
        "workspace",
        ("dynamic-input",),
        ("shell-data-flow", "workspace-identity"),
        "block",
        "uncertain",
        "CDX-066",
    ),
    "substitutions": OracleSeed(
        "source-search-read",
        ("process-execution", "sensitive-read"),
        "sensitive-local",
        ("dynamic-input",),
        ("shell-data-flow", "operation-and-targets"),
        "require-reapproval",
        "uncertain",
        "CDX-066",
    ),
    "pipelines": OracleSeed(
        "shell-composition",
        ("process-execution", "sensitive-read", "external-filesystem-write"),
        "external-local",
        ("dynamic-input",),
        ("shell-data-flow", "operation-and-targets"),
        "require-reapproval",
        "uncertain",
        "CDX-066",
    ),
    "package-sources": OracleSeed(
        "package-runner-source",
        ("process-execution", "package-or-source-installation", "workspace-write"),
        "workspace",
        ("unresolved-launch-identity",),
        ("executable-identity", "dependency-provenance", "launch-chain"),
        "require-reapproval",
        "uncertain",
        "CDX-065",
    ),
    "graphql": OracleSeed(
        "github-remote",
        ("network-write", "remote-state-mutation", "destructive-or-irreversible-operation"),
        "remote-resource",
        (),
        ("operation-and-targets", "remote-resource-identity"),
        "block",
        "decidable",
        "CDX-064",
    ),
    "capability-replay": OracleSeed(
        "credentials-permissions-system-guard-destruction",
        ("guard-control-operation",),
        "guard",
        ("dynamic-input",),
        ("capability-constraints", "operation-and-targets"),
        "block",
        "uncertain",
        "CDX-066",
    ),
}


PAIR_ORACLE: dict[str, tuple[PairOracleFacts, PairOracleFacts]] = {
    "p-navigation-boundary": (
        PairOracleFacts(_READ, "workspace", "reversible", (), ("working-directory-identity",), "review"),
        PairOracleFacts(
            _READ,
            "external-local",
            "reversible",
            (),
            ("working-directory-identity", "operation-and-targets"),
            "require-reapproval",
        ),
    ),
    "p-source-boundary": (
        PairOracleFacts(_READ, "workspace", "reversible", (), ("workspace-identity",), "review"),
        PairOracleFacts(
            _READ,
            "external-local",
            "reversible",
            (),
            ("workspace-identity", "operation-and-targets"),
            "require-reapproval",
        ),
    ),
    "p-typescript-source": (
        PairOracleFacts(
            _PROCESS_READ, "workspace", "reversible", (), ("executable-identity", "dependency-provenance"), "review"
        ),
        PairOracleFacts(
            ("process-execution", "package-or-source-installation", "workspace-write"),
            "workspace",
            "recoverable-with-review",
            ("unresolved-launch-identity",),
            ("executable-identity", "dependency-provenance", "launch-chain"),
            "require-reapproval",
        ),
    ),
    "p-git-history": (
        PairOracleFacts(_READ, "workspace", "reversible", (), ("repository-identity",), "review"),
        PairOracleFacts(
            ("process-execution", "workspace-write", "destructive-or-irreversible-operation"),
            "workspace",
            "recoverable-with-review",
            (),
            ("repository-identity", "operation-and-targets"),
            "block",
        ),
    ),
    "p-github-mutation-impact": (
        PairOracleFacts(
            ("network-write", "remote-state-mutation"),
            "remote-resource",
            "recoverable-with-review",
            (),
            ("remote-resource-identity", "operation-and-targets"),
            "review",
        ),
        PairOracleFacts(
            ("network-write", "remote-state-mutation", "destructive-or-irreversible-operation"),
            "remote-resource",
            "irreversible",
            (),
            ("remote-resource-identity", "operation-and-targets"),
            "block",
        ),
    ),
    "p-package-operation": (
        PairOracleFacts(
            ("process-execution", "network-read", "remote-state-read"),
            "remote-resource",
            "reversible",
            (),
            ("executable-identity", "remote-resource-identity"),
            "review",
        ),
        PairOracleFacts(
            ("process-execution", "network-read", "package-or-source-installation", "workspace-write"),
            "workspace",
            "recoverable-with-review",
            (),
            ("executable-identity", "dependency-provenance", "workspace-identity"),
            "require-reapproval",
        ),
    ),
    "p-shell-data-vs-eval": (
        PairOracleFacts(
            ("process-execution", "workspace-or-public-read"),
            "public-resource",
            "reversible",
            (),
            ("operation-and-targets",),
            "review",
        ),
        PairOracleFacts(
            ("process-execution",),
            "unknown",
            "unknown",
            ("dynamic-input",),
            ("shell-data-flow", "expected-effects"),
            "require-reapproval",
        ),
    ),
    "p-cloud-help-redirection": (
        PairOracleFacts(
            ("process-execution", "workspace-or-public-read"),
            "public-resource",
            "reversible",
            (),
            ("operation-and-targets",),
            "review",
        ),
        PairOracleFacts(
            ("process-execution", "network-write", "remote-state-mutation", "destructive-or-irreversible-operation"),
            "remote-resource",
            "irreversible",
            (),
            ("shell-data-flow", "remote-resource-identity"),
            "block",
        ),
    ),
    "p-patch-check-vs-apply": (
        PairOracleFacts(
            _PROCESS_READ, "workspace", "reversible", (), ("workspace-identity", "operation-and-targets"), "review"
        ),
        PairOracleFacts(
            ("process-execution", "workspace-write"),
            "workspace",
            "reversible",
            (),
            ("workspace-identity", "operation-and-targets"),
            "review",
        ),
    ),
    "p-capability-replay": (
        PairOracleFacts(
            ("guard-control-operation",), "guard", "recoverable-with-review", (), ("capability-constraints",), "review"
        ),
        PairOracleFacts(
            ("guard-control-operation",),
            "guard",
            "recoverable-with-review",
            ("dynamic-input",),
            ("capability-constraints",),
            "block",
        ),
    ),
}


def oracle_record(source_id: str, variant: int, seed: OracleSeed) -> OracleRecord:
    return OracleRecord(
        case_id=stable_case_id(source_id, variant),
        workflow_family=seed.workflow_family,
        effects=seed.effects,
        target_scope=seed.target_scope,
        uncertainties=seed.uncertainties,
        required_proofs=seed.required_proofs,
        provided_proofs=(),
        minimum_floor=seed.minimum_floor,
        decision_status=seed.decision_status,
        source_id=source_id,
        owner=seed.owner,
    )


def iter_benign_oracle() -> Iterator[OracleRecord]:
    manifest = load_seed_manifest()
    variants_value = manifest["benign_variants_per_seed"]
    if not isinstance(variants_value, int):
        raise ValueError("benign_variants_per_seed must be an integer")
    workflows_value = manifest["benign_workflows"]
    if not isinstance(workflows_value, list):
        raise ValueError("benign_workflows must be a list")
    records: list[OracleRecord] = []
    for workflow_value in cast(list[object], workflows_value):
        if not isinstance(workflow_value, dict):
            raise ValueError("benign workflow must be an object")
        workflow = cast(dict[str, object], workflow_value)
        workflow_id, seeds_value = workflow["id"], workflow["seeds"]
        if not isinstance(workflow_id, str) or not isinstance(seeds_value, list):
            raise ValueError("benign workflow shape is invalid")
        for seed_value in cast(list[object], seeds_value):
            if not isinstance(seed_value, list):
                raise ValueError("benign seed shape is invalid")
            seed_list = cast(list[object], seed_value)
            if len(seed_list) != 2 or not isinstance(seed_list[0], str):
                raise ValueError("benign seed shape is invalid")
            seed_id = seed_list[0]
            seed = BENIGN_ORACLE[seed_id]
            if seed.workflow_family != workflow_id:
                raise ValueError(f"oracle workflow mismatch for {seed_id}")
            source_id = f"workflow:{workflow_id}:{seed_id}"
            for variant in range(variants_value):
                records.append(oracle_record(source_id, variant, seed))
    yield from sorted(records, key=lambda record: record.case_id)


def iter_adversarial_oracle() -> Iterator[OracleRecord]:
    manifest = load_seed_manifest()
    target_value, categories_value = manifest["adversarial_target_count"], manifest["adversarial_categories"]
    if not isinstance(target_value, int) or not isinstance(categories_value, list):
        raise ValueError("adversarial manifest shape is invalid")
    categories = cast(list[object], categories_value)
    for position in range(target_value):
        index = (position * 7919 + 22020) % target_value
        category_value = categories[index % len(categories)]
        if not isinstance(category_value, list) or not category_value or not isinstance(category_value[0], str):
            raise ValueError("adversarial category shape is invalid")
        technique = category_value[0]
        yield oracle_record(f"adversarial:{technique}", index // len(categories), ADVERSARIAL_ORACLE[technique])
