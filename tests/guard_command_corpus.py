"""Deterministic command inputs for Guard regression and red-team evaluation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import cast

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "guard-command-corpus"
MANIFEST_PATH = FIXTURE_DIR / "seed-manifest.json"
PAIRS_PATH = FIXTURE_DIR / "minimal-delta-pairs.json"
KNOWN_GAPS_PATH = FIXTURE_DIR / "known-gaps.json"


@dataclass(frozen=True, slots=True)
class CommandCorpusCase:
    """Opaque evaluator input. Security labels live in the oracle sidecar."""

    case_id: str
    command: str
    context: tuple[tuple[str, str], ...] = ()


@lru_cache(maxsize=1)
def load_seed_manifest() -> dict[str, object]:
    payload = cast(object, json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))
    if not isinstance(payload, dict):
        raise ValueError("command corpus seed manifest must be an object")
    manifest = cast(dict[str, object], payload)
    if manifest.get("schema_version") != "1.0.0":
        raise ValueError("command corpus seed manifest must use schema 1.0.0")
    return manifest


def stable_case_id(source_id: str, variant: int) -> str:
    domain = _string(load_seed_manifest().get("corpus_domain"), "corpus_domain")
    digest = hashlib.sha256(f"{domain}\0{source_id}\0{variant}".encode()).hexdigest()
    return f"c-{digest[:24]}"


def iter_benign_corpus(*, shard_index: int = 0, shard_count: int = 1) -> Iterator[CommandCorpusCase]:
    _validate_shard(shard_index, shard_count)
    manifest = load_seed_manifest()
    variants = _integer(manifest.get("benign_variants_per_seed"), "benign_variants_per_seed")
    cases: list[CommandCorpusCase] = []
    for workflow_value in _list(manifest.get("benign_workflows"), "benign_workflows"):
        workflow = _mapping(workflow_value, "benign workflow")
        workflow_id = _string(workflow.get("id"), "workflow.id")
        for seed_value in _list(workflow.get("seeds"), "workflow.seeds"):
            seed = _list(seed_value, "workflow seed")
            if len(seed) != 2:
                raise ValueError("each benign seed must contain an id and command")
            seed_id, template = (_string(seed[0], "seed.id"), _string(seed[1], "seed.command"))
            source_id = f"workflow:{workflow_id}:{seed_id}"
            for variant in range(variants):
                command = (
                    template.replace("{variant}", str(variant))
                    .replace("{variant_path}", "" if variant == 0 else f"-{variant}")
                    .replace("{pr_number}", str(4289 + variant))
                )
                cases.append(CommandCorpusCase(case_id=stable_case_id(source_id, variant), command=command))
    yield from sorted(cases, key=lambda case: case.case_id)[shard_index::shard_count]


def iter_adversarial_corpus(*, shard_index: int = 0, shard_count: int = 1) -> Iterator[CommandCorpusCase]:
    _validate_shard(shard_index, shard_count)
    manifest = load_seed_manifest()
    categories = _list(manifest.get("adversarial_categories"), "adversarial_categories")
    target_count = _integer(manifest.get("adversarial_target_count"), "adversarial_target_count")
    for position in range(shard_index, target_count, shard_count):
        index = (position * 7919 + 22020) % target_count
        seed = _list(categories[index % len(categories)], "adversarial category")
        if len(seed) != 3:
            raise ValueError("each adversarial category must contain an id, provenance, and template")
        technique, template = _string(seed[0], "category.id"), _string(seed[2], "category.template")
        variant = index // len(categories)
        yield CommandCorpusCase(
            case_id=stable_case_id(f"adversarial:{technique}", variant),
            command=_render_adversarial(template, variant=variant),
        )


def _validate_shard(shard_index: int, shard_count: int) -> None:
    if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
        raise ValueError("corpus shard must satisfy 0 <= shard_index < shard_count")


def _render_adversarial(template: str, *, variant: int) -> str:
    flags = ("--output json", "--profile hol-fake", "--no-cli-pager", "--region hol-fake-1")
    sinks = (
        "tee scratch/hol-fake-output",
        "dd of=scratch/hol-fake-output status=none",
        "sed -n '1,5p' > scratch/hol-fake-output",
        "base64 > scratch/hol-fake-output",
    )
    replacements = {
        "{target}": f"fixture-{variant:04x}",
        "{variant}": str(variant),
        "{flag_a}": flags[variant % len(flags)],
        "{flag_b}": flags[(variant * 3 + 1) % len(flags)],
        "{flag_value}": ("--help", "hol-fake-value", "-", "@hol-fake-file")[variant % 4],
        "{wrapper}": ("env", "command", "nice -n 5", "timeout 30")[variant % 4],
        "{redirect}": (">", "2>", ">>", "2>>")[variant % 4],
        "{pipeline_sink}": sinks[variant % len(sinks)],
    }
    command = template
    for marker, value in replacements.items():
        command = command.replace(marker, value)
    return command


def corpus_digest(cases: Iterator[CommandCorpusCase]) -> str:
    """Hash canonical length-framed JSON records without concatenation ambiguity."""

    digest = hashlib.sha256()
    for case in cases:
        record = json.dumps(asdict(case), sort_keys=True, separators=(",", ":")).encode()
        digest.update(len(record).to_bytes(8, "big"))
        digest.update(record)
    return digest.hexdigest()


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty list")
    return cast(list[object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value
