"""Attest a separate paired collector without rebuilding either installed arm."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

FROZEN_CONTRACT_FILES = {
    "driver": "scripts/qualify_guard_native.py",
    "sampling": "scripts/native_slo_qualification.py",
    "contract": "scripts/native_slo_contract.py",
    "acceptance": "scripts/native_slo_acceptance.py",
    "workloads": "scripts/native_slo_workloads.py",
    "workload_cases": "scripts/native_slo_workload_cases.py",
    "corpus": "tests/fixtures/guard-native-qualification/corpus.v1.json",
    "ownership": "docs/guard/contracts/hook-data-plane-ownership.v2.json",
}


class CollectorBindingError(RuntimeError):
    """The external collector no longer matches its admitted commit or contract."""


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True, text=True
    ).stdout.strip()


def _digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise CollectorBindingError("collector_contract_file_unavailable")
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class CollectorBinding:
    root: Path
    candidate: Path
    expected_sha: str
    output_dir: Path
    _before: dict[str, object] | None = field(default=None, init=False)

    def inspect(self) -> dict[str, object]:
        evidence: dict[str, object] = {
            "schema": "hol-guard.paired-collector-binding.v1",
            "scope": "paired_sampling_collector_only",
            "expected_commit": self.expected_sha,
            "matches_expected": False,
        }
        try:
            commit = _git(self.root, "rev-parse", "HEAD")
            tree = _git(self.root, "rev-parse", "HEAD^{tree}")
            is_root = Path(_git(self.root, "rev-parse", "--show-toplevel")).resolve() == self.root.resolve()
            clean = not _git(self.root, "status", "--porcelain", "--untracked-files=all")
            collector = {key: _digest(self.root / name) for key, name in FROZEN_CONTRACT_FILES.items()}
            candidate = {key: _digest(self.candidate / name) for key, name in FROZEN_CONTRACT_FILES.items()}
        except (OSError, subprocess.CalledProcessError, CollectorBindingError):
            evidence["available"] = False
            return evidence
        evidence.update(
            available=True,
            commit=commit,
            tree=tree,
            checkout_root_matches=is_root,
            files_unchanged=clean,
            frozen_contract_digests=collector,
            candidate_contract_digests=candidate,
            frozen_contract_matches=collector == candidate,
            matches_expected=bool(re.fullmatch(r"[0-9a-f]{40}", self.expected_sha))
            and commit == self.expected_sha
            and bool(re.fullmatch(r"[0-9a-f]{40}", tree))
            and is_root
            and clean
            and collector == candidate,
        )
        return evidence

    def _write(self, phase: str, evidence: dict[str, object]) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / f"collector-{phase}.json").write_text(
            json.dumps({**evidence, "phase": phase}, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )

    def __enter__(self) -> CollectorBinding:
        self._before = self.inspect()
        self._write("before", self._before)
        if self._before["matches_expected"] is not True:
            raise CollectorBindingError("collector_binding_rejected_before_sampling")
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        after = self.inspect()
        unchanged = after == self._before
        self._write("after", {**after, "unchanged_during_sampling": unchanged, "paired_failed": exception is not None})
        if after["matches_expected"] is not True or not unchanged:
            raise CollectorBindingError("collector_binding_changed_during_sampling")
