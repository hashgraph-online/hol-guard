"""Isolated native candidate qualification for the Desktop updater."""

from __future__ import annotations

import argparse
import json
import math
import time
import uuid
from pathlib import Path
from typing import TextIO

from ..adapters.base import HarnessContext
from ..daemon.hook_worker import HookWorker
from ..dashboard_launcher import desktop_bootstrap_is_preflight
from ..native_resident_client import close_native_residents
from ..native_runtime import native_runtime_status
from ..runtime_transition import TransitionError
from ..runtime_transition_admission import probe_native_protection, verified_admission_payload
from ..store import GuardStore

CANDIDATE_QUALIFICATION_SCHEMA = "hol-guard.candidate-qualification.v1"


def run_desktop_qualification(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    store: GuardStore,
    output_stream: TextIO,
) -> int:
    """Qualify only a disposable Desktop home, retaining incomplete cleanup."""
    from .commands_dispatch_desktop import _core_version

    document: dict[str, object] = {
        "schema": CANDIDATE_QUALIFICATION_SCHEMA,
        "core_version": _core_version(),
        "operation_id": args.operation_id,
        "generation": args.artifact_generation,
        "qualified": False,
        "cleanup_complete": True,
        "reason_code": None,
    }
    worker: HookWorker | None = None
    deadline: float | None = None
    try:
        home = Path(store.guard_home).resolve(strict=False)
        if (
            not desktop_bootstrap_is_preflight()
            or home != context.home_dir.resolve(strict=False)
            or not home.name.startswith("preflight-home-")
        ):
            raise TransitionError("qualification_isolation_required")
        try:
            uuid.UUID(home.name.removeprefix("preflight-home-"))
            uuid.UUID(args.operation_id)
        except (ValueError, TypeError, AttributeError):
            raise TransitionError("qualification_identity_invalid") from None
        generation = args.artifact_generation
        if (
            not isinstance(generation, str)
            or len(generation) != 64
            or any(character not in "0123456789abcdef" for character in generation)
        ):
            raise TransitionError("qualification_identity_invalid")
        expires = args.deadline_epoch
        if isinstance(expires, bool) or not isinstance(expires, (float, int)) or not math.isfinite(expires):
            raise TransitionError("qualification_deadline_invalid")
        remaining = expires - time.time()
        if not 0 < remaining <= 60:
            raise TransitionError("qualification_deadline_expired")
        deadline = time.monotonic() + remaining
        status = native_runtime_status()
        if (
            status.identity is None
            or not status.available
            or not status.compatible
            or status.mode not in {"auto", "force"}
        ):
            raise TransitionError("qualification_native_unavailable")
        if time.monotonic() >= deadline:
            raise TransitionError("qualification_deadline_expired")
        # Capture ownership before the first publisher start, including a
        # provision/start failure inside the admission barrier.
        worker = HookWorker(store=store, wait_for_native_policy=False, start_native_policy=False)
        workspace = home / "qualification-workspace"
        workspace.mkdir(mode=0o700)
        observation = probe_native_protection(
            worker=worker,
            operation_id=args.operation_id,
            artifact_generation=generation,
            expected_runtime=status.identity,
            home_dir=home,
            workspace=workspace,
            deadline_monotonic=deadline,
        )
        document["native_admission"] = verified_admission_payload(observation)
    except TransitionError as error:
        document["reason_code"] = error.reason
    except (OSError, TimeoutError, ValueError, RuntimeError):
        document["reason_code"] = "qualification_native_failed"
    finally:
        if worker is not None:
            assert deadline is not None
            cleanup_causes = []
            try:
                publisher_closed = worker.close(deadline_monotonic=deadline)
            except Exception:
                publisher_closed = False
                cleanup_causes.append("qualification_publisher_cleanup_failed")
            try:
                residents_closed = close_native_residents(store.guard_home, deadline_monotonic=deadline)
            except Exception:
                residents_closed = False
                cleanup_causes.append("qualification_resident_cleanup_failed")
            document["cleanup_complete"] = publisher_closed and residents_closed
            if cleanup_causes:
                document["cleanup_reason_codes"] = cleanup_causes
            if not document["cleanup_complete"] and document["reason_code"] is None:
                document["reason_code"] = "qualification_cleanup_incomplete"
    document["qualified"] = document["reason_code"] is None and "native_admission" in document
    print(json.dumps(document, sort_keys=True, allow_nan=False), file=output_stream)
    return 0 if document["qualified"] else 2
