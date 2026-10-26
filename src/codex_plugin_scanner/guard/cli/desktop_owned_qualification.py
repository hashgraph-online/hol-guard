"""Read-only predecessor qualification contract for the Desktop controller."""

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from typing import TextIO

from ..adapters.base import HarnessContext
from ..codex_hook_file_integrity import CodexHookIntegrityError
from ..daemon.live_identity import DaemonArtifactBinding
from ..runtime_transition import TransitionError
from ..runtime_transition_admission import verified_admission_payload
from ..runtime_transition_owned_qualification import qualify_owned_codex_native
from ..store import GuardStore

OWNED_QUALIFICATION_SCHEMA = "hol-guard.owned-native-qualification.v1"
MAX_OWNED_QUALIFICATION_BYTES = 64 * 1024


def run_desktop_owned_qualification(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    store: GuardStore,
    output_stream: TextIO,
) -> int:
    """Publish bounded observation data, never a lifecycle approval or replay grant."""
    started, epoch = time.monotonic(), time.time()
    document: dict[str, object] = {
        "schema": OWNED_QUALIFICATION_SCHEMA,
        "operation_id": args.operation_id,
        "generation": args.artifact_generation,
        "qualified": False,
        "reason_code": None,
    }
    try:
        expires = args.deadline_epoch
        if (
            isinstance(expires, bool)
            or not isinstance(expires, (float, int))
            or not math.isfinite(expires)
            or not 0 < expires - epoch <= 60
        ):
            raise TransitionError("owned_qualification_deadline")
        deadline = started + expires - epoch
        binding = DaemonArtifactBinding(
            Path(args.daemon_executable),
            args.daemon_executable_sha256,
            args.daemon_package_version,
        )
        observed = qualify_owned_codex_native(
            operation_id=args.operation_id,
            artifact_generation=args.artifact_generation,
            expected_artifact=binding,
            context=context,
            store=store,
            deadline_monotonic=deadline,
        )
        document["native_admission"] = verified_admission_payload(observed.admission)
        document["daemon_artifact"] = {
            "path": str(binding.executable),
            "sha256": binding.executable_sha256,
            "version": binding.package_version,
        }
        if time.monotonic() >= deadline:
            raise TransitionError("owned_qualification_deadline")
        document["qualified"] = True
    except TransitionError as error:
        document["reason_code"] = error.reason
    except CodexHookIntegrityError as error:
        document["reason_code"] = error.reason
    except TimeoutError:
        document["reason_code"] = "owned_qualification_deadline"
    except (OSError, ValueError, RuntimeError):
        document["reason_code"] = "owned_qualification_unavailable"
    if not document["qualified"]:
        document.pop("native_admission", None)
        document.pop("daemon_artifact", None)
    encoded = json.dumps(document, sort_keys=True, allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_OWNED_QUALIFICATION_BYTES:
        document = {
            "schema": OWNED_QUALIFICATION_SCHEMA,
            "operation_id": str(args.operation_id)[:128],
            "generation": str(args.artifact_generation)[:128],
            "qualified": False,
            "reason_code": "owned_qualification_capacity",
        }
        encoded = json.dumps(document, sort_keys=True, allow_nan=False)
    print(encoded, file=output_stream)
    return 0 if document["qualified"] else 2
