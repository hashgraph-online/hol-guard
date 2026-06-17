from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


def canonical_guard_evidence_payload(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def guard_evidence_hash(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_guard_evidence_payload(payload).encode("utf-8")).hexdigest()
