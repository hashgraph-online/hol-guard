"""Submit bounded public evidence using GitHub alone or a direct object URL."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from .bundle import download


def inline_dispatch_inputs(archive: Path, *, candidate_sha: str, pr_number: int, attested: bool) -> dict[str, str]:
    """Produce small workflow inputs without a separate object-storage account."""
    if re.fullmatch(r"[0-9a-f]{40}", candidate_sha) is None or pr_number < 1 or attested is not True:
        raise ValueError("a candidate, PR number and truthful real-inference attestation are required")
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > 40000:
        raise ValueError("bundle is too large for inline dispatch; use a signed evidence URL instead")
    raw = archive.read_bytes()
    inputs = {
        "candidate_sha": candidate_sha,
        "pr_number": str(pr_number),
        "evidence_base64": base64.b64encode(raw).decode("ascii"),
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "attest_real_inference": "true",
    }
    if len(json.dumps(inputs)) > 60000:
        raise ValueError("inline evidence exceeds the bounded workflow input budget")
    return inputs


def submitted_archive(inputs: dict) -> bytes:
    """Accept one bounded public transport; unpack still verifies every byte."""
    encoded, url = inputs.get("evidence_base64", ""), inputs.get("evidence_url", "")
    if not isinstance(encoded, str) or not isinstance(url, str) or bool(encoded) == bool(url):
        raise ValueError("supply exactly one inline evidence bundle or direct evidence URL")
    if encoded:
        if len(encoded) > 55000:
            raise ValueError("inline evidence exceeds the workflow transport budget")
        return base64.b64decode(encoded, validate=True)
    return download(url)
