"""Identity-bound provider choices, committed with protected extension authority.

The native store writes the choices; this module names their shape and the
digest a dashboard request binds to.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from hashlib import sha256

ProviderUpdate = tuple[str, str, int]


def provider_choices_digest(updates: Sequence[ProviderUpdate]) -> str:
    return sha256(json.dumps(sorted(updates), separators=(",", ":")).encode()).hexdigest()
