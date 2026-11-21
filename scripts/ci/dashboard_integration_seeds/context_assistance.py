"""CIGAR seed for dashboard integration runs.

Guard now runs only the CIGAR engine built into it, so there is no separate
candidate runtime to enroll. Ordinary dashboard runs never start CIGAR; the
mutating CIGAR specs skip unless a seed reports an enrolled candidate.
"""

from __future__ import annotations

from typing import Any

from . import SeedContext


def seed(context: SeedContext) -> dict[str, Any]:
    del context
    return {"candidateEnrolled": False}
