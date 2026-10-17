"""The lanes a qualification run drove, and the ones it left alone.

`qualify` drives one lane: Oh My Pi on the core profile, the only combination
that qualifies a merge. The harness lanes and the full-task profile cover the
work a person actually does, and a release can be green on the qualifying lane
while being unpleasant to use through Claude Code or Codex. A bare
`qualified: true` reads as coverage the run never had, so the record names the
lane it drove and every lane it did not.
"""

from __future__ import annotations

HARNESSES = ("omp", "claude-code", "codex", "cursor")
PROFILES = ("core", "contained-bun-vitest", "full-tasks", "approval-retry")
QUALIFYING_LANE = ("omp", "core")

# Oh My Pi owns the contained Bun/Vitest profile; the approve-then-retry lane
# runs through an installed harness CLI and so is never Oh My Pi's. The
# full-task runner reads a normalized transcript back from the CLI it drove,
# which it knows how to do for Claude Code and Codex, so Cursor has no
# full-task lane to leave undriven.
_OMP_ONLY_PROFILES = frozenset({"contained-bun-vitest"})
_HARNESS_ONLY_PROFILES = frozenset({"approval-retry"})
FULL_TASK_LANE_HARNESSES = frozenset({"omp", "claude-code", "codex"})


def lane_profiles(harness: str) -> tuple[str, ...]:
    """The profiles this harness can drive."""
    if harness not in HARNESSES:
        raise ValueError(f"unknown Gauntlet harness: {harness}")
    excluded = set(_HARNESS_ONLY_PROFILES if harness == "omp" else _OMP_ONLY_PROFILES)
    if harness not in FULL_TASK_LANE_HARNESSES:
        excluded.add("full-tasks")
    return tuple(profile for profile in PROFILES if profile not in excluded)


def lanes() -> tuple[tuple[str, str], ...]:
    """Every harness and profile pair the runner accepts."""
    return tuple((harness, profile) for harness in HARNESSES for profile in lane_profiles(harness))


def lane_coverage(harness: str = "omp", profile: str = "core", *, driven: bool = True) -> dict:
    """Name the lane a run was set up for, whether it drove it, and the rest.

    A run can stop before its first attempt: `--prepare-only` leaves the
    installed candidate behind for a local `run`, and a setup failure never
    reaches the attempt loop. Neither drove anything, so `driven` is null and
    every lane is listed as left alone. `lane` keeps the lane the run was set
    up for, which is what a later `run` against that candidate would drive.
    """
    if profile not in lane_profiles(harness):
        raise ValueError(f"unsupported Gauntlet lane: {harness} {profile}")
    lane = {"harness": harness, "profile": profile}
    return {
        "lane": lane,
        "driven": lane if driven else None,
        "is_qualifying_lane": driven and (harness, profile) == QUALIFYING_LANE,
        "not_driven": [
            {"harness": other_harness, "profile": other_profile}
            for other_harness, other_profile in lanes()
            if not driven or (other_harness, other_profile) != (harness, profile)
        ],
    }
