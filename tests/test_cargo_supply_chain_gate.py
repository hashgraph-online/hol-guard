"""Contracts for the Cargo supply-chain gate in Security Gates.

The gate is what keeps an advisory, an unexpected registry or a second copy of a
crate out of the binary that decides what a harness may do, so the parts that
make it a gate rather than a report are pinned here: the four checks it runs,
the digest it verifies the tool against, and the settings in `rust/deny.toml`
that turn a finding into a failure.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security-gates.yml"
PUBLISH_PATH = ROOT / ".github" / "workflows" / "publish.yml"
DENY_PATH = ROOT / "rust" / "deny.toml"
REQUIRED_CHECKS = ("advisories", "bans", "licenses", "sources")


def _job() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    job = workflow["jobs"]["cargo-deny"]
    assert isinstance(job, dict)
    return job


def _steps() -> list[dict[str, Any]]:
    steps = _job()["steps"]
    assert isinstance(steps, list)
    return steps


def _deny() -> dict[str, Any]:
    return tomllib.loads(DENY_PATH.read_text(encoding="utf-8"))


def _check_command() -> str:
    return next(command for command in (step.get("run", "") for step in _steps()) if "cargo deny" in command)


def _shipped_wheel_targets() -> set[str]:
    """Read the native wheel targets publish.yml approves, as it writes them."""

    text = PUBLISH_PATH.read_text(encoding="utf-8")
    start = text.index("          metadata = {")
    end = text.index("          }", start)
    targets = re.findall(r'"([a-z0-9_]+-[a-z0-9-]+)": \(', text[start:end])
    assert targets, "publish.yml no longer spells its approved wheel targets this way"
    return set(targets)


def test_gate_runs_every_check_against_the_workspace() -> None:
    check = _check_command()

    assert "--workspace" in check
    assert "--locked" in check
    for name in REQUIRED_CHECKS:
        assert f" {name}" in check


def test_the_tool_is_a_digest_verified_pinned_release() -> None:
    install = next(step for step in _steps() if step.get("name") == "Install cargo-deny")
    env = install["env"]
    version = env["CARGO_DENY_VERSION"]

    # The exact digest, not its shape: a new value has to be changed in two
    # places, which is what makes swapping the audited binary a reviewed act.
    assert env["CARGO_DENY_SHA256"] == "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f"
    assert version == "0.20.2"
    assert "sha256sum --check --strict" in install["run"]
    assert "/download/${CARGO_DENY_VERSION}/" in install["run"]

    cache = next(step for step in _steps() if step.get("id") == "cargo-deny-cache")
    # A cache key that outlives a version bump would serve the old binary.
    assert cache["with"]["key"].endswith(f"-v{version}")


def test_the_gate_fails_rather_than_warns() -> None:
    deny = _deny()

    assert deny["advisories"]["yanked"] == "deny"
    # `unmaintained` is the scope an unmaintained advisory is applied over, not
    # how loudly it is reported; "all" is the widest, so every matching crate
    # fails rather than only a workspace dependency or only a transitive one.
    assert deny["advisories"]["unmaintained"] == "all"
    # A skip entry that matches nothing is only a warning by default, so a stale
    # duplicate exception would widen the list without failing anything.
    assert "--deny unmatched-skip" in _check_command()
    assert deny["bans"]["multiple-versions"] == "deny"
    assert deny["bans"]["wildcards"] == "deny"
    assert deny["sources"]["unknown-registry"] == "deny"
    assert deny["sources"]["unknown-git"] == "deny"
    assert deny["sources"]["allow-git"] == []


def test_licenses_are_allow_listed_and_cover_what_ships() -> None:
    licenses = _deny()["licenses"]

    # Everything not named here is denied, so the workspace's own terms and the
    # build scripts that produce the shipped binary both have to be in scope.
    assert "Apache-2.0" in licenses["allow"]
    assert licenses["include-build"] is True
    assert all("GPL" not in entry for entry in licenses["allow"])


def test_every_duplicate_exception_carries_a_reason() -> None:
    bans = _deny()["bans"]

    for entry in bans["skip"]:
        assert "@" in entry["crate"], entry
        assert entry["reason"].strip(), entry
    for entry in bans["deny"]:
        assert entry["reason"].strip(), entry


def test_every_advisory_exception_names_the_advisory_and_why_it_does_not_reach_us() -> None:
    advisories = _deny()["advisories"]

    for entry in advisories["ignore"]:
        # A bare id would mute an advisory without recording what was checked,
        # which is how an ignore outlives the reasoning behind it.
        assert entry["id"].startswith("RUSTSEC-"), entry
        assert entry["reason"].strip(), entry


def test_the_workspace_crates_are_private_so_path_pins_stay_allowed() -> None:
    members = re.findall(r'^\s*"(crates/[^"]+)",', (ROOT / "rust" / "Cargo.toml").read_text(encoding="utf-8"), re.M)
    assert members, "the workspace no longer lists its members this way"

    # `allow-wildcard-paths` only exempts private crates, because crates.io
    # refuses a path dependency. A member that forgets `publish = false` turns
    # every one of its sibling path pins into a wildcard failure.
    for member in members:
        manifest = tomllib.loads((ROOT / "rust" / member / "Cargo.toml").read_text(encoding="utf-8"))
        assert manifest["package"]["publish"] is False, member


def test_audited_targets_cover_every_published_wheel() -> None:
    targets = set(_deny()["graph"]["targets"])

    # A platform that ships a wheel but is missing here is a platform whose
    # advisory, licence and duplicate findings nobody ever sees.
    assert _shipped_wheel_targets() <= targets


def test_a_stable_release_cannot_build_without_a_green_audit() -> None:
    publish = yaml.safe_load(PUBLISH_PATH.read_text(encoding="utf-8"))
    jobs = publish["jobs"]
    gate = jobs["require-supply-chain-audit"]

    assert gate["permissions"] == {"checks": "read"}
    # No `if` on the job: a skipped dependency would satisfy a success check
    # below only by accident, so the channel test lives inside the step.
    assert "if" not in gate
    run = gate["steps"][0]["run"]
    assert "check_name=Cargo+supply+chain" in run
    assert '"$RELEASE_CHANNEL" != "stable"' in run
    assert '"$conclusion" != "success"' in run
    assert "require-supply-chain-audit" in jobs["build"]["needs"]
    assert "needs.require-supply-chain-audit.result == 'success'" in jobs["build"]["if"]

    # A stable repair builds the release tag, which can be older than the commit
    # the run was dispatched from, so the build reads the audit back for the
    # source it resolved rather than trusting the gate above.
    name = "Require a green Cargo supply chain run for the resolved source"
    resolved = next(step for step in jobs["build"]["steps"] if step.get("name") == name)
    assert resolved["env"]["SOURCE_SHA"] == "${{ steps.version.outputs.source_sha }}"
    assert resolved["if"] == "steps.version.outputs.channel == 'stable'"
    assert '"$conclusion" != "success"' in resolved["run"]
    assert jobs["build"]["permissions"]["checks"] == "read"
    assert jobs["build"]["steps"].index(resolved) < next(
        index for index, step in enumerate(jobs["build"]["steps"]) if step.get("id") == "native_wheel_matrix"
    )


def test_a_release_cut_before_the_gate_can_still_be_repaired() -> None:
    publish = yaml.safe_load(PUBLISH_PATH.read_text(encoding="utf-8"))
    name = "Require a green Cargo supply chain run for the resolved source"
    run = next(step for step in publish["jobs"]["build"]["steps"] if step.get("name") == name)["run"]

    # Re-running Security Gates on an old tag runs that tag's own copy of the
    # workflow, so a release tagged before the job existed can never produce the
    # check run. Reading the resolved source's workflow is what separates that
    # from an audit that ran and did not pass, and it is the only thing that
    # keeps a half-published release finishable.
    assert 'git show "${SOURCE_SHA}:.github/workflows/security-gates.yml"' in run
    assert 'grep -q "name: Cargo supply chain"' in run
    # A conclusion that exists at all is a verdict, so only an absent one can be
    # exempt, and only when that commit's Security Gates defines no such job.
    assert '[[ -n "$conclusion" ]] ||' in run
    assert run.index("refusing to build a stable release") < run.index("predates the audit")
