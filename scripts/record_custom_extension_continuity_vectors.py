#!/usr/bin/env python3
"""Record parity vectors for custom-Extension continuity planning.

Usage: GUARD_PY_SNAPSHOT=<path to src dir of the reference snapshot> \
    python scripts/record_custom_extension_continuity_vectors.py [snapshot_src]

The reference snapshot must predate the move of continuity planning to the
native runtime. Each vector is one native request, built from a fake store
snapshot exactly as the client builds it, and the reference answer. The Rust
tests in rust/crates/guard-runtime replay them. Deterministic output. Shared
fixtures live in custom_extension_continuity_vector_support.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from custom_extension_continuity_vector_support import (
    CLI_IDS,
    DEVICE,
    EXPIRES,
    FRESH,
    LATE,
    OBSERVED,
    OUT,
    V1,
    V2,
    WORKSPACE,
    binding,
    bundle,
    detail,
    device_hash,
    h,
    item1,
    item2,
    local,
    local_mutation_vectors,
    obs1,
    obs2,
    plan_vector,
    public_state_vectors,
    random_vectors,
    scoped,
    snap,
)


def fixed_plan_vectors() -> list[dict[str, object]]:
    deploy, build = CLI_IDS[0], CLI_IDS[1]
    base_locals = [local(deploy), local(build, kind="executable", interpreter_name=None, surface="mcp")]
    base_details = {deploy: detail(deploy, grant=None), build: detail(build)}
    base = snap(base_locals, base_details)
    vectors = []
    frames = {
        "not_dict": ["x"],
        "extra_field": {**obs1([]), "extra": 1},
        "missing_field": {k: v for k, v in obs1([]).items() if k != "expiresAt"},
        "schema_unknown": obs1([], schemaVersion="guard.custom-extension-continuity.v3"),
        "revision_zero": obs1([], revision=0),
        "revision_negative": obs1([], revision=-4),
        "revision_bool": obs1([], revision=True),
        "revision_float": obs1([], revision=2.0),
        "revision_text": obs1([], revision="2"),
        "revision_huge": obs1([], revision=2**70),
        "observed_int": obs1([], observedAt=5),
        "observed_naive": obs1([], observedAt="2026-10-01T00:00:00"),
        "observed_garbage": obs1([], observedAt="yesterday"),
        "expires_equal": obs1([], expiresAt=OBSERVED),
        "expires_before": obs1([], expiresAt="2026-09-01T00:00:00Z"),
        "offsets": obs1([], observedAt="2026-10-01T05:00:00+05:00", expiresAt="2026-10-01T00:00:01Z"),
        "offsets_equal": obs1([], observedAt="2026-10-01T05:00:00+05:00", expiresAt="2026-10-01T00:00:00Z"),
        "compact_dates": obs1([], observedAt="20261001T000000Z", expiresAt="2026-W50-1T00:00:00Z"),
        "fraction_dates": obs1([], observedAt="2026-10-01T00:00:00.5Z", expiresAt="2026-10-01T00:00:00.500001Z"),
        "double_z": obs1([], observedAt="2026-10-01T00:00:00ZZ"),
        "items_not_list": obs1({}),  # type: ignore[arg-type]
        "items_limit": obs1([item1(deploy)] * 101),
        "item_not_dict": obs1(["x"]),
        "item_extra": obs1([{**item1(deploy), "x": 1}]),
        "item_bad_id": obs1([item1("local-cli.Bad")]),
        "item_bad_prefix": obs1([item1("cli.deploy")]),
        "item_id_segments": obs1([item1("local-cli.a-b-c-d-e-f-g-h-i-j")]),
        "item_duplicate": obs1([item1(deploy), item1(deploy)]),
        "item_hash_short": obs1([item1(deploy, identity_hash="ab")]),
        "item_hash_upper": obs1([item1(deploy, identity_hash=h(deploy).upper())]),
        "settings_not_dict": obs1([{"cliId": deploy, "identityHash": h(deploy), "settings": []}]),
        "settings_extra": obs1(
            [{"cliId": deploy, "identityHash": h(deploy), "settings": {"state": "allowed", "commands": {}, "x": 1}}]
        ),
        "settings_state": obs1([item1(deploy, state="unset")]),
        "commands_not_dict": obs1([item1(deploy, commands=[])]),
        "commands_limit": obs1([item1(deploy, commands={f"c{i}": "allow" for i in range(102)})]),
        "commands_at_limit": obs1([item1(deploy, commands={f"c{i}": "allow" for i in range(101)})]),
        "command_bad_id": obs1([item1(deploy, commands={"9bad": "allow"})]),
        "command_deep_id": obs1([item1(deploy, commands={"a.b.c.d.e": "allow"})]),
        "command_dotted_ok": obs1([item1(deploy, commands={"a.b-c.d_e": "allow"})]),
        "command_bad_state": obs1([item1(deploy, commands={"sub": "deny"})]),
    }
    for name, value in frames.items():
        vectors.append(plan_vector(f"v1_frame_{name}", base, bundle(value), DEVICE, FRESH))
    for name, now in {
        "now_garbage": "garbage",
        "now_naive": "2026-10-11T00:00:00",
        "now_offset": "2026-12-01T05:00:00+05:00",
        "now_equal_expiry": EXPIRES,
        "now_late": LATE,
    }.items():
        vectors.append(plan_vector(f"v1_{name}", base, bundle(obs1([item1(deploy)])), DEVICE, now))
    item = item1(deploy, commands={"sub": "block"})
    digest_previous = {"cloud_revision": 2, "observation_digest": "0" * 64, "items": {}}
    for name, previous in {
        "previous_backwards": {"cloud_revision": 3},
        "previous_digest_changed": digest_previous,
        "previous_bool_revision": {"cloud_revision": True},
        "previous_float_revision": {"cloud_revision": 9.0},
        "previous_list": [1, 2],
        "previous_lower": {"cloud_revision": 1, "items": {deploy: {"status": "applied"}}},
    }.items():
        vectors.append(
            plan_vector(
                f"v1_{name}", snap(base_locals, base_details, previous=previous), bundle(obs1([item])), DEVICE, FRESH
            )
        )
    first = plan_vector("v1_applied_update", base, bundle(obs1([item])), DEVICE, FRESH)
    vectors.append(first)
    same_digest = first["expected"]["state"]
    vectors.append(
        plan_vector(
            "v1_same_digest_replay",
            snap(base_locals, base_details, previous=same_digest),
            bundle(obs1([item])),
            DEVICE,
            FRESH,
        )
    )
    unchanged = {deploy: detail(deploy, states={"sub": "block"}), build: detail(build)}
    vectors.append(
        plan_vector("v1_applied_unchanged", snap(base_locals, unchanged), bundle(obs1([item])), DEVICE, FRESH)
    )
    vectors.append(
        plan_vector(
            "v1_unobserved_command", base, bundle(obs1([item1(deploy, commands={"nope": "allow"})])), DEVICE, FRESH
        )
    )
    vectors.append(
        plan_vector(
            "v1_bad_kind", snap([local(deploy, kind="binary")], base_details), bundle(obs1([item])), DEVICE, FRESH
        )
    )
    variants = {
        "unobserved": local(deploy, observed_count=0),
        "count_text": local(deploy, observed_count="3"),
        "count_bool": local(deploy, observed_count=True),
        "changed_identity": local(deploy, identity_hash=h("other")),
        "surface_package": local(deploy, surface="package-scripts"),
        "surface_other": local(deploy, surface="desktop"),
        "no_commands": local(deploy, commands=None),
        "odd_commands": local(deploy, commands=[{"command_id": 5}, "x", {"command_id": "root"}]),
    }
    for name, value in variants.items():
        vectors.append(plan_vector(f"v1_{name}", snap([value], base_details), bundle(obs1([item])), DEVICE, FRESH))
    vectors.append(plan_vector("v1_missing_local", snap([], {}), bundle(obs1([item])), DEVICE, FRESH))
    for name, removal in {
        "override_allowed": {"identity_hash": h(deploy), "cloud_revision": 2, "state": "allowed"},
        "override_unset": {"identity_hash": h(deploy), "cloud_revision": 5, "state": "unset"},
        "override_old_revision": {"identity_hash": h(deploy), "cloud_revision": 1, "state": "blocked"},
        "override_other_identity": {"identity_hash": h("x"), "cloud_revision": 2, "state": "blocked"},
        "override_float_revision": {"identity_hash": h(deploy), "cloud_revision": 2.0, "state": "blocked"},
        "override_not_dict": "x",
    }.items():
        removals = {deploy: removal, "local-cli.keep": {"state": "allowed"}}
        vectors.append(
            plan_vector(
                f"v1_{name}", snap(base_locals, base_details, removals=removals), bundle(obs1([item])), DEVICE, FRESH
            )
        )
        vectors.append(
            plan_vector(
                f"v1_{name}_stale",
                snap(base_locals, base_details, removals=removals),
                bundle(obs1([item])),
                DEVICE,
                LATE,
            )
        )
    vectors.append(
        plan_vector(
            "v1_removals_list", snap(base_locals, base_details, removals=[deploy]), bundle(obs1([item])), DEVICE, FRESH
        )
    )
    many = [item1(cli_id) for cli_id in reversed(CLI_IDS)]
    many_locals = [local(cli_id) for cli_id in CLI_IDS] + [local(CLI_IDS[0], name="dup")]
    vectors.append(
        plan_vector(
            "v1_many_items",
            snap(many_locals, {c: detail(c, grant=None) for c in CLI_IDS}),
            bundle(obs1(many)),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(
        plan_vector(
            "v1_non_ascii",
            snap(base_locals, base_details),
            bundle(obs1([item], observedAt="2026-10-01T00:00:00Z")),
            "dévice",
            FRESH,
        )
    )
    return vectors


def fixed_v2_vectors() -> list[dict[str, object]]:
    deploy, build, lint = CLI_IDS[0], CLI_IDS[1], CLI_IDS[2]
    base_locals = [local(deploy), local(build, kind="executable", interpreter_name=None, surface="mcp")]
    base_details = {deploy: detail(deploy, grant=None), build: detail(build)}
    base = snap(base_locals, base_details)
    s_deploy, s_build = scoped(h(deploy)), scoped(h(build))
    vectors = []
    good = obs2([item2(s_deploy), item2(s_build, state="blocked")])
    for name, (workspace, device) in {
        "workspace_missing": (None, DEVICE),
        "workspace_empty": ("", DEVICE),
        "workspace_int": (5, DEVICE),
        "device_missing": (WORKSPACE, None),
    }.items():
        vectors.append(plan_vector(f"v2_{name}", base, bundle(good, workspace), device, FRESH))
    frames = {
        "item_extra": obs2([{**item2(s_deploy), "x": 1}]),
        "item_hash_bad": obs2([item2("zz")]),
        "item_duplicate": obs2([item2(s_deploy), item2(s_deploy)]),
        "devices_empty": obs2([item2(s_deploy, devices=[])]),
        "devices_two": obs2([item2(s_deploy, devices=[device_hash(), h("b")])]),
        "devices_bad": obs2([item2(s_deploy, devices=["x"])]),
        "devices_not_list": obs2([item2(s_deploy, devices=device_hash())]),
        "state_bad": obs2([item2(s_deploy, state="unset")]),
        "items_limit": obs2([item2(h(str(i))) for i in range(101)]),
        "revision_zero": obs2([], revision=0),
    }
    for name, value in frames.items():
        vectors.append(plan_vector(f"v2_frame_{name}", base, bundle(value), DEVICE, FRESH))
    first = plan_vector("v2_applied", base, bundle(good), DEVICE, FRESH)
    vectors.append(first)
    vectors.append(plan_vector("v2_stale", base, bundle(good), DEVICE, LATE))
    vectors.append(plan_vector("v2_other_device", base, bundle(good), "device-b", FRESH))
    vectors.append(plan_vector("v2_other_workspace", base, bundle(good, "ws_2"), DEVICE, FRESH))
    state = first["expected"]["state"]
    vectors.append(
        plan_vector(
            "v2_same_context_replay", snap(base_locals, base_details, previous=state), bundle(good), DEVICE, FRESH
        )
    )
    vectors.append(
        plan_vector(
            "v2_same_context_backwards",
            snap(base_locals, base_details, previous={**state, "cloud_revision": 5}),
            bundle(good),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(
        plan_vector(
            "v2_same_context_digest",
            snap(base_locals, base_details, previous={**state, "observation_digest": "1" * 64}),
            bundle(good),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(
        plan_vector(
            "v2_prior_without_binding",
            snap(base_locals, base_details, previous={"schema_version": V2, "items": {}}),
            bundle(good),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(
        plan_vector(
            "v2_prior_bad_binding",
            snap(base_locals, base_details, previous={"schema_version": V2, "binding": {"x": 1}, "items": {}}),
            bundle(good),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(plan_vector("v2_removed", base, bundle(obs2([item2(s_deploy, state="removed")])), DEVICE, FRESH))
    vectors.append(
        plan_vector(
            "v2_removed_bad_kind",
            snap([local(deploy, kind="weird")], base_details),
            bundle(obs2([item2(s_deploy, state="removed")])),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(
        plan_vector(
            "v2_unchanged",
            snap(
                base_locals,
                {deploy: detail(deploy), build: detail(build, grant={"identity_hash": h(build), "state": "blocked"})},
            ),
            bundle(good),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(plan_vector("v2_pending", snap([], {}), bundle(good), DEVICE, FRESH))
    vectors.append(
        plan_vector("v2_unobserved", snap([local(deploy, observed_count=0)], base_details), bundle(good), DEVICE, FRESH)
    )
    vectors.append(
        plan_vector(
            "v2_unobserved_stale", snap([local(deploy, observed_count=0)], base_details), bundle(good), DEVICE, LATE
        )
    )
    removal = {deploy: {"identity_hash": h(deploy), "cloud_revision": 2, "state": "blocked"}}
    vectors.append(
        plan_vector("v2_override", snap(base_locals, base_details, removals=removal), bundle(good), DEVICE, FRESH)
    )
    # Prior applied state maps the scoped identity to a local whose identity changed.
    prior = {
        "schema_version": V2,
        "cloud_revision": 1,
        "observation_digest": "2" * 64,
        "binding": binding(),
        "items": {
            lint: {"workspace_identity_hash": s_deploy, "status": "applied", "local_identity_hash": h(lint)},
            deploy: {"workspace_identity_hash": s_deploy, "status": "applied"},
        },
    }
    changed_locals = [local(deploy, identity_hash=h("rebuilt")), local(lint, identity_hash=None)]
    vectors.append(
        plan_vector(
            "v2_prior_fallback",
            snap(changed_locals, {deploy: detail(deploy), lint: detail(lint)}, previous=prior),
            bundle(good),
            DEVICE,
            FRESH,
        )
    )
    # A context change unsets prior applied grants that are no longer projected.
    old_context = {
        "schema_version": V2,
        "cloud_revision": 3,
        "binding": binding("ws_old"),
        "items": {
            lint: {"status": "applied", "local_identity_hash": h(lint)},
            build: {"status": "applied", "identity_hash": h(build)},
            deploy: {"status": "applied", "identity_hash": h(deploy)},
            "local-cli.gone": {"status": "applied", "identity_hash": h("gone")},
            "local-cli.pending": {"status": "pending_observation"},
            "bad": "x",
        },
    }
    cleanup_locals = [
        local(deploy),
        local(build),
        local(lint),
        local("local-cli.pending"),
        local("local-cli.unseen", observed_count=0),
    ]
    cleanup_details = {
        deploy: detail(deploy),
        build: detail(build, grant={"identity_hash": h("stale"), "state": "allowed"}),
        lint: detail(lint),
        "local-cli.pending": detail("local-cli.pending"),
    }
    only_deploy = obs2([item2(s_deploy)])
    vectors.append(
        plan_vector(
            "v2_context_cleanup",
            snap(cleanup_locals, cleanup_details, previous=old_context),
            bundle(only_deploy),
            DEVICE,
            FRESH,
        )
    )
    lint_override = {lint: {"identity_hash": h(lint), "cloud_revision": 3, "state": "allowed"}}
    vectors.append(
        plan_vector(
            "v2_context_cleanup_override",
            snap(cleanup_locals, cleanup_details, previous=old_context, removals=lint_override),
            bundle(only_deploy),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(
        plan_vector(
            "v2_context_from_v1",
            snap(cleanup_locals, cleanup_details, previous={**old_context, "schema_version": V1, "binding": None}),
            bundle(only_deploy),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(
        plan_vector(
            "v2_context_float_revision",
            snap(cleanup_locals, cleanup_details, previous={**old_context, "cloud_revision": 3.0}),
            bundle(only_deploy),
            DEVICE,
            FRESH,
        )
    )
    vectors.append(plan_vector("v2_sorted_items", base, bundle(obs2([item2(s_build), item2(s_deploy)])), DEVICE, FRESH))
    vectors.append(
        plan_vector(
            "v2_non_ascii_binding",
            base,
            bundle(obs2([item2(scoped(h(deploy), "wś"), devices=[device_hash("wś", "dévice")])]), "wś"),
            "dévice",
            FRESH,
        )
    )
    vectors.append(plan_vector("v1_schema_with_v2_items", base, bundle(obs1([item2(s_deploy)])), DEVICE, FRESH))
    return vectors


def main() -> None:
    vectors = (
        fixed_plan_vectors()
        + fixed_v2_vectors()
        + random_vectors(200)
        + local_mutation_vectors()
        + public_state_vectors()
    )
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "custom_extension_continuity_vectors.json"
    lines = ",\n".join(json.dumps(vector, ensure_ascii=False, separators=(",", ":")) for vector in vectors)
    target.write_text(f"[\n{lines}\n]\n", encoding="utf-8")
    errors = sum(1 for vector in vectors if vector["expected"].get("error"))
    print(f"wrote {len(vectors)} vectors ({errors} refusals) to {target}")


if __name__ == "__main__":
    main()
