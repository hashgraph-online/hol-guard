#!/usr/bin/env python3
"""Record parity vectors for Managed Controls policy-field parsing.

Usage: GUARD_PY_SNAPSHOT=<path to src dir of the reference snapshot> \
    python scripts/record_managed_controls_policy_fields_vectors.py [snapshot_src]

The reference snapshot must predate the move of the parser to the native
runtime. Each vector is one native request (policy document and negotiated
capabilities; the shared catalog projection is stored once) and the
reference answer. The Rust
tests in rust/crates/guard-runtime replay them. Deterministic output.
"""

from __future__ import annotations

import copy
import json
import os
import random
import sys
from pathlib import Path
from types import SimpleNamespace

snapshot = os.environ.get("GUARD_PY_SNAPSHOT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not snapshot:
    sys.exit("set GUARD_PY_SNAPSHOT or pass the snapshot src directory")
sys.path.insert(0, snapshot)

from codex_plugin_scanner.guard import managed_controls_policy_fields as reference  # noqa: E402
from codex_plugin_scanner.guard.runtime.command_extensions import (  # noqa: E402
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "rust/crates/guard-runtime/tests/fixtures/managed_controls_policy_fields_vectors.json"
FIXTURE = json.loads((ROOT / "contracts/managed-controls/v1/policy-extension-fields.fixtures.json").read_text())
CONTROLS = reference.HOL_EXTENSION_CONTROLS_FIELD
TARGETS = reference.HOL_EXTENSION_TARGETS_FIELD
CONTROLS_SCHEMA = reference.HOL_EXTENSION_CONTROLS_SCHEMA_VERSION
TARGETS_SCHEMA = reference.HOL_EXTENSION_TARGETS_SCHEMA_VERSION
REQUIRED_CAPS = (
    reference.EXTENSION_CONTROL_LAYER_CAPABILITY,
    reference.POLICY_EXTENSION_TARGETS_CAPABILITY,
    reference.MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
)
LEGACY_CAPS = tuple(FIXTURE["legacyCapabilityAliases"])
PACKAGE_CAP = reference.PACKAGE_FIREWALL_CAPABILITY
EXTENSIONS = (
    "command.filesystem",
    "command.git",
    "command.system",
    "command.package.node",
    "command.package.python",
    "command.agentbridge",
    "command.backup.restic",
    "command.appimg",
    "command.guard-self-protection",
)
GHOST_PERMISSION = "command.ghost.permission.run"
MODES = ("personal-shared", "workspace-shared", "managed-restrictive")


def catalog_projection() -> dict[str, object]:
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    extensions = {}
    for extension_id in EXTENSIONS:
        extension = registry.get(extension_id)
        assert extension is not None and extension.extension_id == extension_id
        extensions[extension_id] = {
            "required": extension.required,
            "delegated": extension.delegated_protection is not None,
        }
    permissions = {}
    for permission in registry.permissions:
        if permission.extension_id in extensions:
            permissions[permission.permission_id] = {
                "extension_id": permission.extension_id,
                "owner_delegated": extensions[permission.extension_id]["delegated"],
                "configurable": permission.configurable,
            }
    permissions[GHOST_PERMISSION] = {
        "extension_id": "command.ghost",
        "owner_delegated": None,
        "configurable": True,
    }
    return {"extensions": extensions, "permissions": permissions}


CATALOG = catalog_projection()


class FakeRegistry:
    """The reference parser's view of ``CATALOG``."""

    catalog_digest = "0" * 64

    def get(self, extension_id: str):
        entry = CATALOG["extensions"].get(extension_id)
        if entry is None:
            return None
        return SimpleNamespace(
            extension_id=extension_id,
            required=entry["required"],
            delegated_protection="package-firewall" if entry["delegated"] else None,
        )

    def permission(self, permission_id: str):
        entry = CATALOG["permissions"].get(permission_id)
        if entry is None:
            return None
        return SimpleNamespace(
            permission_id=permission_id,
            extension_id=entry["extension_id"],
            configurable=entry["configurable"],
        )


REGISTRY = FakeRegistry()
PERMISSIONS = sorted(CATALOG["permissions"])
CONFIGURABLE = [pid for pid in PERMISSIONS if CATALOG["permissions"][pid]["configurable"]]
IMMUTABLE = [pid for pid in PERMISSIONS if not CATALOG["permissions"][pid]["configurable"]]
UNKNOWN_EXTENSIONS = ("command.unknown", "command.git.extra")
UNKNOWN_PERMISSIONS = ("command.git.permission.nope", "command.unknown.permission.x")
BAD_IDS = ("Command.git", "command.", "command.git..x", "git", "command.git.permission.", 7, None, "command.a-")


def control_json(control) -> dict[str, str]:
    return {
        "target_kind": control.target.kind.value,
        "target_id": control.target.target_id,
        "state": control.state.value,
    }


def answer(parsed) -> dict[str, object]:
    layer = parsed.signed_cloud_layer
    return {
        "authority_mode": parsed.authority_mode,
        "signed_cloud_layer": None
        if layer is None
        else {
            "global_lockdown": layer.global_lockdown,
            "controls": [control_json(control) for control in layer.controls],
        },
        "managed_controls": [control_json(control) for control in parsed.managed_controls],
        "managed_global_lockdown": parsed.managed_global_lockdown,
        "rule_targets": [
            {
                "rule_id": rule.rule_id,
                "extension_ids": list(rule.extension_ids),
                "permission_ids": list(rule.permission_ids),
            }
            for rule in parsed.rule_targets
        ],
        "delegated_targets": [
            {"target_kind": item.target.kind.value, "target_id": item.target.target_id}
            for item in parsed.delegated_targets
        ],
    }


vectors: list[dict[str, object]] = []
skipped = 0


def record(name: str, document: object, capabilities=REQUIRED_CAPS, package: bool = False) -> None:
    global skipped
    caps = frozenset(capabilities)
    try:
        parsed = reference.parse_managed_controls_policy_fields(
            copy.deepcopy(document),
            registry=REGISTRY,
            negotiated_capabilities=caps,
            package_firewall_supported=package,
        )
        expected: dict[str, object] = {"ok": answer(parsed)}
    except reference.ManagedControlsPolicyError as error:
        expected = {"error": {"code": error.code, "message": str(error)}}
    except (TypeError, AttributeError, ValueError):
        # The reference crashed (an unhashable value, or a control target its
        # own contract types reject); the native parser refuses these and the
        # Rust tests cover them directly.
        skipped += 1
        return
    request_caps = sorted(caps | {PACKAGE_CAP} if package else caps)
    vectors.append(
        {
            "name": f"{len(vectors):04d}-{name}",
            "request": {"document": document, "capabilities": request_caps},
            "expected": expected,
        }
    )


def base() -> dict[str, object]:
    return copy.deepcopy(FIXTURE["document"])


def with_controls(document, field) -> dict[str, object]:
    document[CONTROLS] = field
    return document


def layer(mode: str, controls: list[object], **extra: object) -> dict[str, object]:
    return {"schemaVersion": CONTROLS_SCHEMA, "authorityMode": mode, "controls": controls, **extra}


def ctl(kind: object, target: object, state: object) -> dict[str, object]:
    return {"targetKind": kind, "targetId": target, "state": state}


def targets(extension_ids: object, permission_ids: object, **extra: object) -> dict[str, object]:
    return {"schemaVersion": TARGETS_SCHEMA, "extensionIds": extension_ids, "permissionIds": permission_ids, **extra}


def rules(*items: dict[str, object]) -> dict[str, object]:
    document = base()
    document.pop(CONTROLS, None)
    document["spec"]["rules"] = list(items)
    return document


# Fixture and capability negotiation.
record("fixture", base())
record("fixture-package", base(), package=True)
record("fixture-legacy", base(), capabilities=LEGACY_CAPS)
record("fixture-mixed-caps", base(), capabilities=(*REQUIRED_CAPS[:2], LEGACY_CAPS[2], "other.v1"))
for missing in REQUIRED_CAPS:
    record(f"missing-{missing}", base(), capabilities=tuple(cap for cap in REQUIRED_CAPS if cap != missing))
record("no-caps", base(), capabilities=())
plain = base()
plain.pop(CONTROLS)
for rule in plain["spec"]["rules"]:
    rule.pop(TARGETS, None)
record("no-fields-no-caps", plain, capabilities=())
record("no-fields-junk-rules", rules({"id": "r", "matcher": {"regex": "(a+)+$"}}), capabilities=())

# Document shape.
for name, document in (
    ("not-object", []),
    ("spec-missing", {"kind": "GuardPolicy"}),
    ("spec-list", {"spec": []}),
    ("rules-missing", {"spec": {}}),
    ("rules-object", {"spec": {"rules": {}}}),
    ("rule-not-object", {"spec": {"rules": [1]}}),
    ("rule-null", {"spec": {"rules": [None]}}),
    ("controls-null", with_controls(base(), None)),
    ("controls-list", with_controls(base(), [])),
    ("controls-string", with_controls(base(), "controls")),
    ("targets-null", rules({"id": "r", TARGETS: None})),
    ("targets-list", rules({"id": "r", TARGETS: []})),
):
    record(name, document)

# Control layer header.
for name, field in (
    ("schema-only", {"schemaVersion": CONTROLS_SCHEMA}),
    ("schema-number", {"schemaVersion": 1, "authorityMode": "workspace-shared", "controls": []}),
    ("schema-wrong", layer("workspace-shared", []) | {"schemaVersion": "guard.extension-controls.v2"}),
    ("controls-not-array", layer("workspace-shared", "not-an-array")),
    ("controls-missing", {"schemaVersion": CONTROLS_SCHEMA, "authorityMode": "workspace-shared"}),
    ("unknown-field", layer("workspace-shared", []) | {"extra": 1}),
    ("unknown-field-nul", layer("workspace-shared", []) | {f"{CONTROLS}\x00": {}}),
    ("mode-bad", layer("personal", [])),
    ("mode-number", layer(3, [])),
    ("mode-missing", {"schemaVersion": CONTROLS_SCHEMA, "controls": []}),
    ("lockdown-false", layer("managed-restrictive", [], globalLockdown=False)),
    ("lockdown-null", layer("managed-restrictive", [], globalLockdown=None)),
    ("lockdown-one", layer("managed-restrictive", [], globalLockdown=1)),
    ("lockdown-one-float", layer("managed-restrictive", [], globalLockdown=1.0)),
    ("lockdown-zero", layer("managed-restrictive", [], globalLockdown=0)),
    ("lockdown-string", layer("managed-restrictive", [], globalLockdown="true")),
    ("lockdown-true", layer("managed-restrictive", [], globalLockdown=True)),
    ("lockdown-shared", layer("workspace-shared", [], globalLockdown=True)),
    ("lockdown-personal", layer("personal-shared", [], globalLockdown=True)),
    ("empty-shared", layer("personal-shared", [])),
):
    record(name, with_controls(base(), field))

# Individual controls.
for name, control in (
    ("control-list", []),
    ("control-extra", ctl("extension", "command.git", "disabled") | {"x": 1}),
    ("control-kind-bad", ctl("rule", "command.git", "disabled")),
    ("control-kind-missing", {"targetId": "command.git", "state": "disabled"}),
    ("control-state-bad", ctl("extension", "command.git", "off")),
    ("control-state-before-id", ctl("extension", 5, "off")),
    ("control-ext-as-perm", ctl("permission", "command.git", "disabled")),
    ("control-perm-as-ext", ctl("extension", "command.git.permission.force-push", "disabled")),
    ("control-long-id", ctl("permission", "command." + "a" * 300, "disabled")),
    ("control-ghost-owner", ctl("permission", GHOST_PERMISSION, "disabled")),
    ("control-unicode", ctl("extension", "command.gït", "disabled")),
    ("control-newline", ctl("extension", "command.git\n", "disabled")),
):
    for mode in MODES:
        record(f"{name}-{mode}", with_controls(base(), layer(mode, [control])))
for bad in (*BAD_IDS, *UNKNOWN_EXTENSIONS):
    record(
        f"control-ext-id-{bad!r}", with_controls(base(), layer("workspace-shared", [ctl("extension", bad, "disabled")]))
    )
for bad in (*BAD_IDS, *UNKNOWN_PERMISSIONS):
    record(
        f"control-perm-id-{bad!r}",
        with_controls(base(), layer("workspace-shared", [ctl("permission", bad, "disabled")])),
    )
record(
    "duplicate",
    with_controls(base(), layer("workspace-shared", [ctl("extension", "command.agentbridge", "disabled")] * 2)),
)
record(
    "conflict",
    with_controls(
        base(),
        layer(
            "workspace-shared",
            [ctl("permission", CONFIGURABLE[0], "disabled"), ctl("permission", CONFIGURABLE[0], "enabled")],
        ),
    ),
)

# Rule targets. Size limits are covered by the Rust tests, which build the
# oversized documents in code.
for name, rule_targets in (
    ("targets-extra", targets(["command.git"], [], extra=1)),
    ("targets-schema", targets(["command.git"], []) | {"schemaVersion": "guard.policy-extension-targets.v2"}),
    ("targets-ext-not-list", targets("command.git", [])),
    ("targets-perm-not-list", targets([], {})),
    ("targets-ext-missing", {"schemaVersion": TARGETS_SCHEMA, "permissionIds": []}),
    ("targets-dup", targets(["command.git", "command.git"], [])),
    ("targets-unsorted", targets(["command.system", "command.git"], ["command.git.permission.force-push"])),
    ("targets-mismatch", targets(["command.system"], ["command.git.permission.force-push"])),
    ("targets-perm-only", targets([], ["command.git.permission.force-push"])),
    ("targets-ghost", targets([], [GHOST_PERMISSION])),
    ("targets-ghost-owned", targets(["command.git"], [GHOST_PERMISSION])),
    ("targets-unknown-ext", targets(["command.unknown"], [])),
    ("targets-unknown-perm", targets([], ["command.git.permission.nope"])),
    ("targets-bad-ext", targets(["git"], [])),
    ("targets-bad-perm", targets([], ["command.git"])),
    ("targets-empty", targets([], [])),
    ("targets-delegated-ext", targets(["command.package.node"], [])),
):
    for package in (False, True):
        record(f"{name}-pkg{int(package)}", rules({"id": "r1", TARGETS: rule_targets}), package=package)
for name, rule in (
    ("rule-no-id", {TARGETS: targets(["command.git"], [])}),
    ("rule-empty-id", {"id": "", TARGETS: targets(["command.git"], [])}),
    ("rule-number-id", {"id": 3, TARGETS: targets(["command.git"], [])}),
    ("rule-bad-id-after-bad-target", {"id": "", TARGETS: targets(["command.unknown"], [])}),
):
    record(name, rules(rule))
record("controls-and-bad-rule", with_controls(rules({"id": "r", TARGETS: []}), layer("workspace-shared", [])))

# Randomised layers and rule targets against the catalog projection.
rng = random.Random(4207)
ALL_EXTENSIONS = (*EXTENSIONS, *UNKNOWN_EXTENSIONS)
ALL_PERMISSIONS = (*PERMISSIONS, *UNKNOWN_PERMISSIONS)


def random_control(mode: str) -> dict[str, object]:
    if rng.random() < 0.45:
        target = ("extension", rng.choice(ALL_EXTENSIONS))
    else:
        pool = rng.choice((CONFIGURABLE, IMMUTABLE, ALL_PERMISSIONS))
        target = ("permission", rng.choice(pool))
    disabled = 0.85 if mode == "managed-restrictive" else 0.5
    state = "disabled" if rng.random() < disabled else "enabled"
    return ctl(target[0], target[1], state)


def random_rule(index: int) -> dict[str, object]:
    extension_ids = sorted(set(rng.sample(EXTENSIONS, rng.randint(0, 2))))
    owned = [pid for pid in PERMISSIONS if CATALOG["permissions"][pid]["extension_id"] in extension_ids]
    pool = owned if owned and rng.random() < 0.8 else PERMISSIONS
    permission_ids = sorted(set(rng.sample(pool, min(len(pool), rng.randint(0, 3)))))
    rule: dict[str, object] = {"id": f"rule-{index}"}
    if rng.random() < 0.85:
        rule[TARGETS] = targets(extension_ids, permission_ids)
    return rule


for index in range(260):
    mode = rng.choice(MODES)
    document = rules(*(random_rule(i) for i in range(rng.randint(0, 3))))
    if rng.random() < 0.8:
        controls = [random_control(mode) for _ in range(rng.randint(0, 4))]
        extra = {"globalLockdown": True} if mode == "managed-restrictive" and rng.random() < 0.3 else {}
        document[CONTROLS] = layer(mode, controls, **extra)
    caps = REQUIRED_CAPS if rng.random() < 0.9 else LEGACY_CAPS
    record(f"random-{index}-{mode}", document, capabilities=caps, package=rng.random() < 0.5)

OUT.parent.mkdir(parents=True, exist_ok=True)
body = ",\n".join(json.dumps(vector, sort_keys=True) for vector in vectors)
OUT.write_text('{"catalog": ' + json.dumps(CATALOG, sort_keys=True) + ',\n"vectors": [\n' + body + "\n]}\n")
print(f"wrote {len(vectors)} vectors ({skipped} reference crashes skipped) to {OUT.relative_to(ROOT)}")
