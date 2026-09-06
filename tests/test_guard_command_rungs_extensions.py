"""Structured rungs command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.package_intent import parse_package_intent
from tests.command_extension_contracts import assert_safe_command_cases

_EXTENSION_ID = "command.rungs"
_CHECK = "rungs gate execution command"
_ADD = "rungs module install command"
_UPGRADE = "rungs module upgrade command"

# Behaviour verified against @rungs/cli 0.4.0 (git tag v0.4.0, src/cli.ts): the
# command is argv[2], every later `--` token is a switch wherever it sits, only
# --set consumes a value, and --help after a command is an ordinary switch.
RUNGS_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    # check executes every registered command gate and appends to the ledger.
    ("rungs check", _CHECK, "command.rungs.check"),
    ("rungs check .", _CHECK, "command.rungs.check"),
    ("rungs check . full", _CHECK, "command.rungs.check"),
    ("rungs check --fast", _CHECK, "command.rungs.check"),
    ("rungs check --full", _CHECK, "command.rungs.check"),
    # check never reads --dry-run, so the switch is not a preview.
    ("rungs check --dry-run", _CHECK, "command.rungs.check"),
    # --help is only a help request in the command slot; here the gates run.
    ("rungs check --help", _CHECK, "command.rungs.check"),
    ("rungs.cmd check", _CHECK, "command.rungs.check"),
    ("rungs.exe check", _CHECK, "command.rungs.check"),
    ("./node_modules/.bin/rungs check", _CHECK, "command.rungs.check"),
    # A tier named like a command is still a positional of check. rungs refuses
    # an undeclared tier without running anything, but Guard cannot read the
    # registry, so the run reviews as the execution it can be.
    ("rungs check add", _CHECK, "command.rungs.check"),
    # add writes files, gates, the record and the rendered harness files.
    ("rungs add backlog", _ADD, "command.rungs.add"),
    ("rungs add backlog gates session", _ADD, "command.rungs.add"),
    ("rungs add backlog --into ../repo", _ADD, "command.rungs.add"),
    ("rungs add --set backlog.root=docs/backlog backlog", _ADD, "command.rungs.add"),
    ("rungs add backlog --confirm-paradigm --confirm-threshold", _ADD, "command.rungs.add"),
    ("rungs add backlog --copilot", _ADD, "command.rungs.add"),
    # A bare add still writes the install record and the render report.
    ("rungs add", _ADD, "command.rungs.add"),
    ("rungs add backlog --help", _ADD, "command.rungs.add"),
    # --apply belongs to upgrade; add ignores it and writes.
    ("rungs add backlog --apply", _ADD, "command.rungs.add"),
    # A module named like a command is still an install request.
    ("rungs add check", _ADD, "command.rungs.add"),
    # Forged previews. --set consumes the next token, so the switch never
    # reaches the parser; a value that merely contains the text is a value.
    ("rungs add backlog --set --dry-run", _ADD, "command.rungs.add"),
    ("rungs add backlog --set backlog.root=--dry-run", _ADD, "command.rungs.add"),
    # rungs 0.4.0 would treat these as a dry run, but a disabled assignment
    # and an unknown option that may swallow the switch cannot prove it, so
    # Guard reviews rather than trusts the string.
    ("rungs add backlog --dry-run=false", _ADD, "command.rungs.add"),
    ("rungs add backlog --mystery --dry-run", _ADD, "command.rungs.add"),
    # upgrade writes only with --apply, in any spelling rungs accepts.
    ("rungs upgrade --apply", _UPGRADE, "command.rungs.upgrade"),
    ("rungs upgrade . --apply", _UPGRADE, "command.rungs.upgrade"),
    ("rungs upgrade --apply .", _UPGRADE, "command.rungs.upgrade"),
    # upgrade never reads --dry-run: this writes.
    ("rungs upgrade --apply --dry-run", _UPGRADE, "command.rungs.upgrade"),
    # rungs registers the bare name of an assigned switch, so this applies too.
    ("rungs upgrade --apply=false", _UPGRADE, "command.rungs.upgrade"),
    ("rungs upgrade --apply --help", _UPGRADE, "command.rungs.upgrade"),
)

RUNGS_SAFE_COMMANDS: tuple[str, ...] = (
    # doctor reads the tree, the record and the ledger. --explain runs the
    # detectors in-process, skips command gates and only queries git read-only.
    "rungs doctor",
    "rungs doctor .",
    "rungs doctor ../other-repo",
    "rungs doctor --explain",
    "rungs doctor . --explain",
    "rungs doctor --explain --copilot",
    # doctor ignores every switch but --explain, so a stray one changes nothing.
    "rungs doctor --dry-run",
    "rungs doctor --apply",
    "rungs doctor --full",
    # A positional that spells another command is a path argument of doctor.
    "rungs doctor add",
    "rungs doctor upgrade --explain",
    "rungs doctor check",
    # upgrade without --apply prints the plan and writes nothing.
    "rungs upgrade",
    "rungs upgrade .",
    "rungs upgrade --dry-run",
    "rungs upgrade --explain",
    # --set that swallows --apply is refused by rungs before dispatch.
    "rungs upgrade --set --apply",
    # add --dry-run skips every write site: files, gates, record and render.
    "rungs add backlog --dry-run",
    "rungs add --dry-run backlog",
    "rungs add backlog gates --dry-run",
    "rungs add backlog --into ../repo --dry-run",
    "rungs add backlog --dry-run --into ../repo",
    "rungs add --set backlog.root=docs/backlog backlog --dry-run",
    "rungs add backlog --set=backlog.root=docs --dry-run",
    "rungs add backlog --confirm-paradigm --confirm-conflict --dry-run",
    "rungs add backlog --dry-run=yes",
    "rungs add --dry-run",
    "rungs.cmd add backlog --dry-run",
    # Help and inventory.
    "rungs",
    "rungs --help",
    "rungs -h",
    "rungs help",
    "rungs modules",
    "rungs modules --params",
    # Neither a mention nor a search is an invocation.
    "echo rungs add backlog",
    "grep 'rungs check' docs/getting-started.md",
)

# Deliberately outside this extension: init and eject were deferred by the
# maintainer, and the rest are not part of the first capability boundary. They
# keep Guard's established fallback for a command no extension owns.
RUNGS_OUT_OF_SCOPE_COMMANDS: tuple[str, ...] = (
    "rungs bogus",
    "rungs init . tracked",
    "rungs eject",
    "rungs render",
    "rungs setup git",
    "rungs backlog archive",
    "rungs hook gate-id",
    # A source checkout runs the TypeScript entry point directly.
    "node src/cli.ts check",
)

RUNGS_WRAPPED_CASES: tuple[tuple[str, frozenset[str]], ...] = (
    ("sh -c 'rungs upgrade --apply'", frozenset({"command.rungs.upgrade"})),
    ("bash -lc 'rungs check'", frozenset({"command.rungs.check"})),
    ("time rungs check", frozenset({"command.rungs.check"})),
    ("nohup rungs check", frozenset({"command.rungs.check"})),
    ("env RUNGS_DATE=2026-09-06 rungs add backlog", frozenset({"command.rungs.add"})),
    # Inspection followed by a write: the write is what reviews.
    ("rungs doctor && rungs add backlog", frozenset({"command.rungs.add"})),
    # Two independent effects stay two independent findings.
    ("rungs check || rungs upgrade --apply", frozenset({"command.rungs.check", "command.rungs.upgrade"})),
    # A preview does not launder the real run beside it.
    ("rungs add backlog --dry-run && rungs add backlog", frozenset({"command.rungs.add"})),
    ("cd repo && rungs check", frozenset({"command.rungs.check"})),
)

# The npm launchers fetch and execute a package. Guard's package firewall owns
# that policy, as it does for skill-sunset; this extension matches only the
# installed CLI. The launcher forms therefore keep exactly the treatment they
# had, and doctor behind a launcher is not exempted by anything here.
RUNGS_LAUNCHER_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("npx @rungs/cli doctor", "npx", "@rungs/cli"),
    ("npx rungs add backlog", "npx", "rungs"),
    ("npx @rungs/cli add backlog", "npx", "@rungs/cli"),
    ("npm exec @rungs/cli -- add backlog", "npm", "@rungs/cli"),
    ("bunx @rungs/cli check", "bunx", "@rungs/cli"),
)


def _rungs_control_layer(state: ControlState) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, _EXTENSION_ID),
                state=state,
            ),
        ),
    )


def _enabled_rule_ids(command: str, tmp_path: Path) -> set[str]:
    """Return the rungs rules that review once a local admin enables the extension."""

    evaluation = evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_rungs_control_layer(ControlState.ENABLED),),
    )
    return {owned.match.rule.rule_id for owned in evaluation.matches if owned.extension.extension_id == _EXTENSION_ID}


def test_rungs_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in RUNGS_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path, extension_control_layers=())
        assert evaluation.controlling_rule_id != rule_id, command
        assert all(item.extension.extension_id != _EXTENSION_ID for item in evaluation.extension_observations), command


def test_rungs_rules_review_once_a_local_admin_enables_them(tmp_path: Path) -> None:
    failures: list[str] = []
    for command, action_class, rule_id in RUNGS_REVIEW_CASES:
        enabled = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(_rungs_control_layer(ControlState.ENABLED),),
        )
        matched = {
            owned.match.rule.rule_id for owned in enabled.matches if owned.extension.extension_id == _EXTENSION_ID
        }
        if (
            matched != {rule_id}
            or enabled.controlling_rule_id != rule_id
            or enabled.controlling_action_class != action_class
            or enabled.minimum_action != "review"
        ):
            failures.append(
                f"{command!r}: rules={sorted(matched)!r}, controlling={enabled.controlling_rule_id!r}, "
                f"action={enabled.controlling_action_class!r}, minimum={enabled.minimum_action!r}; "
                f"expected {rule_id!r} / {action_class!r} / 'review'"
            )
        disabled = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(_rungs_control_layer(ControlState.DISABLED),),
        )
        if any(item.extension.extension_id == _EXTENSION_ID for item in disabled.matches):
            failures.append(f"{command!r}: still matched while disabled")
    assert not failures, "\n".join(failures)


def test_rungs_inspection_and_previews_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(RUNGS_SAFE_COMMANDS, tmp_path)
    # The inert default would make the assertion above vacuous for this
    # extension, so prove it again with the extension switched on.
    reviewed = {command: _enabled_rule_ids(command, tmp_path) for command in RUNGS_SAFE_COMMANDS}
    assert not {command: rules for command, rules in reviewed.items() if rules}


def test_rungs_help_switch_is_never_a_preview() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)
    assert extension is not None
    variants = {rule.rule_id: tuple(variant.variant_id for variant in rule.safe_variants) for rule in extension.rules}
    assert variants == {
        "command.rungs.check": (),
        "command.rungs.add": ("dry-run",),
        "command.rungs.upgrade": (),
    }


def test_rungs_wrappers_and_compound_commands_keep_every_effect(tmp_path: Path) -> None:
    failures: list[str] = []
    for command, expected in RUNGS_WRAPPED_CASES:
        matched = _enabled_rule_ids(command, tmp_path)
        if matched != expected:
            failures.append(f"{command!r}: rules={sorted(matched)!r}; expected {sorted(expected)!r}")
    assert not failures, "\n".join(failures)
    # An unresolved `cd` already reviews on its own; the rungs evidence is
    # added beside that finding rather than replacing it.
    payload = inspect_command("cd repo && rungs check", cwd=tmp_path, home_dir=tmp_path)
    assert payload["status"] == "review"


def test_rungs_launchers_keep_guard_package_treatment(tmp_path: Path) -> None:
    for command, manager, package_name in RUNGS_LAUNCHER_COMMANDS:
        assert _enabled_rule_ids(command, tmp_path) == set(), command
        intent = parse_package_intent(command)
        assert intent is not None, command
        assert intent.package_manager == manager, command
        assert intent.intent_kind == "execute", command
        assert intent.targets[0].package_name == package_name, command
    # Repository inspection behind a launcher is not a blanket exemption.
    payload = inspect_command("npx @rungs/cli doctor", cwd=tmp_path, home_dir=tmp_path)
    classification = payload["classification"]
    assert isinstance(classification, dict)
    assert classification["explicitly_benign"] is False


def test_rungs_out_of_scope_commands_keep_guard_fallback(tmp_path: Path) -> None:
    for command in RUNGS_OUT_OF_SCOPE_COMMANDS:
        assert _enabled_rule_ids(command, tmp_path) == set(), command
        payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert payload["status"] == "no_match", command


def test_rungs_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)

    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
    assert extension.risk_classes == ("destructive_shell", "execution")
    assert risk_classes_for_command_action(_CHECK) == ("execution", "destructive_shell")
    assert risk_classes_for_command_action(_ADD) == ("destructive_shell",)
    assert risk_classes_for_command_action(_UPGRADE) == ("destructive_shell",)
