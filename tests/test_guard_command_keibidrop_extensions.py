"""Structured KeibiDrop command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

_EXTENSION_ID = "command.keibidrop"

# A kd peer code is 86 characters of base64 RawURL. This one is random and
# belongs to no identity; it is here to prove no evidence field repeats it.
_PEER_CODE = "gmamImPWNd2aOM2PSe7_umNiqGaBRSKV9ma_5JIRbKPk5v_r52-qcvIS7mYjx1oCE2JOLzdL4TBpiPIZUUalHw"

KEIBIDROP_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "kd add ./quarterly-report.pdf",
        "keibidrop file share command",
        "command.keibidrop.share-file",
    ),
    (
        "kd add /Users/me/.ssh/id_ed25519",
        "keibidrop file share command",
        "command.keibidrop.share-file",
    ),
    (
        "kd add-as ./quarterly-report.pdf holiday-photos.pdf",
        "keibidrop file share command",
        "command.keibidrop.share-file",
    ),
    (
        "kd pull report.mov",
        "keibidrop remote file write command",
        "command.keibidrop.pull-file",
    ),
    (
        "kd pull report.mov ./downloads/report.mov",
        "keibidrop remote file write command",
        "command.keibidrop.pull-file",
    ),
    (
        "kd pull-async report.mov",
        "keibidrop remote file write command",
        "command.keibidrop.pull-file",
    ),
    (
        "kd bench-pull report.mov",
        "keibidrop remote file write command",
        "command.keibidrop.pull-file",
    ),
    (
        f"kd register {_PEER_CODE}",
        "keibidrop peer authorization command",
        "command.keibidrop.register-peer",
    ),
    (
        f"kd register https://keibidrop.com/join.html#{_PEER_CODE}",
        "keibidrop peer authorization command",
        "command.keibidrop.register-peer",
    ),
    (
        "kd pull report.mov --timeout 30",
        "keibidrop remote file write command",
        "command.keibidrop.pull-file",
    ),
    (
        "kd pull --timeout=30 report.mov",
        "keibidrop remote file write command",
        "command.keibidrop.pull-file",
    ),
    (
        "kd add ./notes.txt --unknown-flag",
        "keibidrop file share command",
        "command.keibidrop.share-file",
    ),
)


def _matched_rules(command: str, tmp_path: Path) -> set[str]:
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
        parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
    )
    return {item.rule.rule_id for item in observations if item.extension.extension_id == _EXTENSION_ID}


def test_keibidrop_write_verbs_attribute_to_their_rules(tmp_path: Path) -> None:
    """Every sharing, pulling, and peer-authorizing verb reaches its own rule."""

    for command, _action_class, expected_rule in KEIBIDROP_REVIEW_CASES:
        assert expected_rule in _matched_rules(command, tmp_path), command


KEIBIDROP_LAUNCHER_CASES: tuple[tuple[str, str], ...] = (
    ("/usr/local/bin/kd pull report.mov", "command.keibidrop.pull-file"),
    ("kd.exe pull report.mov", "command.keibidrop.pull-file"),
    ("KD_SAVE_PATH=./received kd pull report.mov", "command.keibidrop.pull-file"),
    ("sudo kd add /etc/shadow", "command.keibidrop.share-file"),
    ("env kd add ./notes.txt", "command.keibidrop.share-file"),
    ("exec kd pull report.mov", "command.keibidrop.pull-file"),
    ("exec kd add-as ./notes.txt readme.txt", "command.keibidrop.share-file"),
    ("xargs kd pull report.mov", "command.keibidrop.pull-file"),
    ("xargs -n 1 kd pull report.mov", "command.keibidrop.pull-file"),
    (f"xargs -n 1 kd register {_PEER_CODE}", "command.keibidrop.register-peer"),
    ("kd list && kd pull report.mov", "command.keibidrop.pull-file"),
    ("kd status; kd add ./notes.txt", "command.keibidrop.share-file"),
    ('kd add "/Users/me/Documents/tax return.pdf"', "command.keibidrop.share-file"),
)


def test_keibidrop_launcher_and_wrapper_invocations_reach_the_same_rules(tmp_path: Path) -> None:
    """Absolute paths, env prefixes, sudo, wrappers, and separators keep meaning."""

    for command, expected_rule in KEIBIDROP_LAUNCHER_CASES:
        assert expected_rule in _matched_rules(command, tmp_path), command


# The read-only half of the kd surface. add-contact and remove-contact sit next
# to add and register by name and must not be pulled in by them.
KEIBIDROP_READ_ONLY_COMMANDS: tuple[str, ...] = (
    "kd list",
    "kd contacts",
    "kd status",
    "kd show",
    "kd show fingerprint",
    "kd show all",
    "kd peer-info",
    "kd transfers",
    "kd mount-info",
    "kd progress report.mov",
    "kd file-size report.mov",
    "kd config-path",
    "kd log-path",
    "kd version",
    "kd help",
    "kd --help",
    "kd -h",
    "kd add-contact Alice " + _PEER_CODE,
    "kd remove-contact " + _PEER_CODE,
    "kd unshare notes.txt",
    "kd invite",
    "kd connect",
    "kd disconnect",
    # kd.exe is also the Microsoft kernel debugger, which takes no verb here.
    "kd.exe -k net:port=50000",
)


def test_keibidrop_read_only_verbs_produce_no_observation(tmp_path: Path) -> None:
    """A read-only verb never reaches a KeibiDrop rule, unlike pull beside it."""

    assert _matched_rules("kd pull report.mov", tmp_path) == {"command.keibidrop.pull-file"}
    for command in KEIBIDROP_READ_ONLY_COMMANDS:
        assert _matched_rules(command, tmp_path) == set(), command


# kd reads its verb at argv[1] and nowhere else, so an option in that position
# means a different command ran. `kd --help pull` prints help and
# `kd --timeout 30 pull x` fails on an unknown verb; neither pulls anything.
KEIBIDROP_OPTION_BEFORE_VERB_COMMANDS: tuple[str, ...] = (
    "kd --timeout 30 pull report.mov",
    "kd --timeout=30 pull report.mov",
    "kd --help pull",
    "kd -h pull",
    "kd --help add ./notes.txt",
    "kd --timeout 30 register " + _PEER_CODE,
)


def test_keibidrop_an_option_before_the_verb_is_not_that_verb(tmp_path: Path) -> None:
    for command in KEIBIDROP_OPTION_BEFORE_VERB_COMMANDS:
        assert _matched_rules(command, tmp_path) == set(), command
    assert_safe_command_cases(KEIBIDROP_OPTION_BEFORE_VERB_COMMANDS, tmp_path)


def test_keibidrop_wrappers_keep_conservative_option_parsing(tmp_path: Path) -> None:
    """An unknown wrapper option still cannot hide the verb behind it."""

    assert _matched_rules("xargs -X kd pull report.mov", tmp_path) == {"command.keibidrop.pull-file"}


def test_keibidrop_read_only_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(KEIBIDROP_READ_ONLY_COMMANDS, tmp_path)


def test_keibidrop_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in KEIBIDROP_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != _EXTENSION_ID for item in evaluation.extension_observations)


def test_keibidrop_evidence_never_carries_the_peer_code_or_shared_path(tmp_path: Path) -> None:
    """A peer code is an identity and a shared path is private; neither is evidence."""

    assert len(_PEER_CODE) == 86
    secrets = (_PEER_CODE, "tax return.pdf", "id_ed25519")
    commands = (
        f"kd register {_PEER_CODE}",
        'kd add "/Users/me/Documents/tax return.pdf"',
        "kd add /Users/me/.ssh/id_ed25519",
    )
    for command in commands:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        for item in observations:
            if item.extension.extension_id != _EXTENSION_ID:
                continue
            rendered = repr(item.to_dict()) + repr(item.matcher_evidence) + repr(item.rule.to_dict())
            for secret in secrets:
                assert secret not in rendered, command


def test_keibidrop_extension_owns_its_declared_surface() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
    assert {rule.rule_id for rule in extension.rules} == {
        "command.keibidrop.share-file",
        "command.keibidrop.pull-file",
        "command.keibidrop.register-peer",
    }
    assert all(rule.default_mode == "review" for rule in extension.rules)
