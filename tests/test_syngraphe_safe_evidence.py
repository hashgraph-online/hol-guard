import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.native_command_test_support import real_native_review_fixture


def test_syngraphe_catalog_only_advertises_reachable_dry_run_variants() -> None:
    extension = next(
        item for item in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions if item.extension_id == "command.syngraphe"
    )
    assert extension.rules
    for rule in extension.rules:
        assert {variant.variant_id for variant in rule.safe_variants} == {"dry-run"}


@pytest.mark.parametrize("executable", ["syngraphe", "syg"])
@pytest.mark.parametrize("operation", ["init", "policy add", "truth new example", "state archive example"])
@pytest.mark.parametrize("flag", ["--help", "-h", "--version", "-v"])
def test_syngraphe_help_and_version_do_not_match_mutating_rules(executable: str, operation: str, flag: str) -> None:
    fixture = real_native_review_fixture(
        f"{executable} {operation} {flag}",
        controls=(("extension", "command.syngraphe", "enabled"),),
    )
    observations = fixture.payload["command_extensions"]["observations"]
    assert all(item["extension_id"] != "command.syngraphe" for item in observations)


@pytest.mark.parametrize(
    "extension,command", [("command.syngraphe", "syngraphe init"), ("command.errand", "errand run example")]
)
def test_contributed_commands_stay_inert_until_enabled(extension: str, command: str) -> None:
    inert = real_native_review_fixture(command).payload["command_extensions"]["observations"]
    assert all(item["extension_id"] != extension for item in inert)
    enabled = real_native_review_fixture(command, controls=(("extension", extension, "enabled"),)).payload[
        "command_extensions"
    ]["observations"]
    assert any(item["extension_id"] == extension and item["effective_segment_indexes"] for item in enabled)
