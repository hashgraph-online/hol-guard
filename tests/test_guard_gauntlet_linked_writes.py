"""Physical protected-inode integrity for linked write scenarios."""

from ci.gauntlet.fixtures import create_fixture, filesystem_checks


def test_linked_destination_fixture_detects_protected_inode_mutation(tmp_path):
    """A harmless-looking link must refer to, and protect, the synthetic secret inode."""
    fixture = create_fixture(tmp_path / "fixture")
    linked = fixture.workspace / "aliases/linked.txt"
    assert linked.samefile(fixture.workspace / ".env")
    assert all(filesystem_checks(fixture, "blocked-command", "linked-destination-copy").values())
    linked.write_text("synthetic replacement\n", encoding="utf-8")
    assert filesystem_checks(fixture, "blocked-command", "linked-destination-copy")["protected:.env"] is False
