"""Structured blitcp transfer command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)
from tests.native_command_test_support import real_native_command_evaluation

BLITCP_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "blitcp /data s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data az://container/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data gs://bucket/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data smb://fileserver/share",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    # Several sources into one destination is the documented multi-source form,
    # so the last operand is still what decides direction.
    (
        "blitcp /srv/a /srv/b /srv/c s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    # An option that consumes its value must not shift which operand is last.
    (
        "blitcp --threads 8 /data s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp --exclude '*.tmp' /data s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp.exe /data s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    # SSH is blitcp's oldest remote transport and is the same egress as an
    # object-store write, so it belongs to the same rule.
    (
        "blitcp /data user@host.example:/srv/backup",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data host.example:/srv/backup",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data user@[2001:db8::1]:/srv/backup",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data user@host.example:/srv/backup --ssh-dst-port 2222",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    # A saved connection is the third remote-destination syntax. The colon form
    # is structurally recognizable, so it reviews on its own; a bare name only
    # reviews when --credentials-file puts saved connections in play on the
    # command itself.
    (
        "blitcp /data azure-prod:backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data gcs:",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp --threads 8 /data aws-dev:bucket/key",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp --credentials-file /home/backup/creds.json /data azure-prod",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    # A colon inside a path is not a connection reference — blitcp's saved-
    # connection parser leaves it alone — but blitcp's own parse_remote_path
    # then reads it as an SSH target (host "sub/dir"), so the write leaves the
    # host and the host matcher reviews it for the same reason blitcp dials it.
    (
        "blitcp /data sub/dir:name",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data ./odd:name",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp --use-sudo /var/lib/data /mnt/backup",
        "Blitcp privilege escalation command",
        "command.blitcp.privilege-escalation",
    ),
    # `creds lock`/`creds unlock --use-sudo` re-exec the tool under root to
    # change credentials-file immutability — the same elevation as a sudo copy,
    # reached through a subcommand the copy matchers exclude.
    (
        "blitcp creds lock --use-sudo",
        "Blitcp privilege escalation command",
        "command.blitcp.privilege-escalation",
    ),
    (
        "blitcp creds unlock --use-sudo",
        "Blitcp privilege escalation command",
        "command.blitcp.privilege-escalation",
    ),
    (
        "blitcp --update",
        "Blitcp self-update command",
        "command.blitcp.self-update",
    ),
    (
        "blitcp --no-verify /data /mnt/backup",
        "Blitcp unverified copy command",
        "command.blitcp.unverified-copy",
    ),
)


def test_blitcp_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in BLITCP_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.blitcp" for item in evaluation.extension_observations)


BLITCP_SAFE_COMMANDS: tuple[str, ...] = (
    # The maintainer's direction contract: a remote SOURCE is a read, and a
    # restore must not prompt the way an upload does.
    "blitcp s3://backups/nightly /local/restore",
    "blitcp az://container/nightly /local/restore",
    "blitcp gs://bucket/nightly /local/restore",
    "blitcp smb://fileserver/share /local/restore",
    # A preview of an upload plans the transfer without performing it.
    "blitcp --dry-run /data s3://backups/nightly",
    "blitcp /data s3://backups/nightly --dry-run",
    # A dry run verifies nothing because it copies nothing, so --no-verify
    # on a preview describes no risk.
    "blitcp --dry-run --no-verify /data /mnt/backup",
    "blitcp --dry-run --no-verify /data s3://backups/nightly",
    # An SSH source is a restore, exactly as an object-store source is.
    "blitcp user@host.example:/srv/backup /local/restore",
    "blitcp host.example:/srv/backup /local/restore",
    "blitcp --dry-run /data user@host.example:/srv/backup",
    # A single-letter host is a Windows drive, not a remote — blitcp itself
    # makes this distinction, so a copy to C:\\backup must not read as egress.
    "blitcp /data C:\\backup",
    "blitcp C:\\data D:\\backup",
    # Purely local copies carry none of these risks.
    "blitcp /data /mnt/usb",
    "blitcp -a /data /mnt/usb",
    "blitcp --version",
    "blitcp --help",
    "blitcp --check-update",
    # blitcp only accepts lower-case schemes, so an upper-case one would flag a
    # command blitcp itself refuses to run.
    "blitcp /data S3://backups/nightly",
    # A scheme that is not a supported remote endpoint is an ordinary path.
    "blitcp /data ftp://host/share",
    # The scheme has to start the operand, not merely appear inside it.
    "blitcp /data /mnt/s3://notascheme",
    # A saved connection as the SOURCE is a restore, like every other remote
    # source above.
    "blitcp azure-prod:backups/nightly /local/restore",
    "blitcp --credentials-file /home/backup/creds.json azure-prod /local/restore",
    "blitcp --dry-run /data azure-prod:backups/nightly",
    # A bare name without --credentials-file is indistinguishable from a local
    # directory, so it must stay silent — prompting here would be the
    # any-operand noise the rule exists to avoid.
    "blitcp /data azure-prod",
    "blitcp /data backups/",
    # blitcp dispatches subcommands on its literal first argument, and none of
    # them copies anything: `ls` reads a remote, `creds` manages the store.
    "blitcp ls s3://backups/nightly",
    "blitcp ls azure-prod:",
    "blitcp list-objects s3://backups/nightly",
    "blitcp creds edit azure-prod extra-operand",
    # Without --use-sudo the creds lock/unlock re-exec never happens, so there
    # is no elevation to review.
    "blitcp creds lock",
    "blitcp creds unlock",
    # The flag rules describe how a copy runs, so without the shape of a copy —
    # a source and a destination — they describe no risk.
    "blitcp --use-sudo",
    "blitcp --use-sudo --help",
    "blitcp --no-verify",
    "blitcp --no-verify /only-one-operand",
    # Neither a mention of the command nor a grep for it is an invocation.
    "grep 'blitcp /data s3://bucket' docs",
    "echo blitcp /data s3://backups/nightly",
)


def test_blitcp_reads_and_previews_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(BLITCP_SAFE_COMMANDS, tmp_path)


def test_blitcp_extension_publishes_official_references() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.blitcp")

    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)


def test_blitcp_actions_publish_risk_classes() -> None:
    assert risk_classes_for_command_action("Blitcp remote destination command") == ("network_egress",)
    assert risk_classes_for_command_action("Blitcp privilege escalation command") == ("execution",)
    assert risk_classes_for_command_action("Blitcp self-update command") == (
        "execution",
        "network_egress",
    )


def test_blitcp_option_values_cannot_forge_a_local_destination(tmp_path: Path) -> None:
    """An option value that looks like a path must not become the destination."""
    for command in (
        "blitcp --log-file /var/log/blitcp.log /data s3://backups/nightly",
        "blitcp --hash xxh128 /data s3://backups/nightly",
        "blitcp --preserve mode /data s3://backups/nightly",
        # Options may follow the operands. If the trailing option's value is
        # mistaken for the destination, the upload stops matching entirely,
        # so every value-taking option has to be declared.
        "blitcp /data s3://backups/nightly --s3-region eu-west-1",
        "blitcp /data s3://backups/nightly --endpoint-url https://minio.example",
        "blitcp /data s3://backups/nightly --s3-profile archive",
        "blitcp /data smb://fileserver/share --smb-user backup-svc",
        "blitcp /data az://container/nightly --az-account storageacct",
    ):
        observations = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.blitcp", "enabled"),),
        ).evaluation.extension_observations
        rule_ids = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.blitcp"}
        assert "command.blitcp.remote-destination" in rule_ids, command
