#!/usr/bin/env python3
"""Testable helpers for the workspace-review authority GitHub workflow."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Final, cast

MAX_AUTHORITY_BYTES: Final = 16 * 1024
REQUEST_ENV: Final = "AUTHORITY_REQUEST"
EXPECTED_DIGEST_ENV: Final = "EXPECTED_REQUEST_DIGEST"


class WorkflowAuthorityError(ValueError):
    """A workflow step rejected its public input or approval evidence."""


def _require_lower_digest(value: str) -> str:
    if len(value) != hashlib.sha256().digest_size * 2 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise WorkflowAuthorityError("invalid workspace review authority digest")
    return value


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise WorkflowAuthorityError("workspace review authority workflow environment is incomplete")
    return value


def _is_github_id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _load_json(path: Path) -> object:
    try:
        return cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise WorkflowAuthorityError("workspace review authority evidence is invalid") from error


def write_request(output: Path, raw: str | None = None) -> None:
    """Create the bounded, private request file exactly once."""

    value = _required_env(REQUEST_ENV) if raw is None else raw
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_AUTHORITY_BYTES:
        raise WorkflowAuthorityError("Authority request exceeds the size limit.")
    previous_umask = os.umask(0o077)
    try:
        try:
            with output.open("xb") as stream:
                _ = stream.write(encoded)
        except OSError as error:
            raise WorkflowAuthorityError("workspace review authority request is unavailable") from error
    finally:
        _ = os.umask(previous_umask)


def record_request(request: Path, *, output: Path | None = None, summary: Path | None = None) -> str:
    """Record the exact request digest and public review summary."""

    try:
        raw = request.read_bytes()
        parsed = cast(object, json.loads(raw))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise WorkflowAuthorityError("workspace review authority request is invalid") from error
    digest = hashlib.sha256(raw).hexdigest()
    output_path = output or Path(_required_env("GITHUB_OUTPUT"))
    summary_path = summary or Path(_required_env("GITHUB_STEP_SUMMARY"))
    try:
        with output_path.open("a", encoding="utf-8") as output_stream:
            _ = output_stream.write(f"digest={digest}\n")
        with summary_path.open("a", encoding="utf-8") as summary_stream:
            _ = summary_stream.write(f"Request SHA-256: `{digest}`\n\n")
            _ = summary_stream.write(
                "Approve only after verifying the workspace, installation, scope and generation bindings.\n\n"
            )
            _ = summary_stream.write(f"Approval comment: `authority-request-sha256:{digest}`\n\n")
            _ = summary_stream.write("```json\n" + json.dumps(parsed, indent=2, sort_keys=True) + "\n```\n")
    except (OSError, TypeError, ValueError) as error:
        raise WorkflowAuthorityError("workspace review authority summary is unavailable") from error
    return digest


def verify_custodian_approval(
    environment: Path,
    reviews: Path,
    *,
    expected_digest: str | None = None,
    initiators: Collection[str] | None = None,
) -> None:
    """Require a listed, independent custodian to approve the exact digest."""

    expected = _require_lower_digest(_required_env(EXPECTED_DIGEST_ENV) if expected_digest is None else expected_digest)
    actors = {
        actor.casefold()
        for actor in (initiators or (_required_env("GITHUB_ACTOR"), _required_env("GITHUB_TRIGGERING_ACTOR")))
    }
    environment_value = _load_json(environment)
    reviews_value = _load_json(reviews)
    if not isinstance(environment_value, dict) or not isinstance(reviews_value, list):
        raise WorkflowAuthorityError("Independent custodian approval of this request digest is required.")
    environment_mapping = cast(dict[object, object], environment_value)
    rules = environment_mapping.get("protection_rules")
    environment_id = environment_mapping.get("id")
    if not isinstance(rules, list) or not _is_github_id(environment_id):
        raise WorkflowAuthorityError("Independent custodian approval of this request digest is required.")

    custodians: set[int] = set()
    for raw_rule in cast(list[object], rules):
        if not isinstance(raw_rule, dict):
            continue
        rule = cast(dict[object, object], raw_rule)
        if rule.get("type") != "required_reviewers" or rule.get("prevent_self_review") is not True:
            continue
        reviewers = rule.get("reviewers")
        if not isinstance(reviewers, list):
            continue
        for raw_reviewer in cast(list[object], reviewers):
            if not isinstance(raw_reviewer, dict):
                continue
            reviewer = cast(dict[object, object], raw_reviewer)
            if reviewer.get("type") != "User" or not isinstance(reviewer.get("reviewer"), dict):
                continue
            identity = cast(dict[object, object], reviewer["reviewer"])
            if _is_github_id(identity.get("id")):
                custodians.add(cast(int, identity["id"]))

    expected_comment = f"authority-request-sha256:{expected}"
    for raw_review in cast(list[object], reviews_value):
        if not isinstance(raw_review, dict):
            continue
        review = cast(dict[object, object], raw_review)
        user = review.get("user")
        if not isinstance(user, dict):
            continue
        user_mapping = cast(dict[object, object], user)
        login = user_mapping.get("login")
        environments = review.get("environments")
        if not isinstance(login, str) or not isinstance(environments, list):
            continue
        environment_match = any(
            isinstance(item, dict)
            and _is_github_id(cast(dict[object, object], item).get("id"))
            and cast(dict[object, object], item).get("id") == environment_id
            for item in cast(list[object], environments)
        )
        if (
            review.get("state") == "approved"
            and isinstance(review.get("comment"), str)
            and cast(str, review["comment"]).strip() == expected_comment
            and _is_github_id(user_mapping.get("id"))
            and user_mapping.get("id") in custodians
            and login.casefold() not in actors
            and environment_match
        ):
            return
    raise WorkflowAuthorityError("Independent custodian approval of this request digest is required.")


def verify_reviewed_request(request: Path, *, expected_digest: str | None = None) -> None:
    """Reject any artifact whose bytes differ from the reviewed request."""

    expected = _require_lower_digest(_required_env(EXPECTED_DIGEST_ENV) if expected_digest is None else expected_digest)
    try:
        actual = hashlib.sha256(request.read_bytes()).hexdigest()
    except OSError as error:
        raise WorkflowAuthorityError("Reviewed authority request changed.") from error
    if not hmac.compare_digest(actual, expected):
        raise WorkflowAuthorityError("Reviewed authority request changed.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a workspace-review authority workflow step.")
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser("write-request")
    _ = write.add_argument("--output", required=True, type=Path)
    record = commands.add_parser("record-request")
    _ = record.add_argument("--request", required=True, type=Path)
    verify_approval = commands.add_parser("verify-custodian-approval")
    _ = verify_approval.add_argument("--environment", required=True, type=Path)
    _ = verify_approval.add_argument("--reviews", required=True, type=Path)
    verify_digest = commands.add_parser("verify-request-digest")
    _ = verify_digest.add_argument("--request", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    command = cast(str, args.command)
    try:
        if command == "write-request":
            write_request(cast(Path, args.output))
        elif command == "record-request":
            _ = record_request(cast(Path, args.request))
        elif command == "verify-custodian-approval":
            verify_custodian_approval(cast(Path, args.environment), cast(Path, args.reviews))
        else:
            verify_reviewed_request(cast(Path, args.request))
    except WorkflowAuthorityError as error:
        print(error, file=sys.stderr)
        return 1
    except Exception:
        print("workspace review authority workflow step rejected", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
