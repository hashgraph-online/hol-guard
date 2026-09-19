"""Synthetic fixtures and independent installed Secrets qualification cases."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .probe_installed_offline_secrets_api import probe_api

if TYPE_CHECKING:
    from .probe_installed_offline_secrets import Probe


def _rich_fixture() -> tuple[dict[str, bytes], list[tuple[str, str, int]]]:
    _api = probe_api()
    files, expected = {}, []
    for index, (rule, name, value) in enumerate(_api._PROVIDERS):
        path = f"src/provider-{index:02d}.ts"
        files[path] = f'{name}="{value}"\n'.encode()
        expected.append((rule, path, 1))
    token = _api._PROVIDERS[0][2]
    generic = f'PAYMENTS_API_SECRET="{_api._BODY}"\n'
    contexts = (
        ("src/generic.ts", generic, "credential-assignment", 1),
        (".env.production", generic, "credential-assignment", 1),
        ("docs/generic.md", generic, None, 0),
        ("tests/fixture.py", "# fixture\n" + f'TOKEN="{token}"\n', None, 0),
        ("tests/.env", "# fixture\n" + f'TOKEN="{token}"\n', "github-token", 2),
        ("docs/provider.md", f'TOKEN="{token}"\n', "github-token", 1),
        ("src/unicode.ts", "# café\r\n# 雪\n" + f'TOKEN="{token}"\n', "github-token", 3),
        ("src/reference.ts", "API_SECRET=process.env.PAYMENTS_API_SECRET\n", None, 0),
        ("src/low.ts", 'API_SECRET="' + "A" * 36 + '"\n', None, 0),
        ("src/unrelated.ts", f'BUILD_CACHE_KEY="{_api._BODY}"\n', None, 0),
        ("android/google-services.json", f'current_key="{_api._PROVIDERS[11][2]}"\n', None, 0),
    )
    for path, text, rule, line in contexts:
        files[path] = text.encode()
        if rule:
            expected.append((rule, path, line))
    return files, expected


def _write_files(root: Path, files: dict[str, bytes]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _links_fixture(line: bytes) -> dict[str, bytes]:
    # NUL remains a Windows device name even with a filename extension.
    return {"original.ts": line, "invalid.ts": b"\xff\xfe", "binary_nul.ts": b"\0TOKEN=ordinary"}


def _exercise(probe: Probe, wheel: Path, source_sha: str) -> None:
    _api = probe_api()
    rich, expected = _api._rich_fixture()
    target = probe.root / "rich"
    probe.repository(target, rich)
    rich_result = probe.scan(
        "rich_launcher", target, expected=expected, files=len(rich), size=sum(map(len, rich.values()))
    )
    alias = probe.scan("rich_dedicated_launcher", target, alias=True, expected=expected)
    repeated = probe.scan(
        "rich_fail_and_repeat", target, arguments=("--fail-on-findings",), exit_code=3, expected=expected
    )
    _api._require(rich_result == alias == repeated, "full_public_entrypoint_parity")
    for relative in rich:
        (target / relative).write_bytes(b"VALUE=ordinary\n")
    probe.scan("safe_unstaged_working_tree", target, expected=[], files=len(rich))
    staged = probe.scan(
        "rich_staged_original_bytes",
        target,
        arguments=("--staged", "--fail-on-findings"),
        exit_code=3,
        expected=expected,
        source="staged",
        files=len(rich),
        size=sum(map(len, rich.values())),
    )
    staged_alias = probe.scan(
        "rich_staged_dedicated_launcher",
        target,
        alias=True,
        arguments=("--staged",),
        expected=expected,
        source="staged",
    )
    _api._require(staged == staged_alias, "full_public_staged_parity")
    normalized = _api.json.loads(_api.json.dumps(staged))
    for finding in normalized["findings"]:
        finding["source"] = "working_tree"
    _api._require(normalized == rich_result, "full_public_working_staged_parity")

    from codex_plugin_scanner.guard.secrets.cli import build_parser
    from codex_plugin_scanner.guard.secrets.secret_detection import scan_secret_text

    defaults = vars(build_parser().parse_args(["scan"]))
    expected_defaults = {
        "max_files": 5000,
        "max_file_bytes": 2097152,
        "max_total_bytes": 134217728,
        "max_findings": 500,
        "max_commits": 500,
    }
    _api._require({key: defaults[key] for key in expected_defaults} == expected_defaults, "installed_default_bounds")
    token = _api._PROVIDERS[0][2]
    line = f'TOKEN="{token}"\n'.encode()
    finding = scan_secret_text(line.decode(), path="src/settings.ts").findings[0]
    key = b"guard-offline-qualification-caller"
    public = finding.to_public_dict(fingerprint_key=key)
    independent_hmac = _api.hmac.new(key, ("github-token\0" + token).encode(), _api.hashlib.sha256).hexdigest()
    _api._require(public["fingerprint"] == independent_hmac, "caller_hmac")
    _api._require(finding.fingerprint(b"different-caller") != independent_hmac, "caller_hmac_separation")
    probe.cases.append(
        {"case": "installed_defaults_and_caller_hmac", "status": "passed", "defaults": expected_defaults}
    )

    bounded = probe.root / "bounds"
    probe.repository(bounded, {"a.ts": line, "b.ts": line})
    for staged_mode in (False, True):
        prefix = ("--staged",) if staged_mode else ()
        label = "staged" if staged_mode else "working"
        source = "staged" if staged_mode else "working_tree"
        for option in ("--max-files", "--max-findings"):
            probe.scan(
                label + option,
                bounded,
                arguments=(*prefix, option, "1", "--fail-on-findings"),
                exit_code=2,
                expected=[("github-token", "a.ts", 1)],
                source=source,
                truncated=True,
            )
        probe.scan(
            label + "_total_byte_bound",
            bounded,
            arguments=(*prefix, "--max-total-bytes", "1"),
            exit_code=2,
            expected=[],
            files=0,
            size=0,
            truncated=True,
        )
        probe.scan(
            label + "_file_byte_bound",
            bounded,
            arguments=(*prefix, "--max-file-bytes", "1"),
            exit_code=2 if staged_mode else 0,
            expected=[],
            files=0,
            size=0,
            truncated=staged_mode,
            errors=["git_staged_blob_unavailable_or_oversized"] if staged_mode else [],
        )
    many = probe.root / "many"
    probe.repository(many, {"a.ts": line * 501, "z.ts": b"VALUE=ordinary\n"})
    for staged_mode in (False, True):
        prefix = ("--staged",) if staged_mode else ()
        label = "staged" if staged_mode else "working"
        source = "staged" if staged_mode else "working_tree"
        probe.scan(
            label + "_default_findings",
            many,
            arguments=(*prefix, "--fail-on-findings"),
            exit_code=2,
            expected=[("github-token", "a.ts", number) for number in range(1, 501)],
            source=source,
            truncated=True,
        )
        probe.scan(
            label + "_explicit_findings",
            many,
            arguments=(*prefix, "--max-findings", "502", "--fail-on-findings"),
            exit_code=3,
            expected=[("github-token", "a.ts", number) for number in range(1, 502)],
            source=source,
        )
    large = probe.root / "large.ts"
    large.write_bytes(line + b" " * (2097153 - len(line)))
    probe.scan("default_file_size", large, expected=[], files=0, size=0)
    probe.scan(
        "explicit_file_size",
        large,
        arguments=("--max-file-bytes", "2097153"),
        expected=[("github-token", "large.ts", 1)],
        files=1,
        size=2097153,
    )
    probe.scan(
        "non_git_staged_error",
        probe.root,
        arguments=("--staged",),
        exit_code=2,
        expected=[],
        files=0,
        size=0,
        truncated=True,
        errors=["git_staged_enumeration_failed"],
    )
    probe.command(
        [str(probe.launchers["hol-guard"]), "secrets", "scan", str(probe.root / "missing"), "--json"],
        expected_exit=2,
        label="missing_target",
    )
    probe.cases[-1].update(status="passed", validation="expected_exit_and_privacy")
    probe.checkpoint()

    history = probe.root / "history"
    probe.repository(history, {"config.ts": line})
    probe.git(history, "commit", "-m", "first")
    (history / "config.ts").write_bytes(line + b"# revision two\n")
    probe.git(history, "add", ".")
    probe.git(history, "commit", "-m", "second")
    history_raw = probe.command(
        [
            str(probe.launchers["hol-guard"]),
            "secrets",
            "scan",
            str(history),
            "--json",
            "--history",
            "--max-commits",
            "1",
            "--fail-on-findings",
        ],
        expected_exit=2,
        label="explicit_history_commit_bound",
    )
    history_result = _api.json.loads(history_raw)
    _api._require(
        set(history_result) == _api._PUBLIC_KEYS
        and history_result["history_enabled"]
        and history_result["truncated"]
        and history_result["commits_scanned"] == 1
        and history_result["finding_count"] == 2
        and history_result["errors"] == []
        and history_result["truncation_reasons"] == ["max_commits"],
        "history_commit_bound",
    )
    _api._require(
        {finding["source"] for finding in history_result["findings"]} == {"working_tree", "git_history"},
        "history_occurrence_sources",
    )
    probe.cases[-1].update(
        status="passed", validation="independent_history_bounds", public_sha256=_api._public_digest(history_result)
    )
    probe.checkpoint()

    links = probe.root / "links"
    probe.repository(links, _api._links_fixture(line))
    link_expected = [("github-token", "original.ts", 1)]
    files = 3
    for name, operation in (
        ("hardlink", lambda path: _api.os.link(links / "original.ts", path)),
        ("internal_symlink", lambda path: path.symlink_to(links / "original.ts")),
    ):
        try:
            operation(links / (name + ".ts"))
        except (OSError, NotImplementedError) as error:
            _api._require(_api._unsupported_link(error), "link_setup_failed")
            probe.cases.append({"case": name, "status": "unsupported_by_host", "error_type": type(error).__name__})
        else:
            link_expected.append(("github-token", name + ".ts", 1))
            files += 1
    outside = probe.root / "outside.ts"
    outside.write_bytes(line)
    symlinks_supported = True
    try:
        (links / "external.ts").symlink_to(outside)
        (links / "dangling.ts").symlink_to(probe.root / "absent")
    except (OSError, NotImplementedError) as error:
        _api._require(_api._unsupported_link(error), "link_setup_failed")
        symlinks_supported = False
        probe.cases.append(
            {
                "case": "external_and_dangling_symlink",
                "status": "unsupported_by_host",
                "error_type": type(error).__name__,
            }
        )
    probe.scan(
        "links_invalid_encoding_binary", links, expected=link_expected, files=files, size=len(line) * len(link_expected)
    )
    for kind in ("growth", "replacement", "symlink"):
        if kind == "symlink" and not symlinks_supported:
            probe.cases.append({"case": "mutation_symlink", "status": "unsupported_by_host"})
            continue
        mutation_root = probe.root / ("mutation-" + kind)
        _api._write_files(mutation_root, {"a-changed.ts": b"initial", "b-observed.ts": line})
        command = [
            _api.sys.executable,
            "-I",
            str(_api.Path(_api.__file__).resolve()),
            "--wheel",
            str(wheel),
            "--source-sha",
            source_sha,
            "--mutation-worker",
            str(mutation_root),
            "--mutation-kind",
            kind,
        ]
        raw = probe.command(command, expected_exit=2, label="installed_entrypoint_mutation_" + kind)
        probe.public_result(
            raw,
            expected=[("github-token", "b-observed.ts", 1)],
            files=1,
            size=len(line),
            truncated=True,
            errors=["working_tree_file_changed"],
        )
    probe.checkpoint()
    _api._require(all(row["status"] in {"passed", "unsupported_by_host"} for row in probe.cases), "unfinished_case")
