"""Prove audited Gitleaks fixtures cannot hide new credentials."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


def verify_fixture_scope(root: Path, executable: str) -> None:
    config = root / ".gitleaks.toml"
    relative = Path("tests/fixtures/bad-plugin/secrets.js")
    fixture = (root / relative).read_text(encoding="utf-8").splitlines()[0]
    # Generated only inside the temporary scanner inputs, never a credential.
    token = "gh" + "p_" + hashlib.sha256(b"gitleaks-scope-negative-control").hexdigest()[:36]
    unexpected = f'const token = "{token}";'
    changed = fixture.split('"', 1)[0] + f'"{token}";'
    cases = (
        ("audited fixture", relative, fixture, False),
        ("same bytes outside fixture", Path("src/production.js"), fixture, True),
        ("different value inside fixture", relative, changed, True),
        ("additional value on fixture line", relative, fixture + " " + unexpected, True),
        ("additional value in fixture file", relative, fixture + "\n" + unexpected, True),
    )
    binary_relative = Path("tests/test_security_binaries.py")
    historical = "SECRET_LINE = 'const token = \"sk-proj-" + "abcdefghijklmnopqrstuvwxyz0123456789\";\\n'"
    cases += (
        ("historical packaged-binary fixture", binary_relative, historical, False),
        ("packaged-binary fixture outside test", Path("src/production.py"), historical, True),
        ("changed packaged-binary fixture", binary_relative, historical.replace("0123456789", "9876543210"), True),
        ("credential beside packaged-binary fixture", binary_relative, historical + " " + unexpected, True),
        ("credential after packaged-binary fixture", binary_relative, historical + "\n" + unexpected, True),
    )
    pem_relative = Path("rust/crates/guard-contained-process/src/runtime_resources/resource_tests.rs")
    pem_lines = (root / pem_relative).read_text(encoding="utf-8").splitlines()
    framing = [index for index, line in enumerate(pem_lines) if "PRIVATE KEY" in line]
    if len(framing) != 2:
        raise RuntimeError("private-key framing fixture changed; re-audit its exception")
    pem_fixture = "\n".join(pem_lines[framing[0] : framing[1] + 1])
    cases += (
        ("audited private-key framing", pem_relative, pem_fixture, False),
        ("private-key framing outside fixture", Path("src/production.rs"), pem_fixture, True),
        ("changed private-key fixture payload", pem_relative, pem_fixture.replace("YWJjZA==", "ZWZnaA=="), True),
        ("extra credential on private-key fixture line", pem_relative, pem_fixture + " " + unexpected, True),
        ("extra credential in private-key fixture file", pem_relative, pem_fixture + "\n" + unexpected, True),
    )
    digest = hashlib.sha256(b"authoring-record-scope-control").hexdigest()
    record = Path("contributions/authoring/command.secret-example/record.json")
    digest_line = f'    "contributions/command-sources/command.secret-example.json": "{digest}",'
    credential_line = f'  "apiSecret": "{digest}"'
    cases += (
        ("authoring managed-file digest", record, digest_line, False),
        ("authoring revision digest", record, f'  "revisionDigest": "{digest}"', False),
        ("hex credential in authoring record", record, credential_line, True),
        ("client secret in authoring record", record, f'  "client_secret": "{digest}"', True),
        ("digest line outside authoring record", Path("src/record.json"), digest_line, True),
        ("digest line in nested record", record.parent / "nested/record.json", digest_line, True),
        ("non-digest managed-file value", record, digest_line.replace(digest, digest + "a"), True),
        ("credential beside authoring digest", record, digest_line + " " + credential_line, True),
        ("credential after authoring digest", record, digest_line + "\n" + credential_line, True),
    )
    vectors = Path("rust/crates/guard-runtime/testdata/guard_store/mcp_provider_read_vectors.json")
    fingerprint = "8d638ce7441755dda07242b347ddc6c5c13b0d7e107c61a7ae41223d466402cd"
    token_line = f'      "catalog_token": "{fingerprint}",'
    cases += (
        ("audited provider-catalog fingerprint", vectors, token_line, False),
        ("fingerprint line outside the vectors", Path("src/production.json"), token_line, True),
        ("changed fingerprint in the vectors", vectors, token_line.replace(fingerprint, fingerprint[::-1]), True),
        ("credential beside the fingerprint", vectors, token_line + " " + unexpected, True),
        ("credential after the fingerprint", vectors, token_line + "\n" + unexpected, True),
    )
    with tempfile.TemporaryDirectory(prefix="gitleaks-fixture-scope-") as temporary:
        base = Path(temporary)
        for index, (name, path, content, expect_leak) in enumerate(cases):
            case = base / str(index)
            target = case / path
            target.parent.mkdir(parents=True)
            target.write_text(content + "\n", encoding="utf-8")
            report = base / f"report-{index}.json"
            process = subprocess.run(
                [
                    executable,
                    "dir",
                    "--config",
                    str(config),
                    "--no-banner",
                    "--redact",
                    "--exit-code",
                    "1",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report),
                    ".",
                ],
                cwd=case,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if process.returncode != int(expect_leak):
                raise RuntimeError(f"{name}: unexpected scanner exit {process.returncode}")
            findings = json.loads(report.read_text(encoding="utf-8"))
            if bool(findings) != expect_leak:
                raise RuntimeError(f"{name}: scanner report did not match the expected result")
            if expect_leak and not any(Path(item["File"]).as_posix() == path.as_posix() for item in findings):
                raise RuntimeError(f"{name}: scanner did not report the injected fixture")
            print(f"PASS: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", default="gitleaks")
    args = parser.parse_args()
    verify_fixture_scope(Path(__file__).resolve().parents[2], args.gitleaks)


if __name__ == "__main__":
    main()
