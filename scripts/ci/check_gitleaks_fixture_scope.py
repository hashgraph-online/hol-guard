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
