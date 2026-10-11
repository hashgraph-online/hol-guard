"""Record environment-secret classification from an unmodified Python checkout.

Run before retiring the Python classifier, with --source-root naming its base
checkout. Only synthetic script contents and portable path markers are saved.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_SOURCE = "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/environment_secret_dump.py"
_COMMANDS = (
    "",
    "ls",
    "printenv",
    "printenv PATH",
    "printenv HOME API_KEY",
    "printenv --null TOKEN",
    "printenv -u TOKEN PATH",
    "env",
    "env -i",
    "env PATH=/bin",
    "env echo hello",
    "env -u TOKEN printenv PATH",
    "env -u TOKEN printenv SECRET",
    "env --unknown",
    "echo $API_KEY",
    "echo ${AWS_SECRET_ACCESS_KEY:-missing}",
    "echo $PATH",
    r"echo \\$TOKEN",
    "printf '%s' $PASSWORD",
    "echo hello; printenv TOKEN",
    "echo hello && printenv HOME",
    "command printenv API_KEY",
    "sudo -u sample printenv TOKEN",
    "X=1 printenv PRIVATE_KEY",
    "python -c 'import os; print(os.environ)'",
    "python -c 'print(os.getenv(\"TOKEN\"))'",
    "python -c 'print(os.environ.get(\"PATH\"))'",
    "python -c 'print(os.environ[\"SECRET\"])'",
    "python -c 'print(os.environ[name])'",
    "python -c 'print(os.environ.copy())'",
    'python -c \'os.environ.setdefault("PATH", "x")\'',
    "python -c 'print(\"hello\")'",
    "python -cprint(os.environ)",
    "python3.12 -c 'print(os.environ.items())'",
    "pythonw.exe -c 'print(os.environ)'",
    "node -e 'console.log(process.env)'",
    "node -e 'console.log(process.env.TOKEN)'",
    "node -e 'console.log(process.env.PATH)'",
    "node -e 'console.log(process.env[name])'",
    "ruby -e 'puts ENV[\"PASSWORD\"]'",
    "perl -e 'print $TOKEN'",
    "php -e 'echo $API_KEY'",
    "bash -c 'echo $TOKEN'",
    "printenv auth_token",
    "printenv monkey",
    "printenv mykey",
    "printenv key",
    "printenv secret-value",
    "printenv PR\u0130VATE_KEY",
    "printenv PR\u0131VATE_KEY",
    "printenv API_\u212aEY",
    "printenv AP\u0130KEY",
    "printenv AP\u0131KEY",
    "printenv CREDENT\u0130ALS",
    "printenv pr\u0131vatekey",
    "printenv 'TOKEN\u001c'",
    "python -c 'print(os.getenv(\"AP\u0130KEY\"))'",
    "node -e 'console.log(process.env[\"TOKEN\u001c\"])'",
    "python -c 'print(os.env\u0131ron[\"TOKEN\"])'",
    "python -c 'print(os.environ[AP\u0131KEY])'",
    "python -c 'print(os.getenv(\u001c\"TOKEN\"))'",
    "node -e 'console.log(process.env[\u001c\"TOKEN\"])'",
    "echo ${TOKEN}",
    "echo $api_key",
    "echo '$TOKEN'",
    "python reader.py",
    "python benign.py",
    "node reader.js",
    "node benign.js",
    "python -m reader",
    "python missing.py",
    "python linked.py",
    "python linked-outside.py",
    "python ./reader.py",
    "python ~/reader.py",
    "python invalid.py",
    "python huge.py",
    "python nested/reader.py",
    "python ../outside.py",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = (args.source_root / _SOURCE).read_bytes()
    if b"def _segment_dumps_environment_secrets(" not in source:
        parser.error("source-root must contain the old Python implementation")
    sys.path.insert(0, str(args.source_root / "src"))
    classifier = importlib.import_module(
        "codex_plugin_scanner.guard.runtime.secret_file_request_services.environment_secret_dump"
    )
    if Path(classifier.__file__).resolve() != (args.source_root / _SOURCE).resolve():
        parser.error("the imported classifier must come from source-root")
    fixtures = {
        "reader.py": 'import os\nprint(os.environ["TOKEN"])\n',
        "benign.py": 'print("hello")\n',
        "reader.js": "console.log(process.env.TOKEN)\n",
        "benign.js": "console.log(process.env.PATH)\n",
        "nested/reader.py": "import os\nprint(os.environ)\n",
    }
    cases = []
    with tempfile.TemporaryDirectory(prefix="environment-secret-vectors-") as temporary:
        root = Path(temporary) / "workspace"
        root.mkdir()
        for name, contents in fixtures.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents, encoding="utf-8")
        (root / "linked.py").symlink_to(root / "reader.py")
        outside = Path(temporary) / "outside.py"
        outside.write_text(fixtures["reader.py"], encoding="utf-8")
        (root / "linked-outside.py").symlink_to(outside)
        (root / "invalid.py").write_bytes(b"\xff\xfe")
        (root / "huge.py").write_bytes(b"#" * (256 * 1024 + 1))
        names = ("PATH", "HOME", "TOKEN", "api_key", "PRIVATE_KEY", "key", "monkey", "secret-value")
        commands = dict.fromkeys(_COMMANDS)
        for name in names:
            for template in (
                "printenv {name}",
                "printenv --null {name}",
                "env printenv {name}",
                "command printenv {name}",
                "echo ${name}",
                "echo ${{{name}:-missing}}",
                "python -c 'print(os.environ[\"{name}\"])'",
                "python -c 'print(os.getenv(\"{name}\"))'",
                "node -e 'console.log(process.env.{name})'",
                "node -e 'console.log(process.env[\"{name}\"])'",
                "ruby -e 'puts ENV[\"{name}\"]'",
                "php -e 'echo System.getenv(\"{name}\")'",
            ):
                commands[template.format(name=name)] = None
        for command in commands:
            result = classifier.environment_secret_dump_request(
                tool_name="Shell",
                normalized_tool_name="shell",
                command_text=command,
                cwd=root,
                home_dir=root,
            )
            cases.append({"command": command, "matched": result is not None})
        previous_cwd = Path.cwd()
        try:
            os.chdir(root)
            for command in ("python reader.py", "python linked.py", "python ../outside.py", "python linked-outside.py"):
                result = classifier.environment_secret_dump_request(
                    tool_name="Shell",
                    normalized_tool_name="shell",
                    command_text=command,
                    cwd=None,
                    home_dir=root,
                )
                cases.append({"command": command, "cwd": None, "matched": result is not None})
        finally:
            os.chdir(previous_cwd)
    head = subprocess.check_output(["git", "-C", str(args.source_root), "rev-parse", "HEAD"], text=True).strip()
    document = {
        "schema": "environment-secret-dump-python-vectors.v1",
        "source_commit": head,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "fixtures": fixtures,
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Recorded {len(cases)} old-Python vectors at {head}")


if __name__ == "__main__":
    main()
