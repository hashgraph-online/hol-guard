from __future__ import annotations

import shutil
import subprocess
import sys


def main() -> int:
    executable = shutil.which("hol-guard")
    if executable is None:
        print("HOL Guard CLI was not installed into the MCPB uv environment.", file=sys.stderr)
        return 127

    completed = subprocess.run(
        [executable, "mcp", "serve", "--stdio"],
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
