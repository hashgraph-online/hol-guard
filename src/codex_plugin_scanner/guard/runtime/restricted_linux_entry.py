"""Compatibility locator for the packaged native fixed-plan namespace entry."""

import sys
from pathlib import Path

PLAN_DIRECTORY = Path("/guard-linux-plan")
PLAN_FILENAME = "linux-plan.json"


def main() -> int:
    # Namespace construction invokes the packaged native launcher directly.
    # Direct legacy Python entry has no authority to execute a command.
    print(
        "HOL Guard could not enforce the validated Linux execution boundary. Execution was not started.",
        file=sys.stderr,
    )
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
