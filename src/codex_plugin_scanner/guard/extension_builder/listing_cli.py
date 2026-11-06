"""Print optional listing metadata from a validated native contribution kit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from .errors import BuilderError
from .kit import load_kit
from .listing import listing_template


def main(argv: list[str] | None = None, *, output: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kit", type=Path, help="Existing contribution kit; no files are changed")
    args = parser.parse_args(argv)
    destination = output if output is not None else sys.stdout
    try:
        kit = load_kit(args.kit)
        rendered = listing_template(kit.discovery.metadata)
    except BuilderError as error:
        print(f"{error.code}: {error}", file=sys.stderr)
        return error.exit_code
    except OSError:
        print("Could not read the contribution kit. No files were changed.", file=sys.stderr)
        return 2
    print(rendered, end="", file=destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
