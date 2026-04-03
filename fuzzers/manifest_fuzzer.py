import sys

import atheris

with atheris.instrument_imports():
    from codex_plugin_scanner.checks.manifest import load_manifest_text


def test_one_input(data: bytes) -> None:
    load_manifest_text(data.decode("utf-8", errors="ignore"))


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
