"""Typed projection of exact native system ELF interpreter admission."""

from pathlib import Path

from ..native_restricted_linux import linux_native


def resolve_linux_elf_loader(executable: Path) -> Path | None:
    value = linux_native("linux_elf_loader", {"executable": executable}, (str, type(None)))
    return None if value is None else Path(value)
