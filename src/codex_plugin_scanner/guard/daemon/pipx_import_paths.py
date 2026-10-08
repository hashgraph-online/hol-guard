"""Resolve pipx shared libraries without executing Python startup hooks."""

from pathlib import Path


def pipx_shared_import_paths(prefix: Path, configured_paths: dict[str, str]) -> tuple[Path, ...]:
    if prefix.parent.name != "venvs":
        return ()
    try:
        shared_root = (prefix.parent.parent / "shared").resolve(strict=True)
    except (OSError, RuntimeError):
        return ()
    paths: list[Path] = []
    for key in ("purelib", "platlib"):
        value = configured_paths.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            local_library = Path(value).expanduser().resolve(strict=True)
            suffix = local_library.relative_to(prefix)
            if not suffix.parts or suffix.parts[0] not in {"lib", "Lib"} or suffix.name != "site-packages":
                continue
            metadata = local_library / "pipx_shared.pth"
            try:
                if metadata.is_symlink():
                    continue
                with metadata.open("rb") as stream:
                    raw = stream.read(4097)
                if len(raw) > 4096:
                    continue
                content = raw.decode("utf-8")
            except FileNotFoundError:
                candidate = shared_root / suffix
            else:
                lines = content.splitlines()
                if len(lines) != 1 or not lines[0] or lines[0] != lines[0].strip():
                    continue
                candidate = Path(lines[0])
                if not candidate.is_absolute():
                    continue
            resolved = candidate.resolve(strict=True)
            relative_shared = resolved.relative_to(shared_root)
            if (
                relative_shared.parts
                and relative_shared.parts[0] in {"lib", "Lib"}
                and resolved.name == "site-packages"
                and resolved.is_dir()
                and resolved not in paths
            ):
                paths.append(resolved)
        except (OSError, RuntimeError, UnicodeError, ValueError):
            continue
    return tuple(paths)
