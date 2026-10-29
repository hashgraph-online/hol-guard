"""Ask native authority where a project's Vite build writes.

Projects often build into a directory other than `dist`, such as a static
folder another package serves. Which directory a config names, and whether the
build-output profile may write there, is native authority's reading: the
grammar, the bound on the config it will read and the admissibility walk live
in `vite_output.rs`, beside the package-script sink that admits the same build.
A second copy here is what drift looks like, so this module only carries the
question across and hands back the answer.
"""

from __future__ import annotations

from pathlib import Path


def declared_vite_output(cwd: Path, workspace: Path, *, config: Path | None = None) -> Path | None:
    """The config's literal output directory, None when the config names none.

    ``config`` is the file named by ``--config``. When the command names one,
    that file is the config Vite will load, so the default ``vite.config.*``
    beside it is not a substitute. A missing file leaves the output to
    ``--outDir`` or ``dist``. Native authority raises when the config names an
    output it cannot verify inside the project, so the build reports why
    instead of failing on a denied write.
    """
    from ..native_restricted_pytest import restricted_native

    fields: dict[str, object] = {"cwd": cwd, "workspace": workspace}
    if config is not None:
        fields["config"] = config
    answer = restricted_native("vite_declared_output", fields, (str, type(None)))
    return None if answer is None else Path(answer)


def config_bundle_directory(cwd: Path, workspace: Path, modules: Path) -> Path | None:
    """Where Vite's default loader writes the bundled config, when Guard can grant it.

    Vite bundles `vite.config.ts` into `node_modules/.vite-temp` next to the
    config, imports that one file and deletes it. Granting that directory lets
    configs that use `__dirname` load as they do outside Guard. None keeps the
    write-free runner loader.
    """
    from ..native_restricted_pytest import restricted_native

    answer = restricted_native(
        "vite_bundle_directory",
        {"cwd": cwd, "workspace": workspace, "modules": modules},
        (str, type(None)),
    )
    return None if answer is None else Path(answer)


__all__ = ["config_bundle_directory", "declared_vite_output"]
