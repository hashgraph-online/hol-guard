"""In-process source for the isolated hook-interpreter identity probe."""

from __future__ import annotations

PROBE_CODE = r"""
import importlib
import importlib.metadata
import json
import pathlib
import sys

expected = json.loads(sys.argv[1])
import_roots = expected["import_roots"]
for root in reversed(import_roots):
    sys.path.insert(0, root)

package = importlib.import_module("codex_plugin_scanner")
crypto = importlib.import_module("cryptography")
cli = importlib.import_module("codex_plugin_scanner.cli")
version_module = importlib.import_module("codex_plugin_scanner.version")

package_file = pathlib.Path(package.__file__).resolve(strict=True)
package_root = package_file.parent.parent
crypto_file = pathlib.Path(crypto.__file__).resolve(strict=True)
crypto_distribution = importlib.metadata.distribution("cryptography")
crypto_distribution_root = pathlib.Path(crypto_distribution.locate_file("")).resolve(strict=True)

try:
    hol_distribution = importlib.metadata.distribution("hol-guard")
except importlib.metadata.PackageNotFoundError:
    hol_distribution = None

if hol_distribution is None:
    hol_distribution_root = None
    entry_point = "codex_plugin_scanner.cli:main" if callable(getattr(cli, "main", None)) else ""
else:
    hol_distribution_root = pathlib.Path(hol_distribution.locate_file("")).resolve(strict=True)
    entry_points = {
        item.name: item.value
        for item in hol_distribution.entry_points
        if item.group == "console_scripts"
    }
    entry_point = entry_points.get("hol-guard", "")

payload = {
    "schema": 2,
    "resolved_executable": str(pathlib.Path(sys.executable).resolve(strict=True)),
    "package_file": str(package_file),
    "package_root": str(package_root),
    "cryptography_file": str(crypto_file),
    "import_roots": import_roots,
    "hol_distribution_root": str(hol_distribution_root) if hol_distribution_root is not None else None,
    "cryptography_distribution_root": str(crypto_distribution_root),
    "version": str(version_module.__version__),
    "entry_point": entry_point,
}
sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
"""

__all__ = ["PROBE_CODE"]
