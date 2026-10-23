"""Original seed data is pinned and parsed inertly before model execution."""

import hashlib

import pytest

from ci.gauntlet.benchmark import developer_seed_inputs as module


@pytest.fixture
def seed(tmp_path, monkeypatch):
    names = sorted(module.legacy_seed_literals())
    root = tmp_path / "gauntlet"
    (root / "benchmark").mkdir(parents=True)
    path = root / "full_tasks.py"
    raw = "\n".join(name + " = " + repr("public seed " + name) for name in names) + "\n"
    path.write_text(raw)
    monkeypatch.setattr(module, "__file__", str(root / "benchmark/developer_seed_inputs.py"))
    return path, names, raw


def test_exact_seed_bytes_are_identity_inputs_and_never_executable(seed, tmp_path):
    path, names, raw = seed
    trap = tmp_path / "must-not-execute"
    path.write_text("from pathlib import Path\nPath(" + repr(str(trap)) + ').write_text("executed")\n' + raw)
    result = module.seed_source_identity()
    assert result == {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "constants": names}
    assert not trap.exists()
    previous = result["sha256"]
    path.write_text(raw + "# changed public bytes\n")
    assert module.seed_source_identity()["sha256"] != previous


@pytest.mark.parametrize("mutation", ["missing", "symlink", "too-large", "missing-constant", "expression", "duplicate"])
def test_missing_or_ambiguous_public_seed_inputs_refused(seed, tmp_path, mutation):
    path, names, raw = seed
    if mutation == "missing":
        path.unlink()
    elif mutation == "symlink":
        other = tmp_path / "other.py"
        other.write_text(raw)
        path.unlink()
        path.symlink_to(other)
    elif mutation == "too-large":
        path.write_bytes(b"#" * (128 * 1024 + 1))
    elif mutation == "missing-constant":
        path.write_text("\n".join(raw.splitlines()[1:]))
    elif mutation == "expression":
        path.write_text(raw.replace(repr("public seed " + names[0]), "dangerous()"))
    else:
        path.write_text(raw + names[0] + ' = "duplicate"\n')
    with pytest.raises(ValueError):
        module.seed_source_identity()
