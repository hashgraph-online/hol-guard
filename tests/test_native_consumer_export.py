"""Native consumer shard export and LCOV merge boundaries."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.ci import native_consumer_coverage as consumer


@pytest.mark.parametrize("boundary", ["unbound-signature", "same-profile-in-two-groups"])
def test_profiles_cannot_be_assigned_to_unbound_or_aliased_binary_groups(artifact_consumer, boundary):
    fixture = artifact_consumer
    profile_directory = consumer.profiles(fixture.root)
    profile_directory.mkdir(parents=True)
    if boundary == "unbound-signature":
        (profile_directory / "ci-native-999_0.profraw").write_bytes(b"foreign binary counters")
    else:
        first = profile_directory / "ci-native-101_0.profraw"
        first.write_bytes(b"one physical binary profile")
        os.link(first, profile_directory / "ci-native-202_0.profraw")
    output = fixture.root / "unqualified-export"
    with pytest.raises(ValueError):
        consumer.export_shard(fixture.root, fixture.bundle_directory, output, 0)
    assert not (output / "metadata.json").exists()


@pytest.mark.parametrize("reverse", [False, True], ids=["runtime-first", "command-source-first"])
def test_binary_piece_cannot_borrow_another_binarys_function_definition(tmp_path, reverse):
    runtime = tmp_path / "hol-guard-runtime.lcov"
    command_source = tmp_path / "guard-command-source.lcov"
    runtime.write_text(
        "SF:rust/crates/example/src/lib.rs\nFNDA:7,shared_symbol\nDA:1,7\nend_of_record\n",
        encoding="utf-8",
    )
    command_source.write_text(
        "SF:rust/crates/example/src/lib.rs\nFN:1,shared_symbol\nFNDA:0,shared_symbol\nDA:1,0\nend_of_record\n",
        encoding="utf-8",
    )
    pieces = [runtime, command_source]
    if reverse:
        pieces.reverse()
    with pytest.raises(ValueError):
        consumer.lcov.merge(pieces)


def test_binary_function_counters_may_precede_their_own_definitions(tmp_path):
    pieces = []
    for name, hits in (("hol-guard-runtime", 2), ("guard-command-source", 5)):
        path = tmp_path / f"{name}.lcov"
        path.write_text(
            "SF:rust/crates/example/src/lib.rs\n"
            f"FNDA:{hits},shared_symbol\nFN:1,shared_symbol\nDA:1,{hits}\n"
            "BRDA:1,0,0,-\nend_of_record\n",
            encoding="utf-8",
        )
        pieces.append(path)
    text = consumer.lcov.merge(pieces)
    assert "FN:1,shared_symbol\nFNDA:7,shared_symbol\nFNF:1\nFNH:1\n" in text
    assert "DA:1,7\nLF:1\nLH:1\n" in text
    assert "BRDA:1,0,0,-\nBRF:1\nBRH:0\n" in text


def test_cargo_uplifted_binary_may_have_two_links_but_downloaded_inputs_may_not(tmp_path):
    built = tmp_path / "deps-binary"
    built.write_bytes(b"binary")
    uplifted = tmp_path / "hol-guard-runtime"
    os.link(built, uplifted)
    assert consumer.regular(uplifted, allow_links=True) == uplifted
    with pytest.raises(ValueError):
        consumer.regular(uplifted)
    link = tmp_path / "symlink"
    link.symlink_to(built)
    with pytest.raises(ValueError):
        consumer.regular(link, allow_links=True)


@pytest.fixture
def recorded_export(artifact_consumer, monkeypatch):
    """Run export_shard against stand-in LLVM tools that record each profile merge."""
    fixture = artifact_consumer
    merges: list[dict] = []

    def fake_command(args, root, *, env=None, capture=False):
        assert args[1] == "merge"
        inputs = [Path(item) for item in args[args.index("--sparse") + 2 : args.index("-o")]]
        merges.append(
            {
                "mode": args[args.index("--sparse") + 1],
                "inputs": [(item.name, item.stat().st_size) for item in inputs],
            }
        )
        Path(args[args.index("-o") + 1]).write_bytes(b"profdata")
        return ""

    def fake_run(args, *, stdout, **_kwargs):
        stdout.write(fixture.zero_lcov)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(consumer, "command", fake_command)
    monkeypatch.setattr(consumer.subprocess, "run", fake_run)
    output = fixture.root / "exported-shard"
    return fixture, output, merges


def test_shard_without_native_execution_merges_an_empty_profile_for_each_binary(recorded_export):
    fixture, output, merges = recorded_export
    consumer.export_shard(fixture.root, fixture.bundle_directory, output, 0)
    assert merges == [{"mode": "--failure-mode=any", "inputs": [("empty-profile.txt", 0)]}] * 2
    lcov = (output / "rust-lcov.info").read_text(encoding="utf-8")
    assert "SF:rust/crates/example/src/lib.rs" in lcov
    hits = [line for line in lcov.splitlines() if line.startswith("DA:")]
    assert hits
    assert all(line.endswith(",0") for line in hits), "a shard with no native execution reports zero hits only"
    assert not (output / "empty-profile.txt").exists()


def test_shard_running_one_binary_keeps_the_other_binarys_zero_hit_mappings(recorded_export):
    fixture, output, merges = recorded_export
    profile_directory = consumer.profiles(fixture.root)
    profile_directory.mkdir(parents=True)
    (profile_directory / "ci-native-101_0.profraw").write_bytes(b"counters")
    consumer.export_shard(fixture.root, fixture.bundle_directory, output, 0)
    assert merges == [
        {"mode": "--failure-mode=any", "inputs": [("ci-native-101_0.profraw", 8)]},
        {"mode": "--failure-mode=any", "inputs": [("empty-profile.txt", 0)]},
    ]


def _llvm_profdata() -> Path | None:
    try:
        sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True, timeout=20).strip()
    except (OSError, subprocess.SubprocessError):
        return None
    for tool in Path(sysroot).glob("lib/rustlib/*/bin/llvm-profdata"):
        return tool
    return None


@pytest.mark.skipif(_llvm_profdata() is None or shutil.which("rustc") is None, reason="llvm-tools unavailable")
def test_real_llvm_profdata_accepts_an_empty_input_and_rejects_corrupt_counters(tmp_path):
    tool = _llvm_profdata()
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    corrupt = tmp_path / "ci-native-1_0.profraw"
    corrupt.write_bytes(b"not a profile")

    merged = subprocess.run(
        [str(tool), "merge", "--sparse", "--failure-mode=any", str(empty), "-o", str(tmp_path / "zero.profdata")],
        capture_output=True,
        check=False,
    )
    rejected = subprocess.run(
        [str(tool), "merge", "--sparse", "--failure-mode=any", str(corrupt), "-o", str(tmp_path / "bad.profdata")],
        capture_output=True,
        check=False,
    )
    assert merged.returncode == 0
    assert rejected.returncode != 0
