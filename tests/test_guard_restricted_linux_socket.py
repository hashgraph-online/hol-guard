"""Socket restrictions preserve private IPC, not access to mounted host services."""

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import restricted_linux_landlock as boundary


def _evaluate(machine, *, arch, number, domain=1, kind=1, protocol=0):
    data = {0: number, 4: arch, 16: domain, 24: kind, 32: protocol}
    instructions = boundary._socket_filter(machine)
    accumulator = index = 0
    for _ in range(len(instructions)):
        code, yes, no, value = instructions[index]
        if code == 0x20:
            accumulator = data[value]
        elif code == 0x54:
            accumulator &= value
        elif code in {0x15, 0x35}:
            condition = accumulator == value if code == 0x15 else accumulator >= value
            index += yes if condition else no
        else:
            assert code == 0x06
            return value
        index += 1
    raise AssertionError("Filter did not return an action")


@pytest.mark.parametrize(
    "machine, arch, pair, socket, connect, ptrace, vmwrite",
    [
        ("x86_64", 0xC000003E, 53, 41, 42, 101, 311),
        ("aarch64", 0xC00000B7, 199, 198, 203, 117, 271),
    ],
)
def test_filter_uses_exact_architecture_and_allows_only_private_stream_pairs(
    machine, arch, pair, socket, connect, ptrace, vmwrite
):
    for number in (socket, connect, ptrace, vmwrite, 425, 426, 427):
        assert _evaluate(machine, arch=arch, number=number) == 0x50001
    for kind in (1, 1 | 0x80000, 1 | 0x800, 1 | 0x80800):
        assert _evaluate(machine, arch=arch, number=pair, kind=kind) == 0x7FFF0000
    for domain, kind, protocol in ((2, 1, 0), (1, 2, 0), (1, 5, 0), (1, 1, 1)):
        assert _evaluate(machine, arch=arch, number=pair, domain=domain, kind=kind, protocol=protocol) == 0x50001
    assert _evaluate(machine, arch=arch, number=0) == 0x7FFF0000
    assert _evaluate(machine, arch=0x40000003, number=0) == 0x80000000
    for number in (0x40000000 | socket, 0xFFFFFFFF):
        assert _evaluate(machine, arch=arch, number=number) == 0x80000000


@pytest.mark.parametrize("failure", [38, 22])
def test_failed_seccomp_installation_never_returns_success(monkeypatch, failure):
    calls = []

    def prctl(option, *args):
        calls.append(option)
        return -1 if option == failure else 0

    monkeypatch.setattr(boundary.platform, "system", lambda: "Linux")
    monkeypatch.setattr(boundary.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(boundary.ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(prctl=prctl))
    with pytest.raises(boundary.LinuxContainmentUnavailableError, match="socket isolation"):
        boundary.enforce_socket_boundary()
    assert calls == ([38] if failure == 38 else [38, 22])


def test_unknown_socket_architecture_is_not_guessed():
    with pytest.raises(boundary.LinuxContainmentUnavailableError, match="architecture"):
        boundary._socket_filter("unknown")
