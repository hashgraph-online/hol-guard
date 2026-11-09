"""Optional hook eligibility must not disable the evidence transport."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_native_policy_snapshot_direct_lane import _publisher


def test_hook_transport_tracks_home_eligibility_without_disabling_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher = _publisher(tmp_path)
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))

    def client(**_kwargs: object) -> bytes:
        return b""

    publisher._last_runtime_status = SimpleNamespace(identity=SimpleNamespace(path=str(tmp_path / "runtime")))
    publisher._client_request = client
    transport = (tmp_path / "runtime", client)
    assert publisher.direct_hook_transport() == transport
    publisher.bind_direct_lane_daemon_home(home)
    assert publisher.direct_hook_transport() == transport
    publisher.bind_direct_lane_daemon_home(tmp_path / "different-home")
    assert publisher.direct_hook_transport() is None
    assert publisher.direct_evidence_transport() == transport
    publisher.bind_direct_lane_daemon_home(home)
    assert publisher.direct_hook_transport() == transport
