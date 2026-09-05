from __future__ import annotations

import json
import sys
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parents[1]
LAB = ROOT / "scripts" / "mdm" / "cloud-lab"
sys.path.insert(0, str(LAB))

from lab_server import CloudServer  # noqa: E402
from lab_support import ADMIN_HEADER  # noqa: E402

_PUBLIC_LAB_AUTHORITY = "public-lab-fixture"


class _ReflectedStateStore:
    def __init__(self, value: str) -> None:
        self.value = value

    def state(self, _workspace_id: str | None) -> dict[str, str]:
        return {"value": self.value}


def test_cloud_lab_json_response_is_html_safe_without_changing_values() -> None:
    hostile_value = "</script><script>alert(1)</script>&"
    server = CloudServer(
        ("127.0.0.1", 0),
        _ReflectedStateStore(hostile_value),  # type: ignore[arg-type]
        _PUBLIC_LAB_AUTHORITY,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_port}/admin/state",
        headers={ADMIN_HEADER: _PUBLIC_LAB_AUTHORITY},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw_body = response.read()
            response_headers = response.headers
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert json.loads(raw_body)["value"] == hostile_value
    assert b"<" not in raw_body
    assert b">" not in raw_body
    assert b"&" not in raw_body
    assert b"\\u003cscript\\u003e" in raw_body
    assert response_headers.get("Content-Type") == "application/json; charset=utf-8"
    assert response_headers.get("X-Content-Type-Options") == "nosniff"
