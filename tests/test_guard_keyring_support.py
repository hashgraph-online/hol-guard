from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast


def test_subprocess_keyring_writes_are_atomic_and_lossless(tmp_path: Path) -> None:
    store_path = tmp_path / "keyring.json"
    support_path = Path(__file__).parent / "support"
    environment = {
        **os.environ,
        "HOL_GUARD_TEST_KEYRING_FILE": str(store_path),
        "PYTHONPATH": str(support_path),
    }

    def write_secret(index: int) -> None:
        _ = subprocess.run(
            [
                sys.executable,
                "-c",
                "import keyring; keyring.set_password('guard', 'secret-' + __import__('sys').argv[1], 'value')",
                str(index),
            ],
            check=True,
            env=environment,
            capture_output=True,
            text=True,
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        _ = tuple(executor.map(write_secret, range(32)))

    payload = cast(object, json.loads(store_path.read_text(encoding="utf-8")))
    assert payload == {"guard": {f"secret-{index}": "value" for index in range(32)}}
