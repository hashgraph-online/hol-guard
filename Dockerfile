FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY docker-requirements.txt LICENSE README.md /app/

RUN python3 -m pip install --require-hashes -r /app/docker-requirements.txt

COPY src /app/src

RUN cat <<'EOF' >/usr/local/bin/codex-plugin-scanner
#!/usr/bin/env python3
from __future__ import annotations

import os
import sys

WORKSPACE = "/workspace"
SOURCE_ROOT = "/app/src"

sys.path = [
    SOURCE_ROOT,
    *[
        path
        for path in sys.path
        if path not in {"", "."}
        and os.path.abspath(path or os.curdir) != WORKSPACE
        and not os.path.abspath(path or os.curdir).startswith(f"{WORKSPACE}{os.sep}")
    ],
]

from codex_plugin_scanner.cli import main

raise SystemExit(main())
EOF
RUN chmod 0755 /usr/local/bin/codex-plugin-scanner

RUN groupadd --system scanner && \
    useradd --system --gid scanner --create-home --home-dir /home/scanner scanner && \
    mkdir -p /workspace && \
    chown -R scanner:scanner /workspace /home/scanner

WORKDIR /workspace

USER scanner

ENTRYPOINT ["codex-plugin-scanner"]
