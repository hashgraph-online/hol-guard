FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

LABEL io.modelcontextprotocol.server.name="io.github.hashgraph-online/hol-guard"

WORKDIR /app

COPY docker-requirements.txt LICENSE README.md /app/

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    python3 -m pip install --no-deps --require-hashes -r /app/docker-requirements.txt && \
    apt-get purge -y --auto-remove gcc libc6-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY src /app/src

RUN cat <<'EOF' >/usr/local/bin/plugin-scanner
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
RUN chmod 0755 /usr/local/bin/plugin-scanner

RUN groupadd --system scanner && \
    useradd --system --gid scanner --create-home --home-dir /home/scanner scanner && \
    mkdir -p /workspace && \
    chown -R scanner:scanner /workspace /home/scanner

WORKDIR /workspace

USER scanner

ENTRYPOINT ["plugin-scanner"]
