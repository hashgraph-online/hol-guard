FROM python:3.14-slim@sha256:44dd04494ee8f3b538294360e7c4b3acb87c8268e4d0a4828a6500b1eff50061

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY docker-requirements.txt LICENSE README.md /app/

RUN python3 -m pip install --no-deps --require-hashes -r /app/docker-requirements.txt

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
