FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY docker-requirements.txt /app/
COPY src /app/src

RUN python3 -m pip install --require-hashes -r /app/docker-requirements.txt

RUN groupadd --system scanner && \
    useradd --system --gid scanner --create-home --home-dir /home/scanner scanner && \
    mkdir -p /workspace && \
    chown -R scanner:scanner /workspace /home/scanner

WORKDIR /workspace

USER scanner

ENTRYPOINT ["python3", "-m", "codex_plugin_scanner.cli"]
