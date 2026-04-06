FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src

RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install /app

WORKDIR /workspace

ENTRYPOINT ["codex-plugin-scanner"]
