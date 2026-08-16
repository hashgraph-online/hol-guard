FROM ghcr.io/astral-sh/uv:0.9.26-python3.12-bookworm-slim

WORKDIR /hol-guard

COPY pyproject.toml uv.lock README.md ./
COPY docs ./docs
COPY src ./src
COPY scripts/mdm ./scripts/mdm

RUN uv sync --extra dev --frozen

ENV PATH="/hol-guard/.venv/bin:${PATH}" \
    PYTHONPATH="/hol-guard/src" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1"

ENTRYPOINT ["python"]
