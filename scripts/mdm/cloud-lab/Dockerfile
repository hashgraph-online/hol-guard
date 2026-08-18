FROM ghcr.io/astral-sh/uv:0.9.26-python3.12-bookworm-slim@sha256:add251a8fbfa14ff5e115adf93cb113c7b58c57bc84f0992164f5b6631b3451f

ARG HOL_MDM_LAB_UID=10001
ARG HOL_MDM_LAB_GID=10001

WORKDIR /hol-guard

COPY pyproject.toml uv.lock README.md ./
COPY docs ./docs
COPY src ./src
COPY scripts/mdm ./scripts/mdm

RUN uv sync --frozen \
    && groupadd --gid "${HOL_MDM_LAB_GID}" hol-mdm \
    && useradd --uid "${HOL_MDM_LAB_UID}" --gid "${HOL_MDM_LAB_GID}" \
        --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin hol-mdm \
    && mkdir -p /state /artifacts /etc/hol-guard \
    && chown -R "${HOL_MDM_LAB_UID}:${HOL_MDM_LAB_GID}" /state /artifacts /etc/hol-guard \
    && chmod 0700 /state /artifacts /etc/hol-guard

RUN mkdir -p /state /artifacts /etc/hol-guard \
    && chmod 1777 /state /artifacts

ENV PATH="/hol-guard/.venv/bin:${PATH}" \
    PYTHONPATH="/hol-guard/src" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1"

USER 10001:10001

ENTRYPOINT ["python"]
