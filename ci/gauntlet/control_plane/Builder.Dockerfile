# Built only from this reviewed controller directory; no candidate build context.
FROM ghcr.io/astral-sh/uv:0.9.26 AS uv
FROM docker.io/library/rust:1.88.0-slim-bookworm
COPY --from=uv /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 ca-certificates git jq npm pkg-config libssl-dev build-essential \
    && rm -rf /var/lib/apt/lists/*
ENV UV_PYTHON_INSTALL_DIR=/opt/gauntlet-python
RUN uv python install 3.12 && chmod -R a+rX /opt/gauntlet-python \
    && ln -s "$(readlink -f "$(uv python find 3.12)")" /usr/local/bin/gauntlet-python \
    && mkdir /work && chown 65532:65532 /work
ENV HOME=/work/home CARGO_HOME=/work/cargo UV_CACHE_DIR=/work/uv-cache \
    CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
COPY build_artifact.py /opt/gauntlet/build_artifact.py
COPY builder_entry.py /opt/gauntlet/builder_entry.py
USER 65532:65532
WORKDIR /work
RUN /usr/local/bin/gauntlet-python -I -B -c "import os,ssl,subprocess; assert os.getuid()==65532; subprocess.run(['/usr/local/cargo/bin/cargo','--version'],check=True)"
ENTRYPOINT ["/usr/local/bin/gauntlet-python", "-I", "-B", "/opt/gauntlet/builder_entry.py"]
