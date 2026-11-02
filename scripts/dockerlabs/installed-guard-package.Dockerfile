FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

COPY --chmod=0444 *.whl /opt/guard-proof/
RUN python -m pip install --no-cache-dir /opt/guard-proof/*.whl \
    && python -m pip check \
    && mkdir -p /opt/guard-proof-neutral \
    && chmod 0755 /opt/guard-proof /opt/guard-proof-neutral \
    && groupadd --system guardproof \
    && useradd --system --gid guardproof --home-dir /nonexistent --shell /usr/sbin/nologin guardproof
COPY --chmod=0555 installed_guard_package_origin.py /opt/guard-proof/installed_guard_package_origin.py

WORKDIR /opt/guard-proof-neutral
USER guardproof
ENTRYPOINT ["python", "/opt/guard-proof/installed_guard_package_origin.py"]
