FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

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
