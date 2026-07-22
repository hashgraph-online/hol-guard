FROM python:3.12-slim

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
