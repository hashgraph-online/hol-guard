FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap git \
    && rm -rf /var/lib/apt/lists/*
ARG HOL_GUARD_LAB_WHEEL
COPY ${HOL_GUARD_LAB_WHEEL} /opt/wheels/
RUN python -m pip install --no-cache-dir /opt/wheels/*.whl \
    && rm -rf /opt/wheels
COPY tests/dockerlabs/command-extension-analytics/installed_server.py /opt/guard-lab/installed_server.py
COPY tests/dockerlabs/command-extension-analytics/github-cli-fixture.sh /opt/guard-lab/github-cli-fixture.sh
RUN chmod 0555 /opt/guard-lab/github-cli-fixture.sh
RUN groupadd --gid 10001 guardlab \
    && useradd --uid 10001 --gid guardlab --no-create-home --shell /usr/sbin/nologin guardlab \
    && install -d -o guardlab -g guardlab -m 0755 /guard-home /workspace
WORKDIR /workspace
EXPOSE 4781
USER guardlab
CMD ["python", "/opt/guard-lab/installed_server.py"]
