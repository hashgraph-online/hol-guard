FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*
ARG HOL_GUARD_LAB_WHEEL
COPY ${HOL_GUARD_LAB_WHEEL} /opt/wheels/
RUN python -m pip install --no-cache-dir /opt/wheels/*.whl \
    && rm -rf /opt/wheels
COPY tests/dockerlabs/command-extension-analytics/installed_server.py /opt/guard-lab/installed_server.py
WORKDIR /workspace
EXPOSE 4781
CMD ["python", "/opt/guard-lab/installed_server.py"]
