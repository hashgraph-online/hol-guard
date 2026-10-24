# Codex CLI browser-approval continuation lab.
# Exercises the same PreToolUse hook command Codex CLI runs after
# `hol-guard install codex`, then proves a browser allow continues the turn.
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

COPY tests/dockerlabs/codex-cli-resume/requirements.txt /opt/guard-lab/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /opt/guard-lab/requirements.txt \
  && rm -rf /root/.cache/pip \
  && groupadd --gid 10001 guardlab \
  && useradd --uid 10001 --gid guardlab --create-home --shell /usr/sbin/nologin guardlab

WORKDIR /hol-guard
ENV PYTHONPATH=/hol-guard/src
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
USER guardlab

CMD ["python", "-m", "pytest", "tests/test_codex_daemon_hook_resume.py", "-q", "--tb=short"]
