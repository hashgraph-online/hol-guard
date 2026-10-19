FROM python:3.12.12-slim-bookworm
WORKDIR /app
COPY server.py /app/server.py
COPY static /app/static
USER 65532:65532
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz',timeout=2).read()"]
ENTRYPOINT ["python", "-I", "-B", "/app/server.py", "--state", "/state", "--bind", "0.0.0.0", "--port", "8787"]
