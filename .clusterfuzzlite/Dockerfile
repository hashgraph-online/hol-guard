FROM gcr.io/oss-fuzz-base/base-builder-python

RUN python3 -m pip install --no-cache-dir --no-binary=:all: --no-deps \
    "atheris==3.0.0"

COPY . $SRC/codex-plugin-scanner
WORKDIR $SRC/codex-plugin-scanner
COPY ./.clusterfuzzlite/build.sh $SRC/build.sh
